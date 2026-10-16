/*
** This file is a part of PassiveDNS.
**
** Copyright (C) 2010-2026, Edward Fjellskål <edwardfjellskaal@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*
** IP fragment reassembly and TCP DNS stream reassembly for PassiveDNS.
**
** Overlapping fragments are discarded. Incomplete fragments expire.
** A TCP stream is resynced when a sequence gap is seen. Each direction
** of a flow has its own buffer, capped at one maximum DNS-over-TCP message.
*/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>

#include "passivedns.h"
#include "dns.h"
#include "reasm.h"

#define FRAG_DATA 65535
#define FRAG_BITS ((FRAG_DATA + 7) / 8)
#define UNFRAG_MAX 512

extern globalconfig config;

typedef struct _ipfrag {
    struct _ipfrag *next;
    uint8_t af;
    uint32_t id;
    uint8_t proto;
    struct in6_addr src;
    struct in6_addr dst;
    time_t last;
    uint8_t *data;
    uint8_t *bits;
    uint8_t hdr[60];
    uint8_t ihl;
    uint8_t have_hdr;
    uint8_t unfrag[UNFRAG_MAX];
    uint16_t unfrag_len;
    uint16_t nh_at;
    uint8_t frag_next;
    uint8_t have_unfrag;
    uint16_t total;
    uint8_t have_last;
    size_t charged;
} ipfrag;

/* One list per capture thread. Hash fanout keeps one datagram together. */
static __thread ipfrag *frags = NULL;
static __thread uint32_t nfrags = 0;

static int bit_test(const uint8_t *b, uint32_t i)
{
    return (b[i >> 3] >> (i & 7)) & 1;
}

static void bit_set(uint8_t *b, uint32_t i)
{
    b[i >> 3] |= (uint8_t)(1u << (i & 7));
}

static void frag_free(ipfrag *f)
{
    ipfrag **pp = &frags;

    while (*pp) {
        if (*pp == f) {
            *pp = f->next;
            break;
        }
        pp = &(*pp)->next;
    }
    if (nfrags)
        nfrags--;
    free(f->data);
    free(f->bits);
    if (f->charged)
        mem_refund(f->charged);
    free(f);
}

static int addr_eq(const struct in6_addr *a, const struct in6_addr *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static void v4_to_addr(struct in6_addr *a, uint32_t ip)
{
    memset(a, 0, sizeof(*a));
#ifdef BSD_DERIVED
    a->__u6_addr.__u6_addr32[0] = ip;
#else
    a->s6_addr32[0] = ip;
#endif
}

static ipfrag *frag_find(uint8_t af, const struct in6_addr *src,
                         const struct in6_addr *dst, uint32_t id, uint8_t proto)
{
    ipfrag *f;

    for (f = frags; f; f = f->next) {
        if (f->af == af && f->id == id && f->proto == proto &&
            addr_eq(&f->src, src) && addr_eq(&f->dst, dst))
            return f;
    }
    return NULL;
}

static ipfrag *frag_new(uint8_t af, const struct in6_addr *src,
                        const struct in6_addr *dst, uint32_t id, uint8_t proto,
                        time_t now)
{
    ipfrag *f;
    size_t charge;

    if (nfrags >= FRAG_MAX)
        return NULL;
    charge = sizeof(ipfrag) + FRAG_DATA + FRAG_BITS;
    if (!mem_charge(charge))
        return NULL;
    f = (ipfrag *)calloc(1, sizeof(ipfrag));
    if (!f) {
        mem_refund(charge);
        return NULL;
    }
    f->data = (uint8_t *)calloc(1, FRAG_DATA);
    f->bits = (uint8_t *)calloc(1, FRAG_BITS);
    if (!f->data || !f->bits) {
        free(f->data);
        free(f->bits);
        free(f);
        mem_refund(charge);
        return NULL;
    }
    f->charged = charge;
    f->af = af;
    f->src = *src;
    f->dst = *dst;
    f->id = id;
    f->proto = proto;
    f->last = now;
    f->next = frags;
    frags = f;
    nfrags++;
    return f;
}

static int frag_cover(ipfrag *f, uint16_t off, const uint8_t *payload, uint16_t len)
{
    uint32_t i;

    if ((uint32_t)off + len > FRAG_DATA)
        return 0;
    for (i = 0; i < len; i++) {
        if (bit_test(f->bits, off + i))
            return 0;
    }
    memcpy(f->data + off, payload, len);
    for (i = 0; i < len; i++)
        bit_set(f->bits, off + i);
    return 1;
}

static int frag_complete(const ipfrag *f)
{
    uint32_t i;

    if (!f->have_last || f->total == 0)
        return 0;
    for (i = 0; i < f->total; i++) {
        if (!bit_test(f->bits, i))
            return 0;
    }
    return 1;
}

static int take_piece(ipfrag *f, uint16_t off, int more,
                      const uint8_t *payload, uint16_t len)
{
    if (len == 0 || (uint32_t)off + len > FRAG_DATA)
        return 0;
    if (!more && (off & 7)) {
        /* The last fragment may end on any byte. */
    }
    else if (more && (len & 7))
        return 0;
    if (more && ((uint32_t)off + len) & 7)
        return 0;
    if (!frag_cover(f, off, payload, len))
        return 0;
    if (!more) {
        if (f->have_last && f->total != (uint16_t)(off + len))
            return 0;
        f->have_last = 1;
        f->total = (uint16_t)(off + len);
    }
    else if (f->have_last && (uint32_t)off + len > f->total)
        return 0;
    return 1;
}

int ip4_defrag(packetinfo *pi)
{
    uint16_t foff;
    uint16_t off;
    int more;
    uint8_t ihl;
    uint16_t ip_len;
    uint16_t pay_len;
    const uint8_t *pay;
    struct in6_addr src, dst;
    ipfrag *f;
    uint8_t *pkt = NULL;

    foff = ntohs(pi->ip4->ip_off);
    off = (uint16_t)((foff & IP_OFFMASK) << 3);
    more = (foff & IP_MF) != 0;
    ihl = (uint8_t)(IP_HL(pi->ip4) * 4);
    ip_len = ntohs(pi->ip4->ip_len);
    if (ip_len < ihl)
        return 0;
    pay_len = (uint16_t)(ip_len - ihl);
    pay = pi->packet + pi->eth_hlen + ihl;
    if (pay > pi->end_ptr || (size_t)(pi->end_ptr - pay) < pay_len) {
        if (pay > pi->end_ptr)
            return 0;
        pay_len = (uint16_t)(pi->end_ptr - pay);
    }
    if (pay_len == 0)
        return 0;

    v4_to_addr(&src, pi->ip4->ip_src);
    v4_to_addr(&dst, pi->ip4->ip_dst);
    f = frag_find(AF_INET, &src, &dst, ntohs(pi->ip4->ip_id), pi->ip4->ip_p);
    if (!f) {
        f = frag_new(AF_INET, &src, &dst, ntohs(pi->ip4->ip_id),
                     pi->ip4->ip_p, pi->pheader->ts.tv_sec);
        if (!f)
            return 0;
    }
    f->last = pi->pheader->ts.tv_sec;
    f->proto = pi->ip4->ip_p;
    if (off == 0) {
        if (ihl > sizeof(f->hdr)) {
            frag_free(f);
            return 0;
        }
        memcpy(f->hdr, pi->ip4, ihl);
        f->ihl = ihl;
        f->have_hdr = 1;
    }
    if (!take_piece(f, off, more, pay, pay_len)) {
        frag_free(f);
        return 0;
    }
    if (!frag_complete(f) || !f->have_hdr)
        return 1;
    if ((uint32_t)f->ihl + f->total > 65535) {
        frag_free(f);
        return 0;
    }

    pkt = (uint8_t *)malloc((size_t)f->ihl + f->total);
    if (!pkt) {
        frag_free(f);
        return 0;
    }
    memcpy(pkt, f->hdr, f->ihl);
    memcpy(pkt + f->ihl, f->data, f->total);
    {
        ip4_header *ip = (ip4_header *)pkt;
        ip->ip_off = 0;
        ip->ip_len = htons((uint16_t)(f->ihl + f->total));
    }
    reasm_continue(pi, 0, pkt, (uint32_t)f->ihl + f->total);
    free(pkt);
    frag_free(f);
    return 1;
}

int ip6_defrag(packetinfo *pi, const uint8_t *unfrag, uint16_t unfrag_len,
               uint16_t nh_at, uint8_t frag_next, uint32_t id,
               uint16_t off_bytes, int more,
               const uint8_t *frag, uint16_t fraglen)
{
    ipfrag *f;
    uint8_t *pkt = NULL;
    uint32_t pktlen;

    if (unfrag_len < IP6_HEADER_LEN || unfrag_len > UNFRAG_MAX || nh_at >= unfrag_len)
        return 0;
    f = frag_find(AF_INET6, &pi->ip6->ip_src, &pi->ip6->ip_dst, id, IP_PROTO_FRAGMENT);
    if (!f) {
        f = frag_new(AF_INET6, &pi->ip6->ip_src, &pi->ip6->ip_dst, id,
                     IP_PROTO_FRAGMENT, pi->pheader->ts.tv_sec);
        if (!f)
            return 0;
    }
    f->last = pi->pheader->ts.tv_sec;
    if (off_bytes == 0) {
        memcpy(f->unfrag, unfrag, unfrag_len);
        f->unfrag_len = unfrag_len;
        f->nh_at = nh_at;
        f->frag_next = frag_next;
        f->have_unfrag = 1;
    }
    if (!take_piece(f, off_bytes, more, frag, fraglen)) {
        frag_free(f);
        return 0;
    }
    if (!frag_complete(f) || !f->have_unfrag)
        return 1;

    pktlen = (uint32_t)f->unfrag_len + f->total;
    if (pktlen < f->unfrag_len || pktlen - IP6_HEADER_LEN > 65535) {
        frag_free(f);
        return 0;
    }
    pkt = (uint8_t *)malloc(pktlen);
    if (!pkt) {
        frag_free(f);
        return 0;
    }
    memcpy(pkt, f->unfrag, f->unfrag_len);
    pkt[f->nh_at] = f->frag_next;
    memcpy(pkt + f->unfrag_len, f->data, f->total);
    {
        ip6_header *ip6 = (ip6_header *)pkt;
        ip6->len = htons((uint16_t)(pktlen - IP6_HEADER_LEN));
    }
    reasm_continue(pi, 1, pkt, pktlen);
    free(pkt);
    frag_free(f);
    return 1;
}

void tcp_buf_free(tcp_buf *tb)
{
    if (!tb)
        return;
    free(tb->data);
    tb->data = NULL;
    if (tb->charged)
        mem_refund(tb->charged);
    tb->charged = 0;
    tb->len = 0;
    tb->cap = 0;
    tb->have_seq = 0;
    tb->expect = 0;
}

static void tcp_buf_reset_data(tcp_buf *tb)
{
    tb->len = 0;
}

/* The first packet of a flow is the originator. Later packets in the
 * other direction belong in the other buffer, whatever sc was labeled. */
static int from_originator(packetinfo *pi)
{
    connection *cxt = pi->cxt;

    if (!cxt)
        return 1;
    if (pi->af == AF_INET6)
        return CMP_ADDR6(&cxt->s_ip, &PI_IP6SRC(pi)) &&
               CMP_PORT(cxt->s_port, pi->s_port);
    if (!pi->ip4)
        return 1;
    return CMP_ADDR4(&cxt->s_ip, pi->ip4->ip_src) &&
           CMP_PORT(cxt->s_port, pi->s_port);
}

static int tcp_buf_append(tcp_buf *tb, const uint8_t *p, uint32_t n)
{
    uint32_t need;
    uint8_t *grown;
    size_t extra;

    if (n > TCP_STREAM_MAX || tb->len > TCP_STREAM_MAX - n)
        return 0;
    need = tb->len + n;
    if (need > tb->cap) {
        uint32_t ncap = tb->cap ? tb->cap : 512;
        while (ncap < need) {
            if (ncap > TCP_STREAM_MAX / 2) {
                ncap = TCP_STREAM_MAX;
                break;
            }
            ncap *= 2;
        }
        if (ncap < need)
            return 0;
        extra = (size_t)ncap - tb->cap;
        if (!mem_charge(extra))
            return 0;
        grown = (uint8_t *)realloc(tb->data, ncap);
        if (!grown) {
            mem_refund(extra);
            return 0;
        }
        tb->data = grown;
        tb->cap = ncap;
        tb->charged += extra;
    }
    memcpy(tb->data + tb->len, p, n);
    tb->len += n;
    return 1;
}

void tcp_reassemble(packetinfo *pi)
{
    connection *cxt = pi->cxt;
    tcp_buf *tb;
    const uint8_t *payload;
    uint32_t plen;
    uint32_t seq;
    uint32_t data_seq;
    uint32_t seg_end;
    int syn;

    if (!cxt || !pi->tcph || !pi->payload)
        return;
    tb = from_originator(pi) ? &cxt->to_server : &cxt->to_client;
    payload = pi->payload;
    plen = pi->plen;
    seq = ntohl(pi->tcph->t_seq);
    syn = TCP_ISFLAGSET(pi->tcph, TF_SYN) ? 1 : 0;
    data_seq = seq + (uint32_t)syn;
    seg_end = data_seq + plen;

    if (!tb->have_seq) {
        tb->expect = data_seq;
        tb->have_seq = 1;
    }
    if (plen == 0)
        return;

    if ((int32_t)(data_seq - tb->expect) > 0) {
        /* A gap. Drop the partial message and resync on this segment. */
        tcp_buf_reset_data(tb);
        tb->expect = data_seq;
    }
    if ((int32_t)(data_seq - tb->expect) < 0) {
        uint32_t skip = tb->expect - data_seq;
        if (skip >= plen)
            return;
        payload += skip;
        plen -= skip;
    }
    if (!tcp_buf_append(tb, payload, plen)) {
        tcp_buf_free(tb);
        tb->have_seq = 1;
        tb->expect = seg_end;
        return;
    }
    tb->expect = seg_end;

    while (tb->len >= 2) {
        uint16_t mlen = (uint16_t)(((uint16_t)tb->data[0] << 8) | tb->data[1]);
        uint32_t used;
        const uint8_t *saved_payload;
        const uint8_t *saved_end;
        uint32_t saved_plen;

        if (mlen < 12 || (uint32_t)mlen + 2 > TCP_STREAM_MAX) {
            tcp_buf_reset_data(tb);
            return;
        }
        if (tb->len < (uint32_t)mlen + 2)
            return;
        saved_payload = pi->payload;
        saved_end = pi->end_ptr;
        saved_plen = pi->plen;
        pi->payload = tb->data + 2;
        pi->plen = mlen;
        pi->end_ptr = pi->payload + mlen;
        dns_parser(pi);
        pi->payload = saved_payload;
        pi->plen = saved_plen;
        pi->end_ptr = saved_end;
        used = (uint32_t)mlen + 2;
        memmove(tb->data, tb->data + used, tb->len - used);
        tb->len -= used;
    }
}

void reasm_expire(time_t now)
{
    ipfrag *f = frags;

    while (f) {
        ipfrag *next = f->next;
        if (now > f->last && (now - f->last) >= FRAG_TIMEOUT)
            frag_free(f);
        f = next;
    }
}

void reasm_shutdown(void)
{
    while (frags)
        frag_free(frags);
}
