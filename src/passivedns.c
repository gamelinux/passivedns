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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/*  I N C L U D E S  **********************************************************/
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <pcap.h>
#include <getopt.h>
#include <time.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <pthread.h>
#include <stdint.h>
#ifdef __linux__
#include <net/if.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if_packet.h>
#include <sys/prctl.h>
#endif /* __linux__ */
#include "passivedns.h"
#include "dns.h"
#include "reasm.h"

#ifdef HAVE_JSON
#include <jansson.h>
#endif /* HAVE_JSON */

#ifdef HAVE_PFRING
#include <pfring.h>
#endif /* HAVE_PFRING */

#ifndef CONFDIR
#define CONFDIR "/etc/passivedns/"
#endif

/*  G L O B A L S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;
connection *bucket[BUCKET_SIZE];
/* Capture threads keep a private flow table. NULL uses the global one. */
static __thread connection **tl_bucket;
static __thread struct timeval tl_tstamp;
static __thread int tl_tstamp_set;
static volatile sig_atomic_t signal_reopen_log_files = 0;

static connection **flow_buckets(void)
{
    return tl_bucket != NULL ? tl_bucket : bucket;
}

/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
static void show_version();
static void show_record_letters();
static void show_snapshot(int snaplen);
static void warn_if_gro(const char *dev);
static int parse_u32(const char *text, uint32_t *out);
void check_vlan (packetinfo *pi);
void prepare_null (packetinfo *pi);
void prepare_raw (packetinfo *pi);
void prepare_sll (packetinfo *pi);
void prepare_eth (packetinfo *pi);
int prepare_ip4 (packetinfo *pi);
void prepare_ip4ip (packetinfo *pi);
int prepare_ip6 (packetinfo *pi);
void prepare_ip6ip (packetinfo *pi);
int prepare_udp (packetinfo *pi);
int prepare_tcp (packetinfo *pi);
void parse_eth (packetinfo *pi);
void parse_ip4 (packetinfo *pi);
void parse_ip6 (packetinfo *pi);
void parse_udp (packetinfo *pi);
void parse_tcp (packetinfo *pi);
const char *u_ntop_src(packetinfo *pi, char *dest);
void set_pkt_end_ptr (packetinfo *pi);
void check_interrupt();
void end_sessions();
void set_end_sessions();
void set_end_dns_records();
void cxt_init();
int connection_tracking(packetinfo *pi);
connection *cxt_new(packetinfo *pi);
void del_connection(connection *, connection **);
void print_pdns_stats();
void free_config();
void reopen_log_files();
void game_over ();
void got_packet(u_char *useless, const struct pcap_pkthdr *pheader,
                const u_char *packet);
#ifdef HAVE_PFRING
void pfring_got_packet(const struct pfring_pkthdr *pfheader,
                       const u_char *packet, const u_char *useless);
#endif /* HAVE_PFRING */

/* F U N C T I O N S  ********************************************************/

static int pi_has(const packetinfo *pi, const uint8_t *p, size_t n)
{
    if (!pi->packet || !pi->end_ptr || !p)
        return 0;
    if (p < pi->packet || p > pi->end_ptr)
        return 0;
    if (n > (size_t)(pi->end_ptr - p))
        return 0;
    return 1;
}

static pthread_mutex_t mem_mu = PTHREAD_MUTEX_INITIALIZER;

int mem_charge(size_t n)
{
    int ok = 1;

    if (config.workers > 1)
        pthread_mutex_lock(&mem_mu);
    if (n > config.mem_limit_max)
        ok = 0;
    else if (config.mem_limit_size > config.mem_limit_max - n)
        ok = 0;
    else
        config.mem_limit_size += n;
    if (config.workers > 1)
        pthread_mutex_unlock(&mem_mu);
    return ok;
}

void mem_refund(size_t n)
{
    if (config.workers > 1)
        pthread_mutex_lock(&mem_mu);
    if (n >= config.mem_limit_size)
        config.mem_limit_size = 0;
    else
        config.mem_limit_size -= n;
    if (config.workers > 1)
        pthread_mutex_unlock(&mem_mu);
}

static void secure_log(FILE *fp)
{
    if (fp && fp != stdout)
        (void)fchmod(fileno(fp), S_IRUSR | S_IWUSR | S_IRGRP);
}

void reasm_continue(packetinfo *parent, int is_v6, uint8_t *buf, uint32_t len)
{
    packetinfo pi;
    struct pcap_pkthdr hdr;

    if (!parent || !buf || len < IP4_HEADER_LEN)
        return;
    memset(&pi, 0, sizeof(pi));
    hdr = *parent->pheader;
    hdr.caplen = len;
    hdr.len = len;
    pi.pheader = &hdr;
    pi.packet = buf;
    pi.end_ptr = buf + len;
    pi.eth_hlen = 0;
    pi.eth_hdr = parent->eth_hdr;
    pi.tunnel = parent->tunnel;
    if (!is_v6) {
        if (!prepare_ip4(&pi))
            return;
        parse_ip4(&pi);
    }
    else {
        if (!prepare_ip6(&pi))
            return;
        parse_ip6(&pi);
    }
}

#ifdef HAVE_PFRING

void pfring_got_packet(const struct pfring_pkthdr *pfheader,
                       const u_char *packet, const u_char *useless)
{
    /* pcap_pkthdr and pfring_pkthdr are identical to each other*/
    struct pcap_pkthdr *pheader = (struct pcap_pkthdr *)pfheader;

    /* Set timestamp if it's not set */
    if (pheader->ts.tv_sec == 0)
        pheader->ts.tv_sec = time(NULL);

    /* pfring_loop orders the arguments differently than pcap_loop */
    got_packet((u_char *)useless, (const struct pcap_pkthdr *)pheader, packet);
}

#endif /* HAVE_PFRING */

void got_packet(u_char *useless, const struct pcap_pkthdr *pheader,
                const u_char *packet)
{
    PDNS_U32_INC(config.p_s.got_packets);
    packetinfo pstruct = {0};
    packetinfo *pi = &pstruct;
    pi->packet = packet;
    pi->pheader = pheader;
    set_pkt_end_ptr (pi);
    /* The cache thread owns config.tstamp. Capture threads keep their own. */
    if (config.workers > 1) {
        tl_tstamp = pi->pheader->ts;
        tl_tstamp_set = 1;
    }
    else {
        memcpy(&config.tstamp, &pi->pheader->ts, sizeof(struct timeval));
        if (signal_reopen_log_files)
            reopen_log_files();
        if (config.intr_flag != 0)
            check_interrupt();
        config.inpacket = 1;
    }

    switch (config.linktype) {
        case DLT_NULL:
            prepare_null(pi);
            break;
        case DLT_RAW:
            prepare_raw(pi);
            break;
#ifdef DLT_LINUX_SLL
        case DLT_LINUX_SLL:
            prepare_sll(pi);
            break;
#endif
        default:
            prepare_eth(pi);
            check_vlan(pi);
            break;
    }

    switch (pi->eth_type) {
        case ETHERNET_TYPE_IP:
            if (prepare_ip4(pi))
                parse_ip4(pi);
            break;
        case ETHERNET_TYPE_IPV6:
            if (prepare_ip6(pi))
                parse_ip6(pi);
            break;
        default:
            PDNS_U32_INC(config.p_s.otherl_recv);
            //vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi->eth_hdr->eth_ip_type);
            break;
    }

    if (config.workers <= 1)
        config.inpacket = 0;
}

void prepare_null(packetinfo *pi)
{
    if (!pi_has(pi, pi->packet, LOOPBACK_HDR_LEN))
        return;
    pi->eth_hlen = LOOPBACK_HDR_LEN;
    if ((u_int32_t)*pi->packet == AF_INET)
        pi->eth_type = ETHERNET_TYPE_IP;
    else
        pi->eth_type = ETHERNET_TYPE_IPV6;
}

void prepare_raw(packetinfo *pi)
{
    pi->eth_hlen = 0;
    if (!pi_has(pi, pi->packet, 1))
        return;
    if (IP_V((ip4_header *)pi->packet) == 4)
        pi->eth_type = ETHERNET_TYPE_IP;
    else
        pi->eth_type = ETHERNET_TYPE_IPV6;
}

void prepare_sll(packetinfo *pi)
{
    pi->eth_hlen = SLL_HDR_LEN;
    if (!pi_has(pi, pi->packet + SLL_HDR_LEN, 1))
        return;
    if (IP_V((ip4_header *)(pi->packet + SLL_HDR_LEN)) == 4)
        pi->eth_type = ETHERNET_TYPE_IP;
    else
        pi->eth_type = ETHERNET_TYPE_IPV6;
}

void prepare_eth(packetinfo *pi)
{
    if (pi->packet + ETHERNET_HEADER_LEN > pi->end_ptr)
        return;

    PDNS_U32_INC(config.p_s.eth_recv);
    pi->eth_hdr = (ether_header *) (pi->packet);
    pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
    pi->eth_hlen = ETHERNET_HEADER_LEN;
}

void check_vlan(packetinfo *pi)
{
    if (!pi->eth_hdr)
        return;

    if (pi->eth_type == ETHERNET_TYPE_8021Q) {
        if (!pi_has(pi, pi->packet, ETHERNET_8021Q_HEADER_LEN))
            return;
        vlog(0x3, "[*] ETHERNET TYPE 8021Q\n");
        PDNS_U32_INC(config.p_s.vlan_recv);
        pi->vlan = pi->eth_hdr->eth_8_vid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_8_ip_type);
        pi->eth_hlen += 4;
        if (pi->eth_type == ETHERNET_TYPE_8021Q) {
            if (!pi_has(pi, pi->packet, ETHERNET_802Q1MT_HEADER_LEN)) {
                pi->eth_type = 0;
                return;
            }
            vlog(0x3, "[*] ETHERNET TYPE 8021Q in 8021Q\n");
            pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
            pi->eth_hlen += 4;
            pi->vlan = pi->eth_hdr->eth_82_vid;
        }
    }
    else if (pi->eth_type == ETHERNET_TYPE_802Q1MT ||
             pi->eth_type == ETHERNET_TYPE_802Q1MT2 ||
             pi->eth_type == ETHERNET_TYPE_802Q1MT3 ||
             pi->eth_type == ETHERNET_TYPE_8021AD) {
        if (!pi_has(pi, pi->packet, ETHERNET_802Q1MT_HEADER_LEN))
            return;
        vlog(0x3, "[*] ETHERNET TYPE 802Q1MT\n");
        pi->mvlan = pi->eth_hdr->eth_82_mvid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
        pi->eth_hlen += 8;
    }
}

int prepare_ip4(packetinfo *pi)
{
    const uint8_t *p;
    uint8_t ihl;
    uint16_t ip_len;

    p = pi->packet + pi->eth_hlen;
    if (!pi_has(pi, p, IP4_HEADER_LEN))
        return 0;
    pi->ip4 = (ip4_header *)p;
    if (IP_V(pi->ip4) != 4)
        return 0;
    ihl = IP_HL(pi->ip4);
    if (ihl < 5)
        return 0;
    if (!pi_has(pi, p, (size_t)ihl * 4))
        return 0;
    ip_len = ntohs(pi->ip4->ip_len);
    if (ip_len < (uint16_t)ihl * 4)
        return 0;
    pi->af = AF_INET;
    pi->s_ttl = pi->ip4->ip_ttl;
    pi->packet_bytes = (uint16_t)(ip_len - (uint16_t)ihl * 4);
    pi->l4_off = pi->eth_hlen + (uint32_t)ihl * 4;
    PDNS_U32_INC(config.p_s.ip4_recv);
    return 1;
}

static int l4_ready(packetinfo *pi, uint8_t proto)
{
    if (proto == IP_PROTO_TCP) {
        if (!prepare_tcp(pi))
            return 0;
        parse_tcp(pi);
        return 1;
    }
    if (proto == IP_PROTO_UDP) {
        if (!prepare_udp(pi))
            return 0;
        parse_udp(pi);
        return 1;
    }
    return 0;
}

void parse_ip4(packetinfo *pi)
{
    uint16_t foff;

    if (!pi->ip4)
        return;
    foff = ntohs(pi->ip4->ip_off);
    if (foff & (IP_MF | IP_OFFMASK)) {
        ip4_defrag(pi);
        return;
    }

    switch (pi->ip4->ip_p) {
        case IP_PROTO_TCP:
        case IP_PROTO_UDP:
            l4_ready(pi, pi->ip4->ip_p);
            break;
        case IP_PROTO_IPIP:
        case IP_PROTO_IP4:
        case IP_PROTO_IP6:
            prepare_ip4ip(pi);
            break;
        default:
            break;
    }
}

static void tunnel_into(packetinfo *pi, const uint8_t *inner, uint8_t proto)
{
    packetinfo pipi;

    if (!inner || inner <= pi->packet + pi->eth_hlen)
        return;
    if (pi->tunnel >= MAX_IP_TUNNEL)
        return;
    if (!pi_has(pi, inner, 1))
        return;
    memset(&pipi, 0, sizeof(pipi));
    pipi.pheader = pi->pheader;
    pipi.packet = inner;
    pipi.end_ptr = pi->end_ptr;
    pipi.eth_hlen = 0;
    pipi.eth_hdr = pi->eth_hdr;
    pipi.tunnel = (uint8_t)(pi->tunnel + 1);
    if (proto == IP_PROTO_IP6) {
        PDNS_U32_INC(config.p_s.ip6ip_recv);
        if (prepare_ip6(&pipi))
            parse_ip6(&pipi);
    }
    else {
        PDNS_U32_INC(config.p_s.ip4ip_recv);
        if (prepare_ip4(&pipi))
            parse_ip4(&pipi);
    }
}

void prepare_ip6ip(packetinfo *pi)
{
    tunnel_into(pi, pi->packet + pi->l4_off, pi->proto == IP_PROTO_IP6 ?
                IP_PROTO_IP6 : IP_PROTO_IPIP);
}

void prepare_ip4ip(packetinfo *pi)
{
    const uint8_t *inner = pi->packet + pi->l4_off;
    uint8_t inner_proto = (pi->ip4 && pi->ip4->ip_p == IP_PROTO_IP6) ?
                          IP_PROTO_IP6 : IP_PROTO_IPIP;
    tunnel_into(pi, inner, inner_proto);
}

int prepare_ip6(packetinfo *pi)
{
    const uint8_t *p;
    uint16_t plen;

    p = pi->packet + pi->eth_hlen;
    if (!pi_has(pi, p, IP6_HEADER_LEN))
        return 0;
    pi->ip6 = (ip6_header *)p;
    if (((ntohl(pi->ip6->vcl) >> 28) & 0xf) != 6)
        return 0;
    plen = ntohs(pi->ip6->len);
    pi->af = AF_INET6;
    pi->s_ttl = pi->ip6->hop_lmt;
    pi->packet_bytes = plen;
    pi->l4_off = pi->eth_hlen + IP6_HEADER_LEN;
    PDNS_U32_INC(config.p_s.ip6_recv);
    return 1;
}

static const uint8_t *ip6_limit(packetinfo *pi)
{
    const uint8_t *start = pi->packet + pi->eth_hlen;
    const uint8_t *claimed = start + IP6_HEADER_LEN + ntohs(pi->ip6->len);

    if (claimed < start)
        return pi->end_ptr;
    if (claimed < pi->end_ptr)
        return claimed;
    return pi->end_ptr;
}

void parse_ip6(packetinfo *pi)
{
    const uint8_t *cur;
    const uint8_t *end;
    const uint8_t *nh_ptr;
    uint8_t nxt;
    int depth = 0;

    if (!pi->ip6)
        return;
    nxt = pi->ip6->next;
    cur = pi->packet + pi->eth_hlen + IP6_HEADER_LEN;
    end = ip6_limit(pi);
    nh_ptr = ((const uint8_t *)pi->ip6) + 6;

    while (depth++ < 8) {
        if (nxt == IP_PROTO_TCP || nxt == IP_PROTO_UDP) {
            if (cur < pi->packet)
                return;
            pi->l4_off = (uint32_t)(cur - pi->packet);
            l4_ready(pi, nxt);
            return;
        }
        if (nxt == IP_PROTO_IPIP || nxt == IP_PROTO_IP4 || nxt == IP_PROTO_IP6) {
            if (cur < pi->packet)
                return;
            pi->l4_off = (uint32_t)(cur - pi->packet);
            pi->proto = nxt;
            prepare_ip6ip(pi);
            return;
        }
        if (nxt == IP_PROTO_HOPOPTS || nxt == IP_PROTO_DSTOPTS ||
            nxt == IP_PROTO_ROUTING) {
            uint32_t skip;
            if (!pi_has(pi, cur, 2) || cur + 2 > end)
                return;
            skip = ((uint32_t)cur[1] + 1) * 8;
            if (!pi_has(pi, cur, skip) || cur + skip > end)
                return;
            nh_ptr = cur;
            nxt = cur[0];
            cur += skip;
            continue;
        }
        if (nxt == IP_PROTO_AH) {
            uint32_t skip;
            if (!pi_has(pi, cur, 2) || cur + 2 > end)
                return;
            skip = ((uint32_t)cur[1] + 2) * 4;
            if (!pi_has(pi, cur, skip) || cur + skip > end)
                return;
            nh_ptr = cur;
            nxt = cur[0];
            cur += skip;
            continue;
        }
        if (nxt == IP_PROTO_FRAGMENT) {
            uint16_t offm;
            uint16_t off_bytes;
            uint32_t id;
            int more;
            const uint8_t *frag;
            const uint8_t *unfrag;
            uint16_t unfrag_len;
            uint16_t nh_at;
            uint16_t fraglen;

            if (!pi_has(pi, cur, 8) || cur + 8 > end)
                return;
            offm = (uint16_t)((cur[2] << 8) | cur[3]);
            off_bytes = (uint16_t)((offm >> 3) * 8);
            more = offm & 0x1;
            memcpy(&id, cur + 4, sizeof(id));
            id = ntohl(id);
            frag = cur + 8;
            if (frag > end)
                return;
            fraglen = (uint16_t)(end - frag);
            if (off_bytes == 0 && !more) {
                nh_ptr = cur;
                nxt = cur[0];
                cur = frag;
                continue;
            }
            unfrag = pi->packet + pi->eth_hlen;
            if (cur < unfrag || (size_t)(cur - unfrag) > 65535)
                return;
            unfrag_len = (uint16_t)(cur - unfrag);
            nh_at = (uint16_t)(nh_ptr - unfrag);
            ip6_defrag(pi, unfrag, unfrag_len, nh_at, cur[0], id,
                       off_bytes, more, frag, fraglen);
            return;
        }
        return;
    }
}

void set_pkt_end_ptr(packetinfo *pi)
{
    /* caplen is the number of bytes libpcap actually provided. */
    pi->end_ptr = pi->packet + pi->pheader->caplen;
}

/* End of the IP datagram, never past the captured bytes.
 * Ethernet padding and a short snaplen stay outside the L4 length. */
static const uint8_t *datagram_end(packetinfo *pi)
{
    const uint8_t *base;
    uint32_t span;

    if (!pi->packet || !pi->end_ptr || pi->end_ptr < pi->packet)
        return pi->end_ptr;
    base = pi->packet + pi->eth_hlen;
    if (base < pi->packet || base > pi->end_ptr)
        return pi->end_ptr;
    if (pi->af == AF_INET && pi->ip4)
        span = ntohs(pi->ip4->ip_len);
    else if (pi->af == AF_INET6 && pi->ip6)
        span = (uint32_t)IP6_HEADER_LEN + ntohs(pi->ip6->len);
    else
        return pi->end_ptr;
    if (span > (uint32_t)(pi->end_ptr - base))
        return pi->end_ptr;
    return base + span;
}

int prepare_tcp(packetinfo *pi)
{
    const uint8_t *th;
    const uint8_t *dend;
    unsigned doff;

    th = pi->packet + pi->l4_off;
    if (!pi_has(pi, th, TCP_HEADER_LEN))
        return 0;
    pi->tcph = (tcp_header *)th;
    doff = TCP_OFFSET(pi->tcph);
    if (doff < 5)
        return 0;
    if (!pi_has(pi, th, (size_t)doff * 4))
        return 0;
    pi->payload = th + (size_t)doff * 4;
    dend = datagram_end(pi);
    if (pi->payload > dend)
        return 0;
    pi->plen = (uint32_t)(dend - pi->payload);
    pi->proto = IP_PROTO_TCP;
    pi->s_port = pi->tcph->src_port;
    pi->d_port = pi->tcph->dst_port;
    PDNS_U32_INC(config.p_s.tcp_recv);
    connection_tracking(pi);
    return pi->cxt != NULL;
}

int prepare_udp(packetinfo *pi)
{
    const uint8_t *uh;
    const uint8_t *dend;
    uint16_t ulen;
    uint32_t have;
    uint32_t claimed;

    uh = pi->packet + pi->l4_off;
    if (!pi_has(pi, uh, UDP_HEADER_LEN))
        return 0;
    pi->udph = (udp_header *)uh;
    ulen = ntohs(pi->udph->len);
    if (ulen < UDP_HEADER_LEN)
        return 0;
    pi->payload = uh + UDP_HEADER_LEN;
    dend = datagram_end(pi);
    if (pi->payload > dend)
        return 0;
    have = (uint32_t)(dend - pi->payload);
    claimed = (uint32_t)ulen - UDP_HEADER_LEN;
    pi->plen = claimed < have ? claimed : have;
    pi->proto = IP_PROTO_UDP;
    pi->s_port = pi->udph->src_port;
    pi->d_port = pi->udph->dst_port;
    PDNS_U32_INC(config.p_s.udp_recv);
    connection_tracking(pi);
    return pi->cxt != NULL;
}

void parse_tcp(packetinfo *pi)
{
    if (!pi->tcph || !pi->cxt)
        return;
    dlog("[D] Parsing TCP packet...\n");
    tcp_reassemble(pi);
}

void parse_udp(packetinfo *pi)
{
    if (!pi->udph || !pi->cxt || pi->plen < 12)
        return;
    dlog("[D] Parsing UDP packet...\n");
    dns_parser(pi);
}

int connection_tracking(packetinfo *pi)
{
    struct in6_addr *ip_src;
    struct in6_addr *ip_dst;
    struct in6_addr ips;
    struct in6_addr ipd;
    uint16_t src_port = pi->s_port;
    uint16_t dst_port = pi->d_port;
    int af = pi->af;
    connection *cxt = NULL;
    connection *head = NULL;
    uint32_t hash;

    if(af == AF_INET6){
        ip_src = &PI_IP6SRC(pi);
        ip_dst = &PI_IP6DST(pi);
    }
    else {
#ifdef BSD_DERIVED
        ips.__u6_addr.__u6_addr32[0] = pi->ip4->ip_src;
        ipd.__u6_addr.__u6_addr32[0] = pi->ip4->ip_dst;
#else
        ips.s6_addr32[0] = pi->ip4->ip_src;
        ipd.s6_addr32[0] = pi->ip4->ip_dst;
#endif
        ip_src = &ips;
        ip_dst = &ipd;
    }

    /* Find the right connection bucket */
    if (af == AF_INET)
        hash = CXT_HASH4(IP4ADDR(ip_src), IP4ADDR(ip_dst), src_port, dst_port,
                         pi->proto);
    else if (af == AF_INET6)
        hash = CXT_HASH6(ip_src, ip_dst, src_port, dst_port, pi->proto);
    else {
        dlog("[D] Only CTX with AF_INET and AF_INET6 are supported: %d\n", af);
        return 0;
    }

    cxt = flow_buckets()[hash];
    head = cxt;

    /* Search through the bucket */
    while (cxt != NULL)
    {
        /* Two-way compare of given connection against connection table */
        if (af == AF_INET) {
            if (CMP_CXT4(cxt, IP4ADDR(ip_src), src_port, IP4ADDR(ip_dst), dst_port)) {
                /* Client sends first packet (TCP/SYN - UDP?) hence this is a client */
                dlog("[D] Found existing v4 client connection.\n");
                return cxt_update_client(cxt, pi);
            }
            else if (CMP_CXT4(cxt, IP4ADDR(ip_dst), dst_port, IP4ADDR(ip_src), src_port)) {
                /* pi->sc is still unset here. A reversed tuple is the other
                 * side of the flow. After a query has stored its id, that
                 * side is the server. Before that, the first packet was the
                 * answer and this packet is the query. */
                if (cxt->plid != 0) {
                    dlog("[D] Found existing v4 server connection.\n");
                    return cxt_update_server(cxt, pi);
                }
                dlog("[D] Found existing unknown v4 server connection.\n");
                return cxt_update_client(cxt, pi);
            }
        }
        else if (af == AF_INET6) {
            if (CMP_CXT6(cxt, ip_src, src_port, ip_dst, dst_port)) {
                dlog("[D] Found existing v6 client connection.\n");
                return cxt_update_client(cxt, pi);
            }
            else if (CMP_CXT6(cxt, ip_dst, dst_port, ip_src, src_port)) {
                dlog("[D] Found existing v6 client connection.\n");
                return cxt_update_server(cxt, pi);
            }
        }
        cxt = cxt->next;
    }
    /* Bucket turned upside down didn't yield anything. New connection */
    dlog("[D] New connection.\n");
    cxt = cxt_new(pi);
    if (cxt == NULL)
        return 0;

    /* New connections are pushed on to the head of bucket[s_hash] */
    cxt->next = head;
    if (head != NULL)
        /* Are we double linked? */
        head->prev = cxt;

    flow_buckets()[hash] = cxt;
    pi->cxt = cxt;
    return cxt_update_unknown(cxt, pi);
}

/* Freshly smelling connection :d */
connection *cxt_new(packetinfo *pi)
{
    struct in6_addr ips;
    struct in6_addr ipd;
    connection *cxt;

    if (config.max_connections && PDNS_U32_GET(config.curcxt) >= config.max_connections)
        return NULL;
    if (!mem_charge(sizeof(connection)))
        return NULL;
    cxt = (connection *) calloc(1, sizeof(connection));
    if (!cxt) {
        mem_refund(sizeof(connection));
        return NULL;
    }
    if (config.workers > 1)
        cxt->cxid = __atomic_add_fetch(&config.cxtrackerid, 1, __ATOMIC_RELAXED);
    else {
        config.cxtrackerid++;
        cxt->cxid = config.cxtrackerid;
    }
    cxt->af = pi->af;

    if (pi->tcph)
        cxt->s_tcpFlags |= pi->tcph->t_flags;

    cxt->start_time = pi->pheader->ts.tv_sec;
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if (pi->af == AF_INET6){
        cxt->s_ip = PI_IP6SRC(pi);
        cxt->d_ip = PI_IP6DST(pi);
    }
    else {
#ifdef BSD_DERIVED
        ips.__u6_addr.__u6_addr32[0] = pi->ip4->ip_src;
        ipd.__u6_addr.__u6_addr32[0] = pi->ip4->ip_dst;
#else
        ips.s6_addr32[0] = pi->ip4->ip_src;
        ipd.s6_addr32[0] = pi->ip4->ip_dst;
#endif
        cxt->s_ip = ips;
        cxt->d_ip = ipd;
    }

    cxt->s_port = pi->s_port;
    cxt->d_port = pi->d_port;
    cxt->proto = pi->proto;

    cxt->check = 0x00;
    cxt->reversed = 0;
    PDNS_U32_INC(config.curcxt);

    return cxt;
}

int cxt_update_client(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if (pi->tcph)
        cxt->s_tcpFlags |= pi->tcph->t_flags;

    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_CLIENT;

    if (cxt->s_total_bytes > MAX_BYTE_CHECK ||
        cxt->s_total_pkts  > MAX_PKT_CHECK) {
        return 0;   /* Don't Check! */
    }

    return SC_CLIENT;
}

int cxt_update_unknown(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if (pi->tcph)
        cxt->s_tcpFlags |= pi->tcph->t_flags;

    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_UNKNOWN;

    if (cxt->s_total_bytes > MAX_BYTE_CHECK ||
        cxt->s_total_pkts  > MAX_PKT_CHECK) {
        return 0;   /* Don't Check! */
    }

    return SC_UNKNOWN;
}

int cxt_update_server(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if (pi->tcph)
        cxt->d_tcpFlags |= pi->tcph->t_flags;

    cxt->d_total_bytes += pi->packet_bytes;
    cxt->d_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_SERVER;

    if (cxt->d_total_bytes > MAX_BYTE_CHECK ||
            cxt->d_total_pkts  > MAX_PKT_CHECK)
        return 0;   /* Don't check! */

    return SC_SERVER;
}

/* Drop a flow whose DNS answer has already been matched. The bucket
 * hash is symmetric, so the stored ends find the same chain the first
 * packet was inserted on. */
void cxt_release(packetinfo *pi)
{
    connection *cxt;
    uint32_t hash;

    if (pi == NULL || pi->cxt == NULL)
        return;
    cxt = pi->cxt;
    if (cxt->af == AF_INET)
        hash = CXT_HASH4(IP4ADDR(&cxt->s_ip), IP4ADDR(&cxt->d_ip),
                         cxt->s_port, cxt->d_port, cxt->proto);
    else if (cxt->af == AF_INET6)
        hash = CXT_HASH6(&cxt->s_ip, &cxt->d_ip,
                         cxt->s_port, cxt->d_port, cxt->proto);
    else
        return;
    pi->cxt = NULL;
    del_connection(cxt, &flow_buckets()[hash]);
}

void end_all_sessions()
{
    connection *cxt;
    int cxkey;
    config.llcxt = 0;

    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++)
    {
        cxt = flow_buckets()[cxkey];
        while (cxt != NULL)
        {
            config.llcxt++;
            if (cxt->prev)
                cxt->prev->next = cxt->next;
            if (cxt->next)
                cxt->next->prev = cxt->prev;
            connection *tmp = cxt;

            cxt = cxt->next;
            del_connection(tmp, &flow_buckets()[cxkey]);
            if (cxt == NULL)
                flow_buckets()[cxkey] = NULL;
        }
    }
    dlog("CXT in list before cleaning: %10u\n", config.llcxt);
    dlog("CXT in list after  cleaning: %10u\n", config.curcxt);
}

void end_sessions()
{
    connection *cxt;
    time_t check_time;
    check_time = tl_tstamp_set ? tl_tstamp.tv_sec : config.tstamp.tv_sec;
    int ended, expired = 0;
    config.llcxt = 0;

    int iter;

    for (iter = 0; iter < BUCKET_SIZE; iter++)
    {
        cxt = flow_buckets()[iter];
        while (cxt != NULL)
        {
            ended = 0;
            config.llcxt++;
            /* TCP */
            if (cxt->proto == IP_PROTO_TCP) {
                /* FIN from both sides, or RST from either side. */
                if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN)
                    ended = 1;
                else if (cxt->s_tcpFlags & TF_RST || cxt->d_tcpFlags & TF_RST)
                    ended = 1;
                else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT)
                    expired = 1;
            }
            /* UDP */
            else if (cxt->proto == IP_PROTO_UDP
                    && (check_time - cxt->last_pkt_time) > UDP_TIMEOUT)
                expired = 1;
            /* ICMP */
            else if (cxt->proto == IP_PROTO_ICMP ||
                    cxt->proto == IP6_PROTO_ICMP) {
                if ((check_time - cxt->last_pkt_time) > ICMP_TIMEOUT)
                     expired = 1;
            }
            /* All other protocols */
            else if ((check_time - cxt->last_pkt_time) > OTHER_TIMEOUT)
                expired = 1;

            if (ended == 1 || expired == 1) {
                /* Remove from the hash */
                if (cxt->prev)
                    cxt->prev->next = cxt->next;
                if (cxt->next)
                    cxt->next->prev = cxt->prev;
                connection *tmp = cxt;
                connection *tmp_pre = cxt->prev;

                ended = expired = 0;

                cxt = cxt->next;

                del_connection(tmp, &flow_buckets()[iter]);
                if (cxt == NULL && tmp_pre == NULL)
                    flow_buckets()[iter] = NULL;
            }
            else
                cxt = cxt->next;
        }
    }
    dlog("CXT in list before cleaning: %10u\n", config.llcxt);
    dlog("CXT in list after  cleaning: %10u\n", config.curcxt);
}

void del_connection(connection * cxt, connection ** bucket_ptr)
{
    connection *prev = cxt->prev;  /* Older connections */
    connection *next = cxt->next;  /* Newer connections */

    if (prev == NULL) {
        /* Beginning of list */
        *bucket_ptr = next;
        /* Not only entry */
        if (next)
            next->prev = NULL;
    }
    else if (next == NULL) {
        /* At end of list! */
        prev->next = NULL;
    }
    else {
        /* A node */
        prev->next = next;
        next->prev = prev;
    }

    tcp_buf_free(&cxt->to_server);
    tcp_buf_free(&cxt->to_client);
    mem_refund(sizeof(connection));
    free(cxt);
    cxt = NULL;
    PDNS_U32_DEC(config.curcxt);
}

const char *u_ntop_src(packetinfo *pi, char *dest)
{
    if (pi->af == AF_INET) {
        if (!inet_ntop(AF_INET, &pi->ip4->ip_src, dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    else if (pi->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &pi->ip6->ip_src, dest,
            INET6_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    return dest;
}

void check_interrupt()
{
    dlog("[D] In interrupt. Flag: %d\n",config.intr_flag);
    if (ISSET_INTERRUPT_END(config))
        game_over();

    else if (ISSET_INTERRUPT_SESSION(config))
        set_end_sessions();

    else if (ISSET_INTERRUPT_DNS(config))
        set_end_dns_records();

    else
        config.intr_flag = 0;
}

void sig_alarm_handler()
{
    time_t now_t;
    now_t = config.tstamp.tv_sec;

    dlog("[D] Got SIG ALRM: %lu\n", now_t);
    /* Each time check for timed out sessions */
    set_end_sessions();
    reasm_expire(now_t);

    /* Only check for timed-out dns records each 10 minutes */
    if ((now_t - config.dnslastchk) >= 600) {
        set_end_dns_records();
    }
    alarm(TIMEOUT);
}

void sig_hup_handler()
{
    signal_reopen_log_files = 1;
}

static int reopen_one(FILE **slot, const char *path)
{
    FILE *nf;

    if (slot == NULL || path == NULL)
        return -1;
    /* stdout has nothing to rotate. */
    if (path[0] == '-' && path[1] == '\0')
        return 0;

    nf = fopen(path, "a");
    if (nf == NULL) {
        elog("[!] Error reopening log file %s: %s\n", path, strerror(errno));
        syslog(LOG_ERR, "Error reopening log file %s: %s", path, strerror(errno));
        return -1;
    }
    secure_log(nf);
    if (*slot != NULL && *slot != stdout)
        fclose(*slot);
    *slot = nf;
    return 0;
}

/* One O_APPEND fd per process. A later write() of a whole line does not
 * share a stdio buffer with the other workers. */
static int open_append_log(const char *path)
{
    int fd;

    if (path == NULL)
        return -1;
    if (path[0] == '-' && path[1] == '\0')
        return STDOUT_FILENO;

    fd = open(path, O_CREAT | O_WRONLY | O_APPEND,
              S_IRUSR | S_IWUSR | S_IRGRP);
    if (fd < 0)
        return -1;
    if (fchmod(fd, S_IRUSR | S_IWUSR | S_IRGRP) != 0) {
        /* Mode is best-effort, same as secure_log(). */
    }
    return fd;
}

static int reopen_raw(int *slot, const char *path)
{
    int fd;

    if (slot == NULL || path == NULL)
        return -1;
    if (path[0] == '-' && path[1] == '\0')
        return 0;

    fd = open_append_log(path);
    if (fd < 0) {
        elog("[!] Error reopening log file %s: %s\n", path, strerror(errno));
        syslog(LOG_ERR, "Error reopening log file %s: %s", path, strerror(errno));
        return -1;
    }
    if (*slot >= 0 && *slot != STDOUT_FILENO && *slot != fd) {
        if (dup2(fd, *slot) < 0) {
            elog("[!] Error reopening log file %s: %s\n", path, strerror(errno));
            close(fd);
            return -1;
        }
        close(fd);
    }
    else
        *slot = fd;
    return 0;
}

void reopen_log_files()
{
    if (config.logfile_raw >= 0 || config.logfile_nxd_raw >= 0) {
        if (config.output_log)
            reopen_raw(&config.logfile_raw, config.logfile);
        if (config.output_log_nxd) {
            if (config.logfile_all)
                config.logfile_nxd_raw = config.logfile_raw;
            else
                reopen_raw(&config.logfile_nxd_raw, config.logfile_nxd);
        }
        signal_reopen_log_files = 0;
        return;
    }

    if (config.output_log)
        reopen_one(&config.logfile_fd, config.logfile);

    if (config.output_log_nxd) {
        if (config.logfile_all)
            config.logfile_nxd_fd = config.logfile_fd;
        else
            reopen_one(&config.logfile_nxd_fd, config.logfile_nxd);
    }
    signal_reopen_log_files = 0;
}

void set_end_dns_records()
{
    config.intr_flag |= INTERRUPT_DNS;

    if (config.inpacket == 0) {
        expire_dns_records();
        config.dnslastchk = config.tstamp.tv_sec;
        config.intr_flag &= ~INTERRUPT_DNS;
    }
}

void set_end_sessions()
{
    config.intr_flag |= INTERRUPT_SESSION;

    if (config.inpacket == 0) {
        end_sessions();
        config.intr_flag &= ~INTERRUPT_SESSION;
    }
}

static int set_chroot(void)
{
   char *absdir;

   if (chdir(config.chroot_dir) != 0) {
       elog("set_chroot: Can not chdir to \"%s\": %s\n",
            config.chroot_dir, strerror(errno));
       return ERROR;
   }

   absdir = getcwd(NULL, 0);
   if (absdir == NULL) {
       elog("set_chroot: getcwd failed: %s\n", strerror(errno));
       return ERROR;
   }

   if (chroot(absdir) < 0) {
       elog("Could not chroot to \"%s\": absolute: %s: %s\n",
            config.chroot_dir, absdir, strerror(errno));
       free(absdir);
       return ERROR;
   }
   free(absdir);

   if (chdir("/") < 0) {
       elog("Could not chdir to \"/\" after chroot: %s\n", strerror(errno));
       return ERROR;
   }

   return SUCCESS;
}

static int privs_resolved;
static int drop_do_setuid;
static int drop_do_setgid;
static int drop_was_root;
static int drop_clear_supp;
static uid_t drop_uid;
static gid_t drop_gid;
static int daemon_pid_fd = -1;
static int daemon_null_fd = -1;

static void resolve_privs(void)
{
    struct group *gr;
    struct passwd *pw = NULL;
    char *endptr;
    unsigned long groupid = 0;
    unsigned long userid = 0;
    const char *init_name = NULL;

    if (privs_resolved || !config.drop_privs_flag)
        return;

    /* Look up names before chroot. An empty jail has no /etc/passwd. */
    drop_was_root = geteuid() == 0;

    if (config.group_name != NULL) {
        drop_do_setgid = 1;
        if (!isdigit((unsigned char)config.group_name[0])) {
            gr = getgrnam(config.group_name);
            if (!gr) {
                elog("ERROR: couldn't get ID for group %s, group does not exist.\n",
                     config.group_name);
                exit(1);
            }
            groupid = gr->gr_gid;
        }
        else {
            groupid = strtoul(config.group_name, &endptr, 10);
            if (endptr == config.group_name || *endptr != '\0') {
                elog("ERROR: invalid group id %s\n", config.group_name);
                exit(1);
            }
        }
    }

    if (config.user_name != NULL) {
        drop_do_setuid = 1;
        if (!isdigit((unsigned char)config.user_name[0])) {
            pw = getpwnam(config.user_name);
            if (pw == NULL) {
                elog("[E] User %s not found!\n", config.user_name);
                exit(1);
            }
            userid = pw->pw_uid;
            init_name = pw->pw_name;
        }
        else {
            userid = strtoul(config.user_name, &endptr, 10);
            if (endptr == config.user_name || *endptr != '\0') {
                elog("ERROR: invalid user id %s\n", config.user_name);
                exit(1);
            }
            pw = getpwuid((uid_t)userid);
            if (pw)
                init_name = pw->pw_name;
        }

        if (config.group_name == NULL && pw != NULL) {
            groupid = pw->pw_gid;
            drop_do_setgid = 1;
        }
    }

    /* A numeric uid with no passwd entry has no primary group. Staying
     * in gid 0 would keep root's group after setuid. */
    if (drop_was_root && drop_do_setuid && !drop_do_setgid) {
        elog("[!] -g is required to drop root's group for uid %s\n",
             config.user_name);
        exit(1);
    }

    /* initgroups needs root and the host group file. */
    if (drop_do_setuid && drop_was_root && init_name) {
        if (initgroups(init_name, (gid_t)groupid) < 0) {
            elog("Unable to init group names (%s/%lu): %s\n",
                 init_name, groupid, strerror(errno));
            exit(1);
        }
    }
    else if (drop_was_root && drop_do_setuid)
        drop_clear_supp = 1;

    endgrent();
    endpwent();
    drop_uid = (uid_t)userid;
    drop_gid = (gid_t)groupid;
    privs_resolved = 1;
}

static void apply_privs(void)
{
    if (!config.drop_privs_flag)
        return;
    resolve_privs();

    /* Clear root's supplementary groups before the uid drop. */
    if (drop_clear_supp && setgroups(0, NULL) < 0) {
        elog("Unable to drop supplementary groups: %s\n", strerror(errno));
        exit(1);
    }

    if (drop_do_setgid) {
        if (setgid(drop_gid) < 0) {
            elog("Unable to set group ID: %s\n", strerror(errno));
            exit(1);
        }
    }

    if (drop_do_setuid) {
        if (setuid(drop_uid) < 0) {
            elog("Unable to set user ID: %s\n", strerror(errno));
            exit(1);
        }
        if (drop_was_root && drop_uid != 0 && setuid(0) == 0) {
            elog("ERROR: privilege drop failed, still able to regain root\n");
            exit(1);
        }
        if (drop_was_root && drop_uid != 0 && drop_gid != 0 && setgid(0) == 0) {
            elog("ERROR: privilege drop failed, still able to regain the root group\n");
            exit(1);
        }
    }
}

int is_valid_path(const char *path)
{
    char dir[STDBUF];
    struct stat st;
    size_t n;
    char *slash;

    if (path == NULL)
        return 0;

    n = strnlen(path, sizeof(dir));
    if (n == 0 || n >= sizeof(dir))
        return 0;
    memcpy(dir, path, n);
    dir[n] = '\0';
    slash = strrchr(dir, '/');
    if (slash == NULL) {
        if (getcwd(dir, sizeof(dir)) == NULL)
            return 0;
    }
    else if (slash == dir)
        dir[1] = '\0';
    else
        *slash = '\0';

    if (stat(dir, &st) != 0)
        return 0;

    if (!S_ISDIR(st.st_mode) || access(dir, W_OK) == -1)
        return 0;

    return 1;
}

static void open_daemon_fds(void)
{
    /* Open as root, before chroot. The child locks and writes its pid
     * after fork; a POSIX lock taken here would not be inherited. */
    if (!is_valid_path(config.pidfile)) {
        elog("[*] Unable to create pidfile '%s'\n", config.pidfile);
        exit(1);
    }

    daemon_pid_fd = open(config.pidfile, O_CREAT | O_WRONLY,
                          S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (daemon_pid_fd < 0) {
        elog("[!] Failed to create pid file %s: %s\n",
             config.pidfile, strerror(errno));
        exit(1);
    }

    daemon_null_fd = open("/dev/null", O_RDWR);
    if (daemon_null_fd < 0) {
        elog("[!] Failed to open /dev/null: %s\n", strerror(errno));
        exit(1);
    }
}

static void refuse_locked_pidfile(int fd)
{
    struct flock lock;

    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(fd, F_GETLK, &lock) == -1) {
        elog("[!] Failed to check pid file %s: %s\n",
             config.pidfile, strerror(errno));
        exit(1);
    }
    if (lock.l_type != F_UNLCK) {
        elog("[!] pid file %s is already locked by pid %d\n",
             config.pidfile, (int)lock.l_pid);
        exit(1);
    }
}

static void write_pid_fd(int fd)
{
    char pid_buffer[12];
    struct flock lock;

    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        elog("[!] Failed to lock pid file %s: %s\n",
             config.pidfile, strerror(errno));
        exit(1);
    }

    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int)getpid());

    if (ftruncate(fd, 0) != 0 ||
        write(fd, pid_buffer, strlen(pid_buffer)) != (ssize_t)strlen(pid_buffer)) {
        elog("[!] Failed to write pid file %s: %s\n",
             config.pidfile, strerror(errno));
        exit(1);
    }

    /* Leave fd open. Closing it drops the flock. */
    if (config.pid_fd >= 0)
        close(config.pid_fd);
    config.pid_fd = fd;
}

static void finish_daemon(void)
{
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        elog("[!] Failed to fork: %s\n", strerror(errno));
        exit(1);
    }
    if (pid > 0)
        exit(0);

    if (setsid() < 0)
        exit(1);

    if (daemon_null_fd >= 0) {
        dup2(daemon_null_fd, 0);
        dup2(daemon_null_fd, 1);
        dup2(daemon_null_fd, 2);
        if (daemon_null_fd > 2)
            close(daemon_null_fd);
    }

    if (daemon_pid_fd >= 0)
        write_pid_fd(daemon_pid_fd);
}

static void start_capture_session(int do_daemon)
{
    /* Chroot and setuid run in the foreground. A failure still has a
     * terminal and a non-zero status. The fork happens only after both. */
    resolve_privs();

    if (do_daemon) {
        open_daemon_fds();
        refuse_locked_pidfile(daemon_pid_fd);
        openlog("passivedns", LOG_PID | LOG_CONS, LOG_DAEMON);
        olog("[*] Daemonizing...\n\n");
    }

    if (config.chroot_dir) {
        olog("[*] Chrooting to dir '%s'..\n", config.chroot_dir);
        if (set_chroot()) {
            elog("[!] failed to chroot\n");
            exit(1);
        }
    }

    if (config.drop_privs_flag) {
        olog("[*] Dropping privs...\n");
        apply_privs();
    }

    if (do_daemon)
        finish_daemon();
}

void game_over()
{
    if (config.inpacket == 0) {
        /* Apply FIN, RST, and idle rules at the last packet time so the
         * open count below is what a live sweep would have removed. */
        end_sessions();
        expire_all_dns_records();
        print_pdns_stats();

        if (config.handle != NULL)
            pcap_close(config.handle);

        config.handle = NULL;

        if (config.hostname != NULL)
            free(config.hostname);

#ifdef HAVE_PFRING
        if (config.use_pfring && config.pfhandle != NULL) {
            pfring_breakloop(config.pfhandle);
            pfring_close(config.pfhandle);
        }
#endif /* HAVE_PFRING */

        reasm_shutdown();
        end_all_sessions();

        if (config.logfile_fd != NULL && config.logfile_fd != stdout)
            fclose(config.logfile_fd);

        /* -l and -L can share one stream. Do not fclose it twice. */
        if (config.logfile_nxd_fd != NULL && config.logfile_nxd_fd != stdout
            && config.logfile_nxd_fd != config.logfile_fd)
            fclose(config.logfile_nxd_fd);

        if (config.logfile_raw >= 0 && config.logfile_raw != STDOUT_FILENO)
            close(config.logfile_raw);
        if (config.logfile_nxd_raw >= 0 && config.logfile_nxd_raw != STDOUT_FILENO
            && config.logfile_nxd_raw != config.logfile_raw)
            close(config.logfile_nxd_raw);

        free_config();
        olog("\n[*] passivedns ended.\n");
        exit(0);
    }
    config.intr_flag |= INTERRUPT_END;
}

void free_config()
{
    if (config.cfilter.bf_insns != NULL)
        free(config.cfilter.bf_insns);
}

void print_pdns_stats()
{
    FILE *handle = stdout;
    if (config.use_stats_file) {
        handle = fopen(config.statsfile, "w");
        if (handle == NULL) {
            olog("[!] Error opening stats file %s: %s\n", config.statsfile,
                 strerror(errno));
            return;
        }
    }

    flog(handle, "\n");
    flog(handle, "-- Total DNS records allocated            :%12u\n",
         PDNS_U32_GET(config.p_s.dns_records));
    flog(handle, "-- Total DNS assets allocated             :%12u\n",
         PDNS_U32_GET(config.p_s.dns_assets));
    flog(handle, "-- Total DNS packets over IPv4/TCP        :%12u\n",
         PDNS_U32_GET(config.p_s.ip4_dns_tcp));
    flog(handle, "-- Total DNS packets over IPv6/TCP        :%12u\n",
         PDNS_U32_GET(config.p_s.ip6_dns_tcp));
    flog(handle, "-- Total DNS packets over TCP decoded     :%12u\n",
         PDNS_U32_GET(config.p_s.ip4_dec_tcp_ok) + PDNS_U32_GET(config.p_s.ip6_dec_tcp_ok));
    flog(handle, "-- Total DNS packets over TCP failed      :%12u\n",
         PDNS_U32_GET(config.p_s.ip4_dec_tcp_er) + PDNS_U32_GET(config.p_s.ip6_dec_tcp_er));
    flog(handle, "-- Total DNS packets over IPv4/UDP        :%12u\n",
         PDNS_U32_GET(config.p_s.ip4_dns_udp));
    flog(handle, "-- Total DNS packets over IPv6/UDP        :%12u\n",
         PDNS_U32_GET(config.p_s.ip6_dns_udp));
    flog(handle, "-- Total DNS packets over UDP decoded     :%12u\n",
         PDNS_U32_GET(config.p_s.ip4_dec_udp_ok) + PDNS_U32_GET(config.p_s.ip6_dec_udp_ok));
    flog(handle, "-- Total DNS packets over UDP failed      :%12u\n",
         PDNS_U32_GET(config.p_s.ip4_dec_udp_er) + PDNS_U32_GET(config.p_s.ip6_dec_udp_er));
    flog(handle, "-- Total packets received from libpcap    :%12u\n",
         PDNS_U32_GET(config.p_s.got_packets));
    flog(handle, "-- Connections open at shutdown           :%12u\n",
         PDNS_U32_GET(config.curcxt));
    if (config.workers > 1)
        flog(handle, "-- Capture threads                        :%12u\n",
             config.workers);
    flog(handle, "-- Total Ethernet packets received        :%12u\n",
         PDNS_U32_GET(config.p_s.eth_recv));
    flog(handle, "-- Total VLAN packets received            :%12u\n",
         PDNS_U32_GET(config.p_s.vlan_recv));

    if (config.use_stats_file) {
        fclose(handle);
    }
}

void usage()
{
    olog("\n");
    olog("USAGE:\n");
    olog(" $ passivedns [options]\n\n");
    olog(" OPTIONS:\n\n");
    olog(" -i <iface>      Network device <iface> (default: eth0).\n");
    olog(" -W <n>          Live workers (default: 1, maximum: %d).\n",
         PDNS_WORKERS_MAX);
    olog("                 More than one uses AF_PACKET fanout hash.\n");
    olog("                 Capture threads share one DNS cache and one log.\n");
    olog("                 Not with -r, -n, or interface \"any\".\n");
    olog(" --fanout-group <id>  Fanout group (default: interface index).\n");
    olog(" -r <file>       Read pcap <file>.\n");
    olog(" -H <hostname>   Choose hostname to print in record.\n");
#ifdef HAVE_PFRING
    olog(" -n              Use PF_RING.\n");
    olog(" -c <cluster_id> Set PF_RING cluster_id.\n");
#endif /* HAVE_PFRING */
    olog(" -l <file>       Logfile normal queries (default: /var/log/passivedns.log).\n");
    olog(" -L <file>       Logfile for SRC Error queries (default: /var/log/passivedns.log).\n");
    olog(" -y              Log to syslog (uses local7 syslog facility).\n");
    olog(" -Y              Log NXDOMAIN to syslog.\n");
    olog(" -d <delimiter>  Delimiter between fields in log file (default: ||).\n");
#ifdef HAVE_JSON
    olog(" -j              Use JSON as output in log file.\n");
    olog(" -J              Use JSON as output in NXDOMAIN log file.\n");
#endif /* HAVE_JSON */
    olog(" -f <fields>     Choose which fields to print (default: -f SMcsCQTAtn).\n");
    olog(" -s <bytes>      Live snapshot length (default: %d, 0 means %d).\n",
         SNAPLENGTH, SNAPLENGTH_MAX);
    olog("                 A longer frame is truncated. On the capture device:\n");
    olog("                 ethtool -K <iface> gro off\n");
    olog(" --stats-file <file>  Write SIGUSR1 stats to this file.\n");
    olog(" -b 'BPF'        Berkley Packet Filter (default: '%s').\n", BPFF);
    olog(" -p <file>       Name of pid file (default: /var/run/passivedns.pid).\n");
    olog(" -S <mem>        Soft memory limit in MB (default: 256).\n");
    olog(" -C <sec>        Seconds to cache DNS objects in memory (default: %u).\n", DNSCACHETIMEOUT);
    olog(" -P <sec>        Seconds between printing duplicate DNS info (default %u).\n", DNSPRINTTIME);
#ifdef PDNS_HAVE_HTTPS
    olog(" -X <flags>      Manually set DNS RR Types to care about (default: -X 46CDNPRShV).\n");
#else
    olog(" -X <flags>      Manually set DNS RR Types to care about (default: -X 46CDNPRS).\n");
#endif
    olog(" -N              Set interface to non promisc. mode.\n");
    olog(" -u <uid>        User ID to drop privileges to.\n");
    olog(" -g <gid>        Group ID to drop privileges to.\n");
    olog(" -T <dir>        Directory to chroot into.\n");
    olog(" -q              Quiet mode (no output except errors).\n");
    olog(" -D              Run as daemon.\n");
    olog(" -V              Show version and exit.\n");
    olog(" -h              This help message.\n\n");
    olog(" FIELDS:\n");
    olog("\n");
    olog("   H: YMD-HMS Stamp S: Timestamp(s)  M: Timestamp(ms)  c: Client IP  \n");
    olog("   s: Server IP     C: Class         Q: Query          T: Type       \n");
    olog("   A: Answer        t: TTL           p: Protocol       n: Count      \n");
    olog("   h: hostname      L: QueryLength   l: AnswerLength   w: Client MAC \n");
    olog("   W: Server MAC    i: Server IP TTL                                 \n");
    olog("\n");
    olog(" FLAGS:\n");
    olog("\n");
    olog(" * For Record Types:\n");
    olog("   4:A      6:AAAA  C:CNAME  D:DNAME  N:NAPTR  O:SOA  L:LOC   F:SPF   I:HINFO\n");
    olog("   P:PTR    R:RP    S:SRV    T:TXT    M:MX     n:NS   d:DNSEC H:SSHFP\n");
#ifdef PDNS_HAVE_HTTPS
    olog("   h:HTTPS  V:SVCB\n");
#endif
    olog("   L also enables GPOS\n");
    olog("   d enables DS, DNSKEY, NSEC, NSEC3, NSEC3PARAM, RRSIG\n");
    olog("\n");
    olog(" * For Server Return Code (SRC) Errors:\n");
    olog("   f:FORMERR   s:SERVFAIL  x:NXDOMAIN  o:NOTIMPL  r:REFUSED\n");
    olog("   y:YXDOMAIN  e:YXRRSET   t:NXRRSET   a:NOTAUTH  z:NOTZONE\n");
    olog("   0:NOERR\n");
    olog("\n");
}

void show_version()
{
    olog("\n");
    olog("[*] PassiveDNS %s\n", PACKAGE_VERSION);
    olog("[*] By Edward Bjarte Fjellskål <edward.fjellskaal@gmail.com>\n");
    olog("[*] Using %s\n", pcap_lib_version());
    olog("[*] Using ldns version %s\n",ldns_version());
#ifdef HAVE_PFRING
    /* Print PF_RING version if PF_RING is used */
    if (config.use_pfring) {
        char pfv[50];
        u_int32_t pf_version;
        pfring_version(config.pfhandle, &pf_version);
        snprintf(pfv, 50, "%d.%d.%d",
                (pf_version & 0xFFFF0000) >> 16,
                (pf_version & 0x0000FF00) >> 8,
                 pf_version & 0x000000FF);
        olog("[*] Using PF_RING version %s\n", pfv);
    }
#endif /* HAVE_PFRING */
#ifdef HAVE_JSON
    if (config.use_json || config.use_json_nxd) {
        olog("[*] Using jansson version %s\n", JANSSON_VERSION);
    }
#endif /* HAVE_JSON */
}

static void add_letter(char *buf, size_t cap, size_t *used, int enabled, char letter)
{
    if (!enabled || *used + 1 >= cap)
        return;
    buf[(*used)++] = letter;
    buf[*used] = '\0';
}

static void show_record_letters(void)
{
    char letters[64];
    size_t used = 0;

    letters[0] = '\0';
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_A, '4');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_AAAA, '6');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_CNAME, 'C');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_DNAME, 'D');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_NAPTR, 'N');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_SOA, 'O');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_LOC, 'L');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_SPF, 'F');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_HINFO, 'I');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_PTR, 'P');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_RP, 'R');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_SRV, 'S');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_TXT, 'T');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_MX, 'M');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_NS, 'n');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_DNSSEC, 'd');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_SSHFP, 'H');
#ifdef PDNS_HAVE_HTTPS
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_HTTPS, 'h');
    add_letter(letters, sizeof(letters), &used, config.dnsf & DNS_CHK_SVCB, 'V');
#endif
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_FORMERR, 'f');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_SERVFAIL, 's');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_NXDOMAIN, 'x');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_NOTIMPL, 'o');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_REFUSED, 'r');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_YXDOMAIN, 'y');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_YXRRSET, 'e');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_NXRRSET, 't');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_NOTAUTH, 'a');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_NOTZONE, 'z');
    add_letter(letters, sizeof(letters), &used, config.dnsfe & DNS_SE_CHK_NOERR, '0');
    olog("[*] Record letters: %s\n", letters[0] ? letters : "(none)");
}

static void show_snapshot(int snaplen)
{
    if (config.pcap_file && config.snaplen_set)
        olog("[*] -s %d does not apply when reading a pcap\n", config.snaplen);
    olog("[*] Snapshot length: %d\n", snaplen);
}

static int parse_u32(const char *text, uint32_t *out)
{
    char *end = NULL;
    unsigned long val;
    const char *num = text;

    if (text == NULL || text[0] == '\0' || text[0] == '-')
        return -1;
    if (text[0] == '+')
        num = text + 1;
    if (num[0] < '0' || num[0] > '9')
        return -1;

    errno = 0;
    val = strtoul(num, &end, 10);
    if (end == num || *end != '\0' || errno == ERANGE || val > UINT32_MAX)
        return -1;
    *out = (uint32_t)val;
    return 0;
}

static void warn_if_gro(const char *dev)
{
#ifdef __linux__
    int fd;
    struct ifreq ifr;
    struct ethtool_value eval;

    if (dev == NULL || dev[0] == '\0' || strcmp(dev, "any") == 0)
        return;
    if (strlen(dev) >= IFNAMSIZ)
        return;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return;

    memset(&ifr, 0, sizeof(ifr));
    memset(&eval, 0, sizeof(eval));
    memcpy(ifr.ifr_name, dev, strlen(dev));
    eval.cmd = ETHTOOL_GGRO;
    ifr.ifr_data = (char *)&eval;
    if (ioctl(fd, SIOCETHTOOL, &ifr) == 0 && eval.data != 0) {
        elog("[!] generic-receive-offload is on for %s; a large TCP DNS answer can arrive as one frame and be cut at the snapshot length.\n", dev);
        elog("[!] Turn it off with: ethtool -K %s gro off\n", dev);
    }
    close(fd);
#else
    (void)dev;
#endif /* __linux__ */
}

#ifdef __linux__

#define CACHE_Q_MAX 8192
#define LOG_Q_MAX 8192

static pcap_t *fanout_handles[PDNS_WORKERS_MAX];
static int fanout_nhandles;
static connection **fanout_buckets[PDNS_WORKERS_MAX];
static pthread_t cap_th[PDNS_WORKERS_MAX];
static pthread_t cache_th;
static pthread_t writer_th;
static int cap_up;
static int cache_up;
static int writer_up;
static volatile sig_atomic_t fanout_stop;
static volatile sig_atomic_t fanout_tick;
static volatile sig_atomic_t fanout_reopen;
static volatile sig_atomic_t fanout_expire_all;

struct cache_job {
    struct cache_job *next;
    ldns_pkt *pkt;
    struct pcap_pkthdr hdr;
    ether_header eth;
    int have_eth;
    uint32_t af;
    struct in6_addr cip;
    struct in6_addr sip;
    uint8_t s_ttl;
    uint8_t proto;
};

struct log_job {
    struct log_job *next;
    int fd;
    char *line;
};

struct cache_q {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct cache_job *head;
    struct cache_job *tail;
    int count;
    int closed;
};

struct log_q {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct log_job *head;
    struct log_job *tail;
    int count;
    int closed;
};

static struct cache_q cache_q;
static struct log_q log_q;
static int queues_ready;

static void queues_init(void)
{
    if (queues_ready)
        return;
    pthread_mutex_init(&cache_q.mu, NULL);
    pthread_cond_init(&cache_q.cv, NULL);
    pthread_mutex_init(&log_q.mu, NULL);
    pthread_cond_init(&log_q.cv, NULL);
    queues_ready = 1;
}

static int cache_push(struct cache_job *job)
{
    pthread_mutex_lock(&cache_q.mu);
    while (cache_q.count >= CACHE_Q_MAX && !cache_q.closed)
        pthread_cond_wait(&cache_q.cv, &cache_q.mu);
    if (cache_q.closed) {
        pthread_mutex_unlock(&cache_q.mu);
        return -1;
    }
    job->next = NULL;
    if (cache_q.tail != NULL)
        cache_q.tail->next = job;
    else
        cache_q.head = job;
    cache_q.tail = job;
    cache_q.count++;
    pthread_cond_signal(&cache_q.cv);
    pthread_mutex_unlock(&cache_q.mu);
    return 0;
}

static struct cache_job *cache_pop(int *closed)
{
    struct cache_job *job = NULL;
    struct timespec ts;

    *closed = 0;
    pthread_mutex_lock(&cache_q.mu);
    if (cache_q.head == NULL && !cache_q.closed) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&cache_q.cv, &cache_q.mu, &ts);
    }
    job = cache_q.head;
    if (job != NULL) {
        cache_q.head = job->next;
        if (cache_q.head == NULL)
            cache_q.tail = NULL;
        cache_q.count--;
        job->next = NULL;
        pthread_cond_signal(&cache_q.cv);
    }
    if (job == NULL && cache_q.closed)
        *closed = 1;
    pthread_mutex_unlock(&cache_q.mu);
    return job;
}

static void cache_close(void)
{
    pthread_mutex_lock(&cache_q.mu);
    cache_q.closed = 1;
    pthread_cond_broadcast(&cache_q.cv);
    pthread_mutex_unlock(&cache_q.mu);
}

static int log_push(struct log_job *job)
{
    pthread_mutex_lock(&log_q.mu);
    while (log_q.count >= LOG_Q_MAX && !log_q.closed)
        pthread_cond_wait(&log_q.cv, &log_q.mu);
    if (log_q.closed) {
        pthread_mutex_unlock(&log_q.mu);
        return -1;
    }
    job->next = NULL;
    if (log_q.tail != NULL)
        log_q.tail->next = job;
    else
        log_q.head = job;
    log_q.tail = job;
    log_q.count++;
    pthread_cond_signal(&log_q.cv);
    pthread_mutex_unlock(&log_q.mu);
    return 0;
}

static struct log_job *log_pop(int *closed)
{
    struct log_job *job = NULL;
    struct timespec ts;

    *closed = 0;
    pthread_mutex_lock(&log_q.mu);
    if (log_q.head == NULL && !log_q.closed) {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        pthread_cond_timedwait(&log_q.cv, &log_q.mu, &ts);
    }
    job = log_q.head;
    if (job != NULL) {
        log_q.head = job->next;
        if (log_q.head == NULL)
            log_q.tail = NULL;
        log_q.count--;
        job->next = NULL;
        pthread_cond_signal(&log_q.cv);
    }
    if (job == NULL && log_q.closed)
        *closed = 1;
    pthread_mutex_unlock(&log_q.mu);
    return job;
}

static void log_close(void)
{
    pthread_mutex_lock(&log_q.mu);
    log_q.closed = 1;
    pthread_cond_broadcast(&log_q.cv);
    pthread_mutex_unlock(&log_q.mu);
}

int pdns_cache_submit(packetinfo *pi, struct ldns_struct_pkt *pkt)
{
    struct cache_job *job;
    ldns_pkt *copy;

    if (pi == NULL || pi->cxt == NULL || pi->pheader == NULL || pkt == NULL)
        return -1;
    copy = ldns_pkt_clone((ldns_pkt *)pkt);
    if (copy == NULL)
        return -1;
    job = (struct cache_job *)calloc(1, sizeof(*job));
    if (job == NULL) {
        ldns_pkt_free(copy);
        return -1;
    }
    job->pkt = copy;
    job->hdr = *pi->pheader;
    job->af = pi->cxt->af;
    job->cip = pi->cxt->s_ip;
    job->sip = pi->cxt->d_ip;
    job->s_ttl = pi->s_ttl;
    job->proto = pi->proto;
    if (pi->eth_hdr != NULL) {
        job->eth = *pi->eth_hdr;
        job->have_eth = 1;
    }
    if (cache_push(job) != 0) {
        ldns_pkt_free(copy);
        free(job);
        return -1;
    }
    return 0;
}

void pdns_log_submit(int fd, const char *line)
{
    struct log_job *job;
    size_t n;

    if (fd < 0 || line == NULL)
        return;
    n = strlen(line);
    job = (struct log_job *)malloc(sizeof(*job));
    if (job == NULL)
        return;
    job->line = (char *)malloc(n + 1);
    if (job->line == NULL) {
        free(job);
        return;
    }
    memcpy(job->line, line, n + 1);
    job->fd = fd;
    job->next = NULL;
    if (log_push(job) != 0) {
        free(job->line);
        free(job);
    }
}

static void cache_handle(struct cache_job *job)
{
    packetinfo pi;
    connection cxt;

    memset(&pi, 0, sizeof(pi));
    memset(&cxt, 0, sizeof(cxt));
    config.tstamp = job->hdr.ts;
    cxt.af = job->af;
    cxt.s_ip = job->cip;
    cxt.d_ip = job->sip;
    cxt.proto = job->proto;
    pi.pheader = &job->hdr;
    pi.cxt = &cxt;
    pi.s_ttl = job->s_ttl;
    pi.proto = job->proto;
    pi.af = job->af;
    if (job->have_eth)
        pi.eth_hdr = &job->eth;
    process_dns_answer(&pi, job->pkt);
    ldns_pkt_free(job->pkt);
    free(job);
}

static void cache_expire_due(void)
{
    time_t now = config.tstamp.tv_sec;

    if (fanout_expire_all) {
        fanout_expire_all = 0;
        expire_all_dns_records();
        return;
    }
    if (now <= 0)
        return;
    if ((now - config.dnslastchk) >= 600) {
        expire_dns_records();
        config.dnslastchk = now;
    }
}

static void *cache_thread(void *arg)
{
    sig_atomic_t seen = fanout_tick;

    (void)arg;
    for (;;) {
        int closed = 0;
        struct cache_job *job = cache_pop(&closed);

        if (job != NULL)
            cache_handle(job);
        if (seen != fanout_tick || fanout_expire_all) {
            seen = fanout_tick;
            cache_expire_due();
        }
        if (closed)
            break;
    }
    expire_all_dns_records();
    return NULL;
}

static void *writer_thread(void *arg)
{
    (void)arg;
    for (;;) {
        int closed = 0;
        struct log_job *job;

        if (fanout_reopen) {
            fanout_reopen = 0;
            reopen_log_files();
        }
        job = log_pop(&closed);
        if (job != NULL) {
            write_log_line(job->fd, job->line);
            free(job->line);
            free(job);
        }
        if (closed)
            break;
    }
    return NULL;
}

static void *capture_thread(void *arg)
{
    int id = (int)(intptr_t)arg;
    pcap_t *h = fanout_handles[id];
    sig_atomic_t seen = fanout_tick;

    tl_bucket = (connection **)calloc(BUCKET_SIZE, sizeof(*tl_bucket));
    if (tl_bucket == NULL) {
        fanout_stop = 1;
        return NULL;
    }
    while (!fanout_stop) {
        int rc = pcap_dispatch(h, 64, got_packet, NULL);

        if (fanout_stop || rc == PCAP_ERROR_BREAK)
            break;
        if (rc < 0) {
            elog("[!] worker %d: %s\n", id + 1, pcap_geterr(h));
            fanout_stop = 1;
            break;
        }
        if (seen != fanout_tick) {
            seen = fanout_tick;
            end_sessions();
            reasm_expire(tl_tstamp_set ? tl_tstamp.tv_sec : time(NULL));
        }
    }
    end_sessions();
    reasm_shutdown();
    fanout_buckets[id] = tl_bucket;
    tl_bucket = NULL;
    return NULL;
}

static int start_pipeline(void)
{
    int i;
    int n = config.workers;

    if (pthread_create(&writer_th, NULL, writer_thread, NULL) != 0)
        return -1;
    writer_up = 1;
    if (pthread_create(&cache_th, NULL, cache_thread, NULL) != 0)
        return -1;
    cache_up = 1;
    for (i = 0; i < n; i++) {
        if (pthread_create(&cap_th[i], NULL, capture_thread,
                           (void *)(intptr_t)i) != 0) {
            fanout_stop = 1;
            return -1;
        }
        cap_up++;
    }
    return 0;
}

static void stop_pipeline(void)
{
    int i;

    fanout_stop = 1;
    for (i = 0; i < fanout_nhandles; i++) {
        if (fanout_handles[i] != NULL)
            pcap_breakloop(fanout_handles[i]);
    }
    for (i = 0; i < cap_up; i++)
        pthread_join(cap_th[i], NULL);
    cap_up = 0;
    cache_close();
    if (cache_up) {
        pthread_join(cache_th, NULL);
        cache_up = 0;
    }
    log_close();
    if (writer_up) {
        pthread_join(writer_th, NULL);
        writer_up = 0;
    }
}

static void release_fanout_buckets(void)
{
    int i;

    for (i = 0; i < PDNS_WORKERS_MAX; i++) {
        if (fanout_buckets[i] == NULL)
            continue;
        tl_bucket = fanout_buckets[i];
        end_all_sessions();
        free(fanout_buckets[i]);
        fanout_buckets[i] = NULL;
        tl_bucket = NULL;
    }
}

static void close_fanout_handles(void)
{
    int i;

    for (i = 0; i < fanout_nhandles; i++) {
        if (fanout_handles[i] != NULL) {
            pcap_close(fanout_handles[i]);
            fanout_handles[i] = NULL;
        }
    }
    fanout_nhandles = 0;
}

static void release_parent_logs(void)
{
    if (config.logfile_raw >= 0 && config.logfile_raw != STDOUT_FILENO)
        close(config.logfile_raw);
    if (config.logfile_nxd_raw >= 0 && config.logfile_nxd_raw != STDOUT_FILENO
        && config.logfile_nxd_raw != config.logfile_raw)
        close(config.logfile_nxd_raw);
    config.logfile_raw = -1;
    config.logfile_nxd_raw = -1;
}

static void prepare_fanout_group(void)
{
    unsigned int idx;

    if (config.dev == NULL || config.dev[0] == '\0' ||
        strcmp(config.dev, "any") == 0) {
        elog("[!] -W cannot use interface \"any\"\n");
        exit(1);
    }
    if (config.fanout_group_set)
        return;

    idx = if_nametoindex(config.dev);
    if (idx == 0 || idx > 65535) {
        elog("[!] No interface index for %s. Pass --fanout-group.\n",
             config.dev);
        exit(1);
    }
    config.fanout_group = (uint16_t)idx;
}

static int open_fanout_handles(void)
{
    int i;
    int compiled = 0;

    for (i = 0; i < config.workers; i++) {
        pcap_t *h;
        int fd;
        uint32_t arg;

        config.errbuf[0] = '\0';
        h = pcap_open_live(config.dev, config.snaplen, config.promisc,
                           500, config.errbuf);
        if (h == NULL) {
            elog("[!] worker %u: pcap_open_live: %s\n",
                 (unsigned)(i + 1), config.errbuf);
            close_fanout_handles();
            return -1;
        }
        /* A cooked fallback does not fan out the way a packet socket does. */
        if (config.errbuf[0] != '\0') {
            elog("[!] worker %u: %s\n", (unsigned)(i + 1), config.errbuf);
            pcap_close(h);
            close_fanout_handles();
            return -1;
        }
        fd = pcap_fileno(h);
        if (fd < 0) {
            elog("[!] worker %u: capture socket is not available\n",
                 (unsigned)(i + 1));
            pcap_close(h);
            close_fanout_handles();
            return -1;
        }
        arg = (uint32_t)config.fanout_group |
              (((uint32_t)PACKET_FANOUT_HASH |
                (uint32_t)PACKET_FANOUT_FLAG_DEFRAG) << 16);
        if (setsockopt(fd, SOL_PACKET, PACKET_FANOUT, &arg, sizeof(arg)) < 0) {
            elog("[!] worker %u: PACKET_FANOUT: %s\n",
                 (unsigned)(i + 1), strerror(errno));
            pcap_close(h);
            close_fanout_handles();
            return -1;
        }
        if (!compiled) {
            config.linktype = pcap_datalink(h);
            if (pcap_compile(h, &config.cfilter, config.bpff, 1,
                             config.net_mask) == -1) {
                elog("[!] worker %u: pcap_compile: %s\n",
                     (unsigned)(i + 1), pcap_geterr(h));
                pcap_close(h);
                close_fanout_handles();
                return -1;
            }
            compiled = 1;
        }
        if (pcap_setfilter(h, &config.cfilter) != 0) {
            elog("[!] worker %u: pcap_setfilter: %s\n",
                 (unsigned)(i + 1), pcap_geterr(h));
            pcap_close(h);
            close_fanout_handles();
            return -1;
        }
        fanout_handles[i] = h;
        fanout_nhandles++;
    }
    return 0;
}

/* Drop a pid file this start created but never locked. A failed fanout
 * start must not look like a running daemon. */
static void abandon_pidfile(void)
{
    if (daemon_pid_fd < 0 && config.pid_fd < 0)
        return;
    if (daemon_pid_fd >= 0 && daemon_pid_fd != config.pid_fd)
        close(daemon_pid_fd);
    if (config.pid_fd >= 0)
        close(config.pid_fd);
    daemon_pid_fd = -1;
    config.pid_fd = -1;
    if (config.pidfile != NULL)
        unlink(config.pidfile);
}

static void fanout_fail(int detach_wr)
{
    close_fanout_handles();
    abandon_pidfile();
    if (detach_wr >= 0) {
        char status = '0';
        if (write(detach_wr, &status, 1) != 1)
            exit(1);
        close(detach_wr);
    }
    exit(1);
}

static void close_raw_logs(void)
{
    if (config.logfile_raw >= 0 && config.logfile_raw != STDOUT_FILENO)
        close(config.logfile_raw);
    if (config.logfile_nxd_raw >= 0 && config.logfile_nxd_raw != STDOUT_FILENO
        && config.logfile_nxd_raw != config.logfile_raw)
        close(config.logfile_nxd_raw);
    config.logfile_raw = -1;
    config.logfile_nxd_raw = -1;
}

static void fanout_main_loop(const sigset_t *set)
{
    while (!fanout_stop) {
        struct timespec ts;
        int sig;

        ts.tv_sec = 1;
        ts.tv_nsec = 0;
        sig = sigtimedwait(set, NULL, &ts);
        if (sig == SIGINT || sig == SIGTERM || sig == SIGQUIT)
            fanout_stop = 1;
        else if (sig == SIGALRM) {
            fanout_tick++;
            alarm(TIMEOUT);
        }
        else if (sig == SIGHUP)
            fanout_reopen = 1;
        else if (sig == SIGUSR1)
            print_pdns_stats();
        else if (sig == SIGUSR2)
            fanout_expire_all = 1;
    }
}

static void run_fanout_workers(int do_daemon)
{
    int detach[2] = {-1, -1};
    int nworkers = config.workers;
    sigset_t set;
    pid_t pid;

    queues_init();
    prepare_fanout_group();
    olog("[*] Fanout workers: %d group: %u hash\n",
         nworkers, config.fanout_group);
    fflush(stdout);
    fflush(stderr);

    if (do_daemon) {
        open_daemon_fds();
        refuse_locked_pidfile(daemon_pid_fd);
        openlog("passivedns", LOG_PID | LOG_CONS, LOG_DAEMON);
        olog("[*] Daemonizing...\n\n");
        fflush(stdout);
        if (pipe(detach) != 0) {
            elog("[!] Failed to create pipe: %s\n", strerror(errno));
            abandon_pidfile();
            exit(1);
        }
        pid = fork();
        if (pid < 0) {
            elog("[!] Failed to fork: %s\n", strerror(errno));
            abandon_pidfile();
            exit(1);
        }
        if (pid > 0) {
            char status = '0';
            close(detach[1]);
            release_parent_logs();
            if (read(detach[0], &status, 1) != 1 || status != '1')
                exit(1);
            exit(0);
        }
        close(detach[0]);
        detach[0] = -1;
        if (setsid() < 0) {
            abandon_pidfile();
            exit(1);
        }
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() == 1) {
            abandon_pidfile();
            exit(1);
        }
    }

    if (open_fanout_handles() != 0)
        fanout_fail(detach[1]);

    if (config.chroot_dir && set_chroot() != 0) {
        elog("[!] failed to chroot\n");
        fanout_fail(detach[1]);
    }
    if (config.drop_privs_flag)
        apply_privs();

    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGQUIT);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGHUP);
    sigaddset(&set, SIGUSR1);
    sigaddset(&set, SIGUSR2);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);

    if (start_pipeline() != 0) {
        elog("[!] Failed to start worker threads\n");
        stop_pipeline();
        fanout_fail(detach[1]);
    }

    if (do_daemon && daemon_pid_fd >= 0)
        write_pid_fd(daemon_pid_fd);

    if (detach[1] >= 0) {
        char status = '1';
        if (write(detach[1], &status, 1) != 1) {
            stop_pipeline();
            abandon_pidfile();
            exit(1);
        }
        close(detach[1]);
        detach[1] = -1;
    }

    if (do_daemon && daemon_null_fd >= 0) {
        dup2(daemon_null_fd, 0);
        dup2(daemon_null_fd, 1);
        dup2(daemon_null_fd, 2);
        if (daemon_null_fd > 2)
            close(daemon_null_fd);
        daemon_null_fd = -1;
    }

    alarm(TIMEOUT);
    fanout_main_loop(&set);
    alarm(0);
    stop_pipeline();
    print_pdns_stats();
    release_fanout_buckets();
    close_fanout_handles();
    close_raw_logs();
    free_config();
    olog("\n[*] passivedns ended.\n");
    exit(0);
}
#endif /* __linux__ */

#ifndef __linux__
int pdns_cache_submit(packetinfo *pi, struct ldns_struct_pkt *pkt)
{
    (void)pi;
    (void)pkt;
    return -1;
}

void pdns_log_submit(int fd, const char *line)
{
    (void)fd;
    (void)line;
}
#endif


static void check_worker_args(void)
{
    if (config.workers > 1 && config.pcap_file) {
        elog("[!] -W cannot be used with -r\n");
        exit(1);
    }
    if (config.workers <= 1 && config.fanout_group_set) {
        elog("[!] --fanout-group requires -W greater than 1\n");
        exit(1);
    }
    if (config.workers <= 1)
        return;
#ifdef HAVE_PFRING
    if (config.use_pfring) {
        elog("[!] -W cannot be used with PF_RING -n\n");
        exit(1);
    }
#endif
#ifndef __linux__
    elog("[!] -W needs Linux AF_PACKET fanout\n");
    exit(1);
#endif
    if (config.dev != NULL && strcmp(config.dev, "any") == 0) {
        elog("[!] -W cannot use interface \"any\"\n");
        exit(1);
    }
}

extern int optind, opterr, optopt; // getopt()

/* magic main */
int main(int argc, char *argv[])
{
    int ch = 0; // verbose_already = 0;
    int daemon = 0;
    memset(&config, 0, sizeof(globalconfig));
    config.pid_fd = -1;
    config.workers = 1;
    config.logfile_raw = -1;
    config.logfile_nxd_raw = -1;
    config.max_connections = MAX_CONNECTIONS;
    config.inpacket = config.intr_flag = 0;
    config.dnslastchk = 0;
    config.bpff = BPFF;
    config.logfile = "/var/log/passivedns.log";
    config.logfile_nxd = "/var/log/passivedns.log";
    config.statsfile = "/var/log/passivedns.stats";
    config.pidfile = "/var/run/passivedns.pid";
    config.promisc = 1;
    config.snaplen = SNAPLENGTH;
    config.output_log = 0;
    config.output_log_nxd = 0;
    config.output_syslog = 0;
    config.output_syslog_nxd = 0;
    /* Default memory limit: 256 MB */
    config.mem_limit_max = (256 * 1024 * 1024);
    config.dnsprinttime = DNSPRINTTIME;
    config.dnscachetimeout =  DNSCACHETIMEOUT;
    config.dnsf = 0;
    config.log_delimiter = "||";
    config.fieldsf = 0;
    config.fieldsf |= FIELD_TIMESTAMP_S;
    config.fieldsf |= FIELD_TIMESTAMP_MS;
    config.fieldsf |= FIELD_CLIENT;
    config.fieldsf |= FIELD_SERVER;
    config.fieldsf |= FIELD_CLASS;
    config.fieldsf |= FIELD_QUERY;
    config.fieldsf |= FIELD_TYPE;
    config.fieldsf |= FIELD_ANSWER;
    config.fieldsf |= FIELD_TTL;
    config.fieldsf |= FIELD_COUNT;
    config.dnsf |= DNS_CHK_A;
    config.dnsf |= DNS_CHK_AAAA;
    config.dnsf |= DNS_CHK_PTR;
    config.dnsf |= DNS_CHK_CNAME;
    config.dnsf |= DNS_CHK_DNAME;
    config.dnsf |= DNS_CHK_NAPTR;
    config.dnsf |= DNS_CHK_RP;
    config.dnsf |= DNS_CHK_SRV;
#ifdef PDNS_HAVE_HTTPS
    config.dnsf |= DNS_CHK_HTTPS;
    config.dnsf |= DNS_CHK_SVCB;
#endif
#ifdef HAVE_PFRING
    config.cluster_id = 0;
    u_int32_t flags = 0;
#endif /* HAVE_PFRING */
    signal(SIGTERM, game_over);
    signal(SIGINT,  game_over);
    signal(SIGQUIT, game_over);
    signal(SIGALRM, sig_alarm_handler);
    signal(SIGHUP,  sig_hup_handler);
    signal(SIGUSR1, print_pdns_stats);
    signal(SIGUSR2, expire_all_dns_records);

#define ARGS "i:H:r:qc:nyYNjJl:s:L:d:hb:Dp:C:P:S:f:X:u:g:T:VW:"
#define OPT_STATS_FILE 256
#define OPT_FANOUT_GROUP 257
    static const struct option long_options[] = {
        {"stats-file", required_argument, NULL, OPT_STATS_FILE},
        {"fanout-group", required_argument, NULL, OPT_FANOUT_GROUP},
        {NULL, 0, NULL, 0}
    };

    while ((ch = getopt_long(argc, argv, ARGS, long_options, NULL)) != -1)
        switch (ch) {
        case 'i':
            config.dev = optarg;
            break;
        case 'W': {
            uint32_t nworkers = 0;

            if (parse_u32(optarg, &nworkers) != 0 || nworkers < 1 ||
                nworkers > PDNS_WORKERS_MAX) {
                elog("[!] -W needs a worker count from 1 to %d\n",
                     PDNS_WORKERS_MAX);
                exit(1);
            }
            config.workers = (uint16_t)nworkers;
            break;
        }
        case OPT_FANOUT_GROUP: {
            uint32_t group = 0;

            if (parse_u32(optarg, &group) != 0 || group == 0 || group > 65535) {
                elog("[!] --fanout-group needs an id from 1 to 65535\n");
                exit(1);
            }
            config.fanout_group = (uint16_t)group;
            config.fanout_group_set = 1;
            break;
        }
        case 'H':
            config.hostname = strdup(optarg);
            break;
        case 'r':
            config.pcap_file = optarg;
            break;
        case 'q':
            config.cflags |= CONFIG_QUIET;
            break;
        case 'L':
            config.output_log_nxd = 1;
            config.logfile_nxd = optarg;
            break;
        case 'l':
            config.output_log = 1;
            config.logfile = optarg;
            break;
        case 'y':
            config.output_syslog = 1;
            break;
        case 'Y':
            config.output_syslog_nxd = 1;
            break;
#ifdef HAVE_JSON
        case 'j':
            config.use_json = 1;
            break;
        case 'J':
            config.use_json_nxd = 1;
            break;
#endif /* HAVE_JSON */
        case 'd':
            config.log_delimiter = optarg;
            break;
        case 'b':
            config.bpff = optarg;
            break;
        case 'p':
            config.pidfile = optarg;
            break;
        case 'C':
            if (parse_u32(optarg, &config.dnscachetimeout) != 0) {
                elog("[!] -C needs a cache time in seconds (0 or a positive integer)\n");
                exit(1);
            }
            break;
        case 'P':
            if (parse_u32(optarg, &config.dnsprinttime) != 0) {
                elog("[!] -P needs a print interval in seconds (0 or a positive integer)\n");
                exit(1);
            }
            break;
        case 'S': {
            uint32_t megabytes = 0;

            if (parse_u32(optarg, &megabytes) != 0 || megabytes == 0) {
                elog("[!] -S needs a memory limit in megabytes (a positive integer)\n");
                exit(1);
            }
            config.mem_limit_max = (uint64_t)megabytes * 1024 * 1024;
            break;
        }
        case 's': {
            char *end = NULL;
            long snap;

            errno = 0;
            snap = strtol(optarg, &end, 10);
            if (optarg[0] == '\0' || end == optarg || *end != '\0' ||
                errno == ERANGE || snap < 0 || snap > SNAPLENGTH_MAX) {
                elog("[!] -s needs a snapshot length from 0 to %d\n", SNAPLENGTH_MAX);
                elog("[!] 0 means %d. SIGUSR1 stats go to --stats-file <file>.\n",
                     SNAPLENGTH_MAX);
                exit(1);
            }
            if (snap == 0)
                snap = SNAPLENGTH_MAX;
            config.snaplen = (int)snap;
            config.snaplen_set = 1;
            break;
        }
        case OPT_STATS_FILE:
            config.use_stats_file = 1;
            config.statsfile = optarg;
            break;
        case 'f':
            parse_field_flags(optarg);
            break;
        case 'X':
            parse_dns_flags(optarg);
            break;
        case 'D':
            daemon = 1;
            break;
        case 'T':
            config.chroot_dir = optarg;
            config.chroot_flag = 1;
            break;
        case 'u':
            config.user_name = optarg;
            config.drop_privs_flag = 1;
            break;
        case 'g':
            config.group_name = optarg;
            config.drop_privs_flag = 1;
            break;
        case 'N':
            config.promisc = 0;
            break;
#ifdef HAVE_PFRING
        case 'n':
            config.use_pfring = 1;
            break;
        case 'c':
            if (parse_u32(optarg, &config.cluster_id) != 0) {
                elog("[!] -c needs a cluster id (0 or a positive integer)\n");
                exit(1);
            }
            break;
#endif /* HAVE_PFRING */
        case 'h':
            usage();
            exit(0);
            break;
        case 'V':
            show_version();
            olog("\n");
            exit(0);
            break;
        case '?':
            elog("unrecognized argument: '%c'\n", optopt);
            break;
        default:
            elog("Did not recognize argument '%c'\n", ch);
    }

    /* Get hostname if not specified by commandline */
    if (config.fieldsf & FIELD_HOSTNAME) {
        if (config.hostname == NULL) {
            config.hostname = calloc(1, HOST_NAME_MAX + 1);
            if (config.hostname == NULL) {
                elog("[!] Failed to allocate hostname\n");
                exit(1);
            }
            if (gethostname(config.hostname, HOST_NAME_MAX + 1) != 0) {
                elog("[!] gethostname failed: %s\n", strerror(errno));
                exit(1);
            }
            config.hostname[HOST_NAME_MAX] = '\0';
        }
    }

    /* A missing account is reported before logs are opened and before
     * a capture device is required. */
    resolve_privs();
    check_worker_args();

    /* Fall back to log file if syslog is not used */
    if (config.output_syslog == 0)
        config.output_log = 1;

    if (config.output_syslog_nxd == 0)
        config.output_log_nxd = 1;

    /* Open log file. Workers use an append fd so each line is one write. */
    if (config.output_log) {
        if (config.workers > 1) {
            config.logfile_raw = open_append_log(config.logfile);
            if (config.logfile_raw < 0) {
                elog("[!] Error opening log file %s\n", config.logfile);
                exit(1);
            }
        }
        else if (config.logfile[0] == '-' && config.logfile[1] == '\0') {
            config.logfile_fd = stdout;
        }
        else {
            config.logfile_fd = fopen(config.logfile, "a");
            if (config.logfile_fd == NULL) {
                elog("[!] Error opening log file %s\n", config.logfile);
                exit(1);
            }
            secure_log(config.logfile_fd);
        }
    }

    /* Open NXDOMAIN log file */
    if (config.output_log_nxd) {
        if (config.output_log && strcmp(config.logfile, config.logfile_nxd) == 0) {
            config.logfile_all = 1;
            if (config.workers > 1)
                config.logfile_nxd_raw = config.logfile_raw;
            else
                config.logfile_nxd_fd = config.logfile_fd;
        }
        else if (config.workers > 1) {
            config.logfile_nxd_raw = open_append_log(config.logfile_nxd);
            if (config.logfile_nxd_raw < 0) {
                elog("[!] Error opening NXDOMAIN log file %s\n", config.logfile_nxd);
                exit(1);
            }
        }
        else if (config.logfile_nxd[0] == '-' && config.logfile_nxd[1] == '\0') {
            config.logfile_nxd_fd = stdout;
        }
        else {
            config.logfile_nxd_fd = fopen(config.logfile_nxd, "a");
            if (config.logfile_nxd_fd == NULL) {
                elog("[!] Error opening NXDOMAIN log file %s\n", config.logfile_nxd);
                exit(1);
            }
            secure_log(config.logfile_nxd_fd);
        }
    }

    show_version();
    show_record_letters();

#ifdef HAVE_PFRING
    if (config.use_pfring) {
        /* PF_RING does not have an option to read PCAP files */
        if (config.pcap_file) {
            elog("[!] Reading PCAP files are not supported when using PF_RING\n");
            exit(1);
        }

        if (config.dev == NULL) {
            elog("[!] Must specify capture NIC\n");
            exit(1);
        }

        show_snapshot(config.snaplen);
        warn_if_gro(config.dev);
        flags |= PF_RING_PROMISC;
        config.pfhandle = pfring_open(config.dev, config.snaplen, flags);

        if (config.pfhandle == NULL) {
            elog("[!] Could not start PF_RING capture\n");
            exit(1);
        }

        config.linktype = DLT_EN10MB;
        pfring_set_application_name(config.pfhandle, "passivedns");

        if (config.cluster_id == 0)
            config.cluster_id = 99; /* Default cluster_id */

        /* Don't add ring to cluster when using ZC or DNA */
        if ((strncmp(config.dev, "zc", 2) != 0) && (strncmp(config.dev, "dna", 3)) != 0) {
            if ((pfring_set_cluster(config.pfhandle, config.cluster_id,
                 cluster_per_flow)) != 0) {
                elog("[!] Could not set PF_RING cluster_id\n");
            }
        }

#ifdef HAVE_PFRING_BPF
        if (*config.bpff != '\0') {
            if ((pfring_set_bpf_filter(config.pfhandle, config.bpff)) != 0) {
                elog("[!] Unable to set bpf filter\n");
            }
        }
#endif /* HAVE_PFRING_BPF */

        if ((pfring_enable_ring(config.pfhandle)) != 0) {
            elog("[!] Could not enable ring\n");
            exit(1);
        }

        start_capture_session(daemon);

        alarm(TIMEOUT);
        olog("[*] Device: %s\n", config.dev);
        olog("[*] Sniffing...\n\n");

        pfring_loop(config.pfhandle, pfring_got_packet, (u_char*)NULL, 1);

        game_over();
        return 0;
    }
#endif /* HAVE_PFRING */

    if (config.pcap_file) {
        /* Read from PCAP file specified by '-r' switch. */
        olog("[*] Reading from file %s\n\n", config.pcap_file);
        if (!(config.handle = pcap_open_offline(config.pcap_file, config.errbuf))) {
            elog("[*] Unable to open %s.  (%s)\n", config.pcap_file, config.errbuf);
            exit(1);
        }
        show_snapshot(pcap_snapshot(config.handle));
        start_capture_session(0);

    }
    else {
        /* Look up an available device if non specified */
        if (config.dev == 0x0) {
            pcap_if_t *alldevs;
            if (0 != pcap_findalldevs(&alldevs, config.errbuf)) {
                elog("[*] Error pcap_findalldevs: %s \n", config.errbuf);
                exit(1);
            }
            config.dev = strdup(alldevs[0].name);
            pcap_freealldevs(alldevs);
        }
        olog("[*] Device: %s\n", config.dev);
        show_snapshot(config.snaplen);
        warn_if_gro(config.dev);

        if (config.workers > 1) {
#ifndef __linux__
            elog("[!] -W needs Linux AF_PACKET fanout\n");
            exit(1);
#else
            run_fanout_workers(daemon);
            return 0;
#endif
        }

        if ((config.handle = pcap_open_live(config.dev, config.snaplen, config.promisc, 500,
             config.errbuf)) == NULL) {
            elog("[*] Error pcap_open_live: %s \n", config.errbuf);
            exit(1);
        }

        if (strlen(config.errbuf) > 0) {
            /* Fix to enable passivedns to run in an OpenVZ container */
            if (strcmp(config.errbuf, "arptype 65535 not supported by libpcap - falling back to cooked socket") == 0) {
                olog("[*] %s \n", config.errbuf);
            }
            else {
                elog("[*] Error errbuf: %s \n", config.errbuf);
                exit(1);
            }
        }

        start_capture_session(daemon);

    }

    if (config.handle == NULL) {
       game_over();
       return 1;
    }

    config.linktype = pcap_datalink(config.handle);

    /* Segfaults on empty pcap! */
    if ((pcap_compile(config.handle, &config.cfilter, config.bpff, 1,
         config.net_mask)) == -1) {
            elog("[*] Error pcap_compile user_filter: %s\n",
                 pcap_geterr(config.handle));
            exit(1);
    }

    if (pcap_setfilter(config.handle, &config.cfilter)) {
            olog("[*] Unable to set pcap filter! %s",
                 pcap_geterr(config.handle));
    }

    alarm(TIMEOUT);

    if (!config.pcap_file) olog("[*] Sniffing...\n\n");

    pcap_loop(config.handle, -1, got_packet, NULL);

    game_over();
    return 0;
}

