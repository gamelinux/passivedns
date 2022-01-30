/*
** This file is a part of PassiveDNS.
**
** Copyright (C) 2010-2013, Edward Fjellskål <edwardfjellskaal@gmail.com>
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
#include "passivedns.h"
#include "dns.h"

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
static volatile sig_atomic_t signal_reopen_log_files = 0;

/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
static void show_version();
void check_vlan (packetinfo *pi);
void prepare_null (packetinfo *pi);
void prepare_raw (packetinfo *pi);
void prepare_sll (packetinfo *pi);
void prepare_eth (packetinfo *pi);
void prepare_ip4 (packetinfo *pi);
void prepare_ip4ip (packetinfo *pi);
void prepare_ip6 (packetinfo *pi);
void prepare_ip6ip (packetinfo *pi);
void prepare_udp (packetinfo *pi);
void prepare_tcp (packetinfo *pi);
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
    config.p_s.got_packets++;
    packetinfo pstruct = {0};
    packetinfo *pi = &pstruct;
    pi->packet = packet;
    pi->pheader = pheader;
    set_pkt_end_ptr (pi);
    memcpy( &config.tstamp, &pi->pheader->ts, sizeof( struct timeval ) ); /* Global */

    if (signal_reopen_log_files)
        reopen_log_files();

    if (config.intr_flag != 0) {
        check_interrupt();
    }
    config.inpacket = 1;

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
            prepare_ip4(pi);
            parse_ip4(pi);
            break;
        case ETHERNET_TYPE_IPV6:
            prepare_ip6(pi);
            parse_ip6(pi);
            break;
        default:
            config.p_s.otherl_recv++;
            //vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi->eth_hdr->eth_ip_type);
            break;
    }

    config.inpacket = 0;
}

void prepare_null(packetinfo *pi)
{
    pi->eth_hlen = LOOPBACK_HDR_LEN;
    if ((u_int32_t)*pi->packet == AF_INET) {
        pi->eth_type = ETHERNET_TYPE_IP;
    } else {
        pi->eth_type = ETHERNET_TYPE_IPV6;
    }
}

void prepare_raw(packetinfo *pi)
{
    pi->eth_hlen = 0;
    if (IP_V((ip4_header *)pi->packet) == 4)
        pi->eth_type = ETHERNET_TYPE_IP;
    else
        pi->eth_type = ETHERNET_TYPE_IPV6;
}

void prepare_sll(packetinfo *pi)
{
    pi->eth_hlen = SLL_HDR_LEN;

    if (IP_V((ip4_header *)(pi->packet + SLL_HDR_LEN)) == 4)
        pi->eth_type = ETHERNET_TYPE_IP;
    else
        pi->eth_type = ETHERNET_TYPE_IPV6;
}

void prepare_eth(packetinfo *pi)
{
    if (pi->packet + ETHERNET_HEADER_LEN > pi->end_ptr)
        return;

    config.p_s.eth_recv++;
    pi->eth_hdr = (ether_header *) (pi->packet);
    pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
    pi->eth_hlen = ETHERNET_HEADER_LEN;
}

void check_vlan(packetinfo *pi)
{
    if (pi->eth_type == ETHERNET_TYPE_8021Q) {
        vlog(0x3, "[*] ETHERNET TYPE 8021Q\n");
        config.p_s.vlan_recv++;
        pi->vlan = pi->eth_hdr->eth_8_vid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_8_ip_type);
        pi->eth_hlen += 4;
        if ( pi->eth_type == ETHERNET_TYPE_8021Q ) {
            vlog(0x3, "[*] ETHERNET TYPE 8021Q in 8021Q\n");
            pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
            pi->eth_hlen += 4;
            pi->vlan = pi->eth_hdr->eth_82_vid;
        }
    }
    else if (pi->eth_type == (ETHERNET_TYPE_802Q1MT  | ETHERNET_TYPE_802Q1MT2 |
                              ETHERNET_TYPE_802Q1MT3 | ETHERNET_TYPE_8021AD)) {
        vlog(0x3, "[*] ETHERNET TYPE 802Q1MT\n");
        pi->mvlan = pi->eth_hdr->eth_82_mvid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
        pi->eth_hlen += 8;
    }
}

void prepare_ip4(packetinfo *pi)
{
    config.p_s.ip4_recv++;
    pi->af = AF_INET;
    pi->ip4 = (ip4_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = (pi->ip4->ip_len - (IP_HL(pi->ip4) * 4));
}

void parse_ip4(packetinfo *pi)
{
    /* Paranoia */
    if (((pi->packet + pi->eth_hlen) + (IP_HL(pi->ip4) * 4)) > pi->end_ptr) {
        dlog("[D] Refusing to parse IPv4 packet: IPv4-hdr passed end_ptr\n");
        return;
    }

    switch (pi->ip4->ip_p) {
        case IP_PROTO_TCP:
            prepare_tcp(pi);
            parse_tcp(pi);
            break;
        case IP_PROTO_UDP:
            prepare_udp(pi);
            parse_udp(pi);
            break;
        case IP_PROTO_IP4:
            prepare_ip4ip(pi);
            break;
        case IP_PROTO_IP6:
            prepare_ip4ip(pi);
            break;
        default:
            break;
    }
}

void prepare_ip6ip(packetinfo *pi)
{
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    config.p_s.ip6ip_recv++;
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
    pipi.end_ptr = pi->end_ptr;

    if (pi->ip6->next == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
    }
    else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
    }
}

void prepare_ip4ip(packetinfo *pi)
{
    packetinfo pipi;
    memset(&pipi, 0, sizeof(packetinfo));
    config.p_s.ip4ip_recv++;
    pipi.pheader = pi->pheader;
    pipi.packet = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
    pipi.end_ptr = pi->end_ptr;

    if (pi->ip4->ip_p == IP_PROTO_IP4) {
        prepare_ip4(&pipi);
        parse_ip4(&pipi);
    }
    else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
    }
}

void prepare_ip6(packetinfo *pi)
{
    config.p_s.ip6_recv++;
    pi->af = AF_INET6;
    pi->ip6 = (ip6_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = pi->ip6->len;
}

void parse_ip6(packetinfo *pi)
{
    switch (pi->ip6->next) {
        case IP_PROTO_TCP:
            prepare_tcp(pi);
            parse_tcp(pi);
            break;
        case IP_PROTO_UDP:
            prepare_udp(pi);
            parse_udp(pi);
            break;
        case IP_PROTO_IP4:
            prepare_ip6ip(pi);
            break;
        case IP_PROTO_IP6:
            prepare_ip6ip(pi);
            break;
        default:
            break;
    }
}

void set_pkt_end_ptr(packetinfo *pi)
{
    /* Paranoia! */
    if (pi->pheader->len <= SNAPLENGTH)
        pi->end_ptr = (pi->packet + pi->pheader->len);
    else
        pi->end_ptr = (pi->packet + SNAPLENGTH);
}

void prepare_tcp(packetinfo *pi)
{
    config.p_s.tcp_recv++;
    if (pi->af == AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen +
                   (IP_HL(pi->ip4) * 4));
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 -
                   (IP_HL(pi->ip4) * 4) - pi->eth_hlen);
        pi->payload = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4) +
                      (TCP_OFFSET(pi->tcph) * 4));
    }
    else if (pi->af == AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 -
                   IP6_HEADER_LEN - pi->eth_hlen);
        pi->payload = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN +
                      (TCP_OFFSET(pi->tcph)*4));
    }
    pi->proto  = IP_PROTO_TCP;
    pi->s_port = pi->tcph->src_port;
    pi->d_port = pi->tcph->dst_port;
    connection_tracking(pi);
}

void prepare_udp(packetinfo *pi)
{
    config.p_s.udp_recv++;
    if (pi->af == AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen +
                   (IP_HL(pi->ip4) * 4));
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    (IP_HL(pi->ip4) * 4) - pi->eth_hlen;
        pi->payload = (pi->packet + pi->eth_hlen +
                        (IP_HL(pi->ip4) * 4) + UDP_HEADER_LEN);
    }
    else if (pi->af == AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen +
                   IP6_HEADER_LEN);
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    IP6_HEADER_LEN - pi->eth_hlen;
        pi->payload = (pi->packet + pi->eth_hlen +
                        IP6_HEADER_LEN + UDP_HEADER_LEN);
    }
    pi->proto  = IP_PROTO_UDP;
    pi->s_port = pi->udph->src_port;
    pi->d_port = pi->udph->dst_port;
    connection_tracking(pi);
}

void parse_tcp(packetinfo *pi)
{
    if (pi->plen <= 0) return;

    /* Reliable traffic comes from the servers (normally on port 53 or 5353)
     * and the client has sent at least one packet on that
     * connecton (Maybe asking for an aswer :) */
    dlog("[D] Parsing TCP packet...\n");
    dns_parser(pi);
}

void parse_udp(packetinfo *pi)
{
    if (pi->plen <= 0) return;

    /* Reliable traffic comes from the servers (normally on port 53 or 5353)
     * and the client has sent at least one packet on that
     * connecton (Maybe asking for an aswer :) */
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

    cxt = bucket[hash];
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

                if (pi->sc == SC_SERVER) {
                    /* This is a server */
                    dlog("[D] Found existing v4 server connection.\n");
                    return cxt_update_server(cxt, pi);
                }
                else {
                    /* This is a client, where we saw a mid-stream DNS response first */
                    dlog("[D] Found existing unknown v4 server connection.\n");
                    return cxt_update_client(cxt, pi);
                }
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

    /* New connections are pushed on to the head of bucket[s_hash] */
    cxt->next = head;
    if (head != NULL)
        /* Are we double linked? */
        head->prev = cxt;

    bucket[hash] = cxt;
    pi->cxt = cxt;
    return cxt_update_unknown(cxt, pi);
}

/* Freshly smelling connection :d */
connection *cxt_new(packetinfo *pi)
{
    struct in6_addr ips;
    struct in6_addr ipd;
    connection *cxt;
    config.cxtrackerid++;
    cxt = (connection *) calloc(1, sizeof(connection));
    cxt->cxid = config.cxtrackerid;
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
    config.curcxt++;

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

void end_all_sessions()
{
    connection *cxt;
    int cxkey;
    config.llcxt = 0;

    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++)
    {
        cxt = bucket[cxkey];
        while (cxt != NULL)
        {
            config.llcxt++;
            if (cxt->prev)
                cxt->prev->next = cxt->next;
            if (cxt->next)
                cxt->next->prev = cxt->prev;
            connection *tmp = cxt;

            cxt = cxt->next;
            del_connection(tmp, &bucket[cxkey]);
            if (cxt == NULL)
                bucket[cxkey] = NULL;
        }
    }
    dlog("CXT in list before cleaning: %10u\n", config.llcxt);
    dlog("CXT in list after  cleaning: %10u\n", config.curcxt);
}

void end_sessions()
{
    connection *cxt;
    time_t check_time;
    check_time = config.tstamp.tv_sec;
    int ended, expired = 0;
    config.llcxt = 0;

    int iter;

    for (iter = 0; iter < BUCKET_SIZE; iter++)
    {
        cxt = bucket[iter];
        while (cxt != NULL)
        {
            ended = 0;
            config.llcxt++;
            /* TCP */
            if (cxt->proto == IP_PROTO_TCP) {
                /* FIN from both sides */
                if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                        && (check_time - cxt->last_pkt_time) > 5)
                    ended = 1;
                /* RST from either side */
                else if ((cxt->s_tcpFlags & TF_RST || cxt->d_tcpFlags & TF_RST)
                        && (check_time - cxt->last_pkt_time) > 5)
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

                del_connection(tmp, &bucket[iter]);
                if (cxt == NULL && tmp_pre == NULL)
                    bucket[iter] = NULL;
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

    /* Free and set to NULL */
    free(cxt);
    cxt = NULL;
    config.curcxt--;
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

void reopen_log_files()
{
    if (config.output_log) {
        if (config.logfile_fd != NULL && config.logfile_fd != stdout)
            fclose(config.logfile_fd);
        config.logfile_fd = fopen(config.logfile, "a");
    }

    if (config.output_log_nxd) {
        if (config.logfile_all) {
            /* Do nothing, since both logs use the same file */
        }
        else {
            if (config.logfile_nxd_fd != NULL && config.logfile_nxd_fd != stdout)
                fclose(config.logfile_nxd_fd);
            config.logfile_nxd_fd = fopen(config.logfile_nxd, "a");
        }
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

   /* Change to the directory */
   if (chdir(config.chroot_dir) != 0)
       printf("set_chroot: Can not chdir to \"%s\": %s\n",
              config.chroot_dir,strerror(errno));

   /* Always returns an absolute pathname */
   absdir = getcwd(NULL, 0);

   /* Make the chroot call */
   if (chroot(absdir) < 0)
       printf("Could not chroot to \"%s\": absolute: %s: %s\n",
              config.chroot_dir, absdir, strerror(errno));

   if (chdir("/") < 0)
       printf("Could not chdir to \"/\" after chroot: %s\n", strerror(errno));

   return 0;
}

int drop_privs(void)
{
    struct group *gr;
    struct passwd *pw;
    char *endptr;
    int i;
    int do_setuid = 0;
    int do_setgid = 0;
    unsigned long groupid = 0;
    unsigned long userid = 0;

    if (config.group_name != NULL) {
        do_setgid = 1;
        if (!isdigit(config.group_name[0])) {
            gr = getgrnam(config.group_name);
            if (!gr) {
                if (config.chroot_dir) {
                    elog("ERROR: you have chrooted and must set numeric group ID.\n");
                    exit(1);
                }
                else {
                    elog("ERROR: couldn't get ID for group %s, group does not exist.", config.group_name);
                    exit(1);
                }
            }
            groupid = gr->gr_gid;
        }
        else {
            groupid = strtoul(config.group_name, &endptr, 10);
        }
    }

    if (config.user_name != NULL) {
        do_setuid = 1;
        do_setgid = 1;
        if (isdigit(config.user_name[0]) == 0) {
            pw = getpwnam(config.user_name);
            if (pw != NULL) {
                userid = pw->pw_uid;
            }
            else {
                printf("[E] User %s not found!\n", config.user_name);
            }
        }
        else {
            userid = strtoul(config.user_name, &endptr, 10);
            pw = getpwuid(userid);
        }

        if (config.group_name == NULL && pw != NULL)
            groupid = pw->pw_gid;
    }

    if (do_setgid) {
        if ((i = setgid(groupid)) < 0)
            printf("Unable to set group ID: %s", strerror(i));
   }

    endgrent();
    endpwent();

    if (do_setuid) {
        if (getuid() == 0 && initgroups(config.user_name, groupid) < 0)
            printf("Unable to init group names (%s/%lu)", config.user_name,
                   groupid);

        if ((i = setuid(userid)) < 0)
            printf("Unable to set user ID: %s\n", strerror(i));
    }
    return 0;
}

int is_valid_path(const char *path)
{
    char dir[STDBUF];
    struct stat st;

    if (path == NULL)
        return 0;

    memcpy(dir, path, strnlen(path, STDBUF));
    dirname(dir);

    if (stat(dir, &st) != 0)
        return 0;

    if (!S_ISDIR(st.st_mode) || access(dir, W_OK) == -1)
        return 0;

    return 1;
}

int create_pid_file(const char *path)
{
    char pid_buffer[12];
    struct flock lock;
    int fd;

    if (!path)
        path = config.pidfile;

    if (!is_valid_path(path))
        printf("PID path \"%s\" aint writable", path);

    if ((fd = open(path, O_CREAT | O_WRONLY,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
        return ERROR;

    /* PID file locking */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        close(fd);
        return ERROR;
    }

    snprintf(pid_buffer, sizeof(pid_buffer), "%d\n", (int)getpid());

    if (ftruncate(fd, 0) != 0) {
        close(fd);
        return ERROR;
    }

    if (write(fd, pid_buffer, strlen(pid_buffer)) != 0) {
        close(fd);
        return ERROR;
    }

    close(fd);
    return SUCCESS;
}

int daemonize()
{
    pid_t pid;
    int fd;

    pid = fork();

    if (pid > 0)
        exit(0);    /* Parent */

    if (pid < 0)
        return ERROR;

    setsid();

    if ((fd = open("/dev/null", O_RDWR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) {
            close(fd);
        }
    }

    if (config.pidfile)
        return create_pid_file(config.pidfile);

    return SUCCESS;
}

void game_over()
{
    if (config.inpacket == 0) {
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

        end_all_sessions();

        if (config.logfile_fd != NULL && config.logfile_fd != stdout)
            fclose(config.logfile_fd);

        if (config.logfile_nxd_fd != NULL && config.logfile_nxd_fd != stdout)
            fclose(config.logfile_nxd_fd);

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
         config.p_s.dns_records);
    flog(handle, "-- Total DNS assets allocated             :%12u\n",
         config.p_s.dns_assets);
    flog(handle, "-- Total DNS packets over IPv4/TCP        :%12u\n",
         config.p_s.ip4_dns_tcp);
    flog(handle, "-- Total DNS packets over IPv6/TCP        :%12u\n",
         config.p_s.ip6_dns_tcp);
    flog(handle, "-- Total DNS packets over TCP decoded     :%12u\n",
         config.p_s.ip4_dec_tcp_ok + config.p_s.ip6_dec_tcp_ok);
    flog(handle, "-- Total DNS packets over TCP failed      :%12u\n",
         config.p_s.ip4_dec_tcp_er + config.p_s.ip6_dec_tcp_er);
    flog(handle, "-- Total DNS packets over IPv4/UDP        :%12u\n",
         config.p_s.ip4_dns_udp);
    flog(handle, "-- Total DNS packets over IPv6/UDP        :%12u\n",
         config.p_s.ip6_dns_udp);
    flog(handle, "-- Total DNS packets over UDP decoded     :%12u\n",
         config.p_s.ip4_dec_udp_ok + config.p_s.ip6_dec_udp_ok);
    flog(handle, "-- Total DNS packets over UDP failed      :%12u\n",
         config.p_s.ip4_dec_udp_er + config.p_s.ip6_dec_udp_er);
    flog(handle, "-- Total packets received from libpcap    :%12u\n",
         config.p_s.got_packets);
    flog(handle, "-- Total Ethernet packets received        :%12u\n",
         config.p_s.eth_recv);
    flog(handle, "-- Total VLAN packets received            :%12u\n",
         config.p_s.vlan_recv);

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
    olog(" -s <file>       Print stats on signal (SIGUSR1) to this file.\n");
    olog(" -b 'BPF'        Berkley Packet Filter (default: 'port 53').\n");
    olog(" -p <file>       Name of pid file (default: /var/run/passivedns.pid).\n");
    olog(" -S <mem>        Soft memory limit in MB (default: 256).\n");
    olog(" -C <sec>        Seconds to cache DNS objects in memory (default: %u).\n", DNSCACHETIMEOUT);
    olog(" -P <sec>        Seconds between printing duplicate DNS info (default %u).\n", DNSPRINTTIME);
    olog(" -X <flags>      Manually set DNS RR Types to care about (default: -X 46CDNPRS).\n");
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
    olog("   W: Server MAC                                                     \n");
    olog("\n");
    olog(" FLAGS:\n");
    olog("\n");
    olog(" * For Record Types:\n");
    olog("   4:A      6:AAAA  C:CNAME  D:DNAME  N:NAPTR  O:SOA  L:LOC   F:SPF   I:HINFO\n");
    olog("   P:PTR    R:RP    S:SRV    T:TXT    M:MX     n:NS   d:DNSEC H:SSHFP\n");
    olog("   L also enables GPOS\n");
#ifdef LDNS_RR_TYPE_NSEC3PARAM
    olog("   d enables DS, DNSKEY, NSEC, NSEC3, RRSIG\n");
#else
    olog("   d enables DS, DNSKEY, NSEC, NSEC3, NSEC3PARAM, RRSIG\n");
#endif /* LDNS_RR_TYPE_NSEC3PARAM */
    olog("\n");
    olog(" * For Server Return Code (SRC) Errors:\n");
    olog("   f:FORMERR   s:SERVFAIL  x:NXDOMAIN  o:NOTIMPL  r:REFUSED\n");
    olog("   y:YXDOMAIN  e:YXRRSET   t:NXRRSET   a:NOTAUTH  z:NOTZONE\n");
    olog("\n");
}

void show_version()
{
    olog("\n");
    olog("[*] PassiveDNS %s\n", VERSION);
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

extern int optind, opterr, optopt; // getopt()

/* magic main */
int main(int argc, char *argv[])
{
    int ch = 0; // verbose_already = 0;
    int daemon = 0;
    memset(&config, 0, sizeof(globalconfig));
    config.inpacket = config.intr_flag = 0;
    config.dnslastchk = 0;
    config.bpff = BPFF;
    config.logfile = "/var/log/passivedns.log";
    config.logfile_nxd = "/var/log/passivedns.log";
    config.statsfile = "/var/log/passivedns.stats";
    config.pidfile = "/var/run/passivedns.pid";
    config.promisc = 1;
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

#define ARGS "i:H:r:qc:nyYNjJl:s:L:d:hb:Dp:C:P:S:f:X:u:g:T:V"

    while ((ch = getopt(argc, argv, ARGS)) != -1)
        switch (ch) {
        case 'i':
            config.dev = optarg;
            break;
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
            config.dnscachetimeout = strtol(optarg, NULL, 0);
            break;
        case 'P':
            config.dnsprinttime = strtol(optarg, NULL, 0);
            break;
        case 'S':
            config.mem_limit_max = (strtol(optarg, NULL, 0) * 1024 * 1024);
            break;
        case 's':
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
            config.cluster_id = strtol(optarg, NULL, 0);
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
            config.hostname = malloc(HOST_NAME_MAX + 1);
            gethostname(config.hostname, HOST_NAME_MAX);
        }
    }

    /* Fall back to log file if syslog is not used */
    if (config.output_syslog == 0)
        config.output_log = 1;

    if (config.output_syslog_nxd == 0)
        config.output_log_nxd = 1;

    /* Open log file */
    if (config.output_log) {
        if (config.logfile[0] == '-' && config.logfile[1] == '\0') {
            config.logfile_fd = stdout;
        }
        else {
            config.logfile_fd = fopen(config.logfile, "a");
            if (config.logfile_fd == NULL) {
                elog("[!] Error opening log file %s\n", config.logfile);
                exit(1);
            }
        }
    }

    /* Open NXDOMAIN log file */
    if (config.output_log_nxd) {
        if (config.output_log && strcmp(config.logfile, config.logfile_nxd) == 0) {
            config.logfile_all = 1;
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
        }
    }

    show_version();

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

        flags |= PF_RING_PROMISC;
        config.pfhandle = pfring_open(config.dev, SNAPLENGTH, flags);

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

        if (config.chroot_dir) {
            olog("[*] Chrooting to dir '%s'..\n", config.chroot_dir);
            if (set_chroot()) {
                elog("[!] failed to chroot\n");
                exit(1);
            }
        }

        if (config.drop_privs_flag) {
            olog("[*] Dropping privs...\n");
            drop_privs();
        }

        if (daemon) {
            if (!is_valid_path(config.pidfile))
                elog("[*] Unable to create pidfile '%s'\n", config.pidfile);
            openlog("passivedns", LOG_PID | LOG_CONS, LOG_DAEMON);
            olog("[*] Daemonizing...\n\n");
            daemonize();
        }

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
            elog("[*] Unable to open %s.  (%s)", config.pcap_file, config.errbuf);
        }

    }
    else {
        /* Look up an available device if non specified */
        if (config.dev == 0x0)
            config.dev = pcap_lookupdev(config.errbuf);
        olog("[*] Device: %s\n", config.dev);

        if ((config.handle = pcap_open_live(config.dev, SNAPLENGTH, config.promisc, 500,
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

        if (config.chroot_dir) {
            olog("[*] Chrooting to dir '%s'..\n", config.chroot_dir);
            if(set_chroot()){
                elog("[!] failed to chroot\n");
                exit(1);
            }
        }

        if (config.drop_privs_flag) {
            olog("[*] Dropping privs...\n");
            drop_privs();
        }

        if (daemon) {
            if (!is_valid_path(config.pidfile))
                elog("[*] Unable to create pidfile '%s'\n", config.pidfile);
            openlog("passivedns", LOG_PID | LOG_CONS, LOG_DAEMON);
            olog("[*] Daemonizing...\n\n");
            daemonize();
        }

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

