/*
** This file is a part of passivedns.
**
** Copyright (C) 2010-2011, Edward Fjellskål <edwardfjellskaal@gmail.com>
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
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h> 
#include <signal.h>
#include <pcap.h>
#include <resolv.h>
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
#include "passivedns.h"
#include "dns.h"

#ifndef CONFDIR
#define CONFDIR "/etc/passivedns/"
#endif

/*  G L O B A L S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;
connection *bucket[BUCKET_SIZE];


/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
void check_vlan (packetinfo *pi);
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

//void dump_payload(const uint8_t* data,uint16_t dlen);
void game_over ();

/* F U N C T I O N S  ********************************************************/

void got_packet(u_char * useless, const struct pcap_pkthdr *pheader,
                const u_char * packet)
{
    config.p_s.got_packets++;
    packetinfo pstruct = {0};
    packetinfo *pi = &pstruct;
    pi->packet = packet;
    pi->pheader = pheader;
    set_pkt_end_ptr (pi);
    config.tstamp = pi->pheader->ts.tv_sec; // Global
    if (config.intr_flag != 0) {
        check_interrupt();
    }
    config.inpacket = 1;
    prepare_eth(pi);
    check_vlan(pi);
    //parse_eth(pi);

    if (pi->eth_type == ETHERNET_TYPE_IP) {
        prepare_ip4(pi);
        parse_ip4(pi);
    } else if (pi->eth_type == ETHERNET_TYPE_IPV6) {
        prepare_ip6(pi);
        parse_ip6(pi);
    } else {
        config.p_s.otherl_recv++;
        //vlog(0x3, "[*] ETHERNET TYPE : %x\n",pi->eth_hdr->eth_ip_type);
    }
    config.inpacket = 0;
    return;
}

void prepare_eth (packetinfo *pi)
{
    if (pi->packet + ETHERNET_HEADER_LEN > pi->end_ptr) return;
    config.p_s.eth_recv++;
    pi->eth_hdr  = (ether_header *) (pi->packet);
    pi->eth_type = ntohs(pi->eth_hdr->eth_ip_type);
    pi->eth_hlen = ETHERNET_HEADER_LEN;
    return;
}

/* void parse_eth (packetinfo *pi)
{
    return;
} */

void check_vlan (packetinfo *pi)
{
    if (pi->eth_type == ETHERNET_TYPE_8021Q) {
        vlog(0x3, "[*] ETHERNET TYPE 8021Q\n");
        config.p_s.vlan_recv++;
        pi->vlan = pi->eth_hdr->eth_8_vid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_8_ip_type);
        pi->eth_hlen += 4;

    /* This is b0rked - kwy and ebf fix */
    } else if (pi->eth_type ==
               (ETHERNET_TYPE_802Q1MT | ETHERNET_TYPE_802Q1MT2 |
                ETHERNET_TYPE_802Q1MT3 | ETHERNET_TYPE_8021AD)) {
        vlog(0x3, "[*] ETHERNET TYPE 802Q1MT\n");
        pi->mvlan = pi->eth_hdr->eth_82_mvid;
        pi->eth_type = ntohs(pi->eth_hdr->eth_82_ip_type);
        pi->eth_hlen += 8;
    }
    return;
}

void prepare_ip4 (packetinfo *pi)
{
    config.p_s.ip4_recv++;
    pi->af = AF_INET;
    pi->ip4 = (ip4_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = (pi->ip4->ip_len - (IP_HL(pi->ip4) * 4));

    //vlog(0x3, "Got IPv4 Packet...\n");
    return;
}

void parse_ip4 (packetinfo *pi)
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
    return;
}

void prepare_ip6ip (packetinfo *pi)
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
        return;
    } else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    }
}

void prepare_ip4ip (packetinfo *pi)
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
        return;
    } else {
        prepare_ip6(&pipi);
        parse_ip6(&pipi);
        return;
    }
}

void prepare_ip6 (packetinfo *pi)
{
    config.p_s.ip6_recv++;
    pi->af = AF_INET6;
    pi->ip6 = (ip6_header *) (pi->packet + pi->eth_hlen);
    pi->packet_bytes = pi->ip6->len;
    //vlog(0x3, "Got IPv6 Packet...\n");
    return;
}

void parse_ip6 (packetinfo *pi)
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
    return;
}

void parse_arp (packetinfo *pi)
{
    vlog(0x3, "[*] Got ARP packet...\n");
    config.p_s.arp_recv++;
    //if (!IS_CSSET(&config,CS_ARP)) return;
    pi->af = AF_INET;
    pi->arph = (ether_arp *) (pi->packet + pi->eth_hlen);
}

void set_pkt_end_ptr (packetinfo *pi)
{
    /* Paranoia! */
    if (pi->pheader->len <= SNAPLENGTH) {
        pi->end_ptr = (pi->packet + pi->pheader->len);
    } else {
        pi->end_ptr = (pi->packet + SNAPLENGTH);
    }
    return;
}

void prepare_tcp (packetinfo *pi)
{
    config.p_s.tcp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - (IP_HL(pi->ip4) * 4) - pi->eth_hlen);
        pi->payload = (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4) + (TCP_OFFSET(pi->tcph) * 4));
    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE TCP:\n");
        pi->tcph = (tcp_header *) (pi->packet + pi->eth_hlen + IP6_HEADER_LEN);
        pi->plen = (pi->pheader->caplen - (TCP_OFFSET(pi->tcph)) * 4 - IP6_HEADER_LEN - pi->eth_hlen);
        pi->payload = (pi->packet + pi->eth_hlen + IP6_HEADER_LEN + (TCP_OFFSET(pi->tcph)*4));
    }
    pi->proto  = IP_PROTO_TCP;
    pi->s_port = pi->tcph->src_port;
    pi->d_port = pi->tcph->dst_port;
    connection_tracking(pi);
    return;
}

void prepare_udp (packetinfo *pi)
{
    config.p_s.udp_recv++;
    if (pi->af==AF_INET) {
        vlog(0x3, "[*] IPv4 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + (IP_HL(pi->ip4) * 4));
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    (IP_HL(pi->ip4) * 4) - pi->eth_hlen;
        pi->payload = (pi->packet + pi->eth_hlen +
                        (IP_HL(pi->ip4) * 4) + UDP_HEADER_LEN);

    } else if (pi->af==AF_INET6) {
        vlog(0x3, "[*] IPv6 PROTOCOL TYPE UDP:\n");
        pi->udph = (udp_header *) (pi->packet + pi->eth_hlen + + IP6_HEADER_LEN);
        pi->plen = pi->pheader->caplen - UDP_HEADER_LEN -
                    IP6_HEADER_LEN - pi->eth_hlen;
        pi->payload = (pi->packet + pi->eth_hlen +
                        IP6_HEADER_LEN + UDP_HEADER_LEN);
    }
    pi->proto  = IP_PROTO_UDP;
    pi->s_port = pi->udph->src_port;
    pi->d_port = pi->udph->dst_port;
    connection_tracking(pi);
    return;
}

void parse_tcp (packetinfo *pi)
{
    if (pi->plen <= 0) return;

    /* Reliable traffic comes from the servers (normally on port 53 or 5353)
     * and the client has sent at least one package on that
     * connecton (Maybe asking for an aswer :) */
//    if ( pi->sc == SC_SERVER && pi->cxt->s_total_pkts > 0 ) {
        dlog("[D] Parsing TCP packet...\n");
        dns_parser(pi);
//    }   
    return;
}

void parse_udp (packetinfo *pi)
{
    if (pi->plen <= 0) return;

    /* Reliable traffic comes from the servers (normally on port 53 or 5353)
     * and the client has sent at least one package on that
     * connecton (Maybe asking for an aswer :) */
    //if ( pi->sc == SC_SERVER && pi->cxt->s_total_pkts > 0 ) {
        dlog("[D] Parsing UDP packet...\n");
        dns_parser(pi);
    //}
    return;
}

int connection_tracking(packetinfo *pi) {
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

    if(af== AF_INET6){
        ip_src = &PI_IP6SRC(pi);
        ip_dst = &PI_IP6DST(pi);
    }else {
        ips.s6_addr32[0] = pi->ip4->ip_src;
        ipd.s6_addr32[0] = pi->ip4->ip_dst;
        ip_src = &ips;
        ip_dst = &ipd;
    }

    // find the right connection bucket
    if (af == AF_INET) {
        hash = CXT_HASH4(IP4ADDR(ip_src),IP4ADDR(ip_dst));
    } else if (af == AF_INET6) {
        hash = CXT_HASH6(ip_src,ip_dst);
    }
    cxt = bucket[hash];
    head = cxt;

   // search through the bucket
    while (cxt != NULL) {
        // Two-way compare of given connection against connection table
        if (af == AF_INET) {
            if (CMP_CXT4(cxt,IP4ADDR(ip_src),src_port,IP4ADDR(ip_dst),dst_port)){
                // Client sends first packet (TCP/SYN - UDP?) hence this is a client
                return cxt_update_client(cxt, pi);
            } else if (CMP_CXT4(cxt,IP4ADDR(ip_dst),dst_port,IP4ADDR(ip_src),src_port)) {
                // This is a server (Maybe not when we start up but in the long run)
                return cxt_update_server(cxt, pi);
            }
        } else if (af == AF_INET6) {
            if (CMP_CXT6(cxt,ip_src,src_port,ip_dst,dst_port)){
                return cxt_update_client(cxt, pi);
            } else if (CMP_CXT6(cxt,ip_dst,dst_port,ip_src,src_port)){
                return cxt_update_server(cxt, pi);
            }
        }
        cxt = cxt->next;
    }
    // bucket turned upside down didn't yeild anything. new connection
    cxt = cxt_new(pi);

    /* New connections are pushed on to the head of bucket[s_hash] */
    cxt->next = head;
    if (head != NULL) {
        // are we doubly linked?
        head->prev = cxt;
    }
    bucket[hash] = cxt;
    pi->cxt = cxt;
    return cxt_update_client(cxt, pi);
}

/* freshly smelling connection :d */
connection *cxt_new(packetinfo *pi)
{
    struct in6_addr ips;
    struct in6_addr ipd;
    connection *cxt;
    config.cxtrackerid++;
    cxt = (connection *) calloc(1, sizeof(connection));
    //assert(cxt);
    cxt->cxid = config.cxtrackerid;

    cxt->af = pi->af;
    if(pi->tcph) cxt->s_tcpFlags |= pi->tcph->t_flags;
    cxt->start_time = pi->pheader->ts.tv_sec;
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if(pi-> af== AF_INET6){
        cxt->s_ip = PI_IP6SRC(pi);
        cxt->d_ip = PI_IP6DST(pi);
    }else {
        ips.s6_addr32[0] = pi->ip4->ip_src;
        ipd.s6_addr32[0] = pi->ip4->ip_dst;
        cxt->s_ip = ips;
        cxt->d_ip = ipd;
    }

    cxt->s_port = pi->s_port;
    cxt->d_port = pi->d_port;
    cxt->proto = pi->proto;

    cxt->check = 0x00;
    cxt->c_asset = NULL;
    cxt->s_asset = NULL;
    cxt->reversed = 0;
    config.curcxt++;

    return cxt;
}

int cxt_update_client(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if(pi->tcph) cxt->s_tcpFlags |= pi->tcph->t_flags;
    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_CLIENT;
    //if(!cxt->c_asset)
    //    cxt->c_asset = pi->asset; // connection client asset
    if (cxt->s_total_bytes > MAX_BYTE_CHECK
        || cxt->s_total_pkts > MAX_PKT_CHECK) {
        return 0;   // Dont Check!
    }
    return SC_CLIENT;
}

int cxt_update_server(connection *cxt, packetinfo *pi)
{
    cxt->last_pkt_time = pi->pheader->ts.tv_sec;

    if(pi->tcph) cxt->d_tcpFlags |= pi->tcph->t_flags;
    cxt->d_total_bytes += pi->packet_bytes;
    cxt->d_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_SERVER;
    //if(!cxt->s_asset)
    //    cxt->s_asset = pi->asset; // server asset
    if (cxt->d_total_bytes > MAX_BYTE_CHECK
        || cxt->d_total_pkts > MAX_PKT_CHECK) {
        return 0;   // Dont check!
    }
    return SC_SERVER;
}

void end_all_sessions()
{
    connection *cxt;
    int cxkey;
    config.llcxt = 0;

    for (cxkey = 0; cxkey < BUCKET_SIZE; cxkey++) {
        cxt = bucket[cxkey];
        while (cxt != NULL) {
            config.llcxt++;
            if (cxt->prev)
                cxt->prev->next = cxt->next;
            if (cxt->next)
                cxt->next->prev = cxt->prev;
            connection *tmp = cxt;

            cxt = cxt->next;
            del_connection(tmp, &bucket[cxkey]);
            if (cxt == NULL) {
                bucket[cxkey] = NULL;
            }
        }
    }
    dlog("CXT in list before cleaning: %10u\n", config.llcxt);
    dlog("CXT in list after  cleaning: %10u\n", config.curcxt);
}

void end_sessions()
{
    connection *cxt;
    time_t check_time;
    check_time = config.tstamp;
    //time(&check_time);
    int ended, expired = 0;
    config.llcxt = 0;

    int iter;

    for (iter = 0; iter < BUCKET_SIZE; iter++) {
        cxt = bucket[iter];
        while (cxt != NULL) {
            ended = 0;
            config.llcxt++;
            /* TCP */
            if (cxt->proto == IP_PROTO_TCP) {
                /* * FIN from both sides */
                if (cxt->s_tcpFlags & TF_FIN && cxt->d_tcpFlags & TF_FIN
                    && (check_time - cxt->last_pkt_time) > 5) {
                    ended = 1;
                } /* * RST from either side */
                else if ((cxt->s_tcpFlags & TF_RST
                          || cxt->d_tcpFlags & TF_RST)
                          && (check_time - cxt->last_pkt_time) > 5) {
                    ended = 1;
                }
                else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                    expired = 1;
                }
            }
            /* UDP */
            else if (cxt->proto == IP_PROTO_UDP
                     && (check_time - cxt->last_pkt_time) > 60) {
                expired = 1;
            }
            /* ICMP */
            else if (cxt->proto == IP_PROTO_ICMP
                     || cxt->proto == IP6_PROTO_ICMP) {
                if ((check_time - cxt->last_pkt_time) > 60) {
                     expired = 1;
                }
            }
            /* All Other protocols */
            else if ((check_time - cxt->last_pkt_time) > TCP_TIMEOUT) {
                expired = 1;
            }

            if (ended == 1 || expired == 1) {
                /* remove from the hash */
                if (cxt->prev)
                    cxt->prev->next = cxt->next;
                if (cxt->next)
                    cxt->next->prev = cxt->prev;
                connection *tmp = cxt;
                connection *tmp_pre = cxt->prev;

                ended = expired = 0;

                cxt = cxt->next;

                del_connection(tmp, &bucket[iter]);
                if (cxt == NULL && tmp_pre == NULL) {
                    bucket[iter] = NULL;
                }
            } else {
                cxt = cxt->next;
            }
        }
    }
    dlog("CXT in list before cleaning: %10u\n", config.llcxt);
    dlog("CXT in list after  cleaning: %10u\n", config.curcxt);
}

void del_connection(connection * cxt, connection ** bucket_ptr)
{
    connection *prev = cxt->prev;       /* OLDER connections */
    connection *next = cxt->next;       /* NEWER connections */

    if (prev == NULL) {
        // beginning of list
        *bucket_ptr = next;
        // not only entry
        if (next)
            next->prev = NULL;
    } else if (next == NULL) {
        // at end of list!
        prev->next = NULL;
    } else {
        // a node.
        prev->next = next;
        next->prev = prev;
    }

    // Free and set to NULL 
    free(cxt);
    cxt = NULL;
    config.curcxt--;
}

const char *u_ntop_src(packetinfo *pi, char *dest)
{
    if (pi->af == AF_INET) {
        if (!inet_ntop
            (AF_INET,
             &pi->ip4->ip_src,
                 dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    } else if (pi->af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &pi->ip6->ip_src, dest, INET6_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    }
    return dest;
}

void check_interrupt()
{
    dlog("[D] In interrupt. Flag: %d\n",config.intr_flag);
    if (ISSET_INTERRUPT_END(config)) {
        game_over();
    } else if (ISSET_INTERRUPT_SESSION(config)) {
        set_end_sessions();
    } else if (ISSET_INTERRUPT_DNS(config)) {
        set_end_dns_records();
    } else {
        config.intr_flag = 0;
    }
}

void sig_alarm_handler()
{
    time_t now_t;
    //config.tstamp = time(); // config.tstamp will stand still if there is no packets
    now_t = config.tstamp;

    dlog("[D] Got SIG ALRM: %lu\n", now_t);
    /* Each time check for timed out sessions */
    set_end_sessions();
    
    /* Only check for timed-out dns records each 10 minutes */
    if ( (now_t - config.dnslastchk) >= 600 ) {
        set_end_dns_records();
    }
    alarm(TIMEOUT);
}

void set_end_dns_records()
{
    config.intr_flag |= INTERRUPT_DNS;

    if (config.inpacket == 0) {
        expire_dns_records();
        config.dnslastchk = config.tstamp;
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

static int set_chroot(void) {
   char *absdir;

   /* logdir = get_abs_path(logpath); */

   /* change to the directory */
   if ( chdir(config.chroot_dir) != 0 ) {
      printf("set_chroot: Can not chdir to \"%s\": %s\n",config.chroot_dir,strerror(errno));
   }

   /* always returns an absolute pathname */
   absdir = getcwd(NULL, 0);

   /* make the chroot call */
   if ( chroot(absdir) < 0 ) {
      printf("Can not chroot to \"%s\": absolute: %s: %s\n",config.chroot_dir,absdir,strerror(errno));
   }

   if ( chdir("/") < 0 ) {
        printf("Can not chdir to \"/\" after chroot: %s\n",strerror(errno));
   }

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
            if(!gr){
                if(config.chroot_dir){
                    elog("ERROR: you have chrooted and must set numeric group ID.\n");
                    exit(1);
                }else{
                    elog("ERROR: couldn't get ID for group %s, group does not exist.", config.group_name)
                    exit(1);
                }
            }
            groupid = gr->gr_gid;
        } else {
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
            } else {
                printf("[E] User %s not found!\n", config.user_name);
            }
        } else {
            userid = strtoul(config.user_name, &endptr, 10);
            pw = getpwuid(userid);
        }

        if (config.group_name == NULL && pw != NULL) {
            groupid = pw->pw_gid;
        }
    }

    if (do_setgid) {
        if ((i = setgid(groupid)) < 0) {
            printf("Unable to set group ID: %s", strerror(i));
        }
   }

    endgrent();
    endpwent();

    if (do_setuid) {
        if (getuid() == 0 && initgroups(config.user_name, groupid) < 0) {
            printf("Unable to init group names (%s/%lu)", config.user_name,
                   groupid);
        }
        if ((i = setuid(userid)) < 0) {
            printf("Unable to set user ID: %s\n", strerror(i));
        }
    }
    return 0;
}

int is_valid_path(const char *path)
{
    char dir[STDBUF];
    struct stat st;

    if (path == NULL) {
        return 0;
    }

    memcpy(dir, path, strnlen(path, STDBUF));
    dirname(dir);

    if (stat(dir, &st) != 0) {
        return 0;
    }
    if (!S_ISDIR(st.st_mode) || access(dir, W_OK) == -1) {
        return 0;
    }
    return 1;
}

int create_pid_file(const char *path)
{
    char pid_buffer[12];
    struct flock lock;
    int rval;
    int fd;

    if (!path) {
        path = config.pidfile;
    }
    if (!is_valid_path(path)) {
        printf("PID path \"%s\" aint writable", path);
    }

    if ((fd = open(path, O_CREAT | O_WRONLY,
                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
        return ERROR;
    }

    /*
     * pid file locking 
     */
    lock.l_type = F_WRLCK;
    lock.l_start = 0;
    lock.l_whence = SEEK_SET;
    lock.l_len = 0;

    if (fcntl(fd, F_SETLK, &lock) == -1) {
        if (errno == EACCES || errno == EAGAIN) {
            rval = ERROR;
        } else {
            rval = ERROR;
        }
        close(fd);
        return rval;
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

    if (pid > 0) {
        exit(0);                /* parent */
    }

    config.use_syslog = 1;
    if (pid < 0) {
        return ERROR;
    }

    setsid();

    if ((fd = open("/dev/null", O_RDWR)) >= 0) {
        dup2(fd, 0);
        dup2(fd, 1);
        dup2(fd, 2);
        if (fd > 2) {
            close(fd);
        }
    }

    if (config.pidfile) {
        return create_pid_file(config.pidfile);
    }

    return SUCCESS;
}

void a_dump_payload(const uint8_t* data,uint16_t dlen) {
  uint8_t  tbuf[PKT_MAXPAY+2];
  uint8_t* t = tbuf;
  uint8_t  i;
  uint8_t  max = dlen > PKT_MAXPAY ? PKT_MAXPAY : dlen;

  if (!dlen) {
     olog(" # No Payload...\n");
     return;
  }

  for (i=0;i<max;i++) {
    if (isprint(*data)) *(t++) = *data;
      else if (!*data)  *(t++) = '?';
      else *(t++) = '.';
    data++;
  }

  *t = 0;

  plog( "  # Payload: \"%s\"%s",tbuf,dlen > PKT_MAXPAY ? "...\n" : "\n");
}

void game_over()
{
    if (config.inpacket == 0) {
        print_pdns_stats();
        if (config.handle != NULL) pcap_close(config.handle);
        config.handle = NULL;
        expire_all_dns_records();
        end_all_sessions();
        free_config();
        olog("\n[*] passivedns ended.\n");
        exit(0);
    }
    config.intr_flag |= INTERRUPT_END;
}

void free_config()
{
    if (config.cfilter.bf_insns != NULL) free (config.cfilter.bf_insns);
// Grr - no nice way to tell if the settings comes from configfile or not :/
    //if (config.pidfile != NULL) free(config.pidfile);
    if (config.user_name != NULL) free(config.user_name);
    if (config.group_name != NULL) free(config.group_name);
    if (config.chroot_dir != NULL) free(config.chroot_dir);
    //if (config.bpff != NULL) free(config.bpff);
    //if (config.dev != NULL) free(config.dev);
    if (config.pcap_file != NULL) free(config.pcap_file);
    //if (config.logfile != NULL) free(config.logfile);
}


void print_pdns_stats()
{
    olog("\n");
    olog("-- Total DNS records allocated            :%12u\n",config.p_s.dns_records);
    olog("-- Total DNS assets allocated             :%12u\n",config.p_s.dns_assets);
    olog("-- Total packets received from libpcap    :%12u\n",config.p_s.got_packets);
    olog("-- Total Ethernet packets received        :%12u\n",config.p_s.eth_recv);
    olog("-- Total VLAN packets received            :%12u\n",config.p_s.vlan_recv);
}

void usage()
{
    olog("\n");
    olog("USAGE:\n");
    olog(" $ passivedns [options]\n\n");
    olog(" passivedns version %s\n",VERSION);
    olog(" %s\n", pcap_lib_version());
    olog("\n");
    olog(" OPTIONS:\n");
    olog("\n");
    olog(" -i <iface>      Network device <iface> (default: eth0).\n");
    olog(" -r <file>       Read pcap <file>.\n");
    olog(" -l <file>       Name of the logfile (default: /var/log/passivedns.log).\n");
    olog(" -L <file>       Name of NXDOMAIN logfile (default: /var/log/passivedns-nxd.log).\n");
    olog(" -b 'BPF'        Berkley Packet Filter (default: 'port 53').\n");
    olog(" -p <file>       Name of pid file (default: /var/run/passivedns.pid).\n");
    olog(" -S <mem>        Soft memory limit in MB (default: 256).\n");
    olog(" -C <sec>        Seconds to cache DNS objects in memory (default %u).\n",DNSCACHETIMEOUT);
    olog(" -P <sec>        Seconds between printing duplicate DNS info (default %u).\n",DNSPRINTTIME);
    olog(" -X <flags>      Manually set DNS RR Types to care about(Default -X 46CDNPRS).\n");
    olog(" -u <uid>        User ID to drop privileges to.\n");
    olog(" -g <gid>        Group ID to drop privileges to.\n");
    olog(" -T <dir>        Directory to chroot into.\n");
    olog(" -D              Run as daemon.\n");
    olog(" -h              This help message.\n\n");
    olog(" FLAGS:\n");
    olog("\n");
    olog("  4:A    6:AAAA  C:CNAME  D:DNAME  N:NAPTR  O:SOA\n");
    olog("  P:PTR  R:RP    S:SRV    T:TXT    M:MX     n:NS\n");
    olog("  x:NXD\n");
    olog("\n");
}

extern int optind, opterr, optopt; // getopt()

/* magic main */
int main(int argc, char *argv[])
{
    int ch = 0; // verbose_already = 0;
    int daemon = 0;
    memset(&config, 0, sizeof(globalconfig));
    //set_default_config_options();
    config.inpacket = config.intr_flag = 0;
    config.dnslastchk = 0;
    //char *pconfile;
#define BPFF "port 53"
    config.bpff = BPFF;
    config.logfile = "/var/log/passivedns.log";
    config.logfile_nxd = "/var/log/passivedns-nxd.log";
    config.pidfile = "/var/run/passivedns.pid";
    config.mem_limit_max = (256 * 1024 * 1024); // 256 MB - default try to limit dns caching to this
    config.dnsprinttime = DNSPRINTTIME;
    config.dnscachetimeout =  DNSCACHETIMEOUT;
    config.dnsf = 0;
    config.dnsf |= DNS_CHK_A;
    config.dnsf |= DNS_CHK_AAAA;
    config.dnsf |= DNS_CHK_PTR;
    config.dnsf |= DNS_CHK_CNAME;
    config.dnsf |= DNS_CHK_DNAME;
    config.dnsf |= DNS_CHK_NAPTR;
    config.dnsf |= DNS_CHK_RP;
    config.dnsf |= DNS_CHK_SRV;
//    config.dnsf |= DNS_CHK_TXT;
//    config.dnsf |= DNS_CHK_SOA;
//    config.dnsf |= DNS_CHK_NS;
//    config.dnsf |= DNS_CHK_MX;
    config.dnsf |= DNS_CHK_NXDOMAIN;

    signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
    signal(SIGQUIT, game_over);
    signal(SIGALRM, sig_alarm_handler);

#define ARGS "i:r:l:L:hb:Dp:C:P:S:X:u:g:T:"

    while ((ch = getopt(argc, argv, ARGS)) != -1)
        switch (ch) {
        case 'i':
            config.dev = strdup(optarg);
            break;
        case 'r':
            config.pcap_file = strdup(optarg);
            break;
        case 'L':
            config.logfile_nxd = strdup(optarg);
            break;
        case 'l':
            config.logfile = strdup(optarg);
            break;
        case 'b':
            config.bpff = strdup(optarg);
            break;
        case 'p':
            config.pidfile = strdup(optarg);
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
        case 'X':
            parse_dns_flags(optarg);
            break;
        case 'D':
            daemon = 1;
            break;
        case 'T':
            config.chroot_dir = strdup(optarg);
            config.chroot_flag = 1;
            break;
        case 'u':
            config.user_name = strdup(optarg);
            config.drop_privs_flag = 1;
            break;
        case 'g':
            config.group_name = strdup(optarg);
            config.drop_privs_flag = 1;
            break;
        case 'h':
            usage();
            exit(0);
            break;
        case '?':
            elog("unrecognized argument: '%c'\n", optopt);
            break;
        default:
            elog("Did not recognize argument '%c'\n", ch);
        }

    olog("\n[*] Running passivedns %s\n", VERSION);
    olog("    Using %s\n", pcap_lib_version());

    if (config.pcap_file) {
        /* Read from PCAP file specified by '-r' switch. */
        olog("[*] Reading from file %s\n", config.pcap_file);
        if (!(config.handle = pcap_open_offline(config.pcap_file, config.errbuf))) {
            olog("[*] Unable to open %s.  (%s)", config.pcap_file, config.errbuf);
        }

    } else {

        /* * look up an available device if non specified */
        if (config.dev == 0x0)
            config.dev = pcap_lookupdev(config.errbuf);
        olog("[*] Device: %s\n", config.dev);

        if ((config.handle = pcap_open_live(config.dev, SNAPLENGTH, 1, 500, config.errbuf)) == NULL) {
            olog("[*] Error pcap_open_live: %s \n", config.errbuf);
            exit(1);
        }
        /* * B0rk if we see an error... */
        if (strlen(config.errbuf) > 0) {
            elog("[*] Error errbuf: %s \n", config.errbuf);
            exit(1);
        }

        if(config.chroot_dir){
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

    /** segfaults on empty pcap! */
    if ((pcap_compile(config.handle, &config.cfilter, config.bpff, 1, config.net_mask)) == -1) {
            olog("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(config.handle));
            exit(1);
    }

    if (pcap_setfilter(config.handle, &config.cfilter)) {
            olog("[*] Unable to set pcap filter!  %s", pcap_geterr(config.handle));
    }

    alarm(TIMEOUT);

    olog("[*] Sniffing...\n\n");
    pcap_loop(config.handle, -1, got_packet, NULL);

    game_over();
    return (0);
}

