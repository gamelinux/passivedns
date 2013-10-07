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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <pcap.h>

#ifdef WIN32
#include <direct.h>
#include <process.h>	//_getpid()
#include <io.h>
#include <sys/locking.h>
#include <share.h>
#include <mbstring.h>
//#include <strsafe.h>	//ErrorExit()
#include <conio.h>
#include <userenv.h>
#include <lm.h>
#include <Shlobj.h>
#include <shellapi.h>

//for CreateThread
#if defined(NTDDI_WS08) && (NTDDI_VERSION >= NTDDI_WS08)
#include <Processthreadsapi.h>	//Windows 8 and Windows Server 2012
#else
#include <windows.h>	//Windows XP, Vista, 7, Server 2003/2008/R2
#endif

#include "wingetopt.h"
#include "inet_ntop.h"

HANDLE  hAlrmThread = NULL;			//alarm thread  handle
HANDLE  hPdnsStatsThread = NULL;	//thred for printing pdns stats

#else
#include <libgen.h>
#include <arpa/inet.h>	//not avail. in Win
#include <netinet/in.h>	//not avail. in Win
#include <resolv.h>
#include <grp.h>	//part of Glibc
#include <pwd.h>	//part of Glibc
#include <unistd.h>
#include <syslog.h>
#endif

#include "passivedns.h"
#include "dns.h"

#define BPFF "port 53"

/*  G L O B A L S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;
connection *bucket[BUCKET_SIZE];


/*  I N T E R N A L   P R O T O T Y P E S  ***********************************/
static void usage();
static void show_version();
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
DWORD WINAPI pdns_stats_hanlder(LPVOID lpParam);
void print_pdns_stats();
void free_config();

//void dump_payload(const uint8_t* data,uint16_t dlen);
void game_over (int sig);

/* F U N C T I O N S  ********************************************************/

void got_packet(u_char * useless, const struct pcap_pkthdr *pheader,
                const u_char * packet)
{
	packetinfo pstruct = {0};
	packetinfo *pi = &pstruct;
    config.p_s.got_packets++;
    pi->packet = packet;
    pi->pheader = pheader;
    set_pkt_end_ptr (pi);
    config.tstamp = pi->pheader->ts; // Global
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
		//copy IPv4 address(4bytes) to IPv6 address
        ips.u.Word[0] = pi->ip4->ip_src & 0xFFFF;
		ips.u.Word[1] = (pi->ip4->ip_src >> 16) & 0xFFFF;
		ipd.u.Word[0] = pi->ip4->ip_dst & 0xFFFF;
		ipd.u.Word[1] = (pi->ip4->ip_dst >> 16) & 0xFFFF;
        ip_src = &ips;
        ip_dst = &ipd;
    }

    // find the right connection bucket
    if (af == AF_INET) {
        hash = CXT_HASH4(IP4ADDR(ip_src),IP4ADDR(ip_dst),src_port,dst_port,pi->proto);
    } else if (af == AF_INET6) {
        hash = CXT_HASH6(ip_src,ip_dst,src_port,dst_port,pi->proto);
    }
    cxt = bucket[hash];
    head = cxt;

   // search through the bucket
    while (cxt != NULL) {
        // Two-way compare of given connection against connection table
        if (af == AF_INET) {
            if (CMP_CXT4(cxt,
						IP4ADDR(ip_src), src_port,
						IP4ADDR(ip_dst), dst_port)){
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
		ips.u.Word[0] = pi->ip4->ip_src & 0xFFFF;
		ips.u.Word[1] = (pi->ip4->ip_src >> 16) & 0xFFFF;
		ipd.u.Word[0] = pi->ip4->ip_dst & 0xFFFF;
		ipd.u.Word[1] = (pi->ip4->ip_dst >> 16) & 0xFFFF;
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

    if(pi->tcph) cxt->s_tcpFlags |= pi->tcph->t_flags;
    cxt->s_total_bytes += pi->packet_bytes;
    cxt->s_total_pkts += 1;

    pi->cxt = cxt;
    pi->sc = SC_CLIENT;
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
    if (cxt->d_total_bytes > MAX_BYTE_CHECK
        || cxt->d_total_pkts > MAX_PKT_CHECK) {
        return 0;   // Dont check!
    }
    return SC_SERVER;
}

void end_all_sessions()
{
    connection *cxt, *tmp;
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
            tmp = cxt;

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
    connection *cxt, *tmp, *tmp_pre;
    time_t check_time;
	int ended, expired = 0, iter;
    check_time = config.tstamp.tv_sec;
    //time(&check_time);
    config.llcxt = 0;

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
                     && (check_time - cxt->last_pkt_time) > UDP_TIMEOUT) {
                expired = 1;
            }
            /* ICMP */
            else if (cxt->proto == IP_PROTO_ICMP
                     || cxt->proto == IP6_PROTO_ICMP) {
                if ((check_time - cxt->last_pkt_time) > ICMP_TIMEOUT) {
                     expired = 1;
                }
            }
            /* All Other protocols */
            else if ((check_time - cxt->last_pkt_time) > OTHER_TIMEOUT) {
                expired = 1;
            }

            if (ended == 1 || expired == 1) {
                /* remove from the hash */
                if (cxt->prev)
                    cxt->prev->next = cxt->next;
                if (cxt->next)
                    cxt->next->prev = cxt->prev;
                tmp = cxt;
                tmp_pre = cxt->prev;

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
        if (!INET_NTOP
            (AF_INET,
             &pi->ip4->ip_src,
                 dest, INET_ADDRSTRLEN + 1)) {
            perror("Something died in inet_ntop");
            return NULL;
        }
    } else if (pi->af == AF_INET6) {
        if (!INET_NTOP(AF_INET6, &pi->ip6->ip_src, dest, INET6_ADDRSTRLEN + 1)) {
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
        game_over(0);
    } else if (ISSET_INTERRUPT_SESSION(config)) {
        set_end_sessions();
    } else if (ISSET_INTERRUPT_DNS(config)) {
        set_end_dns_records();
    } else {
        config.intr_flag = 0;
    }
}

int is_valid_path(const TCHAR *path)
{
    struct _stat st;

    if (path == NULL) {
        return 0;
	}

	if (_wstat(path, &st) != 0) {
        return 0;
    }
    
	//if ( ((st.st_mode & _S_IFDIR) != _S_IFDIR) ||
	//	 (_access_s(dir, 2) == -1)	) {
    //    return 0;
    //}
    return 1;	//path is valid
}

DWORD WINAPI sig_alarm_handler(LPVOID lpParam)
{
	time_t now_t;
	while(true){
		Sleep(TIMEOUT*1000);	//sleep takes time in milliseconds

		now_t = config.tstamp.tv_sec;
	    //config.tstamp = time(); // config.tstamp will stand still if there is no packets
	
	    dlog("[D] Got SIG ALRM: %lu\n", now_t);
	    /* Each time check for timed out sessions */
		(config).intr_flag |= INTERRUPT_SESSION;	//set flag to alert master thread to clean sessions
	    
	    /* Only check for timed-out dns records each 10 minutes */
	    if ( (now_t - config.dnslastchk) >= 600 ) {
			(config).intr_flag |= INTERRUPT_DNS;	//set flag, to alert master thread to clean dns records
	    }

		if ((config.daemon_flag == 1) && //if we are a daemon and
			(is_valid_path(config.pidfile) == 0)){	//pidfile is missing
			config.intr_flag |= INTERRUPT_END;	//interrupt main thread to stop daemon
			if (config.handle != NULL){
				pcap_breakloop(config.handle);	//close pcap to interrupt main thread
			}
		}
	}
	return 0;
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

int create_pid_file(const TCHAR *path)
{
	TCHAR pid_buffer[12]={0};
    int fd = 0, pid_buf_len = 0;

    if (!path) {
        path = config.pidfile;
    }
    
	if (is_valid_path(path) == 1) {	//if pid file exists, dont start!
        _wolog(L"PID path \"%s\" exists. Another daemon running ?\n", path);
		return 1;	//pid file exists, another daemon is running
    }

    if (_wsopen_s(&fd, path, _O_CREAT | _O_TRUNC | O_WRONLY, _SH_DENYWR ,
						_S_IREAD | _S_IWRITE) != 0) {
        return 1;
    }

    //pid file locking
	swprintf_s(pid_buffer, 12, L"%d", _getpid());
	pid_buf_len = wcslen(pid_buffer);
	
	if( _locking( fd, _LK_LOCK, pid_buf_len) == -1 ){
		perror("_locking");
		_close(fd);
		return 1;
	}
   
    if (_write(fd, pid_buffer, pid_buf_len) != pid_buf_len) {
        _close(fd);
        return 1;
    }
    _close(fd);
    return 0;
}

void LastError(LPTSTR lpszFunction){ 
    LPVOID lpMsgBuf;
    DWORD dw = GetLastError();	//Retrieve the system error message for the last-error code

    FormatMessage(	FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
					FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf, 0, NULL );
	wprintf(L"%s: Error %d - %s\n", lpszFunction, dw, (LPCTSTR)lpMsgBuf);
    LocalFree(lpMsgBuf);
}

int daemonize(){
	int fd;
	size_t configpath_len = wcslen(config.configpath);
	size_t daemon_log_len = configpath_len + wcslen(L"\\passivednsd.log");
	TCHAR * daemon_log_path = (TCHAR*) calloc(daemon_log_len, sizeof(TCHAR)); 
	
	wcsncpy_s(daemon_log_path, daemon_log_len, config.configpath, configpath_len);
	wcsncpy_s(&daemon_log_path[configpath_len], daemon_log_len, L"\\passivednsd.log", wcslen(L"\\passivednsd.log"));

	_fcloseall();	//close all fd, without 0,1,2
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
		
	if (_wsopen_s(&fd, daemon_log_path,
			_O_CREAT | _O_WRONLY | _O_APPEND,
			_SH_DENYWR, _S_IREAD | _S_IWRITE ) == 0) {
		//_dup2(fd, _fileno(stdin));
		_dup2(fd, _fileno(stdout));
		_dup2(fd, _fileno(stderr));
		if (fd > _fileno(stderr)) {
			_close(fd);
		}
	}else{
		return 1;
	}
	free(daemon_log_path);

	if(create_pid_file(config.pidfile) == 1){
		game_over(1);
	}
	return 0;
};

int start_daemon(const int argc, const TCHAR * argv[])
{
	int i;
	PROCESS_INFORMATION pi; 
	STARTUPINFO si;
	DWORD creationFlags = CREATE_UNICODE_ENVIRONMENT;
	BOOL bSuccess = TRUE, bDaemon = FALSE;
	size_t params_len = 0, params_max_len=0, arg_max_len = 0, arg_len = 0, j=0;
	LPVOID env;
	const TCHAR * prog_path = argv[0], *usrName = NULL, *usrDomain = NULL;
	TCHAR * params = NULL, *usrPass = NULL;

	HANDLE hToken;
	PROFILEINFO pinfo;
	USER_INFO_4* user_info;

	memset(&pinfo, 0, sizeof(PROFILEINFO));
	pinfo.dwSize = sizeof(PROFILEINFO);
	
	for(i=0; i < argc; i++){
		arg_len = wcslen(argv[i]);
		if(arg_len >= arg_max_len)
			arg_max_len = arg_len;
		params_max_len += arg_len + 1;
	}

	params		= (TCHAR*) calloc(params_max_len, sizeof(TCHAR));

	memset(&si, 0, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);

	//build daemon command line
	for(i=0; i < argc; i++){
		if(wcsncmp(argv[i], L"-u", 2) == 0){
			usrName = argv[++i];
			
		}else if(wcsncmp(argv[i], L"-g", 2) == 0){
			usrDomain = argv[++i];
			
		}else if(wcsncmp(argv[i], L"-D", 2) == 0){
			continue;	//we have added '-d' above
		}else{
			arg_len = wcslen(argv[i]);
			if(argv[i][0] != '-')	//if its a value option
				params[params_len++] = '"';
			
			if(  wcsncpy_s(&params[params_len], params_max_len, argv[i], arg_len) != 0){
				bSuccess = false; break;
			}
			params_len += arg_len;
			if(argv[i][0] != '-')
				params[params_len++] = '"';
			params[params_len++] = ' ';
		}
	}
	if(wcsncpy_s(&params[params_len], params_max_len, L"-d", wcslen(L"-d")) != 0){
		bSuccess = false;
	}
	params_len += wcslen(L"-d");
	creationFlags |= CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW;
	
	if(!bSuccess){
		free(params);
		return 1;
	}

	if(usrName){	//run as another user
		usrPass = (TCHAR*) calloc(100, sizeof(TCHAR));
		wprintf_s(L"Enter user(%s) password:", usrName);
		wscanf_s(L"%s", usrPass, 100);
		if(usrDomain == NULL) usrDomain = _wcsdup(L".");
		
		if (!LogonUser(usrName, usrDomain, usrPass,
						LOGON32_LOGON_INTERACTIVE,
						LOGON32_PROVIDER_DEFAULT, &hToken)){
			LastError(L"LogonUser");
			return 1;
		}
		
		// Load the user's profile.
		pinfo.lpUserName = usrName;
		if (NERR_Success == NetUserGetInfo(usrDomain, usrName, 4, (BYTE**)&user_info)){
			pinfo.lpProfilePath = user_info->usri4_profile;
			if (!LoadUserProfile(hToken, &pinfo)){
				LastError(L"LoadUserProfile");
				return 1;
			}
			NetApiBufferFree(user_info);
		}else{
			LastError(L"NetuserGetInfo");
			return 1;
		}
		
		if(!ImpersonateLoggedOnUser(hToken)){
			LastError(L"ImpersonateLoggedOnUser");
			return 1;
		}

		if(!CreateEnvironmentBlock(&env, hToken, FALSE)){
			LastError(L"CreateEnvironmentBlock");
			return 1;
		}
		/* print process environment
		usrPass = (TCHAR*) env;
		while(usrPass != L"\0"){
			wprintf(L"%s\n", usrPass);
			usrPass += wcslen(usrPass)+1;
		}*/

		bSuccess = CreateProcessAsUser(hToken,
			prog_path, params,	// command line
			NULL, NULL,			//default security attributes
			FALSE,				//don't inherit parent handles
			CREATE_UNICODE_ENVIRONMENT | creationFlags,		//creation flags 
			NULL, NULL,	// use parent's environment and current directory
			&si,	// STARTUPINFO pointer 
			&pi);	// receives PROCESS_INFORMATION
		
		free(usrPass);
		DestroyEnvironmentBlock(env);
	    CloseHandle(hToken);
	}else{	//create a daemon
		bSuccess = CreateProcess(prog_path, params,	// command line 
			NULL, NULL,	// process and primary thread security attributes 
			FALSE,	// handles are not inherited 
			creationFlags,		// creation flags 
			NULL, NULL,	// use parent's environment and current directory
			&si,	// STARTUPINFO pointer 
			&pi);	// receives PROCESS_INFORMATION 
	}
	//free(params);		//CreateProcessAsUser modifies this string!
	
	if (!bSuccess){	// If an error occurs, exit the application. 
		LastError(TEXT("CreateProcess"));
		return 1;
	}else{
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 
		printf("Daemon started with PID %u\n", pi.dwProcessId);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
    return 0;
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

void game_over(int sig)
{
	if (config.inpacket == 0) {
		olog("Game Over for pid %i!\n", _getpid());
		CloseHandle(hAlrmThread);
		if(hPdnsStatsThread != NULL)
			CloseHandle(hPdnsStatsThread);

		if(config.daemon_flag == 1){			//process is a daemon
			_wunlink(config.pidfile);	//remove pidfile
		}else{
			//print_pdns_stats(0);
		}

		expire_all_dns_records();
		if (config.handle != NULL){
			pcap_close(config.handle);
			config.handle = NULL;
		}
        end_all_sessions();
        free_config();
        olog("\n[*] passivedns ended.\n");
        ExitProcess(sig);
    }
    config.intr_flag |= INTERRUPT_END;
}

void free_config()
{
	//TODO: Check if it is freed by pcap ?
	//if (config.cfilter.bf_insns != NULL) free (config.cfilter.bf_insns);
	//if (config.dev != NULL) free(config.dev);
	if (config.configpath != NULL)	free(config.configpath);
	if (config.pidfile != NULL) free(config.pidfile);
    if (config.user_name != NULL) free(config.user_name);
    if (config.domain_name != NULL) free(config.domain_name);
    if (config.bpff != NULL) free(config.bpff);
    if (config.pcap_file != NULL) free(config.pcap_file);
    if (config.logfile != NULL) free(config.logfile);
	if (config.logfile_nxd != NULL) free(config.logfile_nxd);
}

void print_pdns_stats(){
	olog("\n");
	olog("-- Total DNS records allocated            :%12u\n",config.p_s.dns_records);
	olog("-- Total DNS assets allocated             :%12u\n",config.p_s.dns_assets);
	olog("-- Total DNS packets over IPv4/TCP        :%12u\n",config.p_s.ip4_dns_tcp);
	olog("-- Total DNS packets over IPv6/TCP        :%12u\n",config.p_s.ip6_dns_tcp);
	olog("-- Total DNS packets over TCP decoded     :%12u\n",config.p_s.ip4_dec_tcp_ok + config.p_s.ip6_dec_tcp_ok);
	olog("-- Total DNS packets over TCP failed      :%12u\n",config.p_s.ip4_dec_tcp_er + config.p_s.ip6_dec_tcp_er);
	olog("-- Total DNS packets over IPv4/UDP        :%12u\n",config.p_s.ip4_dns_udp);
	olog("-- Total DNS packets over IPv6/UDP        :%12u\n",config.p_s.ip6_dns_udp);
	olog("-- Total DNS packets over UDP decoded     :%12u\n",config.p_s.ip4_dec_udp_ok + config.p_s.ip6_dec_udp_ok);
	olog("-- Total DNS packets over UDP failed      :%12u\n",config.p_s.ip4_dec_udp_er + config.p_s.ip6_dec_udp_er);
	olog("-- Total packets received from libpcap    :%12u\n",config.p_s.got_packets);
	olog("-- Total Ethernet packets received        :%12u\n",config.p_s.eth_recv);
	olog("-- Total VLAN packets received            :%12u\n",config.p_s.vlan_recv);
}

DWORD WINAPI pdns_stats_handler(LPVOID lpParam)
{
	while(true){
		Sleep(10*1000);	//sleep 10 seconds between prints

		print_pdns_stats();
	}
	return 0;
}

void usage()
{
    olog("\n");
    olog("USAGE:\n");
    olog(" $ passivedns [options]\n\n");
    olog(" OPTIONS:\n\n");
    olog(" -i <iface>      Network device <iface> (default: eth0).\n");
    olog(" -r <file>       Read pcap <file>.\n");
	_wolog(L" -l <file>       Logfile normal queries (default: %s).\n", config.logfile);
    _wolog(L" -L <file>       Logfile for SRC Error queries (default: %s).\n", config.logfile_nxd);
	olog(" -b 'BPF'        Berkley Packet Filter (default: '%s').\n", BPFF);
	_wolog(L" -p <file>       Name of pid file (default: %s).\n", config.pidfile);
    olog(" -S <mem>        Soft memory limit in MB (default: 256).\n");
    olog(" -C <sec>        Seconds to cache DNS objects in memory (default %u).\n",DNSCACHETIMEOUT);
    olog(" -P <sec>        Seconds between printing duplicate DNS info (default %u).\n",DNSPRINTTIME);
    olog(" -X <flags>      Manually set DNS RR Types to care about(Default -X 46CDNPRS).\n");
    //olog(" -u USER		   Username to drop privileges to.\n");
    olog(" -g DOMAIN	   Group ID to drop privileges to.\n");
    olog(" -D              Run as daemon.\n");
    olog(" -V              Show version and exit.\n");
    olog(" -h              This help message.\n\n");
    olog(" FLAGS:\n");
    olog("\n");
    olog(" * For Record Types:\n");
    olog("   4:A      6:AAAA  C:CNAME  D:DNAME  N:NAPTR  O:SOA\n");
    olog("   P:PTR    R:RP    S:SRV    T:TXT    M:MX     n:NS\n");
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
}

//extern int optind, opterr, optopt; // getopt()

static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType)
{
	bool rc = false;
  switch (dwCtrlType){
	case CTRL_SHUTDOWN_EVENT:	// System is shutting down. Passed only to services!
	case CTRL_LOGOFF_EVENT:		// User logs off. Passed only to services!	
	case CTRL_CLOSE_EVENT:	// Closing the console window  
	case CTRL_C_EVENT:		// Ctrl+C
	case CTRL_BREAK_EVENT:	// Ctrl+Break
		
		config.intr_flag |= INTERRUPT_END;
		if (config.handle != NULL){
			pcap_breakloop(config.handle);	//close pcap to interrupt main thread
		}

		rc = true;
		break;
	}

  // Return TRUE if handled this message, further handler functions won't be called.
  // Return FALSE to pass this message to further handlers until default handler calls ExitProcess().
  return rc;
}
int get_configpath(){
	
	size_t appdata_path_len = 0, configpath_len = 0, logfile_len = 0;
	struct _stat st;
	int rc;
	TCHAR* appdata_path = (TCHAR*) calloc(MAX_PATH, sizeof(TCHAR));

	//Get path to "Application Data" folder
	if(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appdata_path) != S_OK){
		perror("_dupenv_s");
		return 1;
	}
	appdata_path_len = wcslen(appdata_path);
	configpath_len = appdata_path_len + wcslen(L"\\passivedns") + 1;
	config.configpath = (TCHAR*) calloc(configpath_len, sizeof(TCHAR));
	wcsncpy_s(config.configpath, configpath_len, appdata_path, appdata_path_len);
	wcsncpy_s(&config.configpath[appdata_path_len], configpath_len, L"\\passivedns", wcslen(L"\\passivedns"));
	configpath_len = wcslen(config.configpath);

	free(appdata_path);

	rc = _wstat(config.configpath, &st);
	if ( errno == ENOENT) {
		if(_wmkdir(config.configpath) == -1){
			_wolog(L"Error: Unable to create '%s'", config.configpath);
			return 1;
		}
	}else if(errno == EINVAL){
		_wolog(L"Unable to stat '%s'\n", config.configpath);
		return 1;
	}	
	if(config.logfile == NULL){	//if log file is not set in options
		logfile_len = configpath_len + wcslen(L"\\passivedns.log") + 1;
		config.logfile = (TCHAR *) calloc(logfile_len, sizeof(TCHAR));
		wcsncpy_s(config.logfile, logfile_len, config.configpath, configpath_len);
		wcsncpy_s(&config.logfile[configpath_len], logfile_len, L"\\passivedns.log", wcslen(L"\\passivedns.log"));
	}

	if(config.logfile_nxd == NULL){
		logfile_len = configpath_len + wcslen(L"\\passivedns.log") + 1;
		config.logfile_nxd = (TCHAR *) calloc(logfile_len, sizeof(TCHAR));
		wcsncpy_s(config.logfile_nxd,					logfile_len,	config.configpath, configpath_len);
		wcsncpy_s(&config.logfile_nxd[configpath_len], logfile_len,	L"\\passivedns.log", wcslen(L"\\passivedns.log"));
	}
	if(config.pidfile == NULL){
		logfile_len = configpath_len + wcslen(L"\\passivedns.pid") + 1;
		config.pidfile = (TCHAR *) calloc(logfile_len, sizeof(TCHAR));
		wcsncpy_s(config.pidfile,					 logfile_len,	config.configpath, configpath_len);
		wcsncpy_s(&config.pidfile[configpath_len], logfile_len,	L"\\passivedns.pid", wcslen(L"\\passivedns.pid"));
	}
	return 0;
};

/* magic main */
int main(){
	size_t len = 0, mblen=0;
	int ch = 0;
	DWORD   dwThreadId = 0;
	int opt_daemonize = 0;	//flag. 1 if we will create a daemon process
	int argc = 0;
	TCHAR ** wargv = CommandLineToArgvW(GetCommandLine(), &argc);

    memset(&config, 0, sizeof(globalconfig));
    
    config.inpacket = config.intr_flag = 0;
    config.dnslastchk = 0;
    config.bpff = _strdup(BPFF);
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
//    config.dnsf |= DNS_CHK_NXDOMAIN;

    signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
	SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
	
	while ((ch = getopt(argc, wargv, L"i:r:l:L:hb:dDp:u:g:C:P:S:X:V")) != -1)
        switch (ch) {
        case 'i':
			len = wcslen(optarg);
			config.dev = (char*) calloc(len, sizeof(char));
			wcstombs_s(&mblen, config.dev,len, optarg, len);
            
            break;
        case 'r':
			len = wcslen(optarg);
			config.pcap_file = (char*) calloc(len, sizeof(char));
			wcstombs_s(&mblen, config.pcap_file, len, optarg, len);
            
            break;
        case 'L':
            config.logfile_nxd = _wcsdup(optarg);
            break;
        case 'l':
            config.logfile = _wcsdup(optarg);
            break;
        case 'b':
			len = wcslen(optarg);
			config.bpff = (char*) calloc(len, sizeof(char));
			wcstombs_s(&mblen, config.bpff, len, optarg, len);
            break;
        case 'p':
            config.pidfile = _wcsdup(optarg);
            break;
        case 'C':
			config.dnscachetimeout = wcstoul(optarg, NULL, 0);
            break;
        case 'P':
            config.dnsprinttime = wcstoul(optarg, NULL, 0);
            break;
        case 'S':
            config.mem_limit_max = (wcstoul(optarg, NULL, 0) * 1024 * 1024);
            break;
        case 'X':
            parse_dns_flags(optarg);
            break;
        case 'd':	//we are the daemon
            config.daemon_flag = 1;
            break;
		case 'D':	//create a daemon
			opt_daemonize = 1;
			break;
        case 'u':	//TODO: Working only in Windows XP, Server 2003, but not on Server 2008, 2012
		#define PDNS_USER_OPT	0	//Default is to disaboe the user option
		#if PDNS_USER_OPT	//(NTDDI_VERSION <= NTDDI_WS03)
			opt_daemonize = 1;	//we need the daemon mode to run as another user!
            config.user_name = _wcsdup(optarg);
		#else
			fprintf(stderr, "Error: -u option is tested and working only in Windows XP and Windows Server 2003\n");
			game_over(1);
		#endif
            break;
        case 'g':
            config.domain_name = _wcsdup(optarg);
            break;
        case 'h':
			get_configpath();
            usage();
            exit(0);
            break;
        case 'V':
            show_version();
            olog("\n");
            exit(0);
            break;
        case '?':
            elog(L"unrecognized argument: '%c'\n", optopt);
            break;
        default:
            elog(L"Did not recognize argument '%c'\n", ch);
	}

	if(get_configpath() != 0){
		game_over(1);
	}

	show_version();
	
	if (is_valid_path(config.pidfile) == 1){	//if pidfile exists
		elog(L"[*] pidfile '%s' exists!\n", config.pidfile);
		free(config.pidfile);	//don't delete existing pidfile
		game_over(1);
	}

	if(opt_daemonize) {	//if we create a daemon
		//openlog("passivedns", LOG_PID | LOG_CONS, LOG_DAEMON);
		olog("[*] Daemonizing...\n\n");
		ch = start_daemon(argc, wargv);
		LocalFree(wargv);
		game_over(ch);
	}
	
	LocalFree(wargv);

	if(config.daemon_flag == 1){	//if we are the daemon
		daemonize();
	}else{
		hPdnsStatsThread = CreateThread( 
		        NULL,                   // default security attributes
		        0,                      // use default stack size  
				pdns_stats_handler,     // thread function name
		        NULL,					// argument to thread function 
		        0,                      // use default creation flags 
		        &dwThreadId);			// returns the thread identifier 
		// Check the return value for success.
		if (hPdnsStatsThread == NULL){
			elog(L"Failed to create pdns stats thread!\n");
			game_over(1);
		}
	}

	//create alarm thread for timeout sessions
	hAlrmThread = CreateThread( 
            NULL,                   // default security attributes
            0,                      // use default stack size  
            sig_alarm_handler,      // thread function name
            NULL,					// argument to thread function 
            0,                      // use default creation flags 
            &dwThreadId);			// returns the thread identifier 
	// Check the return value for success.
	if (hAlrmThread == NULL){
		elog(L"Failed to create alarm thread!\n");
		game_over(1);
	}

    if (config.pcap_file) {
        /* Read from PCAP file specified by '-r' switch. */
        olog("L[*] Reading from file %s\n\n", config.pcap_file);
        if (!(config.handle = pcap_open_offline(config.pcap_file, config.errbuf))) {
            olog("L[*] Unable to open %s.  (%s)", config.pcap_file, config.errbuf);
        }

    } else {

        /* * look up an available device if non specified */
		if (config.dev == 0x0){
            config.dev = pcap_lookupdev(config.errbuf);
			if(config.dev == NULL){
				olog("pcap_lookupdev: %s\n", config.errbuf);
				game_over(1);
			}
		}
        olog("[*] Device: %s\n", config.dev);

        if ((config.handle = pcap_open_live(config.dev, SNAPLENGTH, 1, 500, config.errbuf)) == NULL) {
            olog("[*] Error pcap_open_live: %s \n", config.errbuf);
            game_over(1);
        }
        /* * B0rk if we see an error... */
        if (strlen(config.errbuf) > 0) {
            elog(L"[*] Error errbuf: %s \n", config.errbuf);
            game_over(1);
        }
    }

    if (config.handle == NULL) {
       game_over(1);
       return 1;
    }

    /** segfaults on empty pcap! */
    if ((pcap_compile(config.handle, &config.cfilter, config.bpff, 1, config.net_mask)) == -1) {
            olog("[*] Error pcap_compile user_filter: %s\n", pcap_geterr(config.handle));
            game_over(1);
    }

    if (pcap_setfilter(config.handle, &config.cfilter)) {
		olog("[*] Unable to set pcap filter!  %s", pcap_geterr(config.handle));
		game_over(1);
    }

    if (!config.pcap_file)
		olog("[*] Sniffing...\n\n");

    pcap_loop(config.handle, -1, got_packet, NULL);

    game_over(0);
    return 0;
}

