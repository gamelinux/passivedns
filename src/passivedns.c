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
#include <string.h>
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
#include "passivedns.h"
#include "dump_dns.h"

#ifndef CONFDIR
#define CONFDIR "/etc/passivedns/"
#endif

/*  G L O B A L S  *** (or candidates for refactoring, as we say)***********/
globalconfig config;

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
    //config.tstamp = pi->pheader->ts.tv_sec; // Global
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

void parse_eth (packetinfo *pi)
{
    return;
}

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

    //pi->our = filter_packet(pi->af, &PI_IP4SRC(pi));
    //vlog(0x3, "Got %s IPv4 Packet...\n", (pi->our?"our":"foregin"));
    return;
}

void parse_ip4 (packetinfo *pi)
{
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
    // may be dropped due to macros plus
    //pi->ip_src = PI_IP6SRC(pi);
    //pi->ip_dst = PI_IP6DST(pi);
    //pi->our = filter_packet(pi->af, &PI_IP6SRC(pi));
    //vlog(0x3, "Got %s IPv6 Packet...\n", (pi->our?"our":"foregin"));
    return;
}

void parse_ip6 (packetinfo *pi)
{
    switch (pi->ip6->next) {
        case IP_PROTO_TCP:
            prepare_tcp(pi);
            if (!pi->our)
                break;
            parse_tcp(pi);
            break;
        case IP_PROTO_UDP:
            prepare_udp(pi);
            if (!pi->our)
                break;
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

    //if (ntohs(pi->arph->ea_hdr.ar_op) == ARPOP_REPLY) {
    //    if (filter_packet(pi->af, &pi->arph->arp_spa)) {
    //        update_asset_arp(pi->arph->arp_sha, pi);
    //    }
        /* arp_check(eth_hdr,pi->pheader->ts.tv_sec); */
    //} else {
    //    vlog(0x3, "[*] ARP TYPE: %d\n",ntohs(pi->arph->ea_hdr.ar_op));
    //}
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
    //connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    //if(config.payload)
       //dump_payload(pi->payload, (config.payload < pi->plen)?config.payload:pi->plen);
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
    //connection_tracking(pi);
    //cx_track_simd_ipv4(pi);
    //if(config.payload)
       //dump_payload(pi->payload, (config.payload < pi->plen)?config.payload:pi->plen);
    return;
}

void parse_tcp (packetinfo *pi)
{
    //olog("\n[*] Got TCP packet...\n");
    //config.payload = 200;
    //dump_payload(pi->payload, (config.payload < pi->plen)?config.payload:pi->plen);
// dump_dns(const u_char *payload, size_t paylen, FILE *trace, const char *endline)
// pi->payload * const uint8_t
// pi->plen * uint32_t
    //dump_dns(pi->payload, pi->plen, stderr, "\\\n\t");
    return;
}

void parse_udp (packetinfo *pi)
{
    //olog("\n[*] Got UDP packet...\n");
    //olog("\n");
    //config.payload = 200;
    //dump_payload(pi->payload, (config.payload < pi->plen)?config.payload:pi->plen);
    static char ip_addr_s[INET6_ADDRSTRLEN];
    u_ntop_src(pi, ip_addr_s);

    if ( ntohs(pi->s_port) == 53 || ntohs(pi->d_port) == 53 ) {
        dump_dns(pi->payload, pi->plen, stdout, "\n", ip_addr_s, pi->pheader->ts.tv_sec);
    }
    //dump_dns(pi);
    return;
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

    if (config.intr_flag == 1) {
        game_over();
    } else if (config.intr_flag == 2) {
        //update_asset_list();
    } else if (config.intr_flag == 3) {
        //set_end_sessions();
    } else {
        config.intr_flag = 0;
    }
}

int set_chroot(void)
{
    char *absdir;
    //char *logdir;
    int abslen;

    /*
     * logdir = get_abs_path(logpath); 
     */

    /*
     * change to the directory 
     */
    if (chdir(config.chroot_dir) != 0) {
        elog("set_chroot: Can not chdir to \"%s\": %s\n", config.chroot_dir,
               strerror(errno));
    }

    /*
     * always returns an absolute pathname 
     */
    absdir = getcwd(NULL, 0);
    abslen = strlen(absdir);

    /*
     * make the chroot call 
     */
    if (chroot(absdir) < 0) {
        elog("Can not chroot to \"%s\": absolute: %s: %s\n", config.chroot_dir,
               absdir, strerror(errno));
        exit(3);
    }

    if (chdir("/") < 0) {
        elog("Can not chdir to \"/\" after chroot: %s\n",
               strerror(errno));
        exit(3);
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
                    elog("ERROR: you have chrootetd and must set numeric group ID.\n");
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
        return ERROR;
    }
    if (write(fd, pid_buffer, strlen(pid_buffer)) != 0) {
        return ERROR;
    }
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

    /*
     * new process group 
     */
    setsid();

    /*
     * close file handles 
     */
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
       //if(!ISSET_CONFIG_QUIET(config)){
           //print_pdns_stats();
           //if(!config.pcap_file)
               //print_pcap_stats();
        //}
        if (config.handle != NULL) pcap_close(config.handle);
        //free_config();
        olog("\n[*] passivedns ended.\n");
        exit(0);
    }
    config.intr_flag = 1;
}

void print_pdns_stats()
{
    olog("-- Total packets received from libpcap    :%12u\n",config.p_s.got_packets);
    olog("-- Total Ethernet packets received        :%12u\n",config.p_s.eth_recv);
    olog("-- Total VLAN packets received            :%12u\n",config.p_s.vlan_recv);
}

void usage()
{
    olog("USAGE:\n");
    olog(" $ passivedns [options]\n");
    olog("\n");
    olog(" OPTIONS:\n");
    olog("\n");
    olog(" -i <iface>      Network device <iface> (default: eth0).\n");
    olog(" -r <file>       Read pcap <file>.\n");
    olog(" -c <file>       Read config from <file>.\n");
    olog(" -b 'BPF'        Berkley Packet Filter (default: udp and port 53).\n");
    olog(" -h              This help message.\n");
}

extern int optind, opterr, optopt; // getopt()

/* magic main */
int main(int argc, char *argv[])
{
    int32_t rc = 0;
    int ch = 0, verbose_already = 0;
    memset(&config, 0, sizeof(globalconfig));
    //set_default_config_options();
    config.inpacket = config.intr_flag = 0;
    char *pconfile;
#define BPFF "udp and src port 53"
    config.bpff = BPFF;

    signal(SIGTERM, game_over);
    signal(SIGINT, game_over);
    signal(SIGQUIT, game_over);
    //signal(SIGALRM, set_end_sessions);

#define ARGS "i:r:c:hb:"

    while ((ch = getopt(argc, argv, ARGS)) != -1)
        switch (ch) {
        case 'i':
            config.dev = strdup(optarg);
            break;
        case 'r':
            config.pcap_file = strdup(optarg);
            break;
        case 'c':
            pconfile = strdup(optarg);
            break;
        case 'b':
            config.bpff = strdup(optarg);
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

        if (config.daemon_flag) {
            if (!is_valid_path(config.pidfile))
                elog("[*] Unable to create pidfile '%s'\n", config.pidfile);
            openlog("passivedns", LOG_PID | LOG_CONS, LOG_DAEMON);
            olog("[*] Daemonizing...\n\n");
            daemonize(NULL);
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

    //cxt_init();
    olog("[*] Sniffing...\n\n");
    pcap_loop(config.handle, -1, got_packet, NULL);

    game_over();
    //pcap_close(config.handle);
    return (0);
}

