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

#ifndef DNS_H
#define DNS_H

#include <ldns/ldns.h>

/* Default flags for types to handle */
#define DNS_CHK_AAAA        0x00000001
#define DNS_CHK_A           0x00000002
#define DNS_CHK_PTR         0x00000004
#define DNS_CHK_CNAME       0x00000008
#define DNS_CHK_DNAME       0x00000010
#define DNS_CHK_NAPTR       0x00000020
#define DNS_CHK_RP          0x00000040
#define DNS_CHK_SRV         0x00000080
#define DNS_CHK_TXT         0x00000100
#define DNS_CHK_SOA         0x00000200
#define DNS_CHK_MX          0x00000400
#define DNS_CHK_NS          0x00000800
#define DNS_CHK_DNSSEC      0x00001000
#define DNS_CHK_LOC         0x00002000
#define DNS_CHK_SPF         0x00004000
#define DNS_CHK_SSHFP       0x00008000
#define DNS_CHK_HINFO       0x00010000
#define DNS_CHK_ALL         0x80000000
/* Default flags for Server Errors to handle */
#define DNS_SE_CHK_FORMERR  0x0001
#define DNS_SE_CHK_SERVFAIL 0x0002
#define DNS_SE_CHK_NXDOMAIN 0x0004
#define DNS_SE_CHK_NOTIMPL  0x0008
#define DNS_SE_CHK_REFUSED  0x0010
#define DNS_SE_CHK_YXDOMAIN 0x0020
#define DNS_SE_CHK_YXRRSET  0x0040
#define DNS_SE_CHK_NXRRSET  0x0080
#define DNS_SE_CHK_NOTAUTH  0x0100
#define DNS_SE_CHK_NOTZONE  0x0200
#define DNS_SE_CHK_ALL      0x8000

/* Flag for indicating an NXDOMAIN */
#define DNS_NXDOMAIN       0x01

/* Flags for which fields to print */
#define FIELD_TIMESTAMP_S  0x0001
#define FIELD_TIMESTAMP_MS 0x0002
#define FIELD_CLIENT       0x0004
#define FIELD_SERVER       0x0008
#define FIELD_CLASS        0x0010
#define FIELD_QUERY        0x0020
#define FIELD_TYPE         0x0040
#define FIELD_ANSWER       0x0080
#define FIELD_TTL          0x0100
#define FIELD_COUNT        0x0200
#define FIELD_TIMESTAMP_YMDHMS 0x0400
#define FIELD_PROTO        0x0800

/* Static values for print_passet() */
#define PASSET_ERR_TTL     0
#define PASSET_ERR_COUNT   1

/* Syslog */
#define PDNS_IDENT         "passivedns"

/* JSON fields used when printing PDNS */
#define JSON_TIMESTAMP_S   "timestamp_s"
#define JSON_TIMESTAMP_MS  "timestamp_ms"
#define JSON_CLIENT        "client"
#define JSON_SERVER        "server"
#define JSON_PROTO         "proto"
#define JSON_CLASS         "class"
#define JSON_QUERY         "query"
#define JSON_TYPE          "type"
#define JSON_ANSWER        "answer"
#define JSON_TTL           "ttl"
#define JSON_COUNT         "count"

/* To avoid spaming the logfile with duplicate dns info
 * we only print a dns record one time each 24H. This way
 * you will get a last seen timestamp update once a day
 * at least. If the record changes, it will be classified
 * as a new record, and printent. If a record expires and
 * it has been updated since last_print time, it will be
 * printed again.
 */
#define DNSPRINTTIME          86400    /* 24H = 86400 sec */

/* How long we should hold a dns record in our internal
 * cache. It should preferably not be less than DNSPRINTTIME,
 * as that will make it possible to get more than one instance
 * of the record each day in the logfile. That said, setting
 * DNSCACHETIMEOUT to DNSPRINTTIME/2 etc, might help memory
 * usage if that is a concern AND you probably will get a better
 * granularity on the DNS time stamps in the log file.
 * My recomendations are DNSPRINTTIME == 24h and
 * DNSCACHETIMEOUT == 12h.
 */
#define DNSCACHETIMEOUT       43200    /* 12h=43200sec */

/* HASH:
 *     [DOMAIN_HASH_BUCKET]_
 *                          |__[Q-TYPE_BUCKET]_<--- PTR,MX,A...
 *                                            |__[RESPONCE-NAME] <--- FOR PTR is the IPv4/IPv6
 */

typedef struct _pdns_asset {
    struct timeval         first_seen; /* First seen (unix timestamp) */
    struct timeval         last_seen;  /* Last seen (unix timestamp) */
    struct timeval         last_print; /* Last time asset was printet */
    struct ldns_struct_rr  *rr;        /* PTR,MX,TXT,A,AAAA...  */
    uint64_t               seen;       /* Number of times seen */
    unsigned char          *answer;    /* Answer, like 8.8.8.8 or 2001:67c:21e0::16 */
    uint32_t               af;         /* IP version (4/6) AF_INET */
    struct in6_addr        sip;        /* DNS Server IP (v4/6) */
    struct in6_addr        cip;        /* DNS Client IP (v4/6) */
    uint8_t                proto;      /* Protocol */
    struct _pdns_asset     *next;      /* Next dns asset */
    struct _pdns_asset     *prev;      /* Prev dns asset */
} pdns_asset;

typedef struct _pdns_record {
    struct timeval         first_seen; /* First seen (unix timestamp) */
    struct timeval         last_seen;  /* Last seen (unix timestamp) */
    struct timeval         last_print; /* Last time record(NXD) was printet */
    uint64_t               seen;       /* Number of times seen */
    unsigned char          *qname;     /* Query name (gamelinux.org) */
    uint8_t                nxflag;     /* Flag to indicate if this is a NXDOMAIN */
    uint32_t               af;         /* IP version (4/6) AF_INET */
    struct in6_addr        sip;        /* DNS Server IP (v4/6) */
    struct in6_addr        cip;        /* DNS Client IP (v4/6) */
    pdns_asset             *passet;    /* Head of dns assets */
    struct _pdns_record    *next;      /* Next dns record */
    struct _pdns_record    *prev;      /* Prev dns record */
} pdns_record;

/* Declare */
int process_dns_answer (packetinfo *pi, ldns_pkt *decoded_dns);
int cache_dns_objects (packetinfo *pi, ldns_rdf *rdf_data, ldns_buffer *buff, ldns_pkt *dns_pkt);
pdns_record *get_pdns_record (uint64_t dnshash, packetinfo *pi, unsigned char *domain_name);
const char *u_ntop (const struct in6_addr ip_addr, int af, char *dest);
void dns_parser (packetinfo *pi);
void update_pdns_record_asset (packetinfo *pi, pdns_record *pr, ldns_rr *rr, unsigned char *rdomain_name);
void print_passet (pdns_record *l, pdns_asset *p, ldns_rr *rr, ldns_rdf *lname, uint16_t rcode);
void expire_dns_assets (pdns_record *pdnsr, time_t expire_t);
void expire_dns_records();
void expire_all_dns_records();
void delete_dns_record (pdns_record *pdnsr, pdns_record **bucket_ptr);
void delete_dns_asset (pdns_asset **passet_head, pdns_asset *passet);
void update_config_mem_counters();
void parse_field_flags (char *args);
void parse_dns_flags (char *args);
void update_dns_stats(packetinfo *pi, uint8_t code);
uint16_t pdns_chk_dnsfe(uint16_t rcode);

#endif /* DNS_H */

