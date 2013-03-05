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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
//#include <ldns/ldns.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include "passivedns.h"
#include "dns.h"

globalconfig config;

/* The 12th Carol number and 7th Carol prime, 16769023, is also a Carol emirp */
//#define DBUCKET_SIZE     16769023
#define DBUCKET_SIZE     3967 // Carol that is primes

pdns_record *dbucket[DBUCKET_SIZE];

uint64_t hash(unsigned char *str) {
    uint64_t hash = 5381;
    uint64_t c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash % DBUCKET_SIZE;
}

void dns_parser (packetinfo *pi) {
    ldns_status   status;
    ldns_pkt     *dns_pkt;

    status = LDNS_STATUS_ERR; 

    /* In DNS tcp messages, the first 2 bytes signal the
     * amount of data to expect. So we need to skip them in the read.
     */
    if (pi->plen <= 2) return; /* The minimum bytes in a packet - else return */

    if ( pi->af == AF_INET ) {
        switch (pi->ip4->ip_p) {
            case IP_PROTO_TCP:
                status = ldns_wire2pkt(&dns_pkt,pi->payload + 2, pi->plen - 2);
                break;
            case IP_PROTO_UDP:
                status = ldns_wire2pkt(&dns_pkt,pi->payload, pi->plen);
                break;
            default:
                break;
        }
    } else if ( pi->af == AF_INET6 ) {
        switch (pi->ip6->next) {
            case IP_PROTO_TCP:
                status = ldns_wire2pkt(&dns_pkt,pi->payload + 2, pi->plen - 2);
                break;
            case IP_PROTO_UDP:
                status = ldns_wire2pkt(&dns_pkt,pi->payload, pi->plen);
                break;
            default:
                break;
        }
    }

    if (status != LDNS_STATUS_OK) {
        dlog("[D] ldns_wire2pkt status: %d\n", status);
        update_dns_stats(pi,ERROR);
        return;
    }

    /* We dont want to process Truncated packets */
    if (ldns_pkt_tc(dns_pkt)) {
       dlog("[D] DNS packet with Truncated (TC) bit set! Skipping!\n");
       ldns_pkt_free(dns_pkt);
       update_dns_stats(pi,ERROR);
       return;
    }

    /* we only care about answers when we record data */
    if (ldns_pkt_qr(dns_pkt)) {
        /* Answer must come from the server, and the client has to have sent a packet! */
        if ( pi->sc != SC_SERVER || pi->cxt->s_total_pkts == 0 ) {
            dlog("[D] DNS Answer without a Question?: Query TID = %d and Answer TID = %d\n",pi->cxt->plid,ldns_pkt_id(dns_pkt));
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi,ERROR);
            return;
        }
        dlog("[D] DNS Answer\n");
        /* Check the DNS TID */
        if ( (pi->cxt->plid == ldns_pkt_id(dns_pkt)) ) {
            dlog("[D] DNS Query TID match Answer TID: %d\n", pi->cxt->plid);
        } else {
            dlog("[D] DNS Query TID did not match Answer TID: %d != %d - Skipping!\n", pi->cxt->plid, ldns_pkt_id(dns_pkt));
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi,ERROR);
            return;
        }

        /* From isc.org wording: 
         * We do not collect any of the query-response traffic that
         * occurs when the client sets the RD or "Recursion Desired"
         * bit to 1, that is, the traffic that occurs between DNS
         * "stub" clients and the caching server itself, since only the
         * traffic generated in response to a cache miss (RD bit set to 0)
         * is strictly needed in order to build a passive DNS database.
         */
        if (ldns_pkt_rd(dns_pkt)) {
            dlog("[D] DNS packet with Recursion Desired (RD) bit set!\n");
            /* Between DNS-server to DNS-server, we should drop this kind
             * of traffic if we are thinking hardening and correctness!
             * But for people trying this out in a corporate network etc,
             * between a client and a DNS proxy, will need this most likely
             * to see any traffic at all. In the future, this might be
             * controlled by a cmdline switch.
             */ 
            //ldns_pkt_free(decoded_dns);
            //return;
        }

        if (!ldns_pkt_qdcount(dns_pkt)) {
            /* no questions or answers */
            dlog("[D] DNS packet did not contain a question. Skipping!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi,ERROR);
            return;
        }

        // send it off for processing
        if (process_dns_answer(pi, dns_pkt) < 0) {
            dlog("[D] process_dns_answer() returned -1\n");
        }
    } else {
        /* We need to get the DNS TID from the Query to later match with the
         * DNS TID in the answer - to harden the implementation.
         */

        /* Question must come from the client (and the server should not have sent a packet). */
        if ( pi->sc != SC_CLIENT ) {
            dlog("[D] DNS Query not from a client? Skipping!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi,ERROR);
            return;
        }
        
        /* Check for reuse of a session and a hack for
         * no timeout of sessions when reading pcaps atm. :/
         * 60 Secs are default UDP timeout in cxt, and should
         * be enough for a TCP session of DNS too.
         */
        if ( (pi->cxt->plid != 0 && pi->cxt->plid != ldns_pkt_id(dns_pkt)) && ((pi->cxt->last_pkt_time - pi->cxt->start_time) <= 60) ) {
            dlog("[D] DNS Query on an established DNS session - TID: Old:%d New:%d\n", pi->cxt->plid, ldns_pkt_id(dns_pkt));
            /* Some clients have bad or strange random src
             * port generator and will gladly reuse the same
             * src port several times in a short time period.
             * To implment this fully, each cxt should be include
             * the TID in its tuple, but still this will make a mess :/
             */
        } else {
            dlog("[D] New DNS Query\n");
        }

        if (!ldns_pkt_qdcount(dns_pkt)) {
            /* no questions or answers */
            dlog("[D] DNS Query packet did not contain a question? Skipping!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi,ERROR);
            return;
        }

        if ( (pi->cxt->plid = ldns_pkt_id(dns_pkt)) ) {
            dlog("[D] DNS Query with TID = %d\n", pi->cxt->plid);
        } else {
            dlog("[E] Error getting DNS TID from Query!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi,ERROR);
            return;
        }

        /* For hardening, we can extract the query and add it to the cxt
         * and then check it later in the answer, that they match.
         */
        /*
        if (update_query_cxt(pi, dns_pkt) < 0) {
            dlog("[D] update_query_cxt() returned -1\n");
        }
        */
    }

    ldns_pkt_free(dns_pkt);
}

int process_dns_answer(packetinfo *pi, ldns_pkt *dns_pkt) {
    int            rrcount_query;
    int            j;
    ldns_rr_list  *dns_query_domains;
    ldns_buffer   *dns_buff;

    dns_query_domains = ldns_pkt_question(dns_pkt);
    rrcount_query     = ldns_rr_list_rr_count(dns_query_domains);
    dns_buff = ldns_buffer_new(LDNS_MIN_BUFLEN);
    dlog("[*] rrcount_query: %d\n", rrcount_query);
    
    // Do we ever have more than one Question?
    // If we do - are we handling it correct ?
    for (j = 0; j < rrcount_query; j++) {
        ldns_rdf *rdf_data;

        rdf_data = ldns_rr_owner(ldns_rr_list_rr(dns_query_domains, j));
        dlog("[D] rdf_data: %p\n", rdf_data);

        if ( cache_dns_objects(pi, rdf_data, dns_buff, dns_pkt) != 0 ) {
            dlog("[D] cache_dns_objects() returned error\n");
        }
    }

    ldns_buffer_free(dns_buff);
    update_dns_stats(pi,SUCCESS);
    return(0);
}

int cache_dns_objects(packetinfo *pi, ldns_rdf *rdf_data,
                             ldns_buffer *buff, ldns_pkt *dns_pkt) {
    int             j;
    int             dns_answer_domain_cnt;
    uint64_t        dnshash;
    ldns_status     status;
    pdns_record    *pr = NULL;
    ldns_rr_list   *dns_answer_domains;
    unsigned char  *domain_name = 0;

    ldns_buffer_clear(buff);
    status = ldns_rdf2buffer_str(buff, rdf_data);

    if (status != LDNS_STATUS_OK) {
        dlog("[D] Error in ldns_rdf2buffer_str(): %d\n", status);
        return(-1);
    }

    dns_answer_domains    = ldns_pkt_answer(dns_pkt);
    dns_answer_domain_cnt = ldns_rr_list_rr_count(dns_answer_domains);
    domain_name           = (unsigned char *) ldns_buffer2str(buff);

    if (domain_name == NULL) {
        dlog("[D] Error in ldns_buffer2str(%p)\n", buff);
        return(-1);
    } else {
        dlog("[D] domain_name: %s\n", domain_name);
        dlog("[D] dns_answer_domain_cnt: %d\n",dns_answer_domain_cnt);
    }

    if (dns_answer_domain_cnt == 0 && ldns_pkt_get_rcode(dns_pkt) != 0) {
        uint16_t rcode = ldns_pkt_get_rcode(dns_pkt);
        dlog("[D] Error return code: %d\n", rcode);
        /* PROBLEM:
         * As there is no valid ldns_rr here and we cant fake one that will
         * be very unique, we cant push this to the normal
         * bucket[hash->linked_list]. We should probably allocate a static
         * bucket[MAX_NXDOMAIN] to hold NXDOMAINS, and when that is full, pop
         * out the oldest (LRU). A simple script quering for random non existing
         * domains could easly put stress on passivedns (think conficker etc.)
         * if the bucket is to big or non efficient. We would still store data
         * such as: fistseen,lastseen,client_ip,server_ip,class,query,NXDOMAIN
         */
         if (config.dnsfe & (pdns_chk_dnsfe(rcode))) {
            ldns_rr_list  *dns_query_domains;
            ldns_rr_class  class;
            ldns_rr_type   type;
            ldns_rr       *rr;

            dnshash = hash(domain_name);
            dlog("[D] Hash: %lu\n", dnshash);
            /* Check if the node exists, if not, make it */
            pr = get_pdns_record(dnshash, pi, domain_name);
            
            /* Set the SRC flag: */
            //lname_node->srcflag |= pdns_chk_dnsfe(rcode);
            dns_query_domains = ldns_pkt_question(dns_pkt);
            rr    = ldns_rr_list_rr(dns_query_domains, 0);
            class = ldns_rr_get_class(rr);
            type  = ldns_rr_get_type(rr);
            if ((pr->last_seen.tv_sec - pr->last_print.tv_sec) >= config.dnsprinttime) {
                /* Print the SRC Error record */
                print_passet_err(pr, rdf_data, rr, rcode);
            }
        } else {
            dlog("[D] Error return code %d was not processed:%d\n", pdns_chk_dnsfe(rcode),config.dnsfe);
        }
        free(domain_name);
        return(0);
    }
   
    for (j = 0; j < dns_answer_domain_cnt; j++) {
        int             offset = -1;
        ldns_rr        *rr;
        ldns_rdf       *rname;
        unsigned char  *rdomain_name = 0;

        rr = ldns_rr_list_rr(dns_answer_domains, j);

        switch (ldns_rr_get_type(rr)) {
            case LDNS_RR_TYPE_AAAA:
                if (config.dnsf & DNS_CHK_AAAA)
                    offset = 0;
                break; 
            case LDNS_RR_TYPE_A:
                if (config.dnsf & DNS_CHK_A)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_PTR:
                if (config.dnsf & DNS_CHK_PTR)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_CNAME:
                if (config.dnsf & DNS_CHK_CNAME)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_DNAME:
                if (config.dnsf & DNS_CHK_DNAME)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_NAPTR:
                if (config.dnsf & DNS_CHK_NAPTR)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_RP:
                if (config.dnsf & DNS_CHK_RP)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_SRV:
                if (config.dnsf & DNS_CHK_SRV)
                    offset = 3;
                break;
            case LDNS_RR_TYPE_TXT:
                if (config.dnsf & DNS_CHK_TXT)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_SOA:
                if (config.dnsf & DNS_CHK_SOA)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_MX:
                if (config.dnsf & DNS_CHK_MX)
                    offset = 1;
                break;
            case LDNS_RR_TYPE_NS:
                if (config.dnsf & DNS_CHK_NS)
                    offset = 0;
                break;

            default:
                offset = -1;
                dlog("[D] ldns_rr_get_type: %d\n",ldns_rr_get_type(rr));
                break;
        }

        if (offset == -1) {
            dlog("[D] LDNS_RR_TYPE not enabled/supported: %d\n",ldns_rr_get_type(rr));
            //data_offset = 0;
            continue;
        }

        /* Get the rdf data from the rr */
        rname = ldns_rr_rdf(rr, offset);

        if (rname == NULL) {
            dlog("[D] ldns_rr_rdf returned: NULL\n");
            continue;
        }

        ldns_buffer_clear(buff);
        ldns_rdf2buffer_str(buff, rname);
        rdomain_name = (unsigned char *)ldns_buffer2str(buff);

        if (rdomain_name == NULL) {
            dlog("[D] ldns_buffer2str returned: NULL\n");
            continue;
        }
        dlog("[D] rdomain_name: %s\n", rdomain_name);

        if (pr == NULL) {
            dnshash = hash(domain_name);
            dlog("[D] Hash: %lu\n", dnshash);
            /* Check if the node exists, if not, make it */
            pr = get_pdns_record(dnshash, pi, domain_name);
        }

        // Update the pdns record with the pdns asset
        update_pdns_record_asset(pi, pr, rr, rdomain_name);

        // if CNAME, free domain_name, cp rdomain_name to domain_name
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_CNAME) {
            if (config.dnsf & DNS_CHK_CNAME) {
                int len;
                free(domain_name);
                len = strlen((char *)rdomain_name);
                domain_name = calloc(1, (len + 1));
                strncpy((char *)domain_name, (char *)rdomain_name, len);
                dnshash = hash(domain_name);
                dlog("[D] Hash: %lu\n", dnshash);
                pr = get_pdns_record(dnshash, pi, domain_name);
            }
        }

        // Free the rdomain_name
        free(rdomain_name);
    }
    free(domain_name);
    return(0);
}

void update_pdns_record_asset (packetinfo *pi, pdns_record *pr,
                               ldns_rr *rr, unsigned char *rdomain_name) {

    pdns_asset *passet = pr->passet;
    pdns_asset *head   = passet;
    ldns_rr    *prr    = NULL;
    uint32_t    len    = 0;

    dlog("Searching: %u, %s, %s\n",rr->_rr_type, pr->qname, rdomain_name);

    while (passet != NULL) {
        // if found, update
        dlog("Matching: %u, %s, %s\n",passet->rr->_rr_type, pr->qname, passet->answer);
        dlog("[*] RR:%u, %u\n",passet->rr->_rr_type, rr->_rr_type);
        if (passet->rr->_rr_type == rr->_rr_type) {
          dlog("[*] rr match\n");
          dlog("r:%s == a:%s\n",rdomain_name,passet->answer);
          if (strcmp((const char *)rdomain_name,(const char *)passet->answer) == 0 ) {
            dlog("[*] rname/answer match\n");
            // We have this, update & if its over 24h since last print - print it, then return
            passet->seen++;
            passet->last_seen = pi->pheader->ts;
            passet->cip       = pi->cxt->s_ip; // This should always be the client IP
            passet->sip       = pi->cxt->d_ip; // This should always be the server IP
            if (rr->_ttl > passet->rr->_ttl) {
                passet->rr->_ttl = rr->_ttl; // Catch the highest TTL seen
            }
            dlog("[*] DNS asset updated...\n");
            if ((passet->last_seen.tv_sec - passet->last_print.tv_sec) >= config.dnsprinttime) {
                print_passet(passet, pr);
            }
            return;
          }
        }
        passet = passet->next;
    }

    // else, we got a new passet :)
    if ( passet == NULL ) {
        passet = (pdns_asset*) calloc(1, sizeof(pdns_asset));
        dlog("[*] Allocated a new dns asset...\n");
        config.p_s.dns_assets++;
        config.dns_assets++;
        prr = (ldns_rr*) calloc(1, sizeof(ldns_rr));
        prr->_owner        = rr->_owner;
        prr->_ttl          = rr->_ttl;
        prr->_rd_count     = rr->_rd_count;
        prr->_rr_type      = rr->_rr_type;
        prr->_rr_class     = rr->_rr_class;
        prr->_rdata_fields = rr->_rdata_fields;
        passet->seen = 1;
        passet->rr = prr;
    } else {
        dlog("[D] BAD\n");
    }

    if (head != NULL ) {
        head->prev = passet;
        passet->next = head;
    } else {
        passet->next = NULL;
    }

    // populate new values
    passet->first_seen = pi->pheader->ts;
    passet->last_seen  = pi->pheader->ts;
    passet->af         = pi->cxt->af;
    passet->cip        = pi->cxt->s_ip; // This should always be the client IP
    passet->sip        = pi->cxt->d_ip; // This should always be the server IP
    passet->prev       = NULL;
    len                = strlen((char *)rdomain_name);
    passet->answer     = calloc(1, (len + 1));
    strncpy((char *)passet->answer, (char *)rdomain_name, len);

    dlog("[D] Adding: %u, %s, %s\n",passet->rr->_rr_type, pr->qname, rdomain_name);

    pr->passet = passet;

    print_passet(passet, pr);

    return;
}

const char *u_ntop(const struct in6_addr ip_addr, int af, char *dest)
{
    if (af == AF_INET) {
        if (!inet_ntop
            (AF_INET,
         &IP4ADDR(&ip_addr),
         dest, INET_ADDRSTRLEN + 1)) {
            dlog("[E] Something died in inet_ntop\n");
            return NULL;
        }
    } else if (af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &ip_addr, dest, INET6_ADDRSTRLEN + 1)) {
            dlog("[E] Something died in inet_ntop\n");
            return NULL;
        }
    }
    return dest;
}

void print_passet_err (pdns_record *l, ldns_rdf *lname, ldns_rr *rr, uint16_t rcode) {
    FILE *fd;
    uint8_t screen;
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_c[INET6_ADDRSTRLEN];

    if (config.logfile_nxd[0] == '-' && config.logfile_nxd[1] == '\0' ) {
        if (config.handle == NULL) return;
        screen = 1;
        fd = stdout;
    } else {
        screen = 0;
        fd = fopen(config.logfile_nxd, "a");
        if (fd == NULL) {
            plog("[E] ERROR: Cant open file %s\n",config.logfile_nxd);
            l->last_print = l->last_seen;
            return;
        }
    }

    u_ntop(l->sip, l->af, ip_addr_s);
    u_ntop(l->cip, l->af, ip_addr_c);

    /* example output:
     * 1329575805.123456||100.240.60.160||80.160.30.30||IN||sadf.googles.com.||A||NXDOMAIN||0||1
     */
    fprintf(fd,"%lu.%06lu||%s||%s||",l->last_seen.tv_sec, l->last_seen.tv_usec, ip_addr_c, ip_addr_s);

    switch (ldns_rr_get_class(rr)) {
        case LDNS_RR_CLASS_IN:
             fprintf(fd,"IN");
             break;
        case LDNS_RR_CLASS_CH:
             fprintf(fd,"CH");
             break;
        case LDNS_RR_CLASS_HS:
             fprintf(fd,"HS");
             break;
        case LDNS_RR_CLASS_NONE:
             fprintf(fd,"NONE");
             break;
        case LDNS_RR_CLASS_ANY:
             fprintf(fd,"ANY");
             break; 
        default:
             fprintf(fd,"%d",ldns_rr_get_class(rr));
             break;
    }    
    
    fprintf(fd,"||%s||",l->qname);

    switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_PTR:
             fprintf(fd,"PTR");
             break;
        case LDNS_RR_TYPE_A:
             fprintf(fd,"A");
             break;
        case LDNS_RR_TYPE_AAAA:
             fprintf(fd,"AAAA");
             break;
        case LDNS_RR_TYPE_CNAME:
             fprintf(fd,"CNAME");
             break;
        case LDNS_RR_TYPE_DNAME:
             fprintf(fd,"DNAME");
             break;
        case LDNS_RR_TYPE_NAPTR:
             fprintf(fd,"NAPTR");
             break;
        case LDNS_RR_TYPE_RP:
             fprintf(fd,"RP");
             break;
        case LDNS_RR_TYPE_SRV:
             fprintf(fd,"SRV");
             break;
        case LDNS_RR_TYPE_TXT:
             fprintf(fd,"TXT");
             break;
        case LDNS_RR_TYPE_SOA:
             fprintf(fd,"SOA");
             break;
        case LDNS_RR_TYPE_NS:
             fprintf(fd,"NS");
             break;
        case LDNS_RR_TYPE_MX:
             fprintf(fd,"MX");
             break; 
        default:
            fprintf(fd,"%d",ldns_rdf_get_type(lname));
            break;
    }

    switch (rcode) {
        case 1:
            fprintf(fd,"||FORMERR");
            break;
        case 2:
            fprintf(fd,"||SERVFAIL");
            break;
        case 3:
            fprintf(fd,"||NXDOMAIN");
            break;
        case 4:
            fprintf(fd,"||NOTIMPL");
            break;
        case 5:
            fprintf(fd,"||REFUSED");
            break;
        case 6:
            fprintf(fd,"||YXDOMAIN");
            break;
        case 7:
            fprintf(fd,"||YXRRSET");
            break;
        case 8:
            fprintf(fd,"||NXRRSET");
            break;
        case 9:
            fprintf(fd,"||NOTAUTH");
            break;
        case 10:
            fprintf(fd,"||NOTZONE");
            break;
        default:
            fprintf(fd,"||UNKNOWN-ERROR-%d",rcode);
            break;
    }
    fprintf(fd,"||0||1\n");

    if (screen == 0)
        fclose(fd);

    l->last_print = l->last_seen;
    l->seen = 0;
}

void print_passet (pdns_asset *p, pdns_record *l) {

    FILE *fd;
    uint8_t screen;
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_c[INET6_ADDRSTRLEN];

    if (config.logfile[0] == '-' && config.logfile[1] == '\0' ) {
        if (config.handle == NULL) return;
        screen = 1;
        fd = stdout;
    } else {
        screen = 0;
        fd = fopen(config.logfile, "a");
        if (fd == NULL) {
            plog("[E] ERROR: Cant open file %s\n",config.logfile);
            p->last_print = p->last_seen;
            return;
        }
    }

    u_ntop(p->sip, p->af, ip_addr_s);
    u_ntop(p->cip, p->af, ip_addr_c);
    fprintf(fd,"%lu.%06lu||%s||%s||",p->last_seen.tv_sec, p->last_seen.tv_usec, ip_addr_c, ip_addr_s);

    switch (ldns_rr_get_class(p->rr)) {
        case LDNS_RR_CLASS_IN:
             fprintf(fd,"IN");
             break;
        case LDNS_RR_CLASS_CH:
             fprintf(fd,"CH");
             break;
        case LDNS_RR_CLASS_HS:
             fprintf(fd,"HS");
             break;
        case LDNS_RR_CLASS_NONE:
             fprintf(fd,"NONE");
             break;
        case LDNS_RR_CLASS_ANY:
             fprintf(fd,"ANY");
             break;
        default:
             fprintf(fd,"%d",p->rr->_rr_class);
             break;
    }

    fprintf(fd,"||%s||",l->qname);

    switch (ldns_rr_get_type(p->rr)) {
        case LDNS_RR_TYPE_PTR:
             fprintf(fd,"PTR");
             break;
        case LDNS_RR_TYPE_A:
             fprintf(fd,"A");
             break;
        case LDNS_RR_TYPE_AAAA:
             fprintf(fd,"AAAA");
             break;
        case LDNS_RR_TYPE_CNAME:
             fprintf(fd,"CNAME");
             break;
        case LDNS_RR_TYPE_DNAME:
             fprintf(fd,"DNAME");
             break;
        case LDNS_RR_TYPE_NAPTR:
             fprintf(fd,"NAPTR");
             break;
        case LDNS_RR_TYPE_RP:
             fprintf(fd,"RP");
             break;
        case LDNS_RR_TYPE_SRV:
             fprintf(fd,"SRV");
             break;
        case LDNS_RR_TYPE_TXT:
             fprintf(fd,"TXT");
             break;
        case LDNS_RR_TYPE_SOA:
             fprintf(fd,"SOA");
             break;
        case LDNS_RR_TYPE_NS:
             fprintf(fd,"NS");
             break;
        case LDNS_RR_TYPE_MX:
             fprintf(fd,"MX");
             break;
        default:
            fprintf(fd,"%d",p->rr->_rr_type);
            break;
    }

    fprintf(fd,"||%s||%u||%lu\n", p->answer,p->rr->_ttl,p->seen);
    
    if (screen == 0)
        fclose(fd);

    p->last_print = p->last_seen;
    p->seen = 0;
}

pdns_record *get_pdns_record (uint64_t dnshash, packetinfo *pi, unsigned char *domain_name) {

    pdns_record *pdnsr = dbucket[dnshash];
    pdns_record *head  = pdnsr;
    uint32_t     len   = 0;

    // search through the bucket
    while (pdnsr != NULL) {
        // if found, update & return dnsr
        if (strcmp((const char *)domain_name,(const char *)pdnsr->qname) == 0) { // match :)
            pdnsr->last_seen = pi->pheader->ts;
            pdnsr->cip       = pi->cxt->s_ip; // This should always be the client IP
            pdnsr->sip       = pi->cxt->d_ip; // This should always be the server IP
            return pdnsr;
        }
        pdnsr = pdnsr->next;
    }

    // else, we got a new dnsr :)
    if ( pdnsr == NULL ) {
        pdnsr = (pdns_record*) calloc(1, sizeof(pdns_record));
        dlog("[*] Allocated a new dns record...\n");
        config.p_s.dns_records++;
        config.dns_records++;
    }
    if (head != NULL ) {
        head->prev = pdnsr;
    }
    // populate new values
    pdnsr->first_seen = pi->pheader->ts;
    pdnsr->last_seen  = pi->pheader->ts;
    pdnsr->af         = pi->cxt->af;
    pdnsr->nxflag     = 0;
    pdnsr->cip        = pi->cxt->s_ip; // This should always be the client IP
    pdnsr->sip        = pi->cxt->d_ip; // This should always be the server IP
    pdnsr->next       = head;
    pdnsr->prev       = NULL;
    pdnsr->passet     = NULL;
    len               = strlen((char *)domain_name);
    pdnsr->qname      = calloc(1, (len + 1));
    strncpy((char *)pdnsr->qname, (char *)domain_name, len);

    dbucket[dnshash] = pdnsr;
    return pdnsr;
}

void expire_dns_records()
{
    pdns_record *pdnsr;
    uint8_t run = 0;
    time_t expire_t;
    time_t oldest;
    expire_t = (config.tstamp.tv_sec - config.dnscachetimeout);
    oldest = config.tstamp.tv_sec; 

    dlog("[D] Checking for DNS records to be expired\n");

    while ( run == 0 ) {
        uint32_t iter;
        run = 1;
        for (iter = 0; iter < DBUCKET_SIZE; iter++) {
            pdnsr = dbucket[iter];
            while (pdnsr != NULL) {
                if (pdnsr->last_seen.tv_sec < oldest) // Find the LRU asset timestamp
                    oldest = pdnsr->last_seen.tv_sec;

                if (pdnsr->last_seen.tv_sec <= expire_t) {
                    // Expire the record and all its assets
                    /* remove from the hash */
                    if (pdnsr->prev)
                        pdnsr->prev->next = pdnsr->next;
                    if (pdnsr->next)
                        pdnsr->next->prev = pdnsr->prev;
                    pdns_record *tmp = pdnsr;
                    pdns_record *tmp_prev = pdnsr->prev;
    
                    pdnsr = pdnsr->next;
    
                    delete_dns_record(tmp, &dbucket[iter]);
                    if (pdnsr == NULL && tmp_prev == NULL ) {
                        dbucket[iter] = NULL;
                    }
                } else {
                    // Search through a domain record for assets to expire
                    expire_dns_assets(pdnsr, expire_t);
                    pdnsr = pdnsr->next;
                }
            }
        }

        update_config_mem_counters();
        /* If we are using more memory than mem_limit_max
         * decrease expire_t too the oldest seen asset at least
         */
        if (config.mem_limit_size > config.mem_limit_max) {
            expire_t = (oldest + 300); // Oldest asset + 5 minutes
            oldest = config.tstamp.tv_sec;
            run = 0;
        }
    }
}

void update_config_mem_counters()
{
    config.mem_limit_size = (sizeof(pdns_record) * config.dns_records) + (sizeof(pdns_asset) * config.dns_assets);

    dlog("DNS and Memory stats:\n");
    dlog("DNS Records         :       %12u\n",config.dns_records);
    dlog("DNS Assets          :       %12u\n",config.dns_assets);
    dlog("Current memory size :       %12lu Bytes\n",config.mem_limit_size);
    dlog("Max memory size     :       %12lu Bytes\n",config.mem_limit_max);
    dlog("------------------------------------------------\n");
}

void expire_all_dns_records()
{
    pdns_record *pdnsr;

    dlog("[D] Expiring all domain records\n");

    uint32_t iter;
    for (iter = 0; iter < DBUCKET_SIZE; iter++) {
        pdnsr = dbucket[iter];
        while (pdnsr != NULL) {
            // Expire the record and all its assets
            /* remove from the hash */
            if (pdnsr->prev)
                pdnsr->prev->next = pdnsr->next;
            if (pdnsr->next)
                pdnsr->next->prev = pdnsr->prev;
            pdns_record *tmp = pdnsr;

            pdnsr = pdnsr->next;

            delete_dns_record(tmp, &dbucket[iter]);
            if (pdnsr == NULL) {
                dbucket[iter] = NULL;
            }
        }
    }
}

void delete_dns_record (pdns_record * pdnsr, pdns_record ** bucket_ptr)
{
    pdns_record *prev       = pdnsr->prev;       /* OLDER dns record */
    pdns_record *next       = pdnsr->next;       /* NEWER dns record */
    pdns_asset  *asset      = pdnsr->passet;
    pdns_asset  *tmp_asset;
 
    dlog("[D] Deleting domain record: %s\n", pdnsr->qname);

    /* Delete all domain assets */
    while (asset != NULL) {
        /* Print the asset before we expires if it
         * has been updated since it last was printed */
        if (asset->last_seen.tv_sec > asset->last_print.tv_sec) {
            print_passet(asset, pdnsr);
        } else if (asset->last_seen.tv_sec == asset->last_print.tv_sec) {
            if (asset->last_seen.tv_usec > asset->last_print.tv_usec) {
                print_passet(asset, pdnsr);
            }
        }
        tmp_asset = asset;
        asset = asset->next;
        delete_dns_asset(&pdnsr->passet, tmp_asset);
    }

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
    free(pdnsr->qname);
    free(pdnsr);
    pdnsr = NULL;
    config.dns_records--;
}

void expire_dns_assets(pdns_record *pdnsr, time_t expire_t)
{
    dlog("[D] Checking for DNS assets to be expired\n");

    pdns_asset *passet = pdnsr->passet;

    while ( passet != NULL ) {
        if (passet->last_seen.tv_sec <= expire_t) {
            /* Print the asset before we expires if it
             * has been updated since it last was printed */
            if (passet->last_seen.tv_sec > passet->last_print.tv_sec) {
                print_passet(passet, pdnsr);
            } else if (passet->last_seen.tv_sec == passet->last_print.tv_sec) {
                if (passet->last_seen.tv_usec > passet->last_print.tv_usec) {
                    print_passet(passet, pdnsr);
                }
            }
            /* Remove the asset from the linked list */
            if (passet->prev)
                passet->prev->next = passet->next;
            if (passet->next)
                passet->next->prev = passet->prev;
            pdns_asset *tmp = passet;

            passet = passet->next;

            /* Delete the asset */
            delete_dns_asset(&pdnsr->passet, tmp);
        } else {
            passet = passet->next;
        }
    }
    return;
}

void delete_dns_asset(pdns_asset **passet_head, pdns_asset *passet)
{
    dlog("[D] Deleting domain asset: %s\n", passet->answer);

    if (passet == NULL)
        return;

    pdns_asset *tmp_pa = NULL;
    pdns_asset *next_pa = NULL;
    pdns_asset *prev_pa = NULL;

    tmp_pa  = passet;
    next_pa = tmp_pa->next;
    prev_pa = tmp_pa->prev;

    if (prev_pa == NULL) {
        /*
         * beginning of list 
         */
        *passet_head = next_pa;
        /*
         * not only entry 
         */
        if (next_pa)
            next_pa->prev = NULL;
    } else if (next_pa == NULL) {
        /*
         * at end of list! 
         */
        prev_pa->next = NULL;
    } else {
        /*
         * a node 
         */
        prev_pa->next = next_pa;
        next_pa->prev = prev_pa;
    }

    free(passet->rr);
    passet->rr = NULL;
    free(passet->answer);
    passet->answer = NULL;
    free(passet);
    passet = NULL;
    config.dns_assets--;
}

void update_dns_stats(packetinfo *pi, uint8_t code)
{
    if ( pi->af == AF_INET ) {
        switch (pi->ip4->ip_p) {
            case IP_PROTO_TCP:
                config.p_s.ip4_dns_tcp++;
                if (code == SUCCESS)
                    config.p_s.ip4_dec_tcp_ok++;
                else
                    config.p_s.ip4_dec_tcp_er++;
                break;
            case IP_PROTO_UDP:
                config.p_s.ip4_dns_udp++;
                if (code == SUCCESS)
                    config.p_s.ip4_dec_udp_ok++;
                else
                    config.p_s.ip4_dec_udp_er++;
                break;
            default:
               break;
        }
    } else if ( pi->af == AF_INET6 ) {
        switch (pi->ip6->next) {
            case IP_PROTO_TCP:
                 config.p_s.ip6_dns_tcp++;
                if (code == SUCCESS)
                    config.p_s.ip6_dec_tcp_ok++;
                else
                    config.p_s.ip6_dec_tcp_er++;
                break;
            case IP_PROTO_UDP:
                config.p_s.ip6_dns_udp++;
                if (code == SUCCESS)
                    config.p_s.ip6_dec_udp_ok++;
                else
                    config.p_s.ip6_dec_udp_er++;
                break;
            default:
                break;
        }
    }
}

void parse_dns_flags (char *args)
{
    int i   = 0;
    int ok  = 0;
    int len = 0;
    uint8_t tmpf;

    tmpf = config.dnsf; 
    len = strlen(args);

    if (len == 0) {
        plog("[W] No flags are specified!\n");
        plog("[*] Continuing with default flags...\n");
        return;
    }

    config.dnsf  = 0;
    config.dnsfe = 0;

    for (i = 0; i < len; i++){
        switch(args[i]) {
            case '4': // A
               config.dnsf |= DNS_CHK_A; 
               dlog("[D] Enabling flag: DNS_CHK_A\n");
               ok++;
               break;
            case '6': // AAAA
               config.dnsf |= DNS_CHK_AAAA;
               dlog("[D] Enabling flag: DNS_CHK_AAAA\n");
               ok++;
               break;
            case 'P': // PTR
               config.dnsf |= DNS_CHK_PTR;
               dlog("[D] Enabling flag: DNS_CHK_PTR\n");
               ok++;
               break;
            case 'C': // CNAME
               config.dnsf |= DNS_CHK_CNAME;
               dlog("[D] Enabling flag: DNS_CHK_CNAME\n");
               ok++;
               break;
            case 'D': // DNAME
               config.dnsf |= DNS_CHK_DNAME;
               dlog("[D] Enabling flag: DNS_CHK_DNAME\n");
               ok++;
               break;
            case 'N': // NAPTR
               config.dnsf |= DNS_CHK_NAPTR;
               dlog("[D] Enabling flag: DNS_CHK_NAPTR\n");
               ok++;
               break;
            case 'R': // RP
               config.dnsf |= DNS_CHK_RP;
               dlog("[D] Enabling flag: DNS_CHK_RP\n");
               ok++;
               break;
            case 'S': // SRV
               config.dnsf |= DNS_CHK_SRV;
               dlog("[D] Enabling flag: DNS_CHK_SRV\n");
               ok++;
               break;
            case 'T': // TXT
               config.dnsf |= DNS_CHK_TXT;
               dlog("[D] Enabling flag: DNS_CHK_TXT\n");
               ok++;
               break;
            case 'O': // SOA
               config.dnsf |= DNS_CHK_SOA;
               dlog("[D] Enabling flag: DNS_CHK_SOA\n");
               ok++;
               break;
            case 'M': // MX
               config.dnsf |= DNS_CHK_MX;
               dlog("[D] Enabling flag: DNS_CHK_MX\n");
               ok++;
               break;
            case 'n': // NS
               config.dnsf |= DNS_CHK_NS;
               dlog("[D] Enabling flag: DNS_CHK_NS\n");
               ok++;
               break;
            case 'f': // FORMERR
               config.dnsfe |= DNS_SE_CHK_FORMERR;
               dlog("[D] Enabling flag: DNS_SE_CHK_FORMERR\n");
               ok++;
               break;
            case 's': // SERVFAIL
               config.dnsfe |= DNS_SE_CHK_SERVFAIL;
               dlog("[D] Enabling flag: DNS_SE_CHK_SERVFAIL\n");
               ok++;
               break;
            case 'x': // NXDOMAIN
               config.dnsfe |= DNS_SE_CHK_NXDOMAIN;
               dlog("[D] Enabling flag: DNS_SE_CHK_NXDOMAIN\n");
               ok++;
               break;

            case 'o': // 
               config.dnsfe |= DNS_SE_CHK_NOTIMPL;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOTIMPL\n");
               ok++;
               break;
            case 'r': // 
               config.dnsfe |= DNS_SE_CHK_REFUSED;
               dlog("[D] Enabling flag: DNS_SE_CHK_REFUSED\n");
               ok++;
               break;
            case 'y': // 
               config.dnsfe |= DNS_SE_CHK_YXDOMAIN;
               dlog("[D] Enabling flag: DNS_SE_CHK_YXDOMAIN\n");
               ok++;
               break;
            case 'e': // 
               config.dnsfe |= DNS_SE_CHK_YXRRSET;
               dlog("[D] Enabling flag: DNS_SE_CHK_YXRRSET\n");
               ok++;
               break;
            case 't': // 
               config.dnsfe |= DNS_SE_CHK_NXRRSET;
               dlog("[D] Enabling flag: DNS_SE_CHK_NXRRSET\n");
               ok++;
               break;
            case 'a': // 
               config.dnsfe |= DNS_SE_CHK_NOTAUTH;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOTAUTH\n");
               ok++;
               break;
            case 'z': // 
               config.dnsfe |= DNS_SE_CHK_NOTZONE;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOTZONE\n");
               ok++;
               break;
            case '\0':
               dlog("[W] Bad DNS flag - ending flag checks!\n");
               ok = 0;
               continue;
            default:
               plog("[*] Unknown DNS flag '%c'\n",args[i]);
               break;
        }
    }
    if (ok == 0) {
        plog("[W] No valid flags parsed, continuing with defaults.\n");
        config.dnsf = tmpf;
    }
}

uint16_t pdns_chk_dnsfe(uint16_t rcode)
{
    uint16_t retcode = 0x0000;

    switch (rcode) {
        case 1:
            retcode = DNS_SE_CHK_FORMERR;
            break;
        case 2:
            retcode = DNS_SE_CHK_SERVFAIL;
            break;
        case 3:
            retcode = DNS_SE_CHK_NXDOMAIN;
            break;
        case 4:
            retcode = DNS_SE_CHK_NOTIMPL;
            break;
        case 5:
            retcode = DNS_SE_CHK_REFUSED;
            break;
        case 6:
            retcode = DNS_SE_CHK_YXDOMAIN;
            break;
        case 7:
            retcode = DNS_SE_CHK_YXRRSET;
            break;
        case 8:
            retcode = DNS_SE_CHK_NXRRSET;
            break;
        case 9:
            retcode = DNS_SE_CHK_NOTAUTH;
            break;
        case 10:
            retcode = DNS_SE_CHK_NOTZONE;
            break;
        default:
            retcode = 0x0000; // UNKNOWN-ERROR
            break;
    }
    return retcode;
}

