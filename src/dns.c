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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <syslog.h>
#include <pcap.h>
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>
#include "passivedns.h"
#include "dns.h"

#ifdef HAVE_JSON
#include <jansson.h>
#endif /* HAVE_JSON */

extern globalconfig config;

/* The 12th Carol number and 7th Carol prime, 16769023, is also a Carol emirp */
//#define DBUCKET_SIZE     16769023
#define DBUCKET_SIZE  3967   /* Carol that is primes */

pdns_record *dbucket[DBUCKET_SIZE];

/* Record currently being updated. Expiration must not free it. */
static pdns_record *expire_keep = NULL;

uint64_t hash(unsigned char *str)
{
    uint64_t hash = 5381;
    uint64_t c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;   /* hash * 33 + c */
    return hash % DBUCKET_SIZE;
}

void dns_parser(packetinfo *pi)
{
    ldns_status status;
    ldns_pkt    *dns_pkt;

    status = LDNS_STATUS_ERR;

    /* TCP length prefix is removed by tcp_reassemble(). Both paths pass
     * a bare DNS message whose length is already clamped to the buffer. */
    if (pi->payload == NULL || pi->plen < 12)
        return;

    status = ldns_wire2pkt(&dns_pkt, pi->payload, pi->plen);

    if (status != LDNS_STATUS_OK) {
        dlog("[D] ldns_wire2pkt status: %d\n", status);
        update_dns_stats(pi,ERROR);
        return;
    }

    /* We don't want to process truncated packets */
    if (ldns_pkt_tc(dns_pkt)) {
       dlog("[D] DNS packet with Truncated (TC) bit set! Skipping!\n");
       ldns_pkt_free(dns_pkt);
       update_dns_stats(pi, ERROR);
       return;
    }

    /* We only care about answers when we record data */
    if (ldns_pkt_qr(dns_pkt)) {
        /* In situations where the first packet seen is a server response, the
        client/server determination is incorrectly marked as an SC_CLIENT session
        prior to the parsing of the DNS payload.  In high bandwidth data centers
        when running against millions of packet capture files, port reuse in the
        span of a few minutes is not uncommon.  This results in all subsequent
        responses on the reused port being thrown out as if they came from a client. */
        if (pi->sc == SC_UNKNOWN || pi->cxt->s_total_pkts == 0) {
            dlog("[D] DNS Answer without a Question?: Query TID = %d and Answer TID = %d\n",
                 pi->cxt->plid, ldns_pkt_id(dns_pkt));
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi, ERROR);
            return;
        }
        dlog("[D] DNS Answer\n");
        /* plid 0 means the query id was missing or rejected. Id 0 must not match. */
        if (pi->cxt->plid != 0 && pi->cxt->plid == ldns_pkt_id(dns_pkt)) {
            dlog("[D] DNS Query TID match Answer TID: %d\n", pi->cxt->plid);
        }
        else {
            dlog("[D] DNS Query TID did not match Answer TID: %d != %d - Skipping!\n",
                 pi->cxt->plid, ldns_pkt_id(dns_pkt));
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
            /* No questions or answers */
            dlog("[D] DNS packet did not contain a question. Skipping!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi, ERROR);
            return;
        }

        /* Send it off for processing. Capture threads hand the answer
         * to the one cache thread. -W 1 updates the cache here. */
        if (config.workers > 1) {
            if (pdns_cache_submit(pi, dns_pkt) != 0)
                update_dns_stats(pi, ERROR);
        }
        else if (process_dns_answer(pi, dns_pkt) < 0)
            dlog("[D] process_dns_answer() returned -1\n");
        /* The query and this answer have been paired. UDP has no FIN,
         * so drop the flow now instead of holding it for UDP_TIMEOUT.
         * TCP can carry another query before it closes. */
        if (pi->proto == IP_PROTO_UDP)
            cxt_release(pi);
    }
    else {
        /* We need to get the DNS TID from the Query to later match with the
         * DNS TID in the answer - to harden the implementation.
         */

        /* With the new SC_UNKNOWN state, only responses from an SC_SERVER should be ignored. */
        if (pi->sc == SC_SERVER) {
            dlog("[D] DNS Query not from a client? Skipping!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi, ERROR);
            return;
        }

        /* Check for reuse of a session and a hack for
         * no timeout of sessions when reading pcaps atm. :/
         * 60 Secs are default UDP timeout in cxt, and should
         * be enough for a TCP session of DNS too.
         */
        if ((pi->cxt->plid != 0 && pi->cxt->plid != ldns_pkt_id(dns_pkt)) &&
           ((pi->cxt->last_pkt_time - pi->cxt->start_time) <= 60)) {
            dlog("[D] DNS Query on an established DNS session - TID: Old:%d New:%d\n",
                 pi->cxt->plid, ldns_pkt_id(dns_pkt));
            /* Some clients have bad or strange random src
             * port generator and will gladly reuse the same
             * src port several times in a short time period.
             * To implement this fully, each cxt should be include
             * the TID in its tuple, but still this will make a mess :/
             */
        }
        else
            dlog("[D] New DNS Query\n");

        if (!ldns_pkt_qdcount(dns_pkt)) {
            /* No questions or answers */
            dlog("[D] DNS Query packet did not contain a question? Skipping!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi, ERROR);
            return;
        }

        if ((pi->cxt->plid = ldns_pkt_id(dns_pkt)))
            dlog("[D] DNS Query with TID = %d\n", pi->cxt->plid);

        else {
            dlog("[E] Error getting DNS TID from Query!\n");
            ldns_pkt_free(dns_pkt);
            update_dns_stats(pi, ERROR);
            return;
        }
    }

    ldns_pkt_free(dns_pkt);
}

int process_dns_answer(packetinfo *pi, ldns_pkt *dns_pkt)
{
    int rrcount_query;
    int j;
    ldns_rr_list *dns_query_domains;
    ldns_buffer  *dns_buff;

    dns_query_domains = ldns_pkt_question(dns_pkt);
    rrcount_query     = ldns_rr_list_rr_count(dns_query_domains);
    dns_buff = ldns_buffer_new(LDNS_MIN_BUFLEN);
    dlog("[*] rrcount_query: %d\n", rrcount_query);

    /* Do we ever have more than one question?
       If we do, are we handling it correctly? */
    for (j = 0; j < rrcount_query; j++)
    {
        ldns_rdf *rdf_data;

        rdf_data = ldns_rr_owner(ldns_rr_list_rr(dns_query_domains, j));
        dlog("[D] rdf_data: %p\n", rdf_data);

        if (cache_dns_objects(pi, rdf_data, dns_buff, dns_pkt) != 0)
            dlog("[D] cache_dns_objects() returned error\n");
    }

    ldns_buffer_free(dns_buff);
    update_dns_stats(pi, SUCCESS);
    return 0;
}

int cache_dns_objects(packetinfo *pi, ldns_rdf *rdf_data,
                      ldns_buffer *buff, ldns_pkt *dns_pkt)
{
    int j;
    int dns_answer_domain_cnt;
    uint64_t dnshash;
    ldns_status status;
    pdns_record *pr = NULL;
    ldns_rr_list *dns_answer_domains;
    unsigned char *domain_name = 0;

    ldns_buffer_clear(buff);
    status = ldns_rdf2buffer_str(buff, rdf_data);

    if (status != LDNS_STATUS_OK) {
        dlog("[D] Error in ldns_rdf2buffer_str(): %d\n", status);
        return -1;
    }

    dns_answer_domains = ldns_pkt_answer(dns_pkt);
    dns_answer_domain_cnt = ldns_rr_list_rr_count(dns_answer_domains);
    domain_name = (unsigned char *) ldns_buffer2str(buff);

    if (domain_name == NULL) {
        dlog("[D] Error in ldns_buffer2str(%p)\n", buff);
        return -1;
    }
    else {
        dlog("[D] domain_name: %s\n", domain_name);
        dlog("[D] dns_answer_domain_cnt: %d\n",dns_answer_domain_cnt);
    }

    /* rcode 0 with an empty answer is NODATA. It is logged only with -X 0. */
    if (dns_answer_domain_cnt == 0 &&
        (ldns_pkt_get_rcode(dns_pkt) != 0 ||
         (config.dnsfe & DNS_SE_CHK_NOERR))) {
        uint16_t rcode = ldns_pkt_get_rcode(dns_pkt);
        dlog("[D] Error return code: %d\n", rcode);

        /* PROBLEM:
         * As there is no valid ldns_rr here and we can't fake one that will
         * be very unique, we cant push this to the normal
         * bucket[hash->linked_list]. We should probably allocate a static
         * bucket[MAX_NXDOMAIN] to hold NXDOMAINS, and when that is full, pop
         * out the oldest (LRU). A simple script querying for random non-existing
         * domains could easily put stress on passivedns (think conficker etc.)
         * if the bucket is to big or non-efficient. We would still store data
         * such as: firstseen,lastseen,client_ip,server_ip,class,query,NXDOMAIN
         */
         if (config.dnsfe & (pdns_chk_dnsfe(rcode))) {
            ldns_rr_list *dns_query_domains;
            ldns_rr *rr;

            dnshash = hash(domain_name);
            dlog("[D] Hash: %lu\n", dnshash);
            /* Check if the node exists, if not, make it */
            pr = get_pdns_record(dnshash, pi, domain_name);
            if (pr == NULL) {
                free(domain_name);
                return -1;
            }

            /* Set the SRC flag: */
            //lname_node->srcflag |= pdns_chk_dnsfe(rcode);
            dns_query_domains = ldns_pkt_question(dns_pkt);
            rr = ldns_rr_list_rr(dns_query_domains, 0);
            if (rr && (pr->last_seen.tv_sec - pr->last_print.tv_sec) >= config.dnsprinttime) {
                /* Print the SRC Error record */
                print_passet(pr, NULL, rr, rdf_data, rcode);
            }
        }
        else
            dlog("[D] Error return code %d was not processed:%d\n",
                 pdns_chk_dnsfe(rcode), config.dnsfe);

        free(domain_name);
        return 0;
    }

    for (j = 0; j < dns_answer_domain_cnt; j++)
    {
        int offset = -1;
        int to_offset = -1;
        int len;
        ldns_rr *rr;
        ldns_rdf *rname;
        char *rdomain_name = NULL;
        char *tmp1 = NULL;
        char *tmp2 = NULL;

        rr = ldns_rr_list_rr(dns_answer_domains, j);

        switch (ldns_rr_get_type(rr)) {
            case LDNS_RR_TYPE_LOC:
                if (config.dnsf & DNS_CHK_LOC)
                    offset = 0;
                break;
            case LDNS_RR_TYPE_GPOS:
                if (config.dnsf & DNS_CHK_LOC) {
                    offset = 0;
                    to_offset = 3;
                }
                break;
            case LDNS_RR_TYPE_RRSIG:
                if (config.dnsf & DNS_CHK_DNSSEC) {
                    offset = 0;
                    to_offset = 9;
                }
                break;
            case LDNS_RR_TYPE_DNSKEY:
                if (config.dnsf & DNS_CHK_DNSSEC) {
                    offset = 0;
                    to_offset = 4;
                }
                break;

            case LDNS_RR_TYPE_NSEC3PARAM:
                if (config.dnsf & DNS_CHK_DNSSEC) {
                    offset = 0;
                    to_offset = 4;
                }
                break;
            case LDNS_RR_TYPE_NSEC3:
                if (config.dnsf & DNS_CHK_DNSSEC) {
                    offset = 0;
                    to_offset = 5;
                }
                break;

            case LDNS_RR_TYPE_NSEC:
                if (config.dnsf & DNS_CHK_DNSSEC) {
                    offset = 0;
                    to_offset = 2;
                }
                break;
            case LDNS_RR_TYPE_HINFO:
                if (config.dnsf & DNS_CHK_HINFO) {
                    offset = 0;
                    to_offset = 2;
                }
                break;
            case LDNS_RR_TYPE_DS:
                if (config.dnsf & DNS_CHK_DNSSEC) {
                    offset = 0;
                    to_offset = 4;
                }
                break;
            case LDNS_RR_TYPE_SSHFP:
                if (config.dnsf & DNS_CHK_SSHFP) {
                    offset = 0;
                    to_offset = 3;
                }
                break;
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
                if (config.dnsf & DNS_CHK_NAPTR) {
                    offset = 0;
                    to_offset = 6;
                }
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
            case LDNS_RR_TYPE_SPF:
                if (config.dnsf & DNS_CHK_SPF)
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
#ifdef PDNS_HAVE_HTTPS
            case LDNS_RR_TYPE_HTTPS:
                if (config.dnsf & DNS_CHK_HTTPS) {
                    offset = 0;
                    to_offset = (int)ldns_rr_rd_count(rr);
                }
                break;
#endif
#ifdef PDNS_HAVE_HTTPS
            case LDNS_RR_TYPE_SVCB:
                if (config.dnsf & DNS_CHK_SVCB) {
                    offset = 0;
                    to_offset = (int)ldns_rr_rd_count(rr);
                }
                break;
#endif
            default:
                offset = -1;
                dlog("[D] ldns_rr_get_type: %d\n", ldns_rr_get_type(rr));
                break;
        }

        if (offset == -1) {
            dlog("[D] LDNS_RR_TYPE not enabled/supported: %d\n",
                 ldns_rr_get_type(rr));
            continue;
        }
        do {
            /* Get the rdf data from the rr */
            ldns_buffer_clear(buff);
            rname = ldns_rr_rdf(rr, offset);

            if (rname == NULL) {
                dlog("[D] ldns_rr_rdf returned: NULL\n");
                break;
            }

            ldns_rdf2buffer_str(buff, rname);
            rdomain_name = (char *) ldns_buffer2str(buff);

            if (rdomain_name == NULL)
                break;
            len = strlen(rdomain_name) + 5;

            if (tmp1 != NULL)
                len += strlen(tmp1);
            tmp2 = malloc(len);
            if (tmp2 == NULL) {
                free(tmp1);
                free(rdomain_name);
                free(domain_name);
                return -1;
            }

            if (tmp1 != NULL) {
                tmp2 = strcpy(tmp2, tmp1);
                tmp2 = strcat(tmp2, " ");
            }
            else
                tmp2 = strcpy(tmp2, "");

            free(tmp1);
            tmp2 = strcat(tmp2, rdomain_name);
            tmp1 = tmp2;
            free(rdomain_name);
            offset ++;
        } while (offset < to_offset);

        rdomain_name = tmp1;

        if (rname == NULL) {
            free(rdomain_name);
            continue;
        }

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
        if (pr == NULL) {
            free(rdomain_name);
            continue;
        }

        /* Update the pdns record with the pdns asset */
        update_pdns_record_asset(pi, pr, rr, (unsigned char*)rdomain_name);

        /* If CNAME, free domain_name, and cp rdomain_name to domain_name */
        if (ldns_rr_get_type(rr) == LDNS_RR_TYPE_CNAME) {
            if (config.dnsf & DNS_CHK_CNAME) {
                int len;
                free(domain_name);
                len = strlen((char *)rdomain_name);
                domain_name = calloc(1, (len + 1));
                if (domain_name == NULL) {
                    free(rdomain_name);
                    break;
                }
                strncpy((char *)domain_name, (char *)rdomain_name, len);
                dnshash = hash(domain_name);
                dlog("[D] Hash: %lu\n", dnshash);
                pr = get_pdns_record(dnshash, pi, domain_name);
            }
        }

        /* Free the rdomain_name */
        free(rdomain_name);
    }
    free(domain_name);
    return 0;
}

void update_pdns_record_asset(packetinfo *pi, pdns_record *pr,
                              ldns_rr *rr, unsigned char *rdomain_name)
{
    pdns_asset *passet = pr->passet;
    pdns_asset *head = passet;
    ldns_rr *prr = NULL;

    dlog("Searching: %u, %s, %s\n", rr->_rr_type, pr->qname, rdomain_name);

    while (passet != NULL)
    {
        /* If found, update */
        dlog("Matching: %u, %s, %s\n",passet->rr->_rr_type, pr->qname,
             passet->answer);
        dlog("[*] RR:%u, %u\n", passet->rr->_rr_type, rr->_rr_type);
        if (passet->rr->_rr_type == rr->_rr_type) {
            dlog("[*] rr match\n");
            dlog("r:%s == a:%s\n", rdomain_name, passet->answer);
            if (strcmp((const char *)rdomain_name,
                    (const char *)passet->answer) == 0 ) {
                dlog("[*] rname/answer match\n");
                /* We have this, update and if its over 24h since last print -
                   print it, then return */
                passet->seen++;
		memcpy( &passet->last_seen, &pi->pheader->ts, sizeof( struct timeval ) );
                passet->af        = pi->cxt->af;
                passet->cip       = pi->cxt->s_ip; /* This should always be the client IP */
                passet->sip       = pi->cxt->d_ip; /* This should always be the server IP */
                passet->sip_ttl   = pi->s_ttl;
                if (rr->_ttl > passet->rr->_ttl)
                        passet->rr->_ttl = rr->_ttl;   /* Catch the highest TTL seen */
                dlog("[*] DNS asset updated...\n");
                if ((passet->last_seen.tv_sec -
                        passet->last_print.tv_sec) >= config.dnsprinttime)
                    print_passet(pr, passet, passet->rr, NULL, 0);
                return;
            }
        }
        passet = passet->next;
    }

    /* Else, we got a new passet :) */
    if (passet == NULL) {
        size_t alen = strlen((char *)rdomain_name);
        if (!mem_charge(sizeof(pdns_asset) + sizeof(ldns_rr) + alen + 1)) {
            expire_keep = pr;
            expire_dns_records();
            expire_keep = NULL;
            if (!mem_charge(sizeof(pdns_asset) + sizeof(ldns_rr) + alen + 1))
                return;
        }
        passet = (pdns_asset*) calloc(1, sizeof(pdns_asset));
        prr = (ldns_rr*) calloc(1, sizeof(ldns_rr));
        if (!passet || !prr) {
            free(passet);
            free(prr);
            mem_refund(sizeof(pdns_asset) + sizeof(ldns_rr) + alen + 1);
            return;
        }
        dlog("[*] Allocated a new dns asset...\n");
        /* Type, class and TTL are values. The ldns packet that owns the
         * name and rdata is freed when this function returns. */
        prr->_owner = NULL;
        prr->_ttl = rr->_ttl;
        prr->_rd_count = 0;
        prr->_rr_type = rr->_rr_type;
        prr->_rr_class = rr->_rr_class;
        prr->_rdata_fields = NULL;
        passet->seen = 1;
        passet->rr = prr;
        passet->answer = calloc(1, alen + 1);
        if (!passet->answer) {
            free(prr);
            free(passet);
            mem_refund(sizeof(pdns_asset) + sizeof(ldns_rr) + alen + 1);
            return;
        }
        memcpy(passet->answer, rdomain_name, alen);
        PDNS_U32_INC(config.p_s.dns_assets);
        PDNS_U32_INC(config.dns_assets);
    }
    else
        dlog("[D] BAD\n");

    if (head != NULL ) {
        head->prev = passet;
        passet->next = head;
    }
    else
        passet->next = NULL;

    /* Populate new values */
    memcpy( &passet->first_seen, &pi->pheader->ts, sizeof( struct timeval ) );
    memcpy( &passet->last_seen, &pi->pheader->ts, sizeof( struct timeval ) );
    passet->af = pi->cxt->af;
    passet->cip = pi->cxt->s_ip; /* This should always be the client IP */
    passet->sip = pi->cxt->d_ip; /* This should always be the server IP */
    passet->sip_ttl = pi->s_ttl;
    if (pi-> eth_hdr) {
        memcpy(passet->cmac, pi->eth_hdr->ether_dst, 6 * sizeof(u_char));
        memcpy(passet->smac, pi->eth_hdr->ether_src, 6 * sizeof(u_char));
    }
    passet->prev = NULL;

    dlog("[D] Adding: %u, %s, %s\n",passet->rr->_rr_type, pr->qname,
         rdomain_name);

    pr->passet = passet;

    print_passet(pr, passet, passet->rr, NULL, 0);
}

const char *u_ntop(const struct in6_addr ip_addr, int af, char *dest)
{
    if (af == AF_INET) {
        if (!inet_ntop(AF_INET, &IP4ADDR(&ip_addr), dest,
            INET_ADDRSTRLEN + 1)) {
            dlog("[E] Something died in inet_ntop\n");
            return NULL;
        }
    }
    else if (af == AF_INET6) {
        if (!inet_ntop(AF_INET6, &ip_addr, dest, INET6_ADDRSTRLEN + 1)) {
            dlog("[E] Something died in inet_ntop\n");
            return NULL;
        }
    }
    return dest;
}

typedef struct _outbuf {
    char *data;
    size_t len;
    size_t cap;
} outbuf;

static int out_add(outbuf *o, const char *fmt, ...)
{
    va_list ap, aq;
    int need;
    char *grown;
    size_t ncap;

    va_start(ap, fmt);
    va_copy(aq, ap);
    need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0 || o->len + (size_t)need >= LOG_LINE_MAX) {
        va_end(aq);
        return -1;
    }
    if (o->len + (size_t)need + 1 > o->cap) {
        ncap = o->cap ? o->cap : 128;
        while (o->len + (size_t)need + 1 > ncap) {
            if (ncap > LOG_LINE_MAX / 2) {
                ncap = o->len + (size_t)need + 1;
                break;
            }
            ncap *= 2;
        }
        grown = (char *)realloc(o->data, ncap);
        if (!grown) {
            va_end(aq);
            return -1;
        }
        o->data = grown;
        o->cap = ncap;
    }
    vsnprintf(o->data + o->len, o->cap - o->len, fmt, aq);
    va_end(aq);
    o->len += (size_t)need;
    return 0;
}

#define PADD(...) do { \
    if (out_add(&ob, __VA_ARGS__) != 0) \
        goto print_free; \
} while (0)

/* writev stays one record. A short write is continued, not dropped. */
void write_log_line(int fd, const char *line)
{
    struct iovec iov[2];
    char nl = '\n';
    size_t done = 0;
    size_t total;

    if (fd < 0 || line == NULL)
        return;
    iov[0].iov_base = (void *)line;
    iov[0].iov_len = strlen(line);
    iov[1].iov_base = &nl;
    iov[1].iov_len = 1;
    total = iov[0].iov_len + 1;
    while (done < total) {
        ssize_t n = writev(fd, iov, 2);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        if (n == 0)
            return;
        done += (size_t)n;
        if ((size_t)n < iov[0].iov_len) {
            iov[0].iov_base = (char *)iov[0].iov_base + n;
            iov[0].iov_len -= (size_t)n;
        }
        else {
            size_t rest = (size_t)n - iov[0].iov_len;

            iov[0].iov_base = (char *)iov[0].iov_base + iov[0].iov_len;
            iov[0].iov_len = 0;
            if (rest < iov[1].iov_len) {
                iov[1].iov_base = (char *)iov[1].iov_base + rest;
                iov[1].iov_len -= rest;
            }
            else
                iov[1].iov_len = 0;
        }
    }
}

void print_passet(pdns_record *l, pdns_asset *p, ldns_rr *rr,
                  ldns_rdf *lname, uint16_t rcode)
{
    FILE *fd = NULL;
    int raw = -1;
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_c[INET6_ADDRSTRLEN];
    char *d = config.log_delimiter;
    char *proto;
    char *rr_class;
    char *rr_type;
    char *rr_rcode;
    char *output = NULL;
    outbuf ob;
    int text_line = 0;
    uint8_t is_err_record = 0;
    uint8_t server_ttl = 0;

    memset(&ob, 0, sizeof(ob));

#ifdef HAVE_JSON
    json_t *jdata;
    json_t *json_timestamp_ymdhms;
    json_t *json_timestamp_s;
    json_t *json_timestamp_ms;
    json_t *json_hostname;
    json_t *json_client;
    json_t *json_server;
    json_t *json_server_ttl;
    json_t *json_proto;
    json_t *json_class;
    json_t *json_query;
    json_t *json_query_len;
    json_t *json_type;
    json_t *json_answer;
    json_t *json_answer_len;
    json_t *json_ttl;
    json_t *json_count;
    size_t data_flags = 0;

    /* Print in the same order as inserted */
    data_flags |= JSON_PRESERVE_ORDER;

    /* No whitespace between fields */
    data_flags |= JSON_COMPACT;
#endif /* HAVE_JSON */

    /* If pdns_asset is not defined, then this is a NXD record */
    if (p == NULL)
        is_err_record = 1;

    /* A missing file handle must not skip syslog. fprintf checks fd. */
    if (is_err_record && config.output_log_nxd) {
        if (config.logfile_all) {
            fd = config.logfile_fd;
            raw = config.logfile_raw;
        }
        else {
            fd = config.logfile_nxd_fd;
            raw = config.logfile_nxd_raw;
        }
    }
    else if (!is_err_record && config.output_log) {
        fd = config.logfile_fd;
        raw = config.logfile_raw;
    }

    if (is_err_record) {
        u_ntop(l->sip, l->af, ip_addr_s);
        u_ntop(l->cip, l->af, ip_addr_c);
        server_ttl = l->sip_ttl;
    }
    else {
        u_ntop(p->sip, p->af, ip_addr_s);
        u_ntop(p->cip, p->af, ip_addr_c);
        server_ttl = p->sip_ttl;
    }

    proto    = malloc(4);
    rr_class = malloc(10);
    rr_type  = malloc(12);
    rr_rcode = malloc(20);
    if (!proto || !rr_class || !rr_type || !rr_rcode)
        goto print_free;

    switch (l->proto) {
        case IP_PROTO_TCP:
            snprintf(proto, 4, "tcp");
            break;
        case IP_PROTO_UDP:
            snprintf(proto, 4, "udp");
            break;
        default:
            snprintf(proto, 4, "%d", l->proto);
            break;
    }

    switch (ldns_rr_get_class(rr)) {
        case LDNS_RR_CLASS_IN:
            snprintf(rr_class, 10, "IN");
            break;
        case LDNS_RR_CLASS_CH:
            snprintf(rr_class, 10, "CH");
            break;
        case LDNS_RR_CLASS_HS:
            snprintf(rr_class, 10, "HS");
            break;
        case LDNS_RR_CLASS_NONE:
            snprintf(rr_class, 10, "NONE");
            break;
        case LDNS_RR_CLASS_ANY:
            snprintf(rr_class, 10, "ANY");
            break;
        default:
            snprintf(rr_class, 10, "%d", ldns_rr_get_class(rr));
            break;
    }

    switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_HINFO:
            snprintf(rr_type, 10, "HINFO");
            break;
        case LDNS_RR_TYPE_SSHFP:
            snprintf(rr_type, 10, "SSHFP");
            break;
        case LDNS_RR_TYPE_GPOS:
            snprintf(rr_type, 10, "GPOS");
            break;
        case LDNS_RR_TYPE_LOC:
            snprintf(rr_type, 10, "LOC");
            break;
        case LDNS_RR_TYPE_DNSKEY:
            snprintf(rr_type, 10, "DNSKEY");
            break;
        case LDNS_RR_TYPE_NSEC3PARAM:
            snprintf(rr_type, 11, "NSEC3PARAM");
            break;
        case LDNS_RR_TYPE_NSEC3:
            snprintf(rr_type, 10, "NSEC3");
            break;
        case LDNS_RR_TYPE_NSEC:
            snprintf(rr_type, 10, "NSEC");
            break;
        case LDNS_RR_TYPE_RRSIG:
            snprintf(rr_type, 10, "RRSIG");
            break;
        case LDNS_RR_TYPE_DS:
            snprintf(rr_type, 10, "DS");
            break;
        case LDNS_RR_TYPE_PTR:
            snprintf(rr_type, 10, "PTR");
            break;
        case LDNS_RR_TYPE_A:
            snprintf(rr_type, 10, "A");
            break;
        case LDNS_RR_TYPE_AAAA:
            snprintf(rr_type, 10, "AAAA");
            break;
        case LDNS_RR_TYPE_CNAME:
            snprintf(rr_type, 10, "CNAME");
            break;
        case LDNS_RR_TYPE_DNAME:
            snprintf(rr_type, 10, "DNAME");
            break;
        case LDNS_RR_TYPE_NAPTR:
            snprintf(rr_type, 10, "NAPTR");
            break;
        case LDNS_RR_TYPE_RP:
            snprintf(rr_type, 10, "RP");
            break;
        case LDNS_RR_TYPE_SRV:
            snprintf(rr_type, 10, "SRV");
            break;
        case LDNS_RR_TYPE_TXT:
            snprintf(rr_type, 10, "TXT");
            break;
        case LDNS_RR_TYPE_SPF:
            snprintf(rr_type, 10, "SPF");
            break;
        case LDNS_RR_TYPE_SOA:
            snprintf(rr_type, 10, "SOA");
            break;
        case LDNS_RR_TYPE_NS:
            snprintf(rr_type, 10, "NS");
            break;
        case LDNS_RR_TYPE_MX:
            snprintf(rr_type, 10, "MX");
            break;
#ifdef PDNS_HAVE_HTTPS
        case LDNS_RR_TYPE_HTTPS:
            snprintf(rr_type, 10, "HTTPS");
            break;
#endif
#ifdef PDNS_HAVE_HTTPS
        case LDNS_RR_TYPE_SVCB:
            snprintf(rr_type, 10, "SVCB");
            break;
#endif
        default:
            if (is_err_record)
                snprintf(rr_type, 10, "%d", ldns_rdf_get_type(lname));
            else
                snprintf(rr_type, 10, "%d", p->rr->_rr_type);
            break;
    }

    if (is_err_record) {
        switch (rcode) {
            case 0:
                snprintf(rr_rcode, 20, "NOERROR");
                break;
            case 1:
                snprintf(rr_rcode, 20, "FORMERR");
                break;
            case 2:
                snprintf(rr_rcode, 20, "SERVFAIL");
                break;
            case 3:
                snprintf(rr_rcode, 20, "NXDOMAIN");
                break;
            case 4:
                snprintf(rr_rcode, 20, "NOTIMPL");
                break;
            case 5:
                snprintf(rr_rcode, 20, "REFUSED");
                break;
            case 6:
                snprintf(rr_rcode, 20, "YXDOMAIN");
                break;
            case 7:
                snprintf(rr_rcode, 20, "YXRRSET");
                break;
            case 8:
                snprintf(rr_rcode, 20, "NXRRSET");
                break;
            case 9:
                snprintf(rr_rcode, 20, "NOTAUTH");
                break;
            case 10:
                snprintf(rr_rcode, 20, "NOTZONE");
                break;
            default:
                snprintf(rr_rcode, 20, "UNKNOWN-ERROR-%d", rcode);
                break;
        }
    }

#ifdef HAVE_JSON
    if ((is_err_record && config.use_json_nxd) ||
            (!is_err_record && config.use_json)) {
        jdata = json_object();

        /* Print timestamp(ymdhms) */
        if (config.fieldsf & FIELD_TIMESTAMP_YMDHMS) {
            struct tm *tmpTime;
            char timestr[200];
            tmpTime = localtime(&l->last_seen.tv_sec);
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmpTime);
            json_timestamp_ymdhms = json_string(timestr);
            json_object_set(jdata, JSON_TIMESTAMP, json_timestamp_ymdhms);
            json_decref(json_timestamp_ymdhms);
        }

        /* Print timestamp(s) */
        if (config.fieldsf & FIELD_TIMESTAMP_S) {
            json_timestamp_s = json_integer(l->last_seen.tv_sec);
            json_object_set(jdata, JSON_TIMESTAMP_S, json_timestamp_s);
            json_decref(json_timestamp_s);
        }

        /* Print timestamp(ms) */
        if (config.fieldsf & FIELD_TIMESTAMP_MS) {
            json_timestamp_ms = json_integer(l->last_seen.tv_usec);
            json_object_set(jdata, JSON_TIMESTAMP_MS, json_timestamp_ms);
            json_decref(json_timestamp_ms);
        }

        /* Print hostname */
        if (config.fieldsf & FIELD_HOSTNAME) {
            json_hostname = json_string(config.hostname);
            json_object_set(jdata, JSON_HOSTNAME, json_hostname);
            json_decref(json_hostname);
        }

        /* Print client IP */
        if (config.fieldsf & FIELD_CLIENT) {
            json_client = json_string(ip_addr_c);
            json_object_set(jdata, JSON_CLIENT, json_client);
            json_decref(json_client);
        }

        /* Print server IP */
        if (config.fieldsf & FIELD_SERVER) {
            json_server = json_string(ip_addr_s);
            json_object_set(jdata, JSON_SERVER, json_server);
            json_decref(json_server);
        }

        if (config.fieldsf & FIELD_SERVER_TTL) {
            json_server_ttl = json_integer((json_int_t)server_ttl);
            json_object_set(jdata, JSON_SERVER_TTL, json_server_ttl);
            json_decref(json_server_ttl);
        }

        /* Print protocol */
        if (config.fieldsf & FIELD_PROTO) {
            json_proto = json_string(proto);
            json_object_set(jdata, JSON_PROTO, json_proto);
            json_decref(json_proto);
        }

        /* Print class */
        if (config.fieldsf & FIELD_CLASS) {
            json_class = json_string(rr_class);
            json_object_set(jdata, JSON_CLASS, json_class);
            json_decref(json_class);
        }

        /* Print query */
        if (config.fieldsf & FIELD_QUERY) {
            json_query = json_string((const char *)l->qname);
            json_object_set(jdata, JSON_QUERY, json_query);
            json_decref(json_query);
        }

        /* Print query length */
        if (config.fieldsf & FIELD_QUERY_LEN) {
            json_query_len = json_integer(strlen(l->qname));
            json_object_set(jdata, JSON_QUERY_LEN, json_query_len);
            json_decref(json_query_len);
        }

        /* Print type */
        if (config.fieldsf & FIELD_TYPE) {
            json_type = json_string(rr_type);
            json_object_set(jdata, JSON_TYPE, json_type);
            json_decref(json_type);
        }

        if (is_err_record) {
            /* Print answer */
            if (config.fieldsf & FIELD_ANSWER) {
                json_answer = json_string(rr_rcode);
                json_object_set(jdata, JSON_ANSWER, json_answer);
                json_decref(json_answer);
            }

            /* Print answer length */
            if (config.fieldsf & FIELD_ANSWER_LEN) {
                json_answer_len = json_integer(strlen(rr_rcode));
                json_object_set(jdata, JSON_ANSWER_LEN, json_answer_len);
                json_decref(json_answer_len);
            }

            /* Print TTL */
            if (config.fieldsf & FIELD_TTL) {
                json_ttl = json_integer(PASSET_ERR_TTL);
                json_object_set(jdata, JSON_TTL, json_ttl);
                json_decref(json_ttl);
            }

            /* Print count */
            if (config.fieldsf & FIELD_COUNT) {
                json_count = json_integer(PASSET_ERR_COUNT);
                json_object_set(jdata, JSON_COUNT, json_count);
                json_decref(json_count);
            }
        }
        else {
            /* Print answer */
            if (config.fieldsf & FIELD_ANSWER) {
                json_answer = json_string((const char *)p->answer);
                json_object_set(jdata, JSON_ANSWER, json_answer);
                json_decref(json_answer);
            }

            /* Print answer length */
            if (config.fieldsf & FIELD_ANSWER_LEN) {
                json_answer_len = json_integer(strlen(p->answer));
                json_object_set(jdata, JSON_ANSWER_LEN, json_answer_len);
                json_decref(json_answer_len);
            }

            /* Print TTL */
            if (config.fieldsf & FIELD_TTL) {
                json_ttl = json_integer(p->rr->_ttl);
                json_object_set(jdata, JSON_TTL, json_ttl);
                json_decref(json_ttl);
            }

            /* Print count */
            if (config.fieldsf & FIELD_COUNT) {
                json_count = json_integer(p->seen);
                json_object_set(jdata, JSON_COUNT, json_count);
                json_decref(json_count);
            }
        }

        output = json_dumps(jdata, data_flags);
        json_decref(jdata);
        if (output == NULL)
            goto print_free;
    }
    else {
#endif /* HAVE_JSON */
        text_line = 1;
        /* Print timestamp */
        if ((config.fieldsf & FIELD_TIMESTAMP_YMDHMS)) {
            struct tm *tmpTime;
            char timestr[200];
            tmpTime = localtime(&l->last_seen.tv_sec);
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", tmpTime);
            if (is_err_record)
                PADD("%s.%06lu", timestr, l->last_seen.tv_usec);
            else
                PADD("%s.%06lu", timestr, p->last_seen.tv_usec);
        }
        else if ((config.fieldsf & FIELD_TIMESTAMP_S) &&
                 (config.fieldsf & FIELD_TIMESTAMP_MS)) {
            if (is_err_record)
                PADD("%lu.%06lu", l->last_seen.tv_sec, l->last_seen.tv_usec);
            else
                PADD("%lu.%06lu", p->last_seen.tv_sec, p->last_seen.tv_usec);
        }
        else if (config.fieldsf & FIELD_TIMESTAMP_S) {
            if (is_err_record)
                PADD("%lu", l->last_seen.tv_sec);
            else
                PADD("%lu", p->last_seen.tv_sec);
        }
        else if (config.fieldsf & FIELD_TIMESTAMP_MS) {
            if (is_err_record)
                PADD("%06lu", l->last_seen.tv_usec);
            else
                PADD("%06lu", p->last_seen.tv_usec);
        }

        /* Print hostname */
        if (config.fieldsf & FIELD_HOSTNAME) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", config.hostname);
        }

        /* Print client IP */
        if (config.fieldsf & FIELD_CLIENT) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", ip_addr_c);
        }

        /* Print client hardware address. Error records have no asset. */
        if ((config.fieldsf & FIELD_CLT_HWADDR) && p != NULL) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%02x:%02x:%02x:%02x:%02x:%02x",
                p->cmac[0], p->cmac[1], p->cmac[2],
                p->cmac[3], p->cmac[4], p->cmac[5]);
        }

        /* Print server IP */
        if (config.fieldsf & FIELD_SERVER) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", ip_addr_s);
        }

        if (config.fieldsf & FIELD_SERVER_TTL) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%u", (unsigned)server_ttl);
        }

        /* Print server hardware address  */
        if ((config.fieldsf & FIELD_SRV_HWADDR) && p != NULL) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%02x:%02x:%02x:%02x:%02x:%02x",
                p->smac[0], p->smac[1], p->smac[2],
                p->smac[3], p->smac[4], p->smac[5]);
        }

        /* Print protocol */
        if (config.fieldsf & FIELD_PROTO) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", proto);
        }

        /* Print class */
        if (config.fieldsf & FIELD_CLASS) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", rr_class);
        }

        /* Print query */
        if (config.fieldsf & FIELD_QUERY) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", l->qname);
        }

        /* Print query length */
        if (config.fieldsf & FIELD_QUERY_LEN) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%zd", strlen(l->qname));
        }

        /* Print type */
        if (config.fieldsf & FIELD_TYPE) {
            if (ob.len != 0)
                PADD("%s", d);
            PADD("%s", rr_type);
        }

        /* Print answer */
        if (config.fieldsf & FIELD_ANSWER) {
            if (ob.len != 0)
                PADD("%s", d);
            if (is_err_record)
                PADD("%s", rr_rcode);
            else
                PADD("%s", p->answer);
        }

        /* Print answer length*/
        if (config.fieldsf & FIELD_ANSWER_LEN) {
            if (ob.len != 0)
                PADD("%s", d);
            if (is_err_record)
                PADD("%zd", strlen(rr_rcode));
            else
                PADD("%zd", strlen(p->answer));
        }

        /* Print TTL */
        if (config.fieldsf & FIELD_TTL) {
            if (ob.len != 0)
                PADD("%s", d);
            if (is_err_record)
                PADD("%d", PASSET_ERR_TTL);
            else
                PADD("%u", p->rr->_ttl);
        }

        /* Print count */
       if (config.fieldsf & FIELD_COUNT) {
            if (ob.len != 0)
                PADD("%s", d);
            if (is_err_record)
                PADD("%d", PASSET_ERR_COUNT);
            else
                PADD("%"PRIu64, p->seen);
        }
        output = ob.data;

#ifdef HAVE_JSON
    }
#endif /* HAVE_JSON */

    /* The writer thread owns the log fd when capture is threaded. */
    if (output && config.workers > 1)
        pdns_log_submit(raw, output);
    else if (output && raw >= 0)
        write_log_line(raw, output);
    else if (fd && output) {
        fprintf(fd, "%s\n", output);
        fflush(fd);
    }

    /* Print to syslog */
    if (output && ((is_err_record && config.output_syslog_nxd) ||
            (!is_err_record && config.output_syslog))) {
        openlog(PDNS_IDENT, LOG_NDELAY, LOG_LOCAL7);
        syslog(LOG_INFO, "%s", output);
        closelog();
    }

    if (is_err_record) {
        l->last_print = l->last_seen;
        l->seen = 0;
    }
    else if (p) {
        p->last_print = p->last_seen;
        p->seen = 0;
    }

print_free:
    if (text_line)
        free(ob.data);
#ifdef HAVE_JSON
    else if ((is_err_record && config.use_json_nxd) ||
        (!is_err_record && config.use_json))
        free(output);
#endif /* HAVE_JSON */

    free(proto);
    free(rr_class);
    free(rr_type);
    free(rr_rcode);

}

pdns_record *get_pdns_record(uint64_t dnshash, packetinfo *pi,
                             unsigned char *domain_name)
{
    pdns_record *pdnsr = dbucket[dnshash];
    pdns_record *head = pdnsr;

    /* Search through the bucket */
    while (pdnsr != NULL)
    {
        /* If found, update and return dnsr */
        if (strcmp((const char *)domain_name,
                (const char *)pdnsr->qname) == 0) {
            /* match :) */
            memcpy( &pdnsr->last_seen, &pi->pheader->ts, sizeof( struct timeval ) );
            pdnsr->af = pi->cxt->af;
            pdnsr->cip = pi->cxt->s_ip; /* This should always be the client IP */
            pdnsr->sip = pi->cxt->d_ip; /* This should always be the server IP */
            pdnsr->sip_ttl = pi->s_ttl;
            if (pi->eth_hdr){
                memcpy(pdnsr->cmac, pi->eth_hdr->ether_dst, 6 * sizeof(u_char));
                memcpy(pdnsr->smac, pi->eth_hdr->ether_src, 6 * sizeof(u_char));
            }
            return pdnsr;
        }
        pdnsr = pdnsr->next;
    }

    /* Else, we got a new dnsr :) */
    if (pdnsr == NULL) {
        size_t qlen = strlen((char *)domain_name);
        size_t need = sizeof(pdns_record) + qlen + 1;
        if (!mem_charge(need)) {
            expire_dns_records();
            if (!mem_charge(need))
                return NULL;
        }
        pdnsr = (pdns_record*) calloc(1, sizeof(pdns_record));
        if (!pdnsr) {
            mem_refund(need);
            return NULL;
        }
        pdnsr->qname = calloc(1, qlen + 1);
        if (!pdnsr->qname) {
            free(pdnsr);
            mem_refund(need);
            return NULL;
        }
        memcpy(pdnsr->qname, domain_name, qlen);
        dlog("[*] Allocated a new dns record...\n");
        PDNS_U32_INC(config.p_s.dns_records);
        PDNS_U32_INC(config.dns_records);
    }
    if (head != NULL)
        head->prev = pdnsr;

    /* Populate new values */
    memcpy( &pdnsr->first_seen, &pi->pheader->ts, sizeof( struct timeval ) );
    memcpy( &pdnsr->last_seen, &pi->pheader->ts, sizeof( struct timeval ) );
    pdnsr->af = pi->cxt->af;
    pdnsr->nxflag = 0;
    pdnsr->cip = pi->cxt->s_ip; /* This should always be the client IP */
    pdnsr->sip = pi->cxt->d_ip; /* This should always be the server IP */
    pdnsr->sip_ttl = pi->s_ttl;
    if (pi->eth_hdr) {
        memcpy(pdnsr->cmac, pi->eth_hdr->ether_dst, 6 * sizeof(u_char));
        memcpy(pdnsr->smac, pi->eth_hdr->ether_src, 6 * sizeof(u_char));
    }
    pdnsr->next = head;
    pdnsr->prev = NULL;
    pdnsr->passet = NULL;
    pdnsr->proto = pi->proto;

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

    while (run == 0)
    {
        uint32_t iter;
        uint32_t removed = 0;
        uint64_t before;
        run = 1;
        before = config.mem_limit_size;
        for (iter = 0; iter < DBUCKET_SIZE; iter++)
        {
            pdnsr = dbucket[iter];
            while (pdnsr != NULL)
            {
                if (pdnsr->last_seen.tv_sec < oldest)
                    /* Find the LRU asset timestamp */
                    oldest = pdnsr->last_seen.tv_sec;

                if (pdnsr == expire_keep) {
                    pdnsr = pdnsr->next;
                    continue;
                }

                if (pdnsr->last_seen.tv_sec <= expire_t) {
                    /* Expire the record and all its assets */
                    /* Remove from the hash */
                    if (pdnsr->prev)
                        pdnsr->prev->next = pdnsr->next;
                    if (pdnsr->next)
                        pdnsr->next->prev = pdnsr->prev;
                    pdns_record *tmp = pdnsr;
                    pdns_record *tmp_prev = pdnsr->prev;

                    pdnsr = pdnsr->next;

                    delete_dns_record(tmp, &dbucket[iter]);
                    removed++;
                    if (pdnsr == NULL && tmp_prev == NULL)
                        dbucket[iter] = NULL;
                }
                else {
                    /* Search through a domain record for assets to expire */
                    expire_dns_assets(pdnsr, expire_t);
                    pdnsr = pdnsr->next;
                }
            }
        }

        update_config_mem_counters();
        /* If we are using more memory than mem_limit_max
         * decrease expire_t too the oldest seen asset at least.
         * Stop when a pass frees nothing, so flows and fragment
         * buffers cannot spin this loop.
         */
        if (config.mem_limit_size > config.mem_limit_max &&
            removed > 0 && config.mem_limit_size < before) {
            expire_t = (oldest + 300);  /* Oldest asset + 5 minutes */
            oldest = config.tstamp.tv_sec;
            run = 0;
        }
    }
}

void update_config_mem_counters()
{
    /* mem_limit_size is a running total of charged bytes. Rebuilding it
     * from the struct counts used to drop the strings, the flows, and
     * the reassembly buffers. */

    dlog("DNS and Memory stats:\n");
    dlog("DNS Records         :       %12u\n",        config.dns_records);
    dlog("DNS Assets          :       %12u\n",        config.dns_assets);
    dlog("Current memory size :       %12lu Bytes\n", config.mem_limit_size);
    dlog("Max memory size     :       %12lu Bytes\n", config.mem_limit_max);
    dlog("------------------------------------------------\n");
}

void expire_all_dns_records()
{
    pdns_record *pdnsr;

    dlog("[D] Expiring all domain records\n");

    uint32_t iter;
    for (iter = 0; iter < DBUCKET_SIZE; iter++)
    {
        pdnsr = dbucket[iter];
        while (pdnsr != NULL)
        {
            /* Expire the record and all its assets */
            /* Remove from the hash */
            if (pdnsr->prev)
                pdnsr->prev->next = pdnsr->next;
            if (pdnsr->next)
                pdnsr->next->prev = pdnsr->prev;
            pdns_record *tmp = pdnsr;

            pdnsr = pdnsr->next;

            delete_dns_record(tmp, &dbucket[iter]);
            if (pdnsr == NULL)
                dbucket[iter] = NULL;
        }
    }
}

void delete_dns_record(pdns_record * pdnsr, pdns_record ** bucket_ptr)
{
    pdns_record *prev = pdnsr->prev;    /* Older DNS record */
    pdns_record *next = pdnsr->next;    /* Newer DNS record */
    pdns_asset *asset = pdnsr->passet;
    pdns_asset *tmp_asset;

    dlog("[D] Deleting domain record: %s\n", pdnsr->qname);

    /* Delete all domain assets */
    while (asset != NULL)
    {
        /* Print the asset before we expires if it
         * has been updated since it last was printed */
        if (asset->last_seen.tv_sec > asset->last_print.tv_sec)
            print_passet(pdnsr, asset, asset->rr, NULL, 0);

        else if (asset->last_seen.tv_sec == asset->last_print.tv_sec) {
            if (asset->last_seen.tv_usec > asset->last_print.tv_usec)
                print_passet(pdnsr, asset, asset->rr, NULL, 0);
        }
        tmp_asset = asset;
        asset = asset->next;
        delete_dns_asset(&pdnsr->passet, tmp_asset);
    }

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
    if (pdnsr->qname)
        mem_refund(strlen((char *)pdnsr->qname) + 1);
    mem_refund(sizeof(pdns_record));
    free(pdnsr->qname);
    free(pdnsr);
    pdnsr = NULL;
    PDNS_U32_DEC(config.dns_records);
}

void expire_dns_assets(pdns_record *pdnsr, time_t expire_t)
{
    dlog("[D] Checking for DNS assets to be expired\n");

    pdns_asset *passet = pdnsr->passet;

    while (passet != NULL)
    {
        if (passet->last_seen.tv_sec <= expire_t) {
            /* Print the asset before we expires if it
               has been updated since it last was printed */
            if (passet->last_seen.tv_sec > passet->last_print.tv_sec)
                print_passet(pdnsr, passet, passet->rr, NULL, 0);

            else if (passet->last_seen.tv_sec == passet->last_print.tv_sec) {
                if (passet->last_seen.tv_usec > passet->last_print.tv_usec)
                    print_passet(pdnsr, passet, passet->rr, NULL, 0);
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
        }
        else
            passet = passet->next;
    }
}

void delete_dns_asset(pdns_asset **passet_head, pdns_asset *passet)
{
    if (passet == NULL)
        return;

    dlog("[D] Deleting domain asset: %s\n", passet->answer);

    pdns_asset *tmp_pa = NULL;
    pdns_asset *next_pa = NULL;
    pdns_asset *prev_pa = NULL;

    tmp_pa = passet;
    next_pa = tmp_pa->next;
    prev_pa = tmp_pa->prev;

    if (prev_pa == NULL) {
        /* Beginning of list  */
        *passet_head = next_pa;
        /* Not only entry */
        if (next_pa)
            next_pa->prev = NULL;
    }
    else if (next_pa == NULL) {
        /* At end of list! */
        prev_pa->next = NULL;
    }
    else {
        /* A node */
        prev_pa->next = next_pa;
        next_pa->prev = prev_pa;
    }

    if (passet->answer)
        mem_refund(strlen((char *)passet->answer) + 1);
    mem_refund(sizeof(ldns_rr));
    mem_refund(sizeof(pdns_asset));
    free(passet->rr);
    passet->rr = NULL;
    free(passet->answer);
    passet->answer = NULL;
    free(passet);
    passet = NULL;
    PDNS_U32_DEC(config.dns_assets);
}

void update_dns_stats(packetinfo *pi, uint8_t code)
{
    if (pi->af == AF_INET) {
        switch (pi->proto) {
            case IP_PROTO_TCP:
                PDNS_U32_INC(config.p_s.ip4_dns_tcp);
                if (code == SUCCESS)
                    PDNS_U32_INC(config.p_s.ip4_dec_tcp_ok);
                else
                    PDNS_U32_INC(config.p_s.ip4_dec_tcp_er);
                break;
            case IP_PROTO_UDP:
                PDNS_U32_INC(config.p_s.ip4_dns_udp);
                if (code == SUCCESS)
                    PDNS_U32_INC(config.p_s.ip4_dec_udp_ok);
                else
                    PDNS_U32_INC(config.p_s.ip4_dec_udp_er);
                break;
            default:
               break;
        }
    }
    else if (pi->af == AF_INET6) {
        switch (pi->proto) {
            case IP_PROTO_TCP:
                 PDNS_U32_INC(config.p_s.ip6_dns_tcp);
                if (code == SUCCESS)
                    PDNS_U32_INC(config.p_s.ip6_dec_tcp_ok);
                else
                    PDNS_U32_INC(config.p_s.ip6_dec_tcp_er);
                break;
            case IP_PROTO_UDP:
                PDNS_U32_INC(config.p_s.ip6_dns_udp);
                if (code == SUCCESS)
                    PDNS_U32_INC(config.p_s.ip6_dec_udp_ok);
                else
                    PDNS_U32_INC(config.p_s.ip6_dec_udp_er);
                break;
            default:
                break;
        }
    }
}

void parse_field_flags(char *args)
{
    int i;
    int ok = 0;
    int len = 0;
    uint32_t tmpf;

    tmpf = config.fieldsf;
    len = strlen(args);

    if (len == 0) {
        plog("[W] No fields are specified!\n");
        plog("[*] Continuing with default fields...\n");
        return;
    }

    config.fieldsf = 0;

    for (i = 0; i < len; i++)
    {
        switch(args[i]) {
            case 'H': /* Timestamp(YMDHMS) */
                config.fieldsf |= FIELD_TIMESTAMP_YMDHMS;
                dlog("[D] Enabling field: FIELD_TIMESTAMP_YMDHMS\n");
                ok++;
                break;
            case 'S': /* Timestamp(s) */
                config.fieldsf |= FIELD_TIMESTAMP_S;
                dlog("[D] Enabling field: FIELD_TIMESTAMP_S\n");
                ok++;
                break;
            case 'M': /* Timestamp(ms) */
                config.fieldsf |= FIELD_TIMESTAMP_MS;
                dlog("[D] Enabling field: FIELD_TIMESTAMP_MS\n");
                ok++;
                break;
            case 'c': /* Client */
                config.fieldsf |= FIELD_CLIENT;
                dlog("[D] Enabling field: FIELD_CLIENT\n");
                ok++;
                break;
            case 's': /* Server */
                config.fieldsf |= FIELD_SERVER;
                dlog("[D] Enabling field: FIELD_SERVER\n");
                ok++;
                break;
            case 'C': /* Class */
                config.fieldsf |= FIELD_CLASS;
                dlog("[D] Enabling field: FIELD_CLASS\n");
                ok++;
                break;
            case 'Q': /* Query */
                config.fieldsf |= FIELD_QUERY;
                dlog("[D] Enabling field: FIELD_QUERY\n");
                ok++;
                break;
            case 'L': /* Query Length */
                config.fieldsf |= FIELD_QUERY_LEN;
                dlog("[D] Enabling field: FIELD_QUERY_LEN\n");
                ok++;
                break;
            case 'T': /* Type */
                config.fieldsf |= FIELD_TYPE;
                dlog("[D] Enabling field: FIELD_TYPE\n");
                ok++;
                break;
            case 'A': /* Answer */
                config.fieldsf |= FIELD_ANSWER;
                dlog("[D] Enabling field: FIELD_ANSWER\n");
                ok++;
                break;
            case 'l': /* Answer Lenght */
                config.fieldsf |= FIELD_ANSWER_LEN;
                dlog("[D] Enabling field: FIELD_ANSWER_LEN\n");
                ok++;
                break;
            case 't': /* TTL */
                config.fieldsf |= FIELD_TTL;
                dlog("[D] Enabling field: FIELD_TTL\n");
                ok++;
                break;
            case 'p': /* Protocol */
                config.fieldsf |= FIELD_PROTO;
                dlog("[D] Enabling field: FIELD_PROTO\n");
                ok++;
                break;
            case 'n': /* Count */
                config.fieldsf |= FIELD_COUNT;
                dlog("[D] Enabling field: FIELD_COUNT\n");
                ok++;
                break;
            case 'h': /* Hostname */
                config.fieldsf |= FIELD_HOSTNAME;
                dlog("[D] Enabling field: FIELD_HOSTNAME\n");
                ok++;
                break;
            case 'w': /* Client hw address */
                config.fieldsf |= FIELD_CLT_HWADDR;
                dlog("[D] Enabling field: FIELD_CLT_HWADDR\n");
                ok++;
                break;
            case 'W': /* Server hw address */
                config.fieldsf |= FIELD_SRV_HWADDR;
                dlog("[D] Enabling field: FIELD_SRV_HWADDR\n");
                ok++;
                break;
            case 'i': /* IP TTL of the reply */
                config.fieldsf |= FIELD_SERVER_TTL;
                dlog("[D] Enabling field: FIELD_SERVER_TTL\n");
                ok++;
                break;
            default:
               plog("[*] Unknown field '%c'\n",args[i]);
               break;
        }
    }

    if (ok == 0) {
        plog("[W] No valid fields parsed, continuing with defaults.\n");
        config.fieldsf = tmpf;
    }
}

void parse_dns_flags(char *args)
{
    int i;
    int ok = 0;
    int len = 0;
    uint64_t tmpf;

    tmpf = config.dnsf;
    len = strlen(args);

    if (len == 0) {
        plog("[W] No flags are specified!\n");
        plog("[*] Continuing with default flags...\n");
        return;
    }

    config.dnsf = 0;
    config.dnsfe = 0;

    for (i = 0; i < len; i++){
        switch(args[i]) {
            case 'I': /* HINFO */
                config.dnsf |= DNS_CHK_HINFO;
                dlog("[D] Enabling flag: DNS_CHK_HINFO\n");
                ok++;
                break;
            case 'H': /* SSHFP */
                config.dnsf |= DNS_CHK_SSHFP;
                dlog("[D] Enabling flag: DNS_CHK_SSHFP\n");
                ok++;
                break;
            case 'L': /* LOC */
                config.dnsf |= DNS_CHK_LOC;
                dlog("[D] Enabling flag: DNS_CHK_LOC\n");
                ok++;
                break;
            case 'd': /* DNSSEC */
                config.dnsf |= DNS_CHK_DNSSEC;
                dlog("[D] Enabling flag: DNS_CHK_DNSSEC\n");
                ok++;
                break;
            case '4': /* A */
                config.dnsf |= DNS_CHK_A;
                dlog("[D] Enabling flag: DNS_CHK_A\n");
                ok++;
                break;
            case '6': /* AAAA */
                config.dnsf |= DNS_CHK_AAAA;
                dlog("[D] Enabling flag: DNS_CHK_AAAA\n");
                ok++;
                break;
            case 'P': /* PTR */
                config.dnsf |= DNS_CHK_PTR;
                dlog("[D] Enabling flag: DNS_CHK_PTR\n");
                ok++;
                break;
            case 'C': /* CNAME */
                config.dnsf |= DNS_CHK_CNAME;
                dlog("[D] Enabling flag: DNS_CHK_CNAME\n");
                ok++;
                break;
            case 'D': /* DNAME */
                config.dnsf |= DNS_CHK_DNAME;
                dlog("[D] Enabling flag: DNS_CHK_DNAME\n");
                ok++;
                break;
            case 'N': /* NAPTR */
                config.dnsf |= DNS_CHK_NAPTR;
                dlog("[D] Enabling flag: DNS_CHK_NAPTR\n");
                ok++;
                break;
            case 'R': /* RP */
                config.dnsf |= DNS_CHK_RP;
                dlog("[D] Enabling flag: DNS_CHK_RP\n");
                ok++;
                break;
            case 'S': /* SRV */
                config.dnsf |= DNS_CHK_SRV;
                dlog("[D] Enabling flag: DNS_CHK_SRV\n");
                ok++;
                break;
            case 'F': /* SPF */
                config.dnsf |= DNS_CHK_SPF;
                dlog("[D] Enabling flag: DNS_CHK_SPF\n");
                ok++;
                break;
            case 'T': /* TXT */
                config.dnsf |= DNS_CHK_TXT;
                dlog("[D] Enabling flag: DNS_CHK_TXT\n");
                ok++;
                break;
            case 'O': /* SOA */
                config.dnsf |= DNS_CHK_SOA;
                dlog("[D] Enabling flag: DNS_CHK_SOA\n");
                ok++;
                break;
            case 'M': /* MX */
               config.dnsf |= DNS_CHK_MX;
               dlog("[D] Enabling flag: DNS_CHK_MX\n");
               ok++;
               break;
            case 'n': /* NS */
               config.dnsf |= DNS_CHK_NS;
               dlog("[D] Enabling flag: DNS_CHK_NS\n");
               ok++;
               break;
#ifdef PDNS_HAVE_HTTPS
            case 'h': /* HTTPS */
               config.dnsf |= DNS_CHK_HTTPS;
               dlog("[D] Enabling flag: DNS_CHK_HTTPS\n");
               ok++;
               break;
#endif
#ifdef PDNS_HAVE_HTTPS
            case 'V': /* SVCB */
               config.dnsf |= DNS_CHK_SVCB;
               dlog("[D] Enabling flag: DNS_CHK_SVCB\n");
               ok++;
               break;
#endif
            case 'f': /* FORMERR */
               config.dnsfe |= DNS_SE_CHK_FORMERR;
               dlog("[D] Enabling flag: DNS_SE_CHK_FORMERR\n");
               ok++;
               break;
            case 's': /* SERVFAIL */
               config.dnsfe |= DNS_SE_CHK_SERVFAIL;
               dlog("[D] Enabling flag: DNS_SE_CHK_SERVFAIL\n");
               ok++;
               break;
            case 'x': /* NXDOMAIN */
               config.dnsfe |= DNS_SE_CHK_NXDOMAIN;
               dlog("[D] Enabling flag: DNS_SE_CHK_NXDOMAIN\n");
               ok++;
               break;

            case 'o': /* NOTIMPL */
               config.dnsfe |= DNS_SE_CHK_NOTIMPL;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOTIMPL\n");
               ok++;
               break;
            case 'r': /* REFUSED */
               config.dnsfe |= DNS_SE_CHK_REFUSED;
               dlog("[D] Enabling flag: DNS_SE_CHK_REFUSED\n");
               ok++;
               break;
            case 'y': /* YXDOMAIN */
               config.dnsfe |= DNS_SE_CHK_YXDOMAIN;
               dlog("[D] Enabling flag: DNS_SE_CHK_YXDOMAIN\n");
               ok++;
               break;
            case 'e': /* YXRRSET */
               config.dnsfe |= DNS_SE_CHK_YXRRSET;
               dlog("[D] Enabling flag: DNS_SE_CHK_YXRRSET\n");
               ok++;
               break;
            case 't': /* NXRRSET */
               config.dnsfe |= DNS_SE_CHK_NXRRSET;
               dlog("[D] Enabling flag: DNS_SE_CHK_NXRRSET\n");
               ok++;
               break;
            case 'a': /* NOTAUTH */
               config.dnsfe |= DNS_SE_CHK_NOTAUTH;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOTAUTH\n");
               ok++;
               break;
            case 'z': /* NOTZONE */
               config.dnsfe |= DNS_SE_CHK_NOTZONE;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOTZONE\n");
               ok++;
               break;
            case '0': /* empty NOERROR / NODATA */
               config.dnsfe |= DNS_SE_CHK_NOERR;
               dlog("[D] Enabling flag: DNS_SE_CHK_NOERR\n");
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
        case 0:
            retcode = DNS_SE_CHK_NOERR;
            break;
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
            retcode = 0x0000;  /* UNKNOWN-ERROR */
            break;
    }

    return retcode;
}

