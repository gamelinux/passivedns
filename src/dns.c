#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <ldns/ldns.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include "passivedns.h"
#include "dns.h"

static int archive(packetinfo *pi, ldns_rr_list *questions, ldns_rr_list *answers, ldns_rr_list *authorities);
static int archive_lname_list(packetinfo *pi, ldns_rdf *lname,ldns_rr_list *list, ldns_buffer *buf);
void associated_lookup_or_make_insert(pdns_record *lname_node, packetinfo *pi, unsigned char *rname_str, ldns_rr *rr);
pdns_record *pdnsr_lookup_or_make_new(uint64_t dnshash, packetinfo *pi, unsigned char *lname_str);
void print_passet(pdns_asset *p, pdns_record *l);
const char *u_ntop(const struct in6_addr ip_addr, int af, char *dest);

#define DBUCKET_SIZE                   16769023
pdns_record *dbucket[DBUCKET_SIZE];

uint64_t hash(unsigned char *str) {
    uint64_t hash = 5381;
    uint64_t c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    return hash % 10; // TEST - stress the linked lists :)
    //return hash % DBUCKET_SIZE;
}

void dns_parser (packetinfo *pi) {
    ldns_status   status;
    ldns_pkt     *decoded_dns;
    ldns_rr_list *questions;
    ldns_rr_list *answers;
    ldns_rr_list *authorities;

    status = ldns_wire2pkt(&decoded_dns,pi->payload, pi->plen);

    if (status != LDNS_STATUS_OK) {
        dlog("[D] ldns_wire2pkt status = %d\n", status);
        ldns_pkt_free(decoded_dns);
        return;
    }

    /* we only care about answers, no questions allowed! */
    if (ldns_pkt_qr(decoded_dns)) {
        //dns_store(dns_db, decoded_dns);
        if (!ldns_pkt_qdcount(decoded_dns) || !ldns_pkt_ancount(decoded_dns)) {
            /* no questions or answers */
            dlog("[D] dns_archiver() packet did not contain answer\n");
            ldns_pkt_free(decoded_dns);
            return;
        }

        questions   = ldns_pkt_question(decoded_dns);
        answers     = ldns_pkt_answer(decoded_dns);
        authorities = ldns_pkt_authority(decoded_dns);
        // send it off to the linked list
        if (archive(pi, questions, answers, authorities) < 0) {
            dlog("[D] dns_archiver(): archive() returned -1\n");
        }
    }

    ldns_pkt_free(decoded_dns);
}

static int
archive(packetinfo   *pi,
        ldns_rr_list *questions,
        ldns_rr_list *answers,
        ldns_rr_list *authorities)
{
    ldns_buffer *dns_buffer;
    int          qa_rrcount;
    int          an_rrcount;
    int          au_rrcount;
    int          i;

    qa_rrcount = ldns_rr_list_rr_count(questions);
    an_rrcount = ldns_rr_list_rr_count(answers);
    au_rrcount = ldns_rr_list_rr_count(authorities);
    dns_buffer = ldns_buffer_new(LDNS_MIN_BUFLEN);

    dlog("[*] %d qa_rrcount\n", qa_rrcount);

    for (i = 0; i < qa_rrcount; i++) {
        ldns_rr  *question_rr;
        ldns_rdf *rdf_data;
        int       ret;

        question_rr = ldns_rr_list_rr(questions, i);
        rdf_data    = ldns_rr_owner(question_rr);

        dlog("[D] archive(): rdf_data = %p\n", rdf_data);

        /* plop all the answers into the correct archive_node_t's
         * associated_nodes hash. */
        ret = archive_lname_list(pi, rdf_data, answers, dns_buffer);

        if (ret < 0) {
            dlog("[D] archive_lname_list() returned error\n");
        }
        /* archive_lname_list(archive_hash, rdf_data, authorities, dns_buffer); */
    }

    ldns_buffer_free(dns_buffer);
    return(0);
}

static int
archive_lname_list(packetinfo   *pi,
                   ldns_rdf     *lname,
                   ldns_rr_list *list,
                   ldns_buffer  *buf)
{
    int             list_count;
    unsigned char  *lname_str = 0;
    ldns_status     status;
    int             i;
    pdns_record    *lname_node = NULL;
    uint64_t        dnshash;

    ldns_buffer_clear(buf);
    status = ldns_rdf2buffer_str(buf, lname);

    if (status != LDNS_STATUS_OK) {
        dlog("[D] ldns_rdf2buffer_str() returned error %d\n", status);
        return(-1);
    }

    list_count = ldns_rr_list_rr_count(list);
    lname_str  = (unsigned char *)ldns_buffer2str(buf);

    if (lname_str == NULL) {
        dlog("[D] ldns_buffer2str(%p) returned null\n", buf);
        return(-1);
    }
    dlog("[D] lname_str:%s\n", lname_str);

    for (i = 0; i < list_count; i++) {
        ldns_rr       *rr;
        ldns_rdf      *rname;
        unsigned char *rname_str = 0;
        int            data_offset = 0;

        ldns_buffer_clear(buf);

        /* so dns lname's are not always associated with
         *  the actual question. A question may be for blah.com
         *  but a lname can be stupid.com.
         *
         *  The issue becomes is that a caching nameserver may
         *  aggregate records together such is the case when a
         *  resolver returns a CNAME, it will then lookup the
         *  CNAME and plunk that into one response.
         *
         *  That's cool and all, but in the case of our sniffer
         *  we will treat all lname's as the real question, and
         *  all right names as answers for that question.
         *
         *  It servers a purpose within a sniffer like this,
         *  someone could be doing something a bit shady in that
         *  they give out an answer for one address, but then
         *  actually answer a completely different lname. */
        rr = ldns_rr_list_rr(list, i);

        switch (ldns_rr_get_type(rr)) {
            /* at the moment, we only really care about
             * rr's that have an addr or cname for the rname. */
            case LDNS_RR_TYPE_AAAA:
            case LDNS_RR_TYPE_A:
            case LDNS_RR_TYPE_PTR:
            case LDNS_RR_TYPE_CNAME:
                data_offset = 0;
                break;
            default:
                data_offset = -1;
                break;
        }

        if (data_offset == -1) {
            continue;
        }

        // CHECK IF THE NODE EXISTS, IF NOT MAKE IT - RETURN POINTER TO NODE ?
        if (lname_node == NULL) {
            dnshash = hash(lname_str);
            dlog("[D] Hash: %lu\n", dnshash);
            lname_node = pdnsr_lookup_or_make_new(dnshash, pi, lname_str);
        }

        /* now add this answer to the association hash */
        rname = ldns_rr_rdf(rr, data_offset);

        if (rname == NULL) {
            continue;
        }

        ldns_rdf2buffer_str(buf, rname);
        rname_str = (unsigned char *)ldns_buffer2str(buf);

        if (rname_str == NULL) {
            continue;
        }
        dlog("[*] rname_str:%s\n", rname_str);

        // CHECK IF THE NODE HAS THE ASSOCIATED ENTRY, IF NOT ADD IT.
        associated_lookup_or_make_insert(lname_node, pi, rname_str, rr);
        free(rname_str);
    }
    free(lname_str);
    return(0);
}

void associated_lookup_or_make_insert(pdns_record *lname_node, packetinfo *pi, unsigned char *rname_str, ldns_rr *rr) {

    pdns_asset *passet = lname_node->passet;
    pdns_asset *head   = passet;
    ldns_rr    *prr    = NULL;
    uint32_t    len    = 0;

    dlog("Searching: %u, %s, %s\n",rr->_rr_type, lname_node->qname, rname_str);

    while (passet != NULL) {
        // if found, update
        dlog("Matching: %u, %s, %s\n",passet->rr->_rr_type, lname_node->qname, passet->answer);
        dlog("[*] RR:%u, %u\n",passet->rr->_rr_type, rr->_rr_type);
        if (passet->rr->_rr_type == rr->_rr_type) {
          dlog("[*] rr match\n");
          dlog("r:%s == a:%s\n",rname_str,passet->answer);
          if (strcmp((const char *)rname_str,(const char *)passet->answer) == 0 ) {
            dlog("[*] rname/answer match\n");
            // We have this, update & if its over 24h since last print - print it, then return
            passet->last_seen = pi->pheader->ts.tv_sec;
            passet->sip       = pi->cxt->s_ip;
            passet->cip       = pi->cxt->d_ip;
            dlog("[*] DNS asset updated...\n");
            if ((passet->last_seen - passet->last_print) >= 86400) {
                print_passet(passet, lname_node);
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
        prr = (ldns_rr*) calloc(1, sizeof(ldns_rr));
        prr->_owner        = rr->_owner;
        prr->_ttl          = rr->_ttl;
        prr->_rd_count     = rr->_rd_count;
        prr->_rr_type      = rr->_rr_type;
        prr->_rr_class     = rr->_rr_class;
        prr->_rdata_fields = rr->_rdata_fields;
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
    passet->first_seen = pi->pheader->ts.tv_sec;
    passet->last_seen  = pi->pheader->ts.tv_sec;
    passet->af         = pi->cxt->af;
    passet->sip        = pi->cxt->s_ip;
    passet->cip        = pi->cxt->d_ip;
    passet->prev       = NULL;
    len                = strlen((char *)rname_str);
    passet->answer     = calloc(1, (len + 1));
    strncpy((char *)passet->answer, (char *)rname_str, len);

    dlog("[D] Adding: %u, %s, %s\n",passet->rr->_rr_type, lname_node->qname, rname_str);

    lname_node->passet = passet;

    print_passet(passet, lname_node);

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

// A=1, 5=CNAME, PTR=12, AAAA=28
// timestamp||dns-client||dns-server-IP||class||domain||query type||answer
void print_passet(pdns_asset *p, pdns_record *l) {
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_c[INET6_ADDRSTRLEN];

    u_ntop(p->sip, p->af, ip_addr_s);
    u_ntop(p->cip, p->af, ip_addr_c);

    printf("%lu||%s||%s||",p->last_seen, ip_addr_c, ip_addr_s);

    switch (ldns_rr_get_class(p->rr)) {
        case LDNS_RR_CLASS_IN:
             printf("IN");
             break;
        case LDNS_RR_CLASS_CH:
             printf("CH");
             break;
        case LDNS_RR_CLASS_HS:
             printf("HS");
             break;
        case LDNS_RR_CLASS_NONE:
             printf("NONE");
             break;
        case LDNS_RR_CLASS_ANY:
             printf("ANY");
             break;
        default:
             printf("%d",p->rr->_rr_class);
             break;
    }

    printf("||%s||",l->qname);

    switch (ldns_rr_get_type(p->rr)) {
        case LDNS_RR_TYPE_PTR:
             printf("PTR");
             break;
        case LDNS_RR_TYPE_A:
             printf("A");
             break;
        case LDNS_RR_TYPE_AAAA:
             printf("AAAA");
             break;
        case LDNS_RR_TYPE_CNAME:
             printf("CNAME");
             break;
        default:
            printf("%d",p->rr->_rr_type);
            break;
    }

    printf("||%s\n", p->answer);

    p->last_print = p->last_seen;
}

pdns_record *pdnsr_lookup_or_make_new(uint64_t dnshash, packetinfo *pi, unsigned char *lname_str) {

    pdns_record *pdnsr = dbucket[dnshash];
    pdns_record *head  = pdnsr;
    uint32_t     len   = 0;

    // search through the bucket
    while (pdnsr != NULL) {
        // if found, update & return dnsr
        if (strcmp((const char *)lname_str,(const char *)pdnsr->qname) == 0) { // match :)
            pdnsr->last_seen = pi->pheader->ts.tv_sec;
            pdnsr->sip       = pi->cxt->s_ip;
            pdnsr->cip       = pi->cxt->d_ip;
            return pdnsr;
        }
        pdnsr = pdnsr->next;
    }

    // else, we got a new dnsr :)
    if ( pdnsr == NULL ) {
        pdnsr = (pdns_record*) calloc(1, sizeof(pdns_record));
        dlog("[*] Allocated a new dns record...\n");
    }
    if (head != NULL ) {
        head->prev = pdnsr;
    }
    // populate new values
    pdnsr->first_seen = pi->pheader->ts.tv_sec;
    pdnsr->last_seen  = pi->pheader->ts.tv_sec;
    pdnsr->af         = pi->cxt->af;
    pdnsr->sip        = pi->cxt->s_ip;
    pdnsr->cip        = pi->cxt->d_ip;
    pdnsr->next       = head;
    pdnsr->prev       = NULL;
    pdnsr->passet     = NULL;
    len               = strlen((char *)lname_str);
    pdnsr->qname      = calloc(1, (len + 1));
    strncpy((char *)pdnsr->qname, (char *)lname_str, len);

    dbucket[dnshash] = pdnsr;
    return pdnsr;
}
