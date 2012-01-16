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
void expire_dns_assets(pdns_record *pdnsr, time_t expire_t);
void delete_dns_record (pdns_record * pdnsr, pdns_record ** bucket_ptr);
void delete_dns_asset(pdns_asset **passet_head, pdns_asset *passet);

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
    ldns_pkt     *decoded_dns;
    ldns_rr_list *questions;
    ldns_rr_list *answers;
    ldns_rr_list *authorities;

    status = ldns_wire2pkt(&decoded_dns,pi->payload, pi->plen);

    if (status != LDNS_STATUS_OK) {
        dlog("[D] ldns_wire2pkt status = %d\n", status);
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
        int            data_offset = -1;

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
                if (config.dnsf & DNS_CHK_AAAA)
                    data_offset = 0;
                break; 
            case LDNS_RR_TYPE_A:
                if (config.dnsf & DNS_CHK_A)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_PTR:
                if (config.dnsf & DNS_CHK_PTR)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_CNAME:
                if (config.dnsf & DNS_CHK_CNAME)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_DNAME:
                if (config.dnsf & DNS_CHK_DNAME)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_NAPTR:
                if (config.dnsf & DNS_CHK_NAPTR)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_RP:
                if (config.dnsf & DNS_CHK_RP)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_SRV:
                if (config.dnsf & DNS_CHK_SRV)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_TXT:
                if (config.dnsf & DNS_CHK_TXT)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_SOA:
                if (config.dnsf & DNS_CHK_SOA)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_MX:
                if (config.dnsf & DNS_CHK_MX)
                    data_offset = 0;
                break;
            case LDNS_RR_TYPE_NS:
                if (config.dnsf & DNS_CHK_NS)
                    data_offset = 0;
                break;

            default:
                data_offset = -1;
                dlog("[D] ldns_rr_get_type: %d\n",ldns_rr_get_type(rr));
                break;
        }

        if (data_offset == -1) {
            dlog("[D] LDNS_RR_TYPE not enabled/supported: %d\n",ldns_rr_get_type(rr));
            //data_offset = 0;
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
            dlog("[D] ldns_rr_rdf for rname returned NULL\n");
            continue;
        }

        ldns_rdf2buffer_str(buf, rname);
        rname_str = (unsigned char *)ldns_buffer2str(buf);

        if (rname_str == NULL) {
            dlog("[D] ldns_buffer2str on rname returned NULL\n");
            continue;
        }
        dlog("[D] rname_str:%s\n", rname_str);

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
            passet->cip       = pi->cxt->s_ip; // This should always be the client IP
            passet->sip       = pi->cxt->d_ip; // This should always be the server IP
            if (rr->_ttl > passet->rr->_ttl) {
                passet->rr->_ttl = rr->_ttl; // Catch the highest TTL seen
            }
            dlog("[*] DNS asset updated...\n");
            if ((passet->last_seen - passet->last_print) >= config.dnsprinttime) {
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
        config.p_s.dns_assets++;
        config.dns_assets++;
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
    passet->cip        = pi->cxt->s_ip; // This should always be the client IP
    passet->sip        = pi->cxt->d_ip; // This should always be the server IP
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

    FILE *fd;
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_c[INET6_ADDRSTRLEN];

    fd = fopen(config.logfile, "a");
    if (fd == NULL) {
        plog("[E] ERROR: Cant open file %s\n",config.logfile);
        p->last_print = p->last_seen;
        return;
    }

    u_ntop(p->sip, p->af, ip_addr_s);
    u_ntop(p->cip, p->af, ip_addr_c);
    fprintf(fd,"%lu||%s||%s||",p->last_seen, ip_addr_c, ip_addr_s);

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

    //fprintf(fd,"||%s\n", p->answer);
    fprintf(fd,"||%s||%u\n", p->answer,p->rr->_ttl); // Do we want TTL ?
    fclose(fd);

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
        config.p_s.dns_records++;
        config.dns_records++;
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

void expire_dns_records()
{
    pdns_record *pdnsr;
    uint8_t run = 0;
    time_t expire_t;
    time_t oldest;
    //expire_t = (config.tstamp - DNSCACHETIMEOUT);
    expire_t = (config.tstamp - config.dnscachetimeout);
    oldest = config.tstamp; 

    dlog("[D] Checking for DNS records to be expired\n");

    while ( run == 0 ) {
        uint32_t iter;
        run = 1;
        for (iter = 0; iter < DBUCKET_SIZE; iter++) {
            pdnsr = dbucket[iter];
            while (pdnsr != NULL) {
                if (pdnsr->last_seen < oldest) // Find the LRU asset timestamp
                    oldest = pdnsr->last_seen;

                if (pdnsr->last_seen <= expire_t) {
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
            oldest = config.tstamp;
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
        if (asset->last_seen > asset->last_print) {
            print_passet(asset, pdnsr);
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
        if (passet->last_seen <= expire_t) {
            /* Print the asset before we expires if it
             * has been updated since it last was printed */
            if (passet->last_seen > passet->last_print) {
                print_passet(passet, pdnsr);
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
    free(passet);
    passet = NULL;
    config.dns_assets--;
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

    config.dnsf = 0;

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
