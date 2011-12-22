void dns_parser (packetinfo *pi);
void expire_dns_records();
void expire_all_dns_records();
void update_config_mem_counters();

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

typedef enum {
    QUESTION,
    ANSWER
} query_type_t;

typedef struct {
    query_type_t   query_type;
    char          *key;
} archive_node_t;

/* HASH: 
 *     [DOMAIN_HASH_BUCKET]_
 *                          |__[Q-TYPE_BUCKET]_<--- PTR,MX,A... 
 *                                            |__[RESPONCE-NAME] <--- FOR PTR is the IPv4/IPv6
 */

typedef struct _pdns_asset {
    time_t                 first_seen; /* First seen (unix timestamp) */
    time_t                 last_seen;  /* Last seen (unix timestamp) */
    time_t                 last_print; /* Last time asset was printet */
    struct ldns_struct_rr *rr;         /* PTR,MX,TXT,A,AAAA...  */
    unsigned char         *answer;     /* Answer, like 8.8.8.8 or 2001:67c:21e0::16 */
    uint32_t               af;         /* IP version (4/6) AF_INET */
    struct in6_addr        sip;        /* DNS Server IP (v4/6) */
    struct in6_addr        cip;        /* DNS Client IP (v4/6) */
    struct _pdns_asset    *next;       /* Next dns asset */
    struct _pdns_asset    *prev;       /* Prev dns asset */
} pdns_asset;

typedef struct _pdns_record {
    time_t                 first_seen; /* First seen (unix timestamp) */
    time_t                 last_seen;  /* Last seen (unix timestamp) */
    unsigned char         *qname;      /* Query name (gamelinux.org) */
    uint32_t               af;         /* IP version (4/6) AF_INET */
    struct in6_addr        sip;        /* DNS Server IP (v4/6) */
    struct in6_addr        cip;        /* DNS Client IP (v4/6) */
    pdns_asset            *passet;     /* Head of dns assets */
    struct _pdns_record   *next;       /* Next dns record */
    struct _pdns_record   *prev;       /* Prev dns record */
} pdns_record;

