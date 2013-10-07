/*
 * resolver.c
 *
 * resolver implementation
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

#ifdef _MSC_VER
#include <windows.h>
#include <string.h>
#define close(X) closesocket(X)
#else
#include <strings.h>
#endif

/* Access function for reading 
 * and setting the different Resolver 
 * options */

/* read */
uint16_t
ldns_resolver_port(const ldns_resolver *r)
{
	return r->_port;
}

uint16_t
ldns_resolver_edns_udp_size(const ldns_resolver *r)
{
	        return r->_edns_udp_size;
}

uint8_t
ldns_resolver_retry(const ldns_resolver *r)
{
	return r->_retry;
}

uint8_t
ldns_resolver_retrans(const ldns_resolver *r)
{
	return r->_retrans;
}

bool
ldns_resolver_fallback(const ldns_resolver *r)
{
	return r->_fallback;
}

uint8_t
ldns_resolver_ip6(const ldns_resolver *r)
{
	return r->_ip6;
}

bool
ldns_resolver_recursive(const ldns_resolver *r)
{
	return r->_recursive;
}

bool
ldns_resolver_debug(const ldns_resolver *r)
{
	return r->_debug;
}

bool
ldns_resolver_dnsrch(const ldns_resolver *r)
{
	return r->_dnsrch;
}

bool
ldns_resolver_fail(const ldns_resolver *r)
{
	return r->_fail;
}

bool
ldns_resolver_defnames(const ldns_resolver *r)
{
	return r->_defnames;
}

ldns_rdf *
ldns_resolver_domain(const ldns_resolver *r)
{
	return r->_domain;
}

ldns_rdf **
ldns_resolver_searchlist(const ldns_resolver *r)
{
	return r->_searchlist;
}

ldns_rdf **
ldns_resolver_nameservers(const ldns_resolver *r)
{
	return r->_nameservers;
}

size_t
ldns_resolver_nameserver_count(const ldns_resolver *r)
{
	return r->_nameserver_count;
}

bool
ldns_resolver_dnssec(const ldns_resolver *r)
{
	return r->_dnssec;
}

bool
ldns_resolver_dnssec_cd(const ldns_resolver *r)
{
	return r->_dnssec_cd;
}

ldns_rr_list *
ldns_resolver_dnssec_anchors(const ldns_resolver *r)
{
    return r->_dnssec_anchors;
}

bool
ldns_resolver_trusted_key(const ldns_resolver *r, ldns_rr_list * keys, ldns_rr_list * trusted_keys)
{
  size_t i;
  bool result = false;
  
  ldns_rr_list * trust_anchors;
  ldns_rr * cur_rr;

  if (!r || !keys) { return false; }

  trust_anchors = ldns_resolver_dnssec_anchors(r);

  if (!trust_anchors) { return false; }

  for (i = 0; i < ldns_rr_list_rr_count(keys); i++) {

    cur_rr = ldns_rr_list_rr(keys, i);
    if (ldns_rr_list_contains_rr(trust_anchors, cur_rr)) {      
      if (trusted_keys) { ldns_rr_list_push_rr(trusted_keys, cur_rr); }
      result = true;
    }
  }

  return result;
}

bool
ldns_resolver_igntc(const ldns_resolver *r)
{
	return r->_igntc;
}

bool
ldns_resolver_usevc(const ldns_resolver *r)
{
	return r->_usevc;
}

size_t *
ldns_resolver_rtt(const ldns_resolver *r)
{
	return r->_rtt;
}

size_t
ldns_resolver_nameserver_rtt(const ldns_resolver *r, size_t pos)
{
	size_t *rtt;

	assert(r != NULL);
	
	rtt = ldns_resolver_rtt(r);
	
	if (pos >= ldns_resolver_nameserver_count(r)) {
		/* error ?*/
		return 0;
	} else {
		return rtt[pos];
	}

}

struct timeval
ldns_resolver_timeout(const ldns_resolver *r)
{
	return r->_timeout;
} 

char *
ldns_resolver_tsig_keyname(const ldns_resolver *r)
{
	return r->_tsig_keyname;
}

char *
ldns_resolver_tsig_algorithm(const ldns_resolver *r)
{
	return r->_tsig_algorithm;
}

char *
ldns_resolver_tsig_keydata(const ldns_resolver *r)
{
	return r->_tsig_keydata;
}

bool
ldns_resolver_random(const ldns_resolver *r)
{
	return r->_random;
}

size_t
ldns_resolver_searchlist_count(const ldns_resolver *r)
{
	return r->_searchlist_count;
}

/* write */
void
ldns_resolver_set_port(ldns_resolver *r, uint16_t p)
{
	r->_port = p;
}

ldns_rdf *
ldns_resolver_pop_nameserver(ldns_resolver *r)
{
	ldns_rdf **nameservers;
	ldns_rdf *pop;
	size_t ns_count;
	size_t *rtt;

	assert(r != NULL);

	ns_count = ldns_resolver_nameserver_count(r);
	nameservers = ldns_resolver_nameservers(r);
	rtt = ldns_resolver_rtt(r);
	if (ns_count == 0 || !nameservers) {
		return NULL;
	}
	
	pop = nameservers[ns_count - 1];

	nameservers = LDNS_XREALLOC(nameservers, ldns_rdf *, (ns_count - 1));
	rtt = LDNS_XREALLOC(rtt, size_t, (ns_count - 1));

	ldns_resolver_set_nameservers(r, nameservers);
	ldns_resolver_set_rtt(r, rtt);
	/* decr the count */
	ldns_resolver_dec_nameserver_count(r);
	return pop;
}

ldns_status
ldns_resolver_push_nameserver(ldns_resolver *r, ldns_rdf *n)
{
	ldns_rdf **nameservers;
	size_t ns_count;
	size_t *rtt;

	if (ldns_rdf_get_type(n) != LDNS_RDF_TYPE_A &&
			ldns_rdf_get_type(n) != LDNS_RDF_TYPE_AAAA) {
		return LDNS_STATUS_ERR;
	}

	ns_count = ldns_resolver_nameserver_count(r);
	nameservers = ldns_resolver_nameservers(r);
	rtt = ldns_resolver_rtt(r);

	/* make room for the next one */
	nameservers = LDNS_XREALLOC(nameservers, ldns_rdf *, (ns_count + 1));
	/* don't forget the rtt */
	rtt = LDNS_XREALLOC(rtt, size_t, (ns_count + 1));
	
	/* set the new value in the resolver */
	ldns_resolver_set_nameservers(r, nameservers);

	/* slide n in its slot. */
	/* we clone it here, because then we can free the original
	 * rr's where it stood */
	nameservers[ns_count] = ldns_rdf_clone(n);
	rtt[ns_count] = LDNS_RESOLV_RTT_MIN;
	ldns_resolver_incr_nameserver_count(r);
	ldns_resolver_set_rtt(r, rtt);
	return LDNS_STATUS_OK;
}

ldns_status
ldns_resolver_push_nameserver_rr(ldns_resolver *r, ldns_rr *rr)
{
	ldns_rdf *address;
	if ((!rr) || (ldns_rr_get_type(rr) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(rr) != LDNS_RR_TYPE_AAAA)) {
		return LDNS_STATUS_ERR;
	}
	address = ldns_rr_rdf(rr, 0); /* extract the ip number */
	if (address) {
		return ldns_resolver_push_nameserver(r, address);
	} else {
		return LDNS_STATUS_ERR;
	}
}

ldns_status
ldns_resolver_push_nameserver_rr_list(ldns_resolver *r, ldns_rr_list *rrlist)
{
	ldns_rr *rr;
	ldns_status stat;
	size_t i;

	stat = LDNS_STATUS_OK;
	if (rrlist) {
		for(i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
			rr = ldns_rr_list_rr(rrlist, i);
			if (ldns_resolver_push_nameserver_rr(r, rr) != LDNS_STATUS_OK) {
				stat = LDNS_STATUS_ERR;
			}
		}
		return stat;
	} else {
		return LDNS_STATUS_ERR;
	}
}

void
ldns_resolver_set_edns_udp_size(ldns_resolver *r, uint16_t s)
{
	        r->_edns_udp_size = s;
}

void
ldns_resolver_set_recursive(ldns_resolver *r, bool re)
{
	r->_recursive = re;
}

void
ldns_resolver_set_dnssec(ldns_resolver *r, bool d)
{
	r->_dnssec = d;
}

void
ldns_resolver_set_dnssec_cd(ldns_resolver *r, bool d)
{
	r->_dnssec_cd = d;
}

void
ldns_resolver_set_dnssec_anchors(ldns_resolver *r, ldns_rr_list * l)
{
  r->_dnssec_anchors = l;
}

ldns_status
ldns_resolver_push_dnssec_anchor(ldns_resolver *r, ldns_rr *rr)
{
  ldns_rr_list * trust_anchors;

  if ((!rr) || (ldns_rr_get_type(rr) != LDNS_RR_TYPE_DNSKEY)) {
    return LDNS_STATUS_ERR;
  }

  if (!(trust_anchors = ldns_resolver_dnssec_anchors(r))) { /* Initialize */
    trust_anchors = ldns_rr_list_new();
    ldns_resolver_set_dnssec_anchors(r, trust_anchors);
  }

  return (ldns_rr_list_push_rr(trust_anchors, ldns_rr_clone(rr))) ? LDNS_STATUS_OK : LDNS_STATUS_ERR;
}

void
ldns_resolver_set_igntc(ldns_resolver *r, bool i)
{
	r->_igntc = i;
}

void
ldns_resolver_set_usevc(ldns_resolver *r, bool vc)
{
	r->_usevc = vc;
}

void
ldns_resolver_set_debug(ldns_resolver *r, bool d)
{
	r->_debug = d;
}

void
ldns_resolver_set_ip6(ldns_resolver *r, uint8_t ip6)
{
	r->_ip6 = ip6;
}

void
ldns_resolver_set_fail(ldns_resolver *r, bool f)
{
	r->_fail =f;
}

void
ldns_resolver_set_searchlist_count(ldns_resolver *r, size_t c)
{
	r->_searchlist_count = c;
}

void
ldns_resolver_set_nameserver_count(ldns_resolver *r, size_t c)
{
	r->_nameserver_count = c;
}

void
ldns_resolver_set_dnsrch(ldns_resolver *r, bool d)
{
	r->_dnsrch = d;
}

void
ldns_resolver_set_retry(ldns_resolver *r, uint8_t retry)
{
	r->_retry = retry;
}

void
ldns_resolver_set_retrans(ldns_resolver *r, uint8_t retrans)
{
	r->_retrans = retrans;
}

void
ldns_resolver_set_fallback(ldns_resolver *r, bool fallback)
{
	r->_fallback = fallback;
}

void
ldns_resolver_set_nameservers(ldns_resolver *r, ldns_rdf **n)
{
	r->_nameservers = n;
}

void
ldns_resolver_set_defnames(ldns_resolver *r, bool d)
{
	r->_defnames = d;
}

void
ldns_resolver_set_rtt(ldns_resolver *r, size_t *rtt)
{
	r->_rtt = rtt;
}

void
ldns_resolver_set_nameserver_rtt(ldns_resolver *r, size_t pos, size_t value)
{
	size_t *rtt;

	assert(r != NULL);

	rtt = ldns_resolver_rtt(r);
	
	if (pos >= ldns_resolver_nameserver_count(r)) {
		/* error ?*/
	} else {
		rtt[pos] = value;
	}

}

void
ldns_resolver_incr_nameserver_count(ldns_resolver *r)
{
	size_t c;

	c = ldns_resolver_nameserver_count(r);
	ldns_resolver_set_nameserver_count(r, ++c);
}

void
ldns_resolver_dec_nameserver_count(ldns_resolver *r)
{
	size_t c;

	c = ldns_resolver_nameserver_count(r);
	if (c == 0) {
		return;
	} else {
		ldns_resolver_set_nameserver_count(r, --c);
	}
}

void
ldns_resolver_set_domain(ldns_resolver *r, ldns_rdf *d)
{
	r->_domain = d;
}

void
ldns_resolver_set_timeout(ldns_resolver *r, struct timeval timeout)
{
	r->_timeout.tv_sec = timeout.tv_sec;
	r->_timeout.tv_usec = timeout.tv_usec;
}

void
ldns_resolver_push_searchlist(ldns_resolver *r, ldns_rdf *d)
{
	ldns_rdf **searchlist;
	size_t list_count;

	if (ldns_rdf_get_type(d) != LDNS_RDF_TYPE_DNAME) {
		return;
	}

	list_count = ldns_resolver_searchlist_count(r);
	searchlist = ldns_resolver_searchlist(r);

	searchlist = LDNS_XREALLOC(searchlist, ldns_rdf *, (list_count + 1));
	if (searchlist) {
		r->_searchlist = searchlist;

		searchlist[list_count] = ldns_rdf_clone(d);
		ldns_resolver_set_searchlist_count(r, list_count + 1);
	}
}

void
ldns_resolver_set_tsig_keyname(ldns_resolver *r, char *tsig_keyname)
{
	r->_tsig_keyname = tsig_keyname;
}

void
ldns_resolver_set_tsig_algorithm(ldns_resolver *r, char *tsig_algorithm)
{
	r->_tsig_algorithm = tsig_algorithm;
}

void
ldns_resolver_set_tsig_keydata(ldns_resolver *r, char *tsig_keydata)
{
	r->_tsig_keydata = tsig_keydata;
}

void
ldns_resolver_set_random(ldns_resolver *r, bool b)
{
	r->_random = b;
}

/* more sophisticated functions */
ldns_resolver *
ldns_resolver_new(void)
{
	ldns_resolver *r;

	r = LDNS_MALLOC(ldns_resolver);
	if (!r) {
		return NULL;
	}

	r->_searchlist = NULL;
	r->_nameservers = NULL;
	r->_rtt = NULL;

	/* defaults are filled out */
	ldns_resolver_set_searchlist_count(r, 0);
	ldns_resolver_set_nameserver_count(r, 0);
	ldns_resolver_set_usevc(r, 0);
	ldns_resolver_set_port(r, LDNS_PORT);
	ldns_resolver_set_domain(r, NULL);
	ldns_resolver_set_defnames(r, false);
	ldns_resolver_set_retry(r, 3);
	ldns_resolver_set_retrans(r, 2);
	ldns_resolver_set_fallback(r, true);
	ldns_resolver_set_fail(r, false);
	ldns_resolver_set_edns_udp_size(r, 0);
	ldns_resolver_set_dnssec(r, false);
	ldns_resolver_set_dnssec_cd(r, false);
	ldns_resolver_set_dnssec_anchors(r, NULL);
	ldns_resolver_set_ip6(r, LDNS_RESOLV_INETANY);

	/* randomize the nameserver to be queried
	 * when there are multiple
	 */
	ldns_resolver_set_random(r, true);

	ldns_resolver_set_debug(r, 0);
	
	r->_timeout.tv_sec = LDNS_DEFAULT_TIMEOUT_SEC;
	r->_timeout.tv_usec = LDNS_DEFAULT_TIMEOUT_USEC;

	r->_socket = 0;
	r->_axfr_soa_count = 0;
	r->_axfr_i = 0;
	r->_cur_axfr_pkt = NULL;
	
	r->_tsig_keyname = NULL;
	r->_tsig_keydata = NULL;
	r->_tsig_algorithm = NULL;
	return r;
}

#ifdef _MSC_VER
ldns_status
ldns_resolver_new_default(ldns_resolver **res) {
	ldns_resolver *r;
	ldns_rdf *tmp;
	HKEY hKey;
	DWORD data_sz;
	char* buf;
	char* addr;

	RegOpenKeyEx(HKEY_LOCAL_MACHINE, 
		"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", 
		0, KEY_QUERY_VALUE, &hKey);

	RegQueryValueEx(hKey, "DhcpNameServer", NULL, NULL, NULL, &data_sz);
	buf = (char*)malloc(data_sz + 1);

	RegQueryValueEx(hKey, "DhcpNameServer", NULL, NULL, (LPBYTE)buf, &data_sz);

	RegCloseKey(hKey);

	if(buf[data_sz - 1] != 0) {
		buf[data_sz] = 0;
	}

	r = ldns_resolver_new();
	if(!r) {
		free(buf);
		return LDNS_STATUS_MEM_ERR;
	}

	addr = strtok(buf, " ");

	while(addr != NULL) {
		tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, addr);
		if (!tmp) {
			// try ip4
			tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, addr);
		}
		// could not parse it, exit 
		if (!tmp) {
			ldns_resolver_deep_free(r);
			free(buf);
			return LDNS_STATUS_SYNTAX_ERR;
		}
		(void)ldns_resolver_push_nameserver(r, tmp);
		ldns_rdf_deep_free(tmp);
		addr = strtok(NULL, " ");
	}

	free(buf);

	if(res) {
		*res = r;
		return LDNS_STATUS_OK;
	} else {
		return LDNS_STATUS_NULL;
	}
}
#else
ldns_status
ldns_resolver_new_default(ldns_resolver **res) {
	return ldns_resolver_new_frm_file(res, NULL);
}
#endif

ldns_status
ldns_resolver_new_frm_fp(ldns_resolver **res, FILE *fp)
{
	return ldns_resolver_new_frm_fp_l(res, fp, NULL);
}

ldns_status
ldns_resolver_new_frm_fp_l(ldns_resolver **res, FILE *fp, int *line_nr)
{
	ldns_resolver *r;
	const char *keyword[LDNS_RESOLV_KEYWORDS];
	char word[LDNS_MAX_LINELEN + 1];
	int8_t expect;
	uint8_t i;
	ldns_rdf *tmp;
#ifdef HAVE_SSL
	ldns_rr *tmp_rr;
#endif
	ssize_t gtr;
	ldns_buffer *b;

	/* do this better 
	 * expect = 
	 * 0: keyword
	 * 1: default domain dname
	 * 2: NS aaaa or a record
	 */

	/* recognized keywords */
	keyword[LDNS_RESOLV_NAMESERVER] = "nameserver";
	keyword[LDNS_RESOLV_DEFDOMAIN] = "domain";
	keyword[LDNS_RESOLV_SEARCH] = "search";
	/* these two are read but not used atm TODO */
	keyword[LDNS_RESOLV_SORTLIST] = "sortlist";
	keyword[LDNS_RESOLV_OPTIONS] = "options";
	keyword[LDNS_RESOLV_ANCHOR] = "anchor";
	expect = LDNS_RESOLV_KEYWORD;

	r = ldns_resolver_new();
	if (!r) {
		return LDNS_STATUS_MEM_ERR;
	}

	gtr = 1;
	word[0] = 0;
	while (gtr > 0) {
		/* check comments */
		if (word[0] == '#') {
			/* read the rest of the line, should be 1 word */
			gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
			/* prepare the next string for further parsing */
			gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
			continue;
		}
		switch(expect) {
			case LDNS_RESOLV_KEYWORD:
				/* keyword */
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
				if (gtr != 0) {
					for(i = 0; i < LDNS_RESOLV_KEYWORDS; i++) {
						if (strcasecmp(keyword[i], word) == 0) {
							/* chosen the keyword and
							 * expect values carefully
							 */
							expect = i;
							break;
						}
					}
					/* no keyword recognized */
					if (expect == LDNS_RESOLV_KEYWORD) {
						/* skip line */
						/*
						ldns_resolver_deep_free(r);
						return LDNS_STATUS_SYNTAX_KEYWORD_ERR;
						*/
					}
				}
				break;
			case LDNS_RESOLV_DEFDOMAIN:
				/* default domain dname */
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
				if (gtr == 0) {
					return LDNS_STATUS_SYNTAX_MISSING_VALUE_ERR;
				}
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, word);
				if (!tmp) {
					ldns_resolver_deep_free(r);
					return LDNS_STATUS_SYNTAX_DNAME_ERR;
				}

				/* DOn't free, because we copy the pointer */
				ldns_resolver_set_domain(r, tmp);
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_NAMESERVER:
				/* NS aaaa or a record */
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
				if (gtr == 0) {
					return LDNS_STATUS_SYNTAX_MISSING_VALUE_ERR;
				}
				tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, word);
				if (!tmp) {
					/* try ip4 */
					tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, word);
				}
				/* could not parse it, exit */
				if (!tmp) {
					ldns_resolver_deep_free(r);
					return LDNS_STATUS_SYNTAX_ERR;
				}
				(void)ldns_resolver_push_nameserver(r, tmp);
				ldns_rdf_deep_free(tmp);
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_SEARCH:
				/* search list domain dname */
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_SKIP_SPACE, 0, line_nr);
				b = LDNS_MALLOC(ldns_buffer);
				ldns_buffer_new_frm_data(b, word, (size_t) gtr);

				gtr = ldns_bget_token(b, word, LDNS_PARSE_NORMAL, (size_t) gtr);
				while (gtr > 0) {
					tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, word);
					if (!tmp) {
						ldns_resolver_deep_free(r);
						return LDNS_STATUS_SYNTAX_DNAME_ERR;
					}

					ldns_resolver_push_searchlist(r, tmp); 

					ldns_rdf_deep_free(tmp);
					gtr = ldns_bget_token(b, word, LDNS_PARSE_NORMAL, (size_t) gtr);
				}
				ldns_buffer_free(b);
				gtr = 1;
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_SORTLIST:
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_SKIP_SPACE, 0, line_nr);
				/* sortlist not implemented atm */
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_OPTIONS:
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_SKIP_SPACE, 0, line_nr);
				/* options not implemented atm */
				expect = LDNS_RESOLV_KEYWORD;
				break;
			case LDNS_RESOLV_ANCHOR:
				/* a file containing a DNSSEC trust anchor */
				gtr = ldns_fget_token_l(fp, word, LDNS_PARSE_NORMAL, 0, line_nr);
				if (gtr == 0) {
					return LDNS_STATUS_SYNTAX_MISSING_VALUE_ERR;
				}

#ifdef HAVE_SSL
				tmp_rr = ldns_read_anchor_file(word);
				(void) ldns_resolver_push_dnssec_anchor(r, tmp_rr);
				ldns_rr_free(tmp_rr);
#endif
				expect = LDNS_RESOLV_KEYWORD;
				break;
		}
	}
	
	if (res) {
		*res = r;
		return LDNS_STATUS_OK;
	} else {
		return LDNS_STATUS_NULL;
	}
}

ldns_status
ldns_resolver_new_frm_file(ldns_resolver **res, const char *filename)
{
	ldns_resolver *r;
	FILE *fp;
	ldns_status s;

	if (!filename) {
		fp = fopen(LDNS_RESOLV_CONF, "r");

	} else {
		fp = fopen(filename, "r");
	}
	if (!fp) {
		return LDNS_STATUS_FILE_ERR;
	}

	s = ldns_resolver_new_frm_fp(&r, fp);
	fclose(fp);
	if (s == LDNS_STATUS_OK) {
		if (res) {
			*res = r;
			return LDNS_STATUS_OK;
		} else  {
			return LDNS_STATUS_NULL;
		}
	}
	return s;
}

void
ldns_resolver_free(ldns_resolver *res)
{
	LDNS_FREE(res);
}

void
ldns_resolver_deep_free(ldns_resolver *res)
{
	size_t i;
	
	if (res) {
		if (res->_searchlist) {
			for (i = 0; i < ldns_resolver_searchlist_count(res); i++) {
				ldns_rdf_deep_free(res->_searchlist[i]);
			}
			LDNS_FREE(res->_searchlist);
		}
		if (res->_nameservers) {
			for (i = 0; i < res->_nameserver_count; i++) {
				ldns_rdf_deep_free(res->_nameservers[i]);
			}
			LDNS_FREE(res->_nameservers);
		}
		if (ldns_resolver_domain(res)) {
			ldns_rdf_deep_free(ldns_resolver_domain(res));
		}
		if (ldns_resolver_tsig_keyname(res)) {
			LDNS_FREE(res->_tsig_keyname);
		}
		
		if (res->_cur_axfr_pkt) {
			ldns_pkt_free(res->_cur_axfr_pkt);
		}
		
		if (res->_rtt) {
			LDNS_FREE(res->_rtt);
		}
		if (res->_dnssec_anchors) {
			ldns_rr_list_deep_free(res->_dnssec_anchors);
		}
		LDNS_FREE(res);
	}
}

ldns_pkt *
ldns_resolver_search(const ldns_resolver *r,const  ldns_rdf *name, ldns_rr_type type, 
                ldns_rr_class c, uint16_t flags)
{

	char *str_dname;
	ldns_rdf *new_name;
	ldns_rdf **search_list;
	size_t i;
	ldns_pkt *p;

	str_dname = ldns_rdf2str(name);

	if (ldns_dname_str_absolute(str_dname)) {
		/* query as-is */
		return ldns_resolver_query(r, name, type, c, flags);
	} else {
		search_list = ldns_resolver_searchlist(r);
		for (i = 0; i < ldns_resolver_searchlist_count(r); i++) {
			new_name = ldns_dname_cat_clone(name, search_list[i]);

			p = ldns_resolver_query(r, new_name, type, c, flags);
			ldns_rdf_free(new_name);
			if (p) {
				return p;
			}
		}
	}
	return NULL;
}

ldns_pkt *
ldns_resolver_query(const ldns_resolver *r, const ldns_rdf *name, ldns_rr_type type, 
		ldns_rr_class c, uint16_t flags)
{
	ldns_rdf *newname;
	ldns_pkt *pkt;
	ldns_status status;

	pkt = NULL;

	if (!ldns_resolver_defnames(r)) {
		status = ldns_resolver_send(&pkt, (ldns_resolver *)r, name, type, c, 
				flags);
		if (status == LDNS_STATUS_OK) {
			return pkt;
		} else {
			if (pkt) {
				ldns_pkt_free(pkt);
			}
			fprintf(stderr, "error: %s\n", ldns_get_errorstr_by_id(status));
			return NULL;
		}
	}

	if (!ldns_resolver_domain(r)) {
		/* _defnames is set, but the domain is not....?? */
		status = ldns_resolver_send(&pkt, (ldns_resolver *)r, name, type, c, 
				flags);
		if (status == LDNS_STATUS_OK) {
			return pkt;
		} else {
			if (pkt) {
				ldns_pkt_free(pkt);
			}
			return NULL;
		}
	}

	newname = ldns_dname_cat_clone((const ldns_rdf*)name, ldns_resolver_domain(r));
	if (!newname) {
		if (pkt) {
			ldns_pkt_free(pkt);
		}
		return NULL;
	}
	status = ldns_resolver_send(&pkt, (ldns_resolver *)r, newname, type, c, 
			flags);

	ldns_rdf_free(newname);

	return pkt;
}

ldns_status
ldns_resolver_send_pkt(ldns_pkt **answer, ldns_resolver *r, 
				   ldns_pkt *query_pkt)
{
	ldns_pkt *answer_pkt = NULL;
	ldns_status stat = LDNS_STATUS_OK;

	stat = ldns_send(&answer_pkt, (ldns_resolver *)r, query_pkt);
	if (stat != LDNS_STATUS_OK) {
		if(answer_pkt) {
			ldns_pkt_free(answer_pkt);
			answer_pkt = NULL;
		}
	} else {
	
		/* if tc=1 fall back to EDNS and/or TCP */
		/* check for tcp first (otherwise we don't care about tc=1) */
		if (!ldns_resolver_usevc(r) && ldns_resolver_fallback(r)) {
			if (ldns_pkt_tc(answer_pkt)) {
				/* was EDNS0 set? */
				if (ldns_pkt_edns_udp_size(query_pkt) == 0) {
					ldns_pkt_set_edns_udp_size(query_pkt, 4096);
					ldns_pkt_free(answer_pkt);
					stat = ldns_send(&answer_pkt, r, query_pkt);
				}
				/* either way, if it is still truncated, use TCP */
				if (stat != LDNS_STATUS_OK ||
				    ldns_pkt_tc(answer_pkt)) {
					ldns_resolver_set_usevc(r, true);
					ldns_pkt_free(answer_pkt);
					stat = ldns_send(&answer_pkt, r, query_pkt);
					ldns_resolver_set_usevc(r, false);
				}
			}
		}
	}


	if (answer) {
		*answer = answer_pkt;
	}

	return stat;
}

ldns_status
ldns_resolver_prepare_query_pkt(ldns_pkt **query_pkt, ldns_resolver *r,
                                const ldns_rdf *name, ldns_rr_type type, 
                                ldns_rr_class c, uint16_t flags)
{
	/* prepare a question pkt from the parameters
	 * and then send this */
	*query_pkt = ldns_pkt_query_new(ldns_rdf_clone(name), type, c, flags);
	if (!*query_pkt) {
		return LDNS_STATUS_ERR;
	}

	/* set DO bit if necessary */
	if (ldns_resolver_dnssec(r)) {
		if (ldns_resolver_edns_udp_size(r) == 0) {
			ldns_resolver_set_edns_udp_size(r, 4096);
		}
		ldns_pkt_set_edns_do(*query_pkt, true);
		if (ldns_resolver_dnssec_cd(r) || (flags & LDNS_CD)) {
			ldns_pkt_set_cd(*query_pkt, true);
		}
	}

	/* transfer the udp_edns_size from the resolver to the packet */
	if (ldns_resolver_edns_udp_size(r) != 0) {
		ldns_pkt_set_edns_udp_size(*query_pkt, ldns_resolver_edns_udp_size(r));
	}

	if (ldns_resolver_debug(r)) {
		ldns_pkt_print(stdout, *query_pkt);
	}
	
	/* only set the id if it is not set yet */
	if (ldns_pkt_id(*query_pkt) == 0) {
		ldns_pkt_set_random_id(*query_pkt);
	}

	return LDNS_STATUS_OK;
}


ldns_status
ldns_resolver_send(ldns_pkt **answer, ldns_resolver *r, const ldns_rdf *name, 
		ldns_rr_type type, ldns_rr_class c, uint16_t flags)
{
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
	ldns_status status;

	assert(r != NULL);
	assert(name != NULL);

	answer_pkt = NULL;
	
	/* do all the preprocessing here, then fire of an query to 
	 * the network */

	if (0 == type) {
		type = LDNS_RR_TYPE_A;
	}
	if (0 == c) {
		c = LDNS_RR_CLASS_IN;
	}
	if (0 == ldns_resolver_nameserver_count(r)) {
		return LDNS_STATUS_RES_NO_NS;
	}
	if (ldns_rdf_get_type(name) != LDNS_RDF_TYPE_DNAME) {
		return LDNS_STATUS_RES_QUERY;
	}

	status = ldns_resolver_prepare_query_pkt(&query_pkt,
	                                         r,
	                                         name,
	                                         type,
	                                         c,
	                                         flags);
	if (status != LDNS_STATUS_OK) {
		return status;
	}

	/* if tsig values are set, tsign it */
	/* TODO: make last 3 arguments optional too? maybe make complete
	         rr instead of seperate values in resolver (and packet)
	  Jelte
	  should this go in pkt_prepare?
	*/
#ifdef HAVE_SSL
	if (ldns_resolver_tsig_keyname(r) && ldns_resolver_tsig_keydata(r)) {
		status = ldns_pkt_tsig_sign(query_pkt,
		                            ldns_resolver_tsig_keyname(r),
		                            ldns_resolver_tsig_keydata(r),
		                            300, ldns_resolver_tsig_algorithm(r), NULL);
		if (status != LDNS_STATUS_OK) {
			return LDNS_STATUS_CRYPTO_TSIG_ERR;
		}
	}
#endif /* HAVE_SSL */
	status = ldns_resolver_send_pkt(&answer_pkt, r, query_pkt);
	ldns_pkt_free(query_pkt);
	
	/* allows answer to be NULL when not interested in return value */
	if (answer) {
		*answer = answer_pkt;
	}
	return status;
}

ldns_rr *
ldns_axfr_next(ldns_resolver *resolver)
{
	ldns_rr *cur_rr;
	uint8_t *packet_wire;
	size_t packet_wire_size;
	ldns_lookup_table *rcode;
	ldns_status status;
	
	/* check if start() has been called */
	if (!resolver || resolver->_socket == 0) {
		return NULL;
	}
	
	if (resolver->_cur_axfr_pkt) {
		if (resolver->_axfr_i == ldns_pkt_ancount(resolver->_cur_axfr_pkt)) {
			ldns_pkt_free(resolver->_cur_axfr_pkt);
			resolver->_cur_axfr_pkt = NULL;
			return ldns_axfr_next(resolver);
		}
		cur_rr = ldns_rr_clone(ldns_rr_list_rr(
					ldns_pkt_answer(resolver->_cur_axfr_pkt), 
					resolver->_axfr_i));
		resolver->_axfr_i++;
		if (ldns_rr_get_type(cur_rr) == LDNS_RR_TYPE_SOA) {
			resolver->_axfr_soa_count++;
			if (resolver->_axfr_soa_count >= 2) {
				close(resolver->_socket);
				resolver->_socket = 0;
				ldns_pkt_free(resolver->_cur_axfr_pkt);
				resolver->_cur_axfr_pkt = NULL;
			}
		}
		return cur_rr;
	} else {
		packet_wire = ldns_tcp_read_wire(resolver->_socket, &packet_wire_size);
		if(!packet_wire) 
			return NULL;
		
		status = ldns_wire2pkt(&resolver->_cur_axfr_pkt, packet_wire, 
				     packet_wire_size);
		free(packet_wire);

		resolver->_axfr_i = 0;
		if (status != LDNS_STATUS_OK) {
			/* TODO: make status return type of this function (...api change) */
			fprintf(stderr, "Error parsing rr during AXFR: %s\n", ldns_get_errorstr_by_id(status));
			return NULL;
		} else if (ldns_pkt_get_rcode(resolver->_cur_axfr_pkt) != 0) {
			rcode = ldns_lookup_by_id(ldns_rcodes, (int) ldns_pkt_get_rcode(resolver->_cur_axfr_pkt));
			fprintf(stderr, "Error in AXFR: %s\n", rcode->name);
			return NULL;
		} else {
			return ldns_axfr_next(resolver);
		}
		
	}
	
}

bool
ldns_axfr_complete(const ldns_resolver *res) 
{
	/* complete when soa count is 2? */
	return res->_axfr_soa_count == 2;
}

ldns_pkt *
ldns_axfr_last_pkt(const ldns_resolver *res) 
{
	return res->_cur_axfr_pkt;
}

/* random isn't really that good */
void
ldns_resolver_nameservers_randomize(ldns_resolver *r)
{
	uint8_t i, j;
	ldns_rdf **ns, *tmp;

	/* should I check for ldns_resolver_random?? */
	assert(r != NULL);

	ns = ldns_resolver_nameservers(r);
	
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		j = random() % ldns_resolver_nameserver_count(r);
		tmp = ns[i];
		ns[i] = ns[j];
		ns[j] = tmp;
	}
	ldns_resolver_set_nameservers(r, ns);
}

