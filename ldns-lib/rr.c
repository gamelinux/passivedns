/* rr.c
 *
 * access functions for ldns_rr - 
 * a Net::DNS like library for C
 * LibDNS Team @ NLnet Labs
 * 
 * (c) NLnet Labs, 2004-2006
 * See the file LICENSE for the license
 */
#include <ldns/config.h>

#include <ldns/ldns.h>

#ifdef _MSC_VER
#include <string.h>
#else
#include <strings.h>
#endif
#include <limits.h>

#include <errno.h>

#define LDNS_SYNTAX_DATALEN 16
#define LDNS_TTL_DATALEN    21
#define LDNS_RRLIST_INIT    8

ldns_rr *
ldns_rr_new(void)
{
	ldns_rr *rr;
	rr = LDNS_MALLOC(ldns_rr);
        if (!rr) {
                return NULL;
	}
	
	ldns_rr_set_owner(rr, NULL);
	ldns_rr_set_rd_count(rr, 0);
	rr->_rdata_fields = NULL; 
	ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
	ldns_rr_set_ttl(rr, LDNS_DEFAULT_TTL);
        return rr;
}

ldns_rr *
ldns_rr_new_frm_type(ldns_rr_type t)
{
	ldns_rr *rr;
	const ldns_rr_descriptor *desc;
	size_t i;

	rr = LDNS_MALLOC(ldns_rr);
        if (!rr) {
                return NULL;
	}
	
	desc = ldns_rr_descript(t);

	rr->_rdata_fields = LDNS_XMALLOC(ldns_rdf *, ldns_rr_descriptor_minimum(desc));
	for (i = 0; i < ldns_rr_descriptor_minimum(desc); i++) {
		rr->_rdata_fields[i] = NULL;
	}
	
	/* set the count to minimum */
	ldns_rr_set_rd_count(rr, ldns_rr_descriptor_minimum(desc));
	ldns_rr_set_class(rr, LDNS_RR_CLASS_IN);
	ldns_rr_set_ttl(rr, LDNS_DEFAULT_TTL);
	ldns_rr_set_type(rr, t);
	return rr;
}

void
ldns_rr_free(ldns_rr *rr)
{
	size_t i;
	if (rr) {
		if (ldns_rr_owner(rr)) {
			ldns_rdf_deep_free(ldns_rr_owner(rr));
		}
		for (i = 0; i < ldns_rr_rd_count(rr); i++) {
			ldns_rdf_deep_free(ldns_rr_rdf(rr, i));
		}
		LDNS_FREE(rr->_rdata_fields);
		LDNS_FREE(rr);
	}
}

/* 
 * trailing spaces are allowed
 * leading spaces are not allowed
 * allow ttl to be optional
 * class is optional too
 * if ttl is missing, and default_ttl is 0, use DEF_TTL
 * allow ttl to be written as 1d3h
 * So the RR should look like. e.g.
 * miek.nl. 3600 IN MX 10 elektron.atoom.net
 * or
 * miek.nl. 1h IN MX 10 elektron.atoom.net
 * or
 * miek.nl. IN MX 10 elektron.atoom.net
 */
static ldns_status
ldns_rr_new_frm_str_internal(ldns_rr **newrr, const char *str,
                             uint32_t default_ttl, ldns_rdf *origin, 
		             ldns_rdf **prev, bool question)
{
	ldns_rr *new;
	const ldns_rr_descriptor *desc;
	ldns_rr_type rr_type;
	ldns_buffer *rr_buf;
	ldns_buffer *rd_buf;
	uint32_t ttl_val;
	char  *owner; 
	char  *ttl; 
	ldns_rr_class clas_val;
	char  *clas;
	char  *type = NULL;
	char  *rdata;
	char  *rd;
	char  *b64;
	size_t rd_strlen;
	const char *delimiters;
	ssize_t c;
	ldns_rdf *owner_dname;
	
	/* used for types with unknown number of rdatas */
	bool done;
	bool quoted;
		
	ldns_rdf *r = NULL;
	uint16_t r_cnt;
	uint16_t r_min;
	uint16_t r_max;

	uint16_t hex_data_size;
	char *hex_data_str;
	uint16_t cur_hex_data_size;
	uint8_t *hex_data;
	size_t hex_pos;

	new = ldns_rr_new();

	owner = LDNS_XMALLOC(char, LDNS_MAX_DOMAINLEN + 1);
	ttl = LDNS_XMALLOC(char, LDNS_TTL_DATALEN);
	clas = LDNS_XMALLOC(char, LDNS_SYNTAX_DATALEN);
	rdata = LDNS_XMALLOC(char, LDNS_MAX_PACKETLEN + 1);
	rr_buf = LDNS_MALLOC(ldns_buffer);
	rd_buf = LDNS_MALLOC(ldns_buffer);
	rd = LDNS_XMALLOC(char, LDNS_MAX_RDFLEN);
	b64 = LDNS_XMALLOC(char, LDNS_MAX_RDFLEN);
	if (!new || !owner || !ttl || !clas || !rdata || !rr_buf || !rd_buf || !rd || !b64 ) {
		return LDNS_STATUS_MEM_ERR;
	}
	r_cnt = 0;
	ttl_val = 0;
	clas_val = 0;

	ldns_buffer_new_frm_data(rr_buf, (char*)str, strlen(str));
	
	/* split the rr in its parts -1 signals trouble */
	if (ldns_bget_token(rr_buf, owner, "\t\n ", LDNS_MAX_DOMAINLEN) == -1) {
		LDNS_FREE(owner); 
		LDNS_FREE(ttl); 
		LDNS_FREE(clas); 
		LDNS_FREE(rdata);
		LDNS_FREE(rd);
		LDNS_FREE(rd_buf);
		LDNS_FREE(b64);
		ldns_buffer_free(rr_buf);
		ldns_rr_free(new);
		return LDNS_STATUS_SYNTAX_ERR;
	}
	
	if (ldns_bget_token(rr_buf, ttl, "\t\n ", LDNS_TTL_DATALEN) == -1) {
		LDNS_FREE(owner); 
		LDNS_FREE(ttl); 
		LDNS_FREE(clas); 
		LDNS_FREE(rdata);
		LDNS_FREE(rd);
		LDNS_FREE(rd_buf);
		LDNS_FREE(b64);
		ldns_buffer_free(rr_buf);
		ldns_rr_free(new);
		return LDNS_STATUS_SYNTAX_TTL_ERR;
	}
	ttl_val = (uint32_t) strtol(ttl, NULL, 10);

	if (strlen(ttl) > 0 && !isdigit((int) ttl[0])) {
		/* ah, it's not there or something */
		if (default_ttl == 0) {
			ttl_val = LDNS_DEFAULT_TTL;
		} else {
			ttl_val = default_ttl;
		}
		/* we not ASSUMING the TTL is missing and that
		 * the rest of the RR is still there. That is
		 * CLASS TYPE RDATA 
		 * so ttl value we read is actually the class
		 */
		clas_val = ldns_get_rr_class_by_name(ttl);
		/* class can be left out too, assume IN, current
		 * token must be type
		 */
		if (clas_val == 0) {
			clas_val = LDNS_RR_CLASS_IN;
			type = LDNS_XMALLOC(char, strlen(ttl) + 1);
			strncpy(type, ttl, strlen(ttl) + 1);
		}
	} else {
		if (ldns_bget_token(rr_buf, clas, "\t\n ", LDNS_SYNTAX_DATALEN) == -1) {
			LDNS_FREE(owner); 
			LDNS_FREE(ttl); 
			LDNS_FREE(clas); 
			LDNS_FREE(rdata);
			LDNS_FREE(rd);
			LDNS_FREE(rd_buf);
			ldns_buffer_free(rr_buf);
			ldns_rr_free(new);
			return LDNS_STATUS_SYNTAX_CLASS_ERR;
		}
		clas_val = ldns_get_rr_class_by_name(clas);
		/* class can be left out too, assume IN, current
		 * token must be type
		 */
		if (clas_val == 0) {
			clas_val = LDNS_RR_CLASS_IN;
			type = LDNS_XMALLOC(char, strlen(clas) + 1);
			strncpy(type, clas, strlen(clas) + 1);
		}
	}
	/* the rest should still be waiting for us */

	if (!type) {
		type = LDNS_XMALLOC(char, LDNS_SYNTAX_DATALEN);
		if (ldns_bget_token(rr_buf, type, "\t\n ", LDNS_SYNTAX_DATALEN) == -1) {
			LDNS_FREE(owner); 
			LDNS_FREE(ttl); 
			LDNS_FREE(clas); 
			LDNS_FREE(rdata);
			LDNS_FREE(rd);
			LDNS_FREE(rd_buf);
			ldns_buffer_free(rr_buf);
			ldns_rr_free(new);
			return LDNS_STATUS_SYNTAX_TYPE_ERR;
		}
	}
	
	if (ldns_bget_token(rr_buf, rdata, "\0", LDNS_MAX_PACKETLEN) == -1) {
		/* apparently we are done, and it's only a question RR
		 * so do not free and error here
		LDNS_FREE(owner); 
		LDNS_FREE(ttl); 
		LDNS_FREE(clas); 
		LDNS_FREE(type);
		LDNS_FREE(rdata);
		LDNS_FREE(rd);
		LDNS_FREE(rd_buf);
		ldns_buffer_free(rr_buf);
		ldns_rr_free(new);
		return NULL;
		*/
	}

	ldns_buffer_new_frm_data(rd_buf, rdata, strlen(rdata));

	if (strlen(owner) <= 1 && strncmp(owner, "@", 1) == 0) {
		if (origin) {
			ldns_rr_set_owner(new, ldns_rdf_clone(origin));
		} else if (prev && *prev) {
			ldns_rr_set_owner(new, ldns_rdf_clone(*prev));			
		} else {
			/* default to root */
			ldns_rr_set_owner(new, ldns_dname_new_frm_str("."));
		}
	} else {
		if (strlen(owner) == 0) {
			/* no ownername was given, try prev, if that fails 
			 * origin, else default to root */
			if (prev && *prev) {
				ldns_rr_set_owner(new, ldns_rdf_clone(*prev));
			} else if (origin) {
				ldns_rr_set_owner(new, ldns_rdf_clone(origin));
			} else {
				ldns_rr_set_owner(new, ldns_dname_new_frm_str("."));
			}
		} else {
			owner_dname = ldns_dname_new_frm_str(owner);
			if (!owner_dname) {
					LDNS_FREE(owner); 
					LDNS_FREE(ttl); 
					LDNS_FREE(clas); 
					LDNS_FREE(type);
					LDNS_FREE(rdata);
					LDNS_FREE(rd);
					LDNS_FREE(rd_buf);
					ldns_buffer_free(rr_buf);
					ldns_rr_free(new);
					return LDNS_STATUS_SYNTAX_ERR;
			}
			
			ldns_rr_set_owner(new, owner_dname);
			if (!ldns_dname_str_absolute(owner) && origin) {
				if(ldns_dname_cat(ldns_rr_owner(new), 
							origin) != LDNS_STATUS_OK) {
					LDNS_FREE(owner); 
					LDNS_FREE(ttl); 
					LDNS_FREE(clas); 
					LDNS_FREE(type);
					LDNS_FREE(rdata);
					LDNS_FREE(rd);
					LDNS_FREE(rd_buf);
					ldns_buffer_free(rr_buf);
					ldns_rr_free(new);
					return LDNS_STATUS_SYNTAX_ERR;
				} 
			}
			if (prev) {
				ldns_rdf_deep_free(*prev);
				*prev = ldns_rdf_clone(ldns_rr_owner(new));
			}
		}
	}
	LDNS_FREE(owner);

	ldns_rr_set_ttl(new, ttl_val);
	LDNS_FREE(ttl);

	ldns_rr_set_class(new, clas_val);
	LDNS_FREE(clas);

	rr_type = ldns_get_rr_type_by_name(type);
	LDNS_FREE(type);

	desc = ldns_rr_descript((uint16_t)rr_type);
	ldns_rr_set_type(new, rr_type);
	if (desc) {
		/* only the rdata remains */
		r_max = ldns_rr_descriptor_maximum(desc);
		r_min = ldns_rr_descriptor_minimum(desc);
	} else {
		r_min = 1;
		r_max = 1;
	}

	/* depending on the rr_type we need to extract
	 * the rdata differently, e.g. NSEC/NSEC3 */
	switch(rr_type) {
		default:
			done = false;

			for (r_cnt = 0; !done && r_cnt < r_max; 
					r_cnt++) {
				quoted = false;
				/* if type = B64, the field may contain spaces */
				if (ldns_rr_descriptor_field_type(desc, 
					    r_cnt) == LDNS_RDF_TYPE_B64 ||
				    ldns_rr_descriptor_field_type(desc, 
					    r_cnt) == LDNS_RDF_TYPE_HEX ||
				    ldns_rr_descriptor_field_type(desc, 
					    r_cnt) == LDNS_RDF_TYPE_LOC ||
				    ldns_rr_descriptor_field_type(desc, 
					    r_cnt) == LDNS_RDF_TYPE_WKS ||
				    ldns_rr_descriptor_field_type(desc, 
					    r_cnt) == LDNS_RDF_TYPE_NSEC ||
				    ldns_rr_descriptor_field_type(desc, 
					    r_cnt) == LDNS_RDF_TYPE_STR) {
					delimiters = "\n\t";
				} else {
					delimiters = "\n\t ";
				}

				if (ldns_rr_descriptor_field_type(desc, 
							r_cnt) == LDNS_RDF_TYPE_STR &&
                                    ldns_buffer_remaining(rd_buf) > 0
							) {
					/* skip spaces */
					while (*(ldns_buffer_current(rd_buf)) == ' ') {
						ldns_buffer_skip(rd_buf, 1);
					}

					if (*(ldns_buffer_current(rd_buf)) == '\"') {
						delimiters = "\"\0";
						ldns_buffer_skip(rd_buf, 1);
					}

					quoted = true;
				}

				/* because number of fields can be variable, we can't
				   rely on _maximum() only */
				/* skip spaces */
				while (ldns_buffer_position(rd_buf) < ldns_buffer_limit(rd_buf) &&
					*(ldns_buffer_current(rd_buf)) == ' ' 
				      ) {
					ldns_buffer_skip(rd_buf, 1);
				}

				if ((c = ldns_bget_token(rd_buf, rd, delimiters, 
							LDNS_MAX_RDFLEN)) != -1) {
					/* hmmz, rfc3597 specifies that any type can be represented with
					 * \# method, which can contain spaces...
					 * it does specify size though... 
					 */
					rd_strlen = strlen(rd);

					/* unknown RR data */
					if (rd_strlen == 2 && strncmp(rd, "\\#", 2) == 0 && !quoted) {
						c = ldns_bget_token(rd_buf, rd, delimiters, LDNS_MAX_RDFLEN);
						if (c == -1) {
							/* something goes very wrong here */
							ldns_buffer_free(rd_buf);
							LDNS_FREE(rd);
							return LDNS_STATUS_SYNTAX_RDATA_ERR;
						}
						hex_data_size = (uint16_t) atoi(rd);
						/* copy the hex chars into hex str (which is 2 chars per byte) */
						hex_data_str = LDNS_XMALLOC(char, 2 * hex_data_size + 1);
						if (!hex_data_str) {
							/* malloc error */
							ldns_buffer_free(rd_buf);
							LDNS_FREE(rd);
							return LDNS_STATUS_SYNTAX_RDATA_ERR;
						}
						cur_hex_data_size = 0;
						while(cur_hex_data_size < 2 * hex_data_size) {
							c = ldns_bget_token(rd_buf, rd, delimiters, LDNS_MAX_RDFLEN);
							rd_strlen = strlen(rd);
							strncpy(hex_data_str + cur_hex_data_size, rd, rd_strlen);
							cur_hex_data_size += rd_strlen;
						}
						hex_data_str[cur_hex_data_size] = '\0';

						/* correct the rdf type */
						/* if *we* know the type, interpret it as wireformat */
						if (desc) {
							hex_data = LDNS_XMALLOC(uint8_t, hex_data_size + 2);
							ldns_write_uint16(hex_data, hex_data_size);
							ldns_hexstring_to_data(hex_data + 2, hex_data_str);
							hex_pos = 0;
							(void) ldns_wire2rdf(new, hex_data,
							                 hex_data_size+2, &hex_pos);
							LDNS_FREE(hex_data);
						} else {
							r = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_HEX, hex_data_str);
							ldns_rdf_set_type(r, LDNS_RDF_TYPE_UNKNOWN);
							ldns_rr_push_rdf(new, r);
						}
						LDNS_FREE(hex_data_str);
					} else {
						/* Normal RR */
						switch(ldns_rr_descriptor_field_type(desc, r_cnt)) {
						case LDNS_RDF_TYPE_HEX:
						case LDNS_RDF_TYPE_B64:
							/* can have spaces, and will always be the last 
							 * record of the rrdata. Read in the rest */
							if ((c = ldns_bget_token(rd_buf,
												b64,
												"\n",
												LDNS_MAX_RDFLEN))
							    != -1) {
								rd = strncat(rd,
										   b64,
										   LDNS_MAX_RDFLEN
										   - strlen(rd) - 1);
							}
							r = ldns_rdf_new_frm_str(
									ldns_rr_descriptor_field_type(desc, r_cnt),
									rd);
							break;
						case LDNS_RDF_TYPE_DNAME:
							r = ldns_rdf_new_frm_str(
									ldns_rr_descriptor_field_type(desc, r_cnt),
									rd);

							/* check if the origin should be used or concatenated */
							if (ldns_rdf_size(r) > 1 && ldns_rdf_data(r)[0] == 1 
								&& ldns_rdf_data(r)[1] == '@') {
								ldns_rdf_deep_free(r);
								if (origin) {
									r = ldns_rdf_clone(origin);
								} else {
								     /* if this is the SOA, use its own owner name */
									if (rr_type == LDNS_RR_TYPE_SOA) {
										r = ldns_rdf_clone(ldns_rr_owner(new));
									} else {
										r = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, ".");
									}
								}
							} else if (rd_strlen >= 1 && !ldns_dname_str_absolute(rd) && origin) {
								if (ldns_dname_cat(r, origin) != LDNS_STATUS_OK) {
									return LDNS_STATUS_ERR;
								}
							}
							break;
						default:
							r = ldns_rdf_new_frm_str(
									ldns_rr_descriptor_field_type(desc, r_cnt),
									rd);
							break;
						}
						if (r) {
							ldns_rr_push_rdf(new, r);
						} else {
							LDNS_FREE(rd);
							LDNS_FREE(b64);
							ldns_buffer_free(rd_buf);
							ldns_buffer_free(rr_buf);
							LDNS_FREE(rdata);
							ldns_rr_free(new);
							return LDNS_STATUS_SYNTAX_RDATA_ERR;
						}
					}
					if (quoted) {
						if (ldns_buffer_available(rd_buf, 1)) {
							ldns_buffer_skip(rd_buf, 1);
						} else {
							done = true;
						}
					}
				} else {
					done = true;
				}
			}
	}
	LDNS_FREE(rd);
	LDNS_FREE(b64);
	ldns_buffer_free(rd_buf);
	ldns_buffer_free(rr_buf);
	LDNS_FREE(rdata);

	if (!question && desc && ldns_rr_rd_count(new) < r_min) {
		ldns_rr_free(new);
		return LDNS_STATUS_SYNTAX_MISSING_VALUE_ERR;
	}

	if (newrr) {
		*newrr = new;
	}
	return LDNS_STATUS_OK;
}

ldns_status
ldns_rr_new_frm_str(ldns_rr **newrr, const char *str,
                    uint32_t default_ttl, ldns_rdf *origin, 
		    ldns_rdf **prev)
{
	return ldns_rr_new_frm_str_internal(newrr,
	                                    str,
	                                    default_ttl,
	                                    origin,
	                                    prev,
	                                    false);
}

ldns_status
ldns_rr_new_question_frm_str(ldns_rr **newrr, const char *str,
                             ldns_rdf *origin, ldns_rdf **prev)
{
	return ldns_rr_new_frm_str_internal(newrr,
	                                    str,
	                                    0,
	                                    origin,
	                                    prev,
	                                    true);
}

ldns_status
ldns_rr_new_frm_fp(ldns_rr **newrr, FILE *fp, uint32_t *ttl, ldns_rdf **origin, ldns_rdf **prev)
{
	return ldns_rr_new_frm_fp_l(newrr, fp, ttl, origin, prev, NULL);
}

ldns_status
ldns_rr_new_frm_fp_l(ldns_rr **newrr, FILE *fp, uint32_t *default_ttl, ldns_rdf **origin, ldns_rdf **prev, int *line_nr)
{
	char *line;
	const char *endptr;  /* unused */
	ldns_rr *rr;
	char *keyword;
	uint32_t ttl;
	ldns_rdf *tmp;
	ldns_status s;
	ssize_t size;

	s = LDNS_STATUS_ERR;
	if (default_ttl) {
		ttl = *default_ttl;
	} else {
		ttl = 0;
	}

	line = LDNS_XMALLOC(char, LDNS_MAX_LINELEN + 1);
	if (!line) {
		return LDNS_STATUS_MEM_ERR;
	}

	/* read an entire line in from the file */
	if ((size = ldns_fget_token_l(fp, line, LDNS_PARSE_SKIP_SPACE, LDNS_MAX_LINELEN, line_nr)) == -1) {
		LDNS_FREE(line);
		/* if last line was empty, we are now at feof, which is not
		 * always a parse error (happens when for instance last line
		 * was a comment)
		 */
		return LDNS_STATUS_SYNTAX_ERR;
	}

	/* we can have the situation, where we've read ok, but still got
	 * no bytes to play with, in this case size is 0 
	 */
	if (size == 0) {
		LDNS_FREE(line);
		return LDNS_STATUS_SYNTAX_EMPTY;
	}
	
	if ((keyword = strstr(line, "$ORIGIN "))) {
		if (*origin) {
			ldns_rdf_deep_free(*origin);
			*origin = NULL;
		}
		tmp = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, keyword + 8);
		if (!tmp) {
			/* could not parse what next to $ORIGIN */
			LDNS_FREE(line);
			return LDNS_STATUS_SYNTAX_DNAME_ERR;
		}
		*origin = tmp;
		s = LDNS_STATUS_SYNTAX_ORIGIN;
	} else if ((keyword = strstr(line, "$TTL "))) {
		if (default_ttl) {
			*default_ttl = ldns_str2period(keyword + 5, &endptr);
		}
		s = LDNS_STATUS_SYNTAX_TTL;
	} else {
		if (origin && *origin) {
			s = ldns_rr_new_frm_str(&rr, (const char*) line, ttl, *origin, prev);
		} else {
			s = ldns_rr_new_frm_str(&rr, (const char*) line, ttl, NULL, prev);
		}
	
	}
	LDNS_FREE(line);
	if (newrr && s == LDNS_STATUS_OK) {
		*newrr = rr;
	}
	return s;
}

void
ldns_rr_set_owner(ldns_rr *rr, ldns_rdf *owner)
{
	rr->_owner = owner;
}

void
ldns_rr_set_ttl(ldns_rr *rr, uint32_t ttl)
{
	rr->_ttl = ttl;
}

void
ldns_rr_set_rd_count(ldns_rr *rr, size_t count)
{
	rr->_rd_count = count;
}

void
ldns_rr_set_type(ldns_rr *rr, ldns_rr_type rr_type)
{
	rr->_rr_type = rr_type;
}

void
ldns_rr_set_class(ldns_rr *rr, ldns_rr_class rr_class)
{
	rr->_rr_class = rr_class;
}

ldns_rdf *
ldns_rr_set_rdf(ldns_rr *rr, const ldns_rdf *f, size_t position)
{
	size_t rd_count;
	ldns_rdf *pop;
	ldns_rdf **rdata_fields;

	rd_count = ldns_rr_rd_count(rr);
	if (position < rd_count) {
		rdata_fields = rr->_rdata_fields;
		/* dicard the old one */
		pop = rr->_rdata_fields[position];
		rr->_rdata_fields[position] = (ldns_rdf*)f;
		return pop;
	} else {
		return NULL;
	}
}

bool
ldns_rr_push_rdf(ldns_rr *rr, const ldns_rdf *f)
{
	size_t rd_count;
	ldns_rdf **rdata_fields;
	
	rd_count = ldns_rr_rd_count(rr);
	
	/* grow the array */
	rdata_fields = LDNS_XREALLOC(
		rr->_rdata_fields, ldns_rdf *, rd_count + 1);
	if (!rdata_fields) {
		return false;
	}
	
	/* add the new member */
	rr->_rdata_fields = rdata_fields;
	rr->_rdata_fields[rd_count] = (ldns_rdf*)f;

	ldns_rr_set_rd_count(rr, rd_count + 1);
	return true;
}

ldns_rdf *
ldns_rr_pop_rdf(ldns_rr *rr)
{
	size_t rd_count;
	ldns_rdf *pop;
	
	rd_count = ldns_rr_rd_count(rr);

	if (rd_count == 0) {
		return NULL;
	}

	pop = rr->_rdata_fields[rd_count - 1];
	
	/* shrink the array */
	rr->_rdata_fields = LDNS_XREALLOC(
		rr->_rdata_fields, ldns_rdf *, rd_count - 1);

	ldns_rr_set_rd_count(rr, rd_count - 1);
	return pop;
}

ldns_rdf *
ldns_rr_rdf(const ldns_rr *rr, size_t nr)
{
	if (nr < ldns_rr_rd_count(rr)) {
		return rr->_rdata_fields[nr];
	} else {
		return NULL;
	}
}

ldns_rdf *
ldns_rr_owner(const ldns_rr *rr)
{
	return rr->_owner;
}

uint32_t
ldns_rr_ttl(const ldns_rr *rr)
{
	return rr->_ttl;
}

size_t
ldns_rr_rd_count(const ldns_rr *rr)
{
	return rr->_rd_count;
}

ldns_rr_type
ldns_rr_get_type(const ldns_rr *rr)
{
        return rr->_rr_type;
}

ldns_rr_class
ldns_rr_get_class(const ldns_rr *rr)
{
        return rr->_rr_class;
}

/* rr_lists */

size_t
ldns_rr_list_rr_count(const ldns_rr_list *rr_list)
{
	if (rr_list) {
		return rr_list->_rr_count;
	} else {
		return 0;
	}
}

ldns_rr *
ldns_rr_list_set_rr(ldns_rr_list *rr_list, const ldns_rr *r, size_t count)
{
	ldns_rr *old;

	if (count > ldns_rr_list_rr_count(rr_list)) {
		return NULL;
	}

	old = ldns_rr_list_rr(rr_list, count);

	/* overwrite old's pointer */
	rr_list->_rrs[count] = (ldns_rr*)r;
	return old;
}

void
ldns_rr_list_set_rr_count(ldns_rr_list *rr_list, size_t count)
{
	assert(count <= rr_list->_rr_capacity);
	rr_list->_rr_count = count;
}

ldns_rr *
ldns_rr_list_rr(const ldns_rr_list *rr_list, size_t nr)
{
	if (nr < ldns_rr_list_rr_count(rr_list)) {
		return rr_list->_rrs[nr];
	} else {
		return NULL;
	}
}

ldns_rr_list *
ldns_rr_list_new()
{
	ldns_rr_list *rr_list = LDNS_MALLOC(ldns_rr_list);
	rr_list->_rr_count = 0;
	rr_list->_rr_capacity = 0;
	rr_list->_rrs = NULL;
	return rr_list;
}

void
ldns_rr_list_free(ldns_rr_list *rr_list)
{
	if (rr_list) {
		LDNS_FREE(rr_list->_rrs);
		LDNS_FREE(rr_list);
	}
}

void
ldns_rr_list_deep_free(ldns_rr_list *rr_list)
{
	size_t i;
	
	if (rr_list) {
		for (i=0; i < ldns_rr_list_rr_count(rr_list); i++) {
			ldns_rr_free(ldns_rr_list_rr(rr_list, i));
		}
		LDNS_FREE(rr_list->_rrs);
		LDNS_FREE(rr_list);
	}
}


/* add right to left. So we modify *left! */
bool
ldns_rr_list_cat(ldns_rr_list *left, ldns_rr_list *right)
{
	size_t r_rr_count;
	size_t l_rr_count;
	size_t i;

	if (left) {
		l_rr_count = ldns_rr_list_rr_count(left);
	} else {
		return false;
	}

	if (right) {
		r_rr_count = ldns_rr_list_rr_count(right);
	} else {
		r_rr_count = 0;
	}
	
	/* push right to left */
	for(i = 0; i < r_rr_count; i++) {
		ldns_rr_list_push_rr(left, ldns_rr_list_rr(right, i));
	}
	return true;
}

ldns_rr_list *
ldns_rr_list_cat_clone(ldns_rr_list *left, ldns_rr_list *right)
{
	size_t l_rr_count;
	size_t r_rr_count;
	size_t i;
	ldns_rr_list *cat;

	l_rr_count = 0;

	if (left) {
		l_rr_count = ldns_rr_list_rr_count(left);
	} else {
		return ldns_rr_list_clone(right);
	}

	if (right) {
		r_rr_count = ldns_rr_list_rr_count(right);
	} else {
		r_rr_count = 0;
	}
	
	cat = ldns_rr_list_new();

	if (!cat) {
		return NULL;
	}

	/* left */
	for(i = 0; i < l_rr_count; i++) {
		ldns_rr_list_push_rr(cat, 
				ldns_rr_clone(ldns_rr_list_rr(left, i)));
	}
	/* right */
	for(i = 0; i < r_rr_count; i++) {
		ldns_rr_list_push_rr(cat, 
				ldns_rr_clone(ldns_rr_list_rr(right, i)));
	}
	return cat;
}

ldns_rr_list *
ldns_rr_list_subtype_by_rdf(ldns_rr_list *l, ldns_rdf *r, size_t pos)
{
	size_t i;
	ldns_rr_list *subtyped;
	ldns_rdf *list_rdf;

	subtyped = ldns_rr_list_new();

	for(i = 0; i < ldns_rr_list_rr_count(l); i++) {
		list_rdf = ldns_rr_rdf(
			ldns_rr_list_rr(l, i),
			pos);
		if (!list_rdf) {
			/* pos is too large or any other error */
			ldns_rr_list_deep_free(subtyped);
			return NULL;
		}

		if (ldns_rdf_compare(list_rdf, r) == 0) {
			/* a match */
			ldns_rr_list_push_rr(subtyped, 
					ldns_rr_clone(ldns_rr_list_rr(l, i)));
		}
	}

	if (ldns_rr_list_rr_count(subtyped) > 0) {
		return subtyped;
	} else {
		ldns_rr_list_free(subtyped);
		return NULL;
	}
}

bool
ldns_rr_list_push_rr(ldns_rr_list *rr_list, const ldns_rr *rr)
{
	size_t rr_count;
	size_t cap;
	
	rr_count = ldns_rr_list_rr_count(rr_list);
	cap = rr_list->_rr_capacity;

	/* grow the array */
	if(rr_count+1 > cap) {
		ldns_rr **rrs;

		if(cap == 0)
			cap = LDNS_RRLIST_INIT;  /* initial list size */
		else	cap *= 2; 
		rrs = LDNS_XREALLOC(rr_list->_rrs, ldns_rr *, cap);
		if (!rrs) {
			return false;
		}
		rr_list->_rrs = rrs;
		rr_list->_rr_capacity = cap;
	}
	
	/* add the new member */
	rr_list->_rrs[rr_count] = (ldns_rr*)rr;

	ldns_rr_list_set_rr_count(rr_list, rr_count + 1);
	return true;
}

bool
ldns_rr_list_push_rr_list(ldns_rr_list *rr_list, const ldns_rr_list *push_list)
{
	size_t i;
	
	for(i = 0; i < ldns_rr_list_rr_count(push_list); i++) {
		if (!ldns_rr_list_push_rr(rr_list,
				ldns_rr_list_rr(push_list, i))) {
			return false;
		}
	}
	return true;
}

ldns_rr *
ldns_rr_list_pop_rr(ldns_rr_list *rr_list)
{
	size_t rr_count;
	size_t cap;
	ldns_rr *pop;
	
	rr_count = ldns_rr_list_rr_count(rr_list);

	if (rr_count == 0) {
		return NULL;
	}

	cap = rr_list->_rr_capacity;
	pop = ldns_rr_list_rr(rr_list, rr_count - 1);
	
	/* shrink the array */
	if(cap > LDNS_RRLIST_INIT && rr_count-1 <= cap/2) {
		cap /= 2;
		rr_list->_rrs = LDNS_XREALLOC(rr_list->_rrs, ldns_rr *, cap);
		rr_list->_rr_capacity = cap;
	}

	ldns_rr_list_set_rr_count(rr_list, rr_count - 1);

	return pop;
}

ldns_rr_list *
ldns_rr_list_pop_rr_list(ldns_rr_list *rr_list, size_t howmany) 
{
	/* pop a number of rr's and put them in a rr_list */
	ldns_rr_list *popped;
	ldns_rr *p;
	size_t i = howmany;

	popped = ldns_rr_list_new();

	if (!popped) {
		return NULL;
	}


	while(i > 0 && 
			(p = ldns_rr_list_pop_rr(rr_list)) != NULL) {
		ldns_rr_list_push_rr(popped, p);
		i--;
	}

	if (i == howmany) {
		return NULL;
	} else {
		return popped;
	}
}


bool
ldns_rr_list_contains_rr(const ldns_rr_list *rr_list, ldns_rr *rr)
{
	size_t i;
	
	if (!rr_list || !rr || ldns_rr_list_rr_count(rr_list) == 0) {
		return false;
	}

	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		if (rr == ldns_rr_list_rr(rr_list, i)) {
			return true;
		} else if (ldns_rr_compare(rr, ldns_rr_list_rr(rr_list, i)) == 0) {
			return true;
		}
	}
	return false;
}

bool
ldns_is_rrset(ldns_rr_list *rr_list)
{
	ldns_rr_type t; 
	ldns_rr_class c;
	ldns_rdf *o;
	ldns_rr *tmp;
	size_t i;
	
	if (!rr_list || ldns_rr_list_rr_count(rr_list) == 0) {
		return false;
	}

	tmp = ldns_rr_list_rr(rr_list, 0);

	t = ldns_rr_get_type(tmp);
	c = ldns_rr_get_class(tmp);
	o = ldns_rr_owner(tmp);

	/* compare these with the rest of the rr_list, start with 1 */
	for (i = 1; i < ldns_rr_list_rr_count(rr_list); i++) {
		tmp = ldns_rr_list_rr(rr_list, i);
		if (t != ldns_rr_get_type(tmp)) {
			return false;
		}
		if (c != ldns_rr_get_class(tmp)) {
			return false;
		}
		if (ldns_rdf_compare(o, ldns_rr_owner(tmp)) != 0) {
			return false;
		}
	}
	return true;
}

bool
ldns_rr_set_push_rr(ldns_rr_list *rr_list, ldns_rr *rr)
{
	size_t rr_count;
	size_t i;
	ldns_rr *last;

	assert(rr != NULL);

	rr_count = ldns_rr_list_rr_count(rr_list);

	if (rr_count == 0) {
		/* nothing there, so checking it is 
		 * not needed */
		return ldns_rr_list_push_rr(rr_list, rr);
	} else {
		/* check with the final rr in the rr_list */
		last = ldns_rr_list_rr(rr_list, rr_count - 1);

		if (ldns_rr_get_class(last) != ldns_rr_get_class(rr)) {
			return false;
		}
		if (ldns_rr_get_type(last) != ldns_rr_get_type(rr)) {
			return false;
		}
		/* only check if not equal to RRSIG */
		if (ldns_rr_get_type(rr) != LDNS_RR_TYPE_RRSIG) {
			if (ldns_rr_ttl(last) != ldns_rr_ttl(rr)) {
				return false;
			}
		}
		if (ldns_rdf_compare(ldns_rr_owner(last),
					ldns_rr_owner(rr)) != 0) {
			return false;
		}
		/* ok, still alive - check if the rr already
		 * exists - if so, dont' add it */
		for(i = 0; i < rr_count; i++) {
			if(ldns_rr_compare(
					ldns_rr_list_rr(rr_list, i), rr) == 0) {
				return false;
			}
		}
		/* it's safe, push it */
		return ldns_rr_list_push_rr(rr_list, rr);
	}
}

ldns_rr *
ldns_rr_set_pop_rr(ldns_rr_list *rr_list)
{
	return ldns_rr_list_pop_rr(rr_list);
}

ldns_rr_list *
ldns_rr_list_pop_rrset(ldns_rr_list *rr_list)
{
	ldns_rr_list *rrset;
	ldns_rr *last_rr = NULL;
	ldns_rr *next_rr;
	
	if (!rr_list) {
		return NULL;
	}
	
	rrset = ldns_rr_list_new();
	if (!last_rr) {
		last_rr = ldns_rr_list_pop_rr(rr_list);
		if (!last_rr) {
			ldns_rr_list_free(rrset);
			return NULL;
		} else {
			ldns_rr_list_push_rr(rrset, last_rr);
		}
	}

	if (ldns_rr_list_rr_count(rr_list) > 0) {
		next_rr = ldns_rr_list_rr(rr_list, ldns_rr_list_rr_count(rr_list) - 1);
	} else {
		next_rr = NULL;
	}

	while (next_rr) {
		if (
			ldns_rdf_compare(ldns_rr_owner(next_rr),
					 ldns_rr_owner(last_rr)) == 0
			&&
			ldns_rr_get_type(next_rr) == ldns_rr_get_type(last_rr)
			&&
			ldns_rr_get_class(next_rr) == ldns_rr_get_class(last_rr)
		   ) {
			ldns_rr_list_push_rr(rrset, ldns_rr_list_pop_rr(rr_list));
			if (ldns_rr_list_rr_count(rr_list) > 0) {
				last_rr = next_rr;
				next_rr = ldns_rr_list_rr(rr_list, ldns_rr_list_rr_count(rr_list) - 1);
			} else {
				next_rr = NULL;
			}
		} else {
			next_rr = NULL;
		}
	}

	return rrset;
}

ldns_rr *
ldns_rr_clone(const ldns_rr *rr)
{
	size_t i;
	ldns_rr *new_rr;

	if (!rr) {
		return NULL;
	}
		
	new_rr = ldns_rr_new();
	if (!new_rr) {
		return NULL;
	}
	if (ldns_rr_owner(rr)) {
		ldns_rr_set_owner(new_rr, ldns_rdf_clone(ldns_rr_owner(rr)));
  	}
	ldns_rr_set_ttl(new_rr, ldns_rr_ttl(rr));
	ldns_rr_set_type(new_rr, ldns_rr_get_type(rr));
	ldns_rr_set_class(new_rr, ldns_rr_get_class(rr));
	
	for (i = 0; i < ldns_rr_rd_count(rr); i++) {
        	if (ldns_rr_rdf(rr,i)) {
        		ldns_rr_push_rdf(new_rr, ldns_rdf_clone(ldns_rr_rdf(rr, i)));
                }
	}

	return new_rr;
}

ldns_rr_list *
ldns_rr_list_clone(const ldns_rr_list *rrlist)
{
	size_t i;
	ldns_rr_list *new_list;
	ldns_rr *r;

	if (!rrlist) {
		return NULL;
	}

	new_list = ldns_rr_list_new();
	if (!new_list) {
		return NULL;
	}
	for (i = 0; i < ldns_rr_list_rr_count(rrlist); i++) {
		r = ldns_rr_clone(
			ldns_rr_list_rr(rrlist, i)
		    );
		if (!r) {
			/* huh, failure in cloning */
			ldns_rr_list_deep_free(new_list);
			return NULL;
		}
		ldns_rr_list_push_rr(new_list, r);
	}
	return new_list;
}


int
qsort_rr_compare(const void *a, const void *b)
{
	const ldns_rr *rr1 = * (const ldns_rr **) a;
	const ldns_rr *rr2 = * (const ldns_rr **) b;

	if (rr1 == NULL && rr2 == NULL) {
		return 0;
	}
	if (rr1 == NULL) {
		return -1;
	} 
	if (rr2 == NULL) {
		return 1;
	}
	return ldns_rr_compare(rr1, rr2);
}

int
qsort_schwartz_rr_compare(const void *a, const void *b)
{
	int result = 0;
	ldns_rr *rr1, *rr2;
	ldns_buffer *rr1_buf, *rr2_buf;
	struct ldns_schwartzian_compare_struct *sa = *(struct ldns_schwartzian_compare_struct **) a;
	struct ldns_schwartzian_compare_struct *sb = *(struct ldns_schwartzian_compare_struct **) b;
	/* if we are doing 2wire, we need to do lowercasing on the dname (and maybe on the rdata)
	 * this must be done for comparison only, so we need to have a temp var for both buffers,
	 * which is only used when the transformed object value isn't there yet
	 */
	ldns_rr *canonical_a, *canonical_b;

	rr1 = (ldns_rr *) sa->original_object;
	rr2 = (ldns_rr *) sb->original_object;
	
	result = ldns_rr_compare_no_rdata(rr1, rr2);
	
	if (result == 0) {
		if (!sa->transformed_object) {
			canonical_a = ldns_rr_clone(sa->original_object);
			ldns_rr2canonical(canonical_a);
			sa->transformed_object = ldns_buffer_new(ldns_rr_uncompressed_size(canonical_a));
			if (ldns_rr2buffer_wire(sa->transformed_object, canonical_a, LDNS_SECTION_ANY) != LDNS_STATUS_OK) {
				fprintf(stderr, "ERR!\n");
				ldns_rr_free(canonical_a);
				return 0;
			}
			ldns_rr_free(canonical_a);
		}
		if (!sb->transformed_object) {
			canonical_b = ldns_rr_clone(sb->original_object);
			ldns_rr2canonical(canonical_b);
			sb->transformed_object = ldns_buffer_new(ldns_rr_uncompressed_size(canonical_b));
			if (ldns_rr2buffer_wire(sb->transformed_object, canonical_b, LDNS_SECTION_ANY) != LDNS_STATUS_OK) {
				fprintf(stderr, "ERR!\n");
				ldns_rr_free(canonical_b);
				return 0;
			}
			ldns_rr_free(canonical_b);
		}
		rr1_buf = (ldns_buffer *) sa->transformed_object;
		rr2_buf = (ldns_buffer *) sb->transformed_object;
		
		result = ldns_rr_compare_wire(rr1_buf, rr2_buf);
	}
	
	return result;
}

void
ldns_rr_list_sort(ldns_rr_list *unsorted)
{
	struct ldns_schwartzian_compare_struct **sortables;
	size_t item_count;
	size_t i;
	
	if (unsorted) {
		item_count = ldns_rr_list_rr_count(unsorted);
		
		sortables = LDNS_XMALLOC(struct ldns_schwartzian_compare_struct *,
					 item_count);
		for (i = 0; i < item_count; i++) {
			sortables[i] = LDNS_XMALLOC(struct ldns_schwartzian_compare_struct, 1);
			sortables[i]->original_object = ldns_rr_list_rr(unsorted, i);
			sortables[i]->transformed_object = NULL;
		}
		qsort(sortables,
		      item_count,
		      sizeof(struct ldns_schwartzian_compare_struct *),
		      qsort_schwartz_rr_compare);
		for (i = 0; i < item_count; i++) {
			unsorted->_rrs[i] = sortables[i]->original_object;
			if (sortables[i]->transformed_object) {
				ldns_buffer_free(sortables[i]->transformed_object);
			}
			LDNS_FREE(sortables[i]);
		}
		LDNS_FREE(sortables);
	}
}

int
ldns_rr_compare_no_rdata(const ldns_rr *rr1, const ldns_rr *rr2)
{
	size_t rr1_len;
	size_t rr2_len;
        size_t offset;

	assert(rr1 != NULL);
	assert(rr2 != NULL);

	rr1_len = ldns_rr_uncompressed_size(rr1);
	rr2_len = ldns_rr_uncompressed_size(rr2);

	if (ldns_dname_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2)) < 0) {
		return -1;
	} else if (ldns_dname_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2)) > 0) {
		return 1;
	}

        if (ldns_rr_get_class(rr1) != ldns_rr_get_class(rr2)) {
            return ldns_rr_get_class(rr2) - ldns_rr_get_class(rr1);
        }

        if (ldns_rr_get_type(rr1) != ldns_rr_get_type(rr2)) {
            return ldns_rr_get_type(rr2) - ldns_rr_get_type(rr1);
        }
        
        /* offset is the owername length + ttl + type + class + rdlen == start of wire format rdata */
        offset = ldns_rdf_size(ldns_rr_owner(rr1)) + 4 + 2 + 2 + 2;
        /* if either record doesn't have any RDATA... */
        if (offset > rr1_len || offset > rr2_len) {
            if (rr1_len == rr2_len) {
              return 0;
            }
            return ((int) rr2_len - (int) rr1_len);
        }

	return 0;
}

int ldns_rr_compare_wire(ldns_buffer *rr1_buf, ldns_buffer *rr2_buf)
{
        size_t rr1_len, rr2_len, min_len, i, offset;

        rr1_len = ldns_buffer_capacity(rr1_buf);
        rr2_len = ldns_buffer_capacity(rr2_buf);

        /* jump past dname (checked in earlier part)
         * and especially past TTL */
        offset = 0;
        while (offset < rr1_len && *ldns_buffer_at(rr1_buf, offset) != 0) {
          offset += *ldns_buffer_at(rr1_buf, offset) + 1;
        }
        /* jump to rdata section (PAST the rdata length field, otherwise
           rrs with different lengths might be sorted erroneously */
        offset += 11;
	   min_len = (rr1_len < rr2_len) ? rr1_len : rr2_len;
        /* Compare RRs RDATA byte for byte. */
        for(i = offset; i < min_len; i++) {
                if (*ldns_buffer_at(rr1_buf,i) < *ldns_buffer_at(rr2_buf,i)) {
                        return -1;
                } else if (*ldns_buffer_at(rr1_buf,i) > *ldns_buffer_at(rr2_buf,i)) {
                        return +1;
                }
        }

        /* If both RDATAs are the same up to min_len, then the shorter one sorts first. */
        if (rr1_len < rr2_len) {
                return -1;
        } else if (rr1_len > rr2_len) {
                return +1;
	}
        /* The RDATAs are equal. */
        return 0;

}

int
ldns_rr_compare(const ldns_rr *rr1, const ldns_rr *rr2)
{
	int result;
	size_t rr1_len, rr2_len;
	
	ldns_buffer *rr1_buf;
	ldns_buffer *rr2_buf;

	result = ldns_rr_compare_no_rdata(rr1, rr2);
	if (result == 0) {
		rr1_len = ldns_rr_uncompressed_size(rr1);
		rr2_len = ldns_rr_uncompressed_size(rr2);

		rr1_buf = ldns_buffer_new(rr1_len);
		rr2_buf = ldns_buffer_new(rr2_len);

		if (ldns_rr2buffer_wire_canonical(rr1_buf,
								    rr1,
								    LDNS_SECTION_ANY) 
		    != LDNS_STATUS_OK) {
			ldns_buffer_free(rr1_buf);
			ldns_buffer_free(rr2_buf);
			return 0; 
		}
		if (ldns_rr2buffer_wire_canonical(rr2_buf,
								    rr2,
								    LDNS_SECTION_ANY)
		    != LDNS_STATUS_OK) {
			ldns_buffer_free(rr1_buf);
			ldns_buffer_free(rr2_buf);
			return 0;
		}

		result = ldns_rr_compare_wire(rr1_buf, rr2_buf);

		ldns_buffer_free(rr1_buf);
		ldns_buffer_free(rr2_buf);
	}

	return result;
}

/* convert dnskey to a ds with the given algorithm,
 * then compare the result with the given ds */
static int
ldns_rr_compare_ds_dnskey(ldns_rr *ds,
                          ldns_rr *dnskey)
{
	ldns_rr *ds_gen;
	bool result = false;
	ldns_algorithm algo;
	
	if (!dnskey || !ds ||
	    ldns_rr_get_type(ds) != LDNS_RR_TYPE_DS ||
	    ldns_rr_get_type(dnskey) != LDNS_RR_TYPE_DNSKEY) {
		return false;
	}
	
	algo = ldns_rdf2native_int8(ldns_rr_rdf(ds, 2));

	ds_gen = ldns_key_rr2ds(dnskey, algo);
	if (ds_gen) {
		result = ldns_rr_compare(ds, ds_gen) == 0;
		ldns_rr_free(ds_gen);
	}
	return result;
}

bool
ldns_rr_compare_ds(const ldns_rr *orr1, const ldns_rr *orr2)
{
	bool result;
	ldns_rr *rr1 = ldns_rr_clone(orr1);
	ldns_rr *rr2 = ldns_rr_clone(orr2);
	
	/* set ttls to zero */
	ldns_rr_set_ttl(rr1, 0);
	ldns_rr_set_ttl(rr2, 0);

	if (ldns_rr_get_type(rr1) == LDNS_RR_TYPE_DS &&
	    ldns_rr_get_type(rr2) == LDNS_RR_TYPE_DNSKEY) {
		result = ldns_rr_compare_ds_dnskey(rr1, rr2);
	} else if (ldns_rr_get_type(rr1) == LDNS_RR_TYPE_DNSKEY &&
	    ldns_rr_get_type(rr2) == LDNS_RR_TYPE_DS) {
		result = ldns_rr_compare_ds_dnskey(rr2, rr1);
	} else {
		result = (ldns_rr_compare(rr1, rr2) == 0);
	}	
	
	ldns_rr_free(rr1);
	ldns_rr_free(rr2);

	return result;
}

int
ldns_rr_list_compare(const ldns_rr_list *rrl1, const ldns_rr_list *rrl2)
{
	size_t i = 0;
	int rr_cmp;

	assert(rrl1 != NULL);
	assert(rrl2 != NULL);

	for (i = 0; i < ldns_rr_list_rr_count(rrl1) && i < ldns_rr_list_rr_count(rrl2); i++) {
		rr_cmp = ldns_rr_compare(ldns_rr_list_rr(rrl1, i), ldns_rr_list_rr(rrl2, i));
		if (rr_cmp != 0) {
			return rr_cmp;
		}
	}

	if (i == ldns_rr_list_rr_count(rrl1) &&
	    i != ldns_rr_list_rr_count(rrl2)) {
		return 1;
	} else if (i == ldns_rr_list_rr_count(rrl2) &&
	           i != ldns_rr_list_rr_count(rrl1)) {
		return -1;
	} else {
		return 0;
	}
}

size_t
ldns_rr_uncompressed_size(const ldns_rr *r)
{
	size_t rrsize;
	size_t i;

	rrsize = 0;
	/* add all the rdf sizes */
	for(i = 0; i < ldns_rr_rd_count(r); i++) {
		rrsize += ldns_rdf_size(ldns_rr_rdf(r, i));
	}
	/* ownername */
	rrsize += ldns_rdf_size(ldns_rr_owner(r));
	rrsize += LDNS_RR_OVERHEAD;
	return rrsize;
}

void
ldns_rr2canonical(ldns_rr *rr)
{
	uint16_t i;
	
	if (!rr) {
	  return;
        }

        ldns_dname2canonical(ldns_rr_owner(rr));

	/*
	 * lowercase the rdata dnames if the rr type is one
	 * of the list in chapter 7 of RFC3597
	 */
	switch(ldns_rr_get_type(rr)) {
        	case LDNS_RR_TYPE_NS:
        	case LDNS_RR_TYPE_MD:
        	case LDNS_RR_TYPE_MF:
        	case LDNS_RR_TYPE_CNAME:
        	case LDNS_RR_TYPE_SOA:
        	case LDNS_RR_TYPE_MB:
        	case LDNS_RR_TYPE_MG:
        	case LDNS_RR_TYPE_MR:
        	case LDNS_RR_TYPE_PTR:
        	case LDNS_RR_TYPE_HINFO:
        	case LDNS_RR_TYPE_MINFO:
        	case LDNS_RR_TYPE_MX:
        	case LDNS_RR_TYPE_RP:
        	case LDNS_RR_TYPE_AFSDB:
        	case LDNS_RR_TYPE_RT:
        	case LDNS_RR_TYPE_SIG:
        	case LDNS_RR_TYPE_PX:
        	case LDNS_RR_TYPE_NXT:
        	case LDNS_RR_TYPE_NAPTR:
        	case LDNS_RR_TYPE_KX:
        	case LDNS_RR_TYPE_SRV:
        	case LDNS_RR_TYPE_DNAME:
        	case LDNS_RR_TYPE_A6:
			for (i = 0; i < ldns_rr_rd_count(rr); i++) {
				ldns_dname2canonical(ldns_rr_rdf(rr, i));
			}
			return;
		default:
			/* do nothing */
			return;
	}
}

void
ldns_rr_list2canonical(ldns_rr_list *rr_list)
{
	size_t i;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(rr_list, i));
	}
}

uint8_t 
ldns_rr_label_count(ldns_rr *rr)
{
	if (!rr) {
		return 0;
	}
	return ldns_dname_label_count(
			ldns_rr_owner(rr));
}

/** \cond */
static const ldns_rdf_type type_0_wireformat[] = { LDNS_RDF_TYPE_UNKNOWN };
static const ldns_rdf_type type_a_wireformat[] = { LDNS_RDF_TYPE_A };
static const ldns_rdf_type type_ns_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_md_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mf_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_cname_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_soa_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_INT32, 
	LDNS_RDF_TYPE_PERIOD, LDNS_RDF_TYPE_PERIOD, LDNS_RDF_TYPE_PERIOD,
	LDNS_RDF_TYPE_PERIOD
};
static const ldns_rdf_type type_mb_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mg_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_mr_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_wks_wireformat[] = {
	LDNS_RDF_TYPE_A, LDNS_RDF_TYPE_WKS
};
static const ldns_rdf_type type_ptr_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_hinfo_wireformat[] = {
	LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_minfo_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_mx_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_rp_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_afsdb_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_x25_wireformat[] = { LDNS_RDF_TYPE_STR };
static const ldns_rdf_type type_isdn_wireformat[] = {
	LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_rt_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_nsap_wireformat[] = {
	LDNS_RDF_TYPE_NSAP
};
static const ldns_rdf_type type_nsap_ptr_wireformat[] = {
	LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_sig_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_TIME,
	LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT32, LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_key_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_px_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_gpos_wireformat[] = {
	LDNS_RDF_TYPE_STR,
	LDNS_RDF_TYPE_STR,
	LDNS_RDF_TYPE_STR
};
static const ldns_rdf_type type_aaaa_wireformat[] = { LDNS_RDF_TYPE_AAAA };
static const ldns_rdf_type type_loc_wireformat[] = { LDNS_RDF_TYPE_LOC };
static const ldns_rdf_type type_nxt_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_UNKNOWN
};
static const ldns_rdf_type type_eid_wireformat[] = {
	LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_nimloc_wireformat[] = {
	LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_srv_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_atma_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_naptr_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_STR, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_kx_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME
};
static const ldns_rdf_type type_cert_wireformat[] = {
	 LDNS_RDF_TYPE_CERT_ALG, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_a6_wireformat[] = { LDNS_RDF_TYPE_UNKNOWN };
static const ldns_rdf_type type_dname_wireformat[] = { LDNS_RDF_TYPE_DNAME };
static const ldns_rdf_type type_sink_wireformat[] = { LDNS_RDF_TYPE_INT8,
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_apl_wireformat[] = {
	LDNS_RDF_TYPE_APL
};
static const ldns_rdf_type type_ds_wireformat[] = {
	LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_sshfp_wireformat[] = {
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_HEX
};
static const ldns_rdf_type type_ipseckey_wireformat[] = {
	LDNS_RDF_TYPE_IPSECKEY
};
static const ldns_rdf_type type_rrsig_wireformat[] = {
	LDNS_RDF_TYPE_TYPE, LDNS_RDF_TYPE_ALG, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT32,
	LDNS_RDF_TYPE_TIME, LDNS_RDF_TYPE_TIME, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_nsec_wireformat[] = {
	LDNS_RDF_TYPE_DNAME, LDNS_RDF_TYPE_NSEC
};
static const ldns_rdf_type type_dhcid_wireformat[] = {
	LDNS_RDF_TYPE_B64
};
/* nsec3 is some vars, followed by same type of data of nsec */
static const ldns_rdf_type type_nsec3_wireformat[] = {
/*	LDNS_RDF_TYPE_NSEC3_VARS, LDNS_RDF_TYPE_NSEC3_NEXT_OWNER, LDNS_RDF_TYPE_NSEC*/
	LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT8, LDNS_RDF_TYPE_INT16, LDNS_RDF_TYPE_NSEC3_SALT, LDNS_RDF_TYPE_NSEC3_NEXT_OWNER, LDNS_RDF_TYPE_NSEC
};

static const ldns_rdf_type type_nsec3params_wireformat[] = {
/*	LDNS_RDF_TYPE_NSEC3_PARAMS_VARS*/
	LDNS_RDF_TYPE_INT8,
	LDNS_RDF_TYPE_INT8,
	LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_NSEC3_SALT
};

static const ldns_rdf_type type_dnskey_wireformat[] = {
	LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_INT8,
	LDNS_RDF_TYPE_ALG,
	LDNS_RDF_TYPE_B64
};
static const ldns_rdf_type type_tsig_wireformat[] = {
	LDNS_RDF_TYPE_DNAME,
	LDNS_RDF_TYPE_TSIGTIME,
	LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_INT16_DATA,
	LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_INT16,
	LDNS_RDF_TYPE_INT16_DATA
}; 
/** \endcond */

/** \cond */
/* All RR's defined in 1035 are well known and can thus
 * be compressed. See RFC3597. These RR's are:
 * CNAME HINFO MB MD MF MG MINFO MR MX NULL NS PTR SOA TXT
 */
static ldns_rr_descriptor rdata_field_descriptors[] = {
	/* 0 */
	{ 0, NULL, 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 1 */
	{LDNS_RR_TYPE_A, "A", 1, 1, type_a_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 2 */
	{LDNS_RR_TYPE_NS, "NS", 1, 1, type_ns_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 3 */
	{LDNS_RR_TYPE_MD, "MD", 1, 1, type_md_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 4 */ 
	{LDNS_RR_TYPE_MF, "MF", 1, 1, type_mf_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 5 */
	{LDNS_RR_TYPE_CNAME, "CNAME", 1, 1, type_cname_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 6 */
	{LDNS_RR_TYPE_SOA, "SOA", 7, 7, type_soa_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 2 },
	/* 7 */
	{LDNS_RR_TYPE_MB, "MB", 1, 1, type_mb_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 8 */
	{LDNS_RR_TYPE_MG, "MG", 1, 1, type_mg_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 9 */
	{LDNS_RR_TYPE_MR, "MR", 1, 1, type_mr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 10 */
	{LDNS_RR_TYPE_NULL, "NULL", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 11 */
	{LDNS_RR_TYPE_WKS, "WKS", 2, 2, type_wks_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 12 */
	{LDNS_RR_TYPE_PTR, "PTR", 1, 1, type_ptr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 13 */
	{LDNS_RR_TYPE_HINFO, "HINFO", 2, 2, type_hinfo_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 14 */
	{LDNS_RR_TYPE_MINFO, "MINFO", 2, 2, type_minfo_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 2 },
	/* 15 */
	{LDNS_RR_TYPE_MX, "MX", 2, 2, type_mx_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_COMPRESS, 1 },
	/* 16 */
	{LDNS_RR_TYPE_TXT, "TXT", 1, 0, NULL, LDNS_RDF_TYPE_STR, LDNS_RR_NO_COMPRESS, 0 },
	/* 17 */
	{LDNS_RR_TYPE_RP, "RP", 2, 2, type_rp_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 2 },
	/* 18 */
	{LDNS_RR_TYPE_AFSDB, "AFSDB", 2, 2, type_afsdb_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 19 */
	{LDNS_RR_TYPE_X25, "X25", 1, 1, type_x25_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 20 */
	{LDNS_RR_TYPE_ISDN, "ISDN", 1, 2, type_isdn_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 21 */
	{LDNS_RR_TYPE_RT, "RT", 2, 2, type_rt_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 22 */
	{LDNS_RR_TYPE_NSAP, "NSAP", 1, 1, type_nsap_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 23 */
	{LDNS_RR_TYPE_NSAP_PTR, "NSAP-PTR", 1, 1, type_nsap_ptr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 24 */
	{LDNS_RR_TYPE_SIG, "SIG", 9, 9, type_sig_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 25 */
	{LDNS_RR_TYPE_KEY, "KEY", 4, 4, type_key_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 26 */
	{LDNS_RR_TYPE_PX, "PX", 3, 3, type_px_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 2 },
	/* 27 */
	{LDNS_RR_TYPE_GPOS, "GPOS", 1, 1, type_gpos_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 28 */
	{LDNS_RR_TYPE_AAAA, "AAAA", 1, 1, type_aaaa_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 29 */
	{LDNS_RR_TYPE_LOC, "LOC", 1, 1, type_loc_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 30 */
	{LDNS_RR_TYPE_NXT, "NXT", 2, 2, type_nxt_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 31 */
	{LDNS_RR_TYPE_EID, "EID", 1, 1, type_eid_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 32 */
	{LDNS_RR_TYPE_NIMLOC, "NIMLOC", 1, 1, type_nimloc_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 33 */
	{LDNS_RR_TYPE_SRV, "SRV", 4, 4, type_srv_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 34 */
	{LDNS_RR_TYPE_ATMA, "ATMA", 1, 1, type_atma_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 35 */
	{LDNS_RR_TYPE_NAPTR, "NAPTR", 6, 6, type_naptr_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 36 */
	{LDNS_RR_TYPE_KX, "KX", 2, 2, type_kx_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 37 */
	{LDNS_RR_TYPE_CERT, "CERT", 4, 4, type_cert_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 38 */
	{LDNS_RR_TYPE_A6, "A6", 1, 1, type_a6_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 39 */
	{LDNS_RR_TYPE_DNAME, "DNAME", 1, 1, type_dname_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 40 */
	{LDNS_RR_TYPE_SINK, "SINK", 1, 1, type_sink_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 41 */
	{LDNS_RR_TYPE_OPT, "OPT", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 42 */
	{LDNS_RR_TYPE_APL, "APL", 0, 0, type_apl_wireformat, LDNS_RDF_TYPE_APL, LDNS_RR_NO_COMPRESS, 0 },
	/* 43 */
	{LDNS_RR_TYPE_DS, "DS", 4, 4, type_ds_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 44 */
	{LDNS_RR_TYPE_SSHFP, "SSHFP", 3, 3, type_sshfp_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 45 */
	{LDNS_RR_TYPE_IPSECKEY, "IPSECKEY", 1, 1, type_ipseckey_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 46 */
	{LDNS_RR_TYPE_RRSIG, "RRSIG", 9, 9, type_rrsig_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 1 },
	/* 47 */
	{LDNS_RR_TYPE_NSEC, "NSEC", 1, 2, type_nsec_wireformat, LDNS_RDF_TYPE_NSEC, LDNS_RR_NO_COMPRESS, 1 },
	/* 48 */
	{LDNS_RR_TYPE_DNSKEY, "DNSKEY", 4, 4, type_dnskey_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 49 */
{LDNS_RR_TYPE_DHCID, "DHCID", 1, 1, type_dhcid_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 50 */
	{LDNS_RR_TYPE_NSEC3, "NSEC3", 5, 6, type_nsec3_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 51 */
{LDNS_RR_TYPE_NSEC3PARAMS, "NSEC3PARAM", 4, 4, type_nsec3params_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
	/* 52 */
{LDNS_RR_TYPE_NULL, "TYPE52", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE53", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE54", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE55", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE56", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE57", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE58", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE59", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE60", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE61", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE62", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE63", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE64", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE65", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE66", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE67", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE68", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE69", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE70", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE71", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE72", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE73", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE74", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE75", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE76", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE77", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE78", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE79", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE80", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE81", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE82", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE83", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE84", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE85", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE86", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE87", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE88", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE89", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE90", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE91", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE92", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE93", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE94", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE95", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE96", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE97", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE98", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_SPF,  "SPF", 1, 0, NULL, LDNS_RDF_TYPE_STR, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE100", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE101", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE102", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE103", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE104", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE105", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE106", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE107", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE108", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE109", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE110", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE111", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE112", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE113", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE114", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE115", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE116", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE117", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE118", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE119", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE120", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE121", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE122", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE123", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE124", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE125", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE126", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE127", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE128", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE129", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE130", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE131", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE132", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE133", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE134", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE135", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE136", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE137", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE138", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE139", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE140", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE141", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE142", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE143", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE144", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE145", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE146", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE147", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE148", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE149", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE150", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE151", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE152", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE153", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE154", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE155", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE156", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE157", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE158", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE159", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE160", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE161", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE162", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE163", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE164", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE165", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE166", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE167", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE168", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE169", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE170", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE171", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE172", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE173", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE174", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE175", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE176", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE177", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE178", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE179", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE180", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE181", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE182", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE183", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE184", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE185", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE186", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE187", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE188", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE189", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE190", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE191", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE192", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE193", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE194", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE195", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE196", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE197", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE198", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE199", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE200", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE201", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE202", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE203", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE204", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE205", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE206", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE207", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE208", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE209", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE210", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE211", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE212", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE213", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE214", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE215", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE216", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE217", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE218", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE219", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE220", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE221", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE222", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE223", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE224", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE225", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE226", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE227", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE228", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE229", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE230", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE231", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE232", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE233", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE234", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE235", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE236", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE237", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE238", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE239", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE240", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE241", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE242", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE243", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE244", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE245", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE246", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE247", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE248", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_NULL, "TYPE249", 1, 1, type_0_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
{LDNS_RR_TYPE_TSIG, "TSIG", 8, 9, type_tsig_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 },
/* split in array, no longer contiguous */
{LDNS_RR_TYPE_DLV, "DLV", 4, 4, type_ds_wireformat, LDNS_RDF_TYPE_NONE, LDNS_RR_NO_COMPRESS, 0 }
};
/** \endcond */

/**
 * \def LDNS_RDATA_FIELD_DESCRIPTORS_COUNT
 * computes the number of rdata fields
 */
#define LDNS_RDATA_FIELD_DESCRIPTORS_COUNT \
	(sizeof(rdata_field_descriptors)/sizeof(rdata_field_descriptors[0]))

const ldns_rr_descriptor *
ldns_rr_descript(uint16_t type)
{
	size_t i;
	if (type <= LDNS_RDATA_FIELD_DESCRIPTORS_COMMON) {
		return &rdata_field_descriptors[type];
	} else {
		/* because not all array index equals type code */
		for (i = LDNS_RDATA_FIELD_DESCRIPTORS_COMMON;
		     i < LDNS_RDATA_FIELD_DESCRIPTORS_COUNT;
		     i++) {
		        if (rdata_field_descriptors[i]._type == type) {
		     		return &rdata_field_descriptors[i];
			}
		}
                return &rdata_field_descriptors[0];
	}
}

size_t
ldns_rr_descriptor_minimum(const ldns_rr_descriptor *descriptor)
{
	if (descriptor) {
		return descriptor->_minimum;
	} else {
		return 0;
	}
}

size_t
ldns_rr_descriptor_maximum(const ldns_rr_descriptor *descriptor)
{
	if (descriptor) {
		if (descriptor->_variable != LDNS_RDF_TYPE_NONE) {
			/* Should really be SIZE_MAX... bad FreeBSD.  */
			return UINT_MAX;
		} else {
			return descriptor->_maximum;
		}
	} else {
		return 0;
	}
}

ldns_rdf_type
ldns_rr_descriptor_field_type(const ldns_rr_descriptor *descriptor,
                              size_t index)
{
	assert(descriptor != NULL);
	assert(index < descriptor->_maximum
	       || descriptor->_variable != LDNS_RDF_TYPE_NONE);
	if (index < descriptor->_maximum) {
		return descriptor->_wireformat[index];
	} else {
		return descriptor->_variable;
	}
}

ldns_rr_type
ldns_get_rr_type_by_name(const char *name)
{
	unsigned int i;
	const char *desc_name;
	const ldns_rr_descriptor *desc;
	
	/* TYPEXX representation */
	if (strlen(name) > 4 && strncasecmp(name, "TYPE", 4) == 0) {
		return atoi(name + 4);
	}

	/* Normal types */
	for (i = 0; i < (unsigned int) LDNS_RDATA_FIELD_DESCRIPTORS_COUNT; i++) {
		desc = &rdata_field_descriptors[i];
		desc_name = desc->_name;
		if(desc_name &&
		   strlen(name) == strlen(desc_name) &&
		   strncasecmp(name, desc_name, strlen(desc_name)) == 0) {
			/* because not all array index equals type code */
			return desc->_type;
		}
	}
	
	/* special cases for query types */
	if (strlen(name) == 4 && strncasecmp(name, "IXFR", 4) == 0) {
		return 251;
	} else if (strlen(name) == 4 && strncasecmp(name, "AXFR", 4) == 0) {
		return 252;
	} else if (strlen(name) == 5 && strncasecmp(name, "MAILB", 5) == 0) {
		return 253;
	} else if (strlen(name) == 5 && strncasecmp(name, "MAILA", 5) == 0) {
		return 254;
	} else if (strlen(name) == 3 && strncasecmp(name, "ANY", 3) == 0) {
		return 255;
	}
	
	return 0;
}

ldns_rr_class
ldns_get_rr_class_by_name(const char *name)
{
	ldns_lookup_table *lt;
	
	/* CLASSXX representation */
	if (strlen(name) > 5 && strncasecmp(name, "CLASS", 5) == 0) {
		return atoi(name + 5);
	}
	
	/* Normal types */
	lt = ldns_lookup_by_name(ldns_rr_classes, name);

	if (lt) {
		return lt->id;
	}
	return 0;
}


ldns_rr_type
ldns_rdf2rr_type(const ldns_rdf *rd)
{
        ldns_rr_type r;

        if (!rd) {
                return 0;
        }

        if (ldns_rdf_get_type(rd) != LDNS_RDF_TYPE_TYPE) {
                return 0;
        }

        r = (ldns_rr_type) ldns_rdf2native_int16(rd);
        return r;
}

ldns_rr_type
ldns_rr_list_type(const ldns_rr_list *rr_list)
{
	if (rr_list && ldns_rr_list_rr_count(rr_list) > 0) {
		return ldns_rr_get_type(ldns_rr_list_rr(rr_list, 0));
	} else {
		return 0;
	}
}

ldns_rdf *
ldns_rr_list_owner(const ldns_rr_list *rr_list)
{
	if (rr_list && ldns_rr_list_rr_count(rr_list) > 0) {
		return ldns_rr_owner(ldns_rr_list_rr(rr_list, 0));
	} else {
		return NULL;
	}
}

