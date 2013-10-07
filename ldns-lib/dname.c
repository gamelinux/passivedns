/*
 * dname.c
 *
 * dname specific rdata implementations
 * A dname is a rdf structure with type LDNS_RDF_TYPE_DNAME
 * It is not a /real/ type! All function must therefor check
 * for LDNS_RDF_TYPE_DNAME.
 *
 * a Net::DNS like library for C
 *
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

ldns_rdf *
ldns_dname_cat_clone(const ldns_rdf *rd1, const ldns_rdf *rd2)
{
	ldns_rdf * _new;
	uint16_t new_size;
	uint8_t *buf;
	uint16_t left_size;

	if (ldns_rdf_get_type(rd1) != LDNS_RDF_TYPE_DNAME ||
			ldns_rdf_get_type(rd2) != LDNS_RDF_TYPE_DNAME) {
		return NULL;
	}

	/* remove root label if it is present at the end of the left
	 * rd, by reducing the size with 1
	 */
	left_size = ldns_rdf_size(rd1);
	if (left_size > 0 &&ldns_rdf_data(rd1)[left_size - 1] == 0) {
		left_size--;
	}

	/* we overwrite the nullbyte of rd1 */
	new_size = left_size + ldns_rdf_size(rd2);
	buf = LDNS_XMALLOC(uint8_t, new_size);
	if (!buf) {
		return NULL;
	}

	/* put the two dname's after each other */
	memcpy(buf, ldns_rdf_data(rd1), left_size);
	memcpy(buf + left_size, ldns_rdf_data(rd2), ldns_rdf_size(rd2));
	
	_new = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, new_size, buf);

	LDNS_FREE(buf);
	return _new;
}

ldns_status
ldns_dname_cat(ldns_rdf *rd1, ldns_rdf *rd2)
{
	uint16_t left_size;
	uint16_t size;

	if (ldns_rdf_get_type(rd1) != LDNS_RDF_TYPE_DNAME ||
			ldns_rdf_get_type(rd2) != LDNS_RDF_TYPE_DNAME) {
		return LDNS_STATUS_ERR;
	}

	/* remove root label if it is present at the end of the left
	 * rd, by reducing the size with 1
	 */
	left_size = ldns_rdf_size(rd1);
	if (left_size > 0 &&ldns_rdf_data(rd1)[left_size - 1] == 0) {
		left_size--;
	}

	size = left_size + ldns_rdf_size(rd2);

	ldns_rdf_set_data(rd1, LDNS_XREALLOC(ldns_rdf_data(rd1), uint8_t, size));
	memcpy(ldns_rdf_data(rd1) + left_size, ldns_rdf_data(rd2), 
			ldns_rdf_size(rd2));
	ldns_rdf_set_size(rd1, size);

	return LDNS_STATUS_OK;
}

ldns_rdf *
ldns_dname_reverse(const ldns_rdf *d)
{
	ldns_rdf *_new;
	ldns_rdf *tmp;
	ldns_rdf *d_tmp;
	ldns_status status;

	d_tmp = ldns_rdf_clone(d);

	_new = ldns_dname_new_frm_str(".");

	while(ldns_dname_label_count(d_tmp) > 0) {
		tmp = ldns_dname_label(d_tmp, 0);
		status = ldns_dname_cat(tmp, _new);
		ldns_rdf_deep_free(_new);
		_new = tmp;
		tmp = ldns_dname_left_chop(d_tmp);
		ldns_rdf_deep_free(d_tmp);
		d_tmp = tmp;
	}
	ldns_rdf_deep_free(d_tmp);

	return _new;
}

ldns_rdf *
ldns_dname_clone_from(const ldns_rdf *d, uint16_t n)
{
	uint8_t *data;
	uint8_t label_size;
	size_t data_size;
	
	if (!d ||
	    ldns_rdf_get_type(d) != LDNS_RDF_TYPE_DNAME ||
	    ldns_dname_label_count(d) < n) {
		return NULL;
	}

	data = ldns_rdf_data(d);
	data_size = ldns_rdf_size(d);
	while (n > 0) {
		label_size = data[0] + 1;
		data += label_size;
		if (data_size < label_size) {
			/* this label is very broken */
			return NULL;
		}
		data_size -= label_size;
		n--;
	}

	return ldns_dname_new_frm_data(data_size, data);
}

ldns_rdf *
ldns_dname_left_chop(const ldns_rdf *d)
{
	uint8_t label_pos;
	ldns_rdf *chop;

	if (!d) {
		return NULL;
	}
		
	if (ldns_rdf_get_type(d) != LDNS_RDF_TYPE_DNAME) {
		return NULL;
	}
	if (ldns_dname_label_count(d) == 0) {
		/* root label */
		return NULL;
	}
	/* 05blaat02nl00 */
	label_pos = ldns_rdf_data(d)[0];

	chop = ldns_dname_new_frm_data(ldns_rdf_size(d) - label_pos - 1,
			ldns_rdf_data(d) + label_pos + 1);
	return chop;
}

uint8_t         
ldns_dname_label_count(const ldns_rdf *r)
{       
        uint16_t src_pos;
        uint16_t len;
        uint8_t i;
        size_t r_size;

	if (!r) {
		return 0;
	}

        i = 0; 
	src_pos = 0;
        r_size = ldns_rdf_size(r);

        if (ldns_rdf_get_type(r) != LDNS_RDF_TYPE_DNAME) {
                return 0;
        } else {
                len = ldns_rdf_data(r)[src_pos]; /* start of the label */

                /* single root label */
                if (1 == r_size) {
                        return 0; 
                } else {
                        while ((len > 0) && src_pos < r_size) {
                                src_pos++;
                                src_pos += len;
                                len = ldns_rdf_data(r)[src_pos];
                                i++;
                        }
                }
                return i;
        }
}

ldns_rdf *
ldns_dname_new(uint16_t s, void *d)
{
        ldns_rdf *rd;

        rd = LDNS_MALLOC(ldns_rdf);
        if (!rd) {
                return NULL;
        }
        ldns_rdf_set_size(rd, s);
        ldns_rdf_set_type(rd, LDNS_RDF_TYPE_DNAME);
        ldns_rdf_set_data(rd, d);
        return rd;
}

ldns_rdf *
ldns_dname_new_frm_str(const char *str)
{
	return ldns_rdf_new_frm_str(LDNS_RDF_TYPE_DNAME, str);
}

ldns_rdf *
ldns_dname_new_frm_data(uint16_t size, const void *data)
{
	return ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, size, data);
}

void
ldns_dname2canonical(const ldns_rdf *rd)
{
	uint8_t *rdd;
	uint16_t i;

	if (ldns_rdf_get_type(rd) != LDNS_RDF_TYPE_DNAME) {
		return;
	}

	rdd = (uint8_t*)ldns_rdf_data(rd);
	for (i = 0; i < ldns_rdf_size(rd); i++, rdd++) {
		*rdd = (uint8_t)LDNS_DNAME_NORMALIZE((int)*rdd);
	}
}

bool
ldns_dname_is_subdomain(const ldns_rdf *sub, const ldns_rdf *parent)
{
	uint8_t sub_lab;
	uint8_t par_lab;
	int8_t i, j;
	ldns_rdf *tmp_sub;
	ldns_rdf *tmp_par;

	if (ldns_rdf_get_type(sub) != LDNS_RDF_TYPE_DNAME ||
			ldns_rdf_get_type(parent) != LDNS_RDF_TYPE_DNAME ||
			ldns_rdf_compare(sub, parent) == 0) {
		return false;
	}

	sub_lab = ldns_dname_label_count(sub);
	par_lab = ldns_dname_label_count(parent);

	/* if sub sits above parent, it cannot be a child/sub domain */
	if (sub_lab < par_lab) {
		return false;
	}
	
	/* check all labels the from the parent labels, from right to left. 
	 * When they /all/ match we have found a subdomain
	 */
	j = sub_lab - 1; /* we count from zero, thank you */
	for (i = par_lab -1; i >= 0; i--) {
		tmp_sub = ldns_dname_label(sub, j);
		tmp_par = ldns_dname_label(parent, i);
		if (!tmp_sub || !tmp_par) {
			/* deep free does null check */
			ldns_rdf_deep_free(tmp_sub);
			ldns_rdf_deep_free(tmp_par);
			return false;
		}

		if (ldns_rdf_compare(tmp_sub, tmp_par) != 0) {
			/* they are not equal */
			ldns_rdf_deep_free(tmp_sub);
			ldns_rdf_deep_free(tmp_par);
			return false;
		}
		ldns_rdf_deep_free(tmp_sub);
		ldns_rdf_deep_free(tmp_par);
		j--;
	}
	return true; 
}

int
ldns_dname_compare(const ldns_rdf *dname1, const ldns_rdf *dname2)
{
	size_t lc1, lc2, lc1f, lc2f;
	size_t i;
	int result = 0;
	uint8_t *lp1, *lp2;

	/* see RFC4034 for this algorithm */
	/* this algorithm assumes the names are normalized to case */

        /* only when both are not NULL we can say anything about them */
        if (!dname1 && !dname2) {
                return 0;
        }
        if (!dname1 || !dname2) {
                return -1;
        }
	/* asserts must happen later as we are looking in the
	 * dname, which could be NULL. But this case is handled
	 * above
	 */
	assert(ldns_rdf_get_type(dname1) == LDNS_RDF_TYPE_DNAME);
	assert(ldns_rdf_get_type(dname2) == LDNS_RDF_TYPE_DNAME);

	
	lc1 = ldns_dname_label_count(dname1);
	lc2 = ldns_dname_label_count(dname2);
	
	if (lc1 == 0 && lc2 == 0) {
		return 0;
	}
	if (lc1 == 0) {
		return -1;
	}
	if (lc2 == 0) {
		return 1;
	}
	lc1--;
	lc2--;
	/* we start at the last label */
	while (true) {
		/* find the label first */
		lc1f = lc1;
		lp1 = ldns_rdf_data(dname1);
		while (lc1f > 0) {
			lp1 += *lp1 + 1;
			lc1f--;
		}
		
		/* and find the other one */
		lc2f = lc2;
		lp2 = ldns_rdf_data(dname2);
		while (lc2f > 0) {
			lp2 += *lp2 + 1;
			lc2f--;
		}
		
		/* now check the label character for character. */
		for (i = 1; i < (size_t)(*lp1 + 1); i++) {
			if (i > *lp2) {
				/* apparently label 1 is larger */
				result = 1;
				goto done;
			}
			if (LDNS_DNAME_NORMALIZE((int) *(lp1 + i)) <
			    LDNS_DNAME_NORMALIZE((int) *(lp2 + i))) {
			    result = -1;
			    goto done;
			} else if (LDNS_DNAME_NORMALIZE((int) *(lp1 + i)) >
			    LDNS_DNAME_NORMALIZE((int) *(lp2 + i))) {
			    result = 1;
			    goto done;
			}
		}
		if (*lp1 < *lp2) {
			/* apparently label 2 is larger */
			result = -1;
			goto done;
		}
		if (lc1 == 0 && lc2 > 0) {
			result = -1;
			goto done;
		} else if (lc1 > 0 && lc2 == 0) {
			result = 1;
			goto done;
		} else if (lc1 == 0 && lc2 == 0) {
			result = 0;
			goto done;
		}
		lc1--;
		lc2--;
	}
		
	
	done:
	return result;
}

int
ldns_dname_match_wildcard(const ldns_rdf *dname, const ldns_rdf *wildcard)
{
	ldns_rdf *wc_chopped;
	int result;
	/* check whether it really is a wildcard */
	if (ldns_dname_label_count(wildcard) > 0 &&
	    ldns_rdf_data(wildcard)[0] == 1 &&
	    ldns_rdf_data(wildcard)[1] == '*') {
		/* ok, so the dname needs to be a subdomain of the wildcard
		 * without the *
		 */
		wc_chopped = ldns_dname_left_chop(wildcard);
		result = (int) ldns_dname_is_subdomain(dname, wc_chopped);
		ldns_rdf_deep_free(wc_chopped);
	} else {
		result = (ldns_dname_compare(dname, wildcard) == 0);
	}
	return result;
}

/* nsec test: does prev <= middle < next 
 * -1 = yes
 * 0 = error/can't tell
 * 1 = no
 */
int
ldns_dname_interval(const ldns_rdf *prev, const ldns_rdf *middle, 
		const ldns_rdf *next)
{
	int prev_check, next_check;

	assert(ldns_rdf_get_type(prev) == LDNS_RDF_TYPE_DNAME);
	assert(ldns_rdf_get_type(middle) == LDNS_RDF_TYPE_DNAME);
	assert(ldns_rdf_get_type(next) == LDNS_RDF_TYPE_DNAME);

	prev_check = ldns_dname_compare(prev, middle);
	next_check = ldns_dname_compare(middle, next);
	/* <= next. This cannot be the case for nsec, because then we would
	 * have gotten the nsec of next...
	 */
	if (next_check == 0) {
		return 0;
	}

			/* <= */
	if ((prev_check == -1 || prev_check == 0) &&
			/* < */
			next_check == -1) {
		return -1;
	} else {
		return 1; 
	}
}


bool
ldns_dname_str_absolute(const char *dname_str)
{
	if(dname_str && strcmp(dname_str, ".") == 0)
		return 1;
	return (dname_str && 
	        strlen(dname_str) > 1 && 
	        dname_str[strlen(dname_str) - 1] == '.' &&
	        dname_str[strlen(dname_str) - 2] != '\\');
}

ldns_rdf *
ldns_dname_label(const ldns_rdf *rdf, uint8_t labelpos)
{
	uint8_t labelcnt;
	uint16_t src_pos;
	uint16_t len;
	ldns_rdf *tmpnew;
	size_t s;
	
	if (ldns_rdf_get_type(rdf) != LDNS_RDF_TYPE_DNAME) {
		return NULL;
	}

	labelcnt = 0; 
	src_pos = 0;
	s = ldns_rdf_size(rdf);
	
	len = ldns_rdf_data(rdf)[src_pos]; /* label start */
	while ((len > 0) && src_pos < s) {
		if (labelcnt == labelpos) {
			/* found our label */
			tmpnew = LDNS_MALLOC(ldns_rdf);
			if (!tmpnew) {
				return NULL;
			}
			tmpnew->_type = LDNS_RDF_TYPE_DNAME;
			tmpnew->_data = LDNS_XMALLOC(uint8_t, len + 2);
			if (!tmpnew->_data) {
				LDNS_FREE(tmpnew);
				return NULL;
			}
			memset(tmpnew->_data, 0, len + 2);
			memcpy(tmpnew->_data, ldns_rdf_data(rdf) + src_pos, len + 1);
			tmpnew->_size = len + 2;
			return tmpnew;
		}
		src_pos++;
		src_pos += len;
		len = ldns_rdf_data(rdf)[src_pos];
		labelcnt++;
	}
	return NULL;
}
