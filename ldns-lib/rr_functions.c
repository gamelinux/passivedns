/*
 * rr_function.c
 *
 * function that operate on specific rr types
 *
 * (c) NLnet Labs, 2004-2006
 * See the file LICENSE for the license
 */

/*
 * These come strait from perldoc Net::DNS::RR::xxx
 * first the read variant, then the write. This is
 * not complete.
 */

#include <ldns/config.h>

#include <ldns/ldns.h>

#include <limits.h>
#ifdef _MSC_VER
#include <string.h>
#else
#include <strings.h>
#endif

/**
 * return a specific rdf
 * \param[in] type type of RR
 * \param[in] rr   the rr itself
 * \param[in] pos  at which postion to get it
 * \return the rdf sought
 */
static ldns_rdf *
ldns_rr_function(ldns_rr_type type, const ldns_rr *rr, size_t pos)
{
        if (!rr || ldns_rr_get_type(rr) != type) {
                return NULL;
        }
        return ldns_rr_rdf(rr, pos);
}

/**
 * set a specific rdf
 * \param[in] type type of RR
 * \param[in] rr   the rr itself
 * \param[in] rdf  the rdf to set
 * \param[in] pos  at which postion to set it
 * \return true or false
 */
static bool
ldns_rr_set_function(ldns_rr_type type, ldns_rr *rr, ldns_rdf *rdf, size_t pos)
{
        ldns_rdf *pop;
        if (!rr || ldns_rr_get_type(rr) != type) {
                return false;
        }
        pop = ldns_rr_set_rdf(rr, rdf, pos);
 	ldns_rdf_deep_free(pop);
        return true;
}

/* A/AAAA records */
ldns_rdf *
ldns_rr_a_address(const ldns_rr *r)
{
	/* 2 types to check, cannot use the macro */
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return NULL;
	}
	return ldns_rr_rdf(r, 0);
}

bool
ldns_rr_a_set_address(ldns_rr *r, ldns_rdf *f)
{
	/* 2 types to check, cannot use the macro... */
	ldns_rdf *pop;
	if (!r || (ldns_rr_get_type(r) != LDNS_RR_TYPE_A &&
			ldns_rr_get_type(r) != LDNS_RR_TYPE_AAAA)) {
		return false;
	}
	pop = ldns_rr_set_rdf(r, f, 0);
	if (pop) {
		LDNS_FREE(pop);
		return true;
	} else {
		return false;
	}
}

/* NS record */
ldns_rdf *
ldns_rr_ns_nsdname(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_NS, r, 0);
}

/* MX record */
ldns_rdf *
ldns_rr_mx_preference(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_MX, r, 0);
}

ldns_rdf *
ldns_rr_mx_exchange(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_MX, r, 1);
}

/* RRSIG record */
ldns_rdf *
ldns_rr_rrsig_typecovered(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 0);
}

bool
ldns_rr_rrsig_set_typecovered(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 0);
}

ldns_rdf *
ldns_rr_rrsig_algorithm(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 1);
}

bool
ldns_rr_rrsig_set_algorithm(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 1);
}

ldns_rdf *
ldns_rr_rrsig_labels(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 2);
}

bool
ldns_rr_rrsig_set_labels(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 2);
}

ldns_rdf *
ldns_rr_rrsig_origttl(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 3);
}

bool
ldns_rr_rrsig_set_origttl(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 3);
}

ldns_rdf *
ldns_rr_rrsig_expiration(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 4);
}

bool
ldns_rr_rrsig_set_expiration(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 4);
}

ldns_rdf *
ldns_rr_rrsig_inception(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 5);
}

bool
ldns_rr_rrsig_set_inception(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 5);
}

ldns_rdf *
ldns_rr_rrsig_keytag(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 6);
}

bool
ldns_rr_rrsig_set_keytag(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 6);
}

ldns_rdf *
ldns_rr_rrsig_signame(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 7);
}

bool
ldns_rr_rrsig_set_signame(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 7);
}

ldns_rdf *
ldns_rr_rrsig_sig(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_RRSIG, r, 8);
}

bool
ldns_rr_rrsig_set_sig(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_RRSIG, r, f, 8);
}

/* DNSKEY record */
ldns_rdf *
ldns_rr_dnskey_flags(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 0);
}

bool
ldns_rr_dnskey_set_flags(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 0);
}

ldns_rdf *
ldns_rr_dnskey_protocol(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 1);
}

bool
ldns_rr_dnskey_set_protocol(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 1);
}

ldns_rdf *
ldns_rr_dnskey_algorithm(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 2);
}

bool
ldns_rr_dnskey_set_algorithm(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 2);
}

ldns_rdf *
ldns_rr_dnskey_key(const ldns_rr *r)
{
	return ldns_rr_function(LDNS_RR_TYPE_DNSKEY, r, 3);
}

bool
ldns_rr_dnskey_set_key(ldns_rr *r, ldns_rdf *f)
{
	return ldns_rr_set_function(LDNS_RR_TYPE_DNSKEY, r, f, 3);
}

size_t
ldns_rr_dnskey_key_size_raw(const unsigned char* keydata,
                            const size_t len,
                            const ldns_algorithm alg)
{
	/* for DSA keys */
	uint8_t t;
	
	/* for RSA keys */
	uint16_t exp;
	uint16_t int16;
	
	switch (alg) {
	case LDNS_SIGN_DSA:
	case LDNS_SIGN_DSA_NSEC3:
		if (len > 0) {
			t = keydata[0];
			return (64 + t*8)*8;
		} else {
			return 0;
		}
		break;
	case LDNS_SIGN_RSAMD5:
	case LDNS_SIGN_RSASHA1:
	case LDNS_SIGN_RSASHA1_NSEC3:
#ifdef USE_SHA2
	case LDNS_SIGN_RSASHA256:
	case LDNS_SIGN_RSASHA512:
#endif
		if (len > 0) {
			if (keydata[0] == 0) {
				/* big exponent */
				if (len > 3) {
					memmove(&int16, keydata + 1, 2);
					exp = ntohs(int16);
					return (len - exp - 3)*8;
				} else {
					return 0;
				}
			} else {
				exp = keydata[0];
				return (len-exp-1)*8;
			}
		} else {
			return 0;
		}
		break;
#ifdef USE_GOST
	case LDNS_SIGN_GOST:
		return 512;
		break;
#endif
	case LDNS_SIGN_HMACMD5:
		return len;
		break;
	default:
		return 0;
	}
}

size_t 
ldns_rr_dnskey_key_size(const ldns_rr *key) 
{
	if (!key) {
		return 0;
	}
	return ldns_rr_dnskey_key_size_raw(ldns_rdf_data(ldns_rr_dnskey_key(key)),
	                                   ldns_rdf_size(ldns_rr_dnskey_key(key)),
	                                   ldns_rdf2native_int8(ldns_rr_dnskey_algorithm(key))
	                                  );
}
