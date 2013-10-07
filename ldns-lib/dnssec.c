/* 
 * dnssec.c
 *
 * contains the cryptographic function needed for DNSSEC in ldns
 * The crypto library used is openssl
 *
 * (c) NLnet Labs, 2004-2008
 *
 * See the file LICENSE for the license
 */

#include <ldns/config.h>

#include <ldns/ldns.h>
#include <ldns/dnssec.h>

#ifdef _MSC_VER
#include <string.h>
#else
#include <strings.h>
#endif
#include <time.h>

#ifdef HAVE_SSL
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#endif

ldns_rr *
ldns_dnssec_get_rrsig_for_name_and_type(const ldns_rdf *name,
                                        const ldns_rr_type type,
                                        const ldns_rr_list *rrs)
{
	size_t i;
	ldns_rr *candidate;
	
	if (!name || !rrs) {
		return NULL;
	}
	
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		candidate = ldns_rr_list_rr(rrs, i);
		if (ldns_rr_get_type(candidate) == LDNS_RR_TYPE_RRSIG) {
			if (ldns_dname_compare(ldns_rr_owner(candidate),
			                       name) == 0 &&
			    ldns_rdf2native_int8(ldns_rr_rrsig_typecovered(candidate))
			    == type
			    ) {
				return candidate;
			}
		}
	}
	
	return NULL;
}

ldns_rr *
ldns_dnssec_get_dnskey_for_rrsig(const ldns_rr *rrsig,
						   const ldns_rr_list *rrs)
{
	size_t i;
	ldns_rr *candidate;
	
	if (!rrsig || !rrs) {
		return NULL;
	}
	
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		candidate = ldns_rr_list_rr(rrs, i);
		if (ldns_rr_get_type(candidate) == LDNS_RR_TYPE_DNSKEY) {
			if (ldns_dname_compare(ldns_rr_owner(candidate),
			                       ldns_rr_rrsig_signame(rrsig)) == 0 &&
			    ldns_rdf2native_int16(ldns_rr_rrsig_keytag(rrsig)) ==
			    ldns_calc_keytag(candidate)
			    ) {
				return candidate;
			}
		}
	}
	
	return NULL;
}

ldns_rdf *
ldns_nsec_get_bitmap(ldns_rr *nsec) {
	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		return ldns_rr_rdf(nsec, 1);
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		return ldns_rr_rdf(nsec, 5);
	} else {
		return NULL;
	}
}

/*return the owner name of the closest encloser for name from the list of rrs */
/* this is NOT the hash, but the original name! */
ldns_rdf *
ldns_dnssec_nsec3_closest_encloser(ldns_rdf *qname,
                                   ATTR_UNUSED(ldns_rr_type qtype),
                                   ldns_rr_list *nsec3s)
{
	/* remember parameters, they must match */
	uint8_t algorithm;
	uint32_t iterations;
	uint8_t salt_length;
	uint8_t *salt;

	ldns_rdf *sname, *hashed_sname, *tmp;
	ldns_rr *ce;
	bool flag;
	
	bool exact_match_found;
	bool in_range_found;
	
	ldns_status status;
	ldns_rdf *zone_name;
	
	size_t nsec_i;
	ldns_rr *nsec;
	ldns_rdf *result = NULL;
	qtype = qtype;
	
	if (!qname || !nsec3s || ldns_rr_list_rr_count(nsec3s) < 1) {
		return NULL;
	}

	nsec = ldns_rr_list_rr(nsec3s, 0);
	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt_data(nsec);
	iterations = ldns_nsec3_iterations(nsec);

	sname = ldns_rdf_clone(qname);

	ce = NULL;
	flag = false;
	
	zone_name = ldns_dname_left_chop(ldns_rr_owner(nsec));

	/* algorithm from nsec3-07 8.3 */
	while (ldns_dname_label_count(sname) > 0) {
		exact_match_found = false;
		in_range_found = false;
		
		hashed_sname = ldns_nsec3_hash_name(sname,
									 algorithm,
									 iterations,
									 salt_length,
									 salt);

		status = ldns_dname_cat(hashed_sname, zone_name);

		for (nsec_i = 0; nsec_i < ldns_rr_list_rr_count(nsec3s); nsec_i++) {
			nsec = ldns_rr_list_rr(nsec3s, nsec_i);
			
			/* check values of iterations etc! */
			
			/* exact match? */
			if (ldns_dname_compare(ldns_rr_owner(nsec), hashed_sname) == 0) {
			 	exact_match_found = true;
			} else if (ldns_nsec_covers_name(nsec, hashed_sname)) {
				in_range_found = true;
			}
			
		}
		if (!exact_match_found && in_range_found) {
			flag = true;
		} else if (exact_match_found && flag) {
			result = ldns_rdf_clone(sname);
		} else if (exact_match_found && !flag) {
			/* error! */
			ldns_rdf_deep_free(hashed_sname);
			goto done;
		} else {
			flag = false;
		}
		
		ldns_rdf_deep_free(hashed_sname);
		tmp = sname;
		sname = ldns_dname_left_chop(sname);
		ldns_rdf_deep_free(tmp);
	}

	done:
	LDNS_FREE(salt);
	ldns_rdf_deep_free(zone_name);
	ldns_rdf_deep_free(sname);

	return result;
}

bool
ldns_dnssec_pkt_has_rrsigs(const ldns_pkt *pkt)
{
	size_t i;
	for (i = 0; i < ldns_pkt_ancount(pkt); i++) {
		if (ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_answer(pkt), i)) ==
		    LDNS_RR_TYPE_RRSIG) {
			return true;
		}
	}
	for (i = 0; i < ldns_pkt_nscount(pkt); i++) {
		if (ldns_rr_get_type(ldns_rr_list_rr(ldns_pkt_authority(pkt), i)) ==
		    LDNS_RR_TYPE_RRSIG) {
			return true;
		}
	}
	return false;
}

ldns_rr_list *
ldns_dnssec_pkt_get_rrsigs_for_name_and_type(const ldns_pkt *pkt,
									ldns_rdf *name,
									ldns_rr_type type)
{
	uint16_t t_netorder;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	
	sigs = ldns_pkt_rr_list_by_name_and_type(pkt,
									 name,
									 LDNS_RR_TYPE_RRSIG,
									 LDNS_SECTION_ANY_NOQUESTION
									 );

	t_netorder = htons(type); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE, LDNS_RDF_SIZE_WORD, &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	ldns_rdf_free(rdf_t);
	ldns_rr_list_deep_free(sigs);

	return sigs_covered;

}

ldns_rr_list *
ldns_dnssec_pkt_get_rrsigs_for_type(const ldns_pkt *pkt, ldns_rr_type type)
{
	uint16_t t_netorder;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	
	sigs = ldns_pkt_rr_list_by_type(pkt,
	                                LDNS_RR_TYPE_RRSIG,
	                                LDNS_SECTION_ANY_NOQUESTION
							  );

	t_netorder = htons(type); /* rdf are in network order! */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE,
					 2,
					 &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	ldns_rdf_free(rdf_t);
	ldns_rr_list_deep_free(sigs);

	return sigs_covered;

}

/* used only on the public key RR */
uint16_t
ldns_calc_keytag(const ldns_rr *key)
{
	uint16_t ac16;
	ldns_buffer *keybuf;
	size_t keysize;

	if (!key) {
		return 0;
	}

	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY &&
	    ldns_rr_get_type(key) != LDNS_RR_TYPE_KEY
	    ) {
		return 0;
	}

	/* rdata to buf - only put the rdata in a buffer */
	keybuf = ldns_buffer_new(LDNS_MIN_BUFLEN); /* grows */
	if (!keybuf) {
		return 0;
	}
	(void)ldns_rr_rdata2buffer_wire(keybuf, key);
	/* the current pos in the buffer is the keysize */
	keysize= ldns_buffer_position(keybuf);

	ac16 = ldns_calc_keytag_raw(ldns_buffer_begin(keybuf), keysize);
	ldns_buffer_free(keybuf);
	return ac16;
}

uint16_t ldns_calc_keytag_raw(uint8_t* key, size_t keysize)
{
	unsigned int i;
	uint32_t ac32;
	uint16_t ac16;

	if(keysize < 4) {
		return 0;
	}
	/* look at the algorithm field, copied from 2535bis */
	if (key[3] == LDNS_RSAMD5) {
		ac16 = 0;
		if (keysize > 4) {
			memmove(&ac16, key + keysize - 3, 2);
		}
		ac16 = ntohs(ac16);
		return (uint16_t) ac16;
	} else {
		ac32 = 0;
		for (i = 0; (size_t)i < keysize; ++i) {
			ac32 += (i & 1) ? key[i] : key[i] << 8;
		}
		ac32 += (ac32 >> 16) & 0xFFFF;
		return (uint16_t) (ac32 & 0xFFFF);
	}
}

#ifdef HAVE_SSL
DSA *
ldns_key_buf2dsa(ldns_buffer *key)
{
	return ldns_key_buf2dsa_raw((unsigned char*)ldns_buffer_begin(key),
						   ldns_buffer_position(key));
}

DSA *
ldns_key_buf2dsa_raw(unsigned char* key, size_t len)
{
	uint8_t T;
	uint16_t length;
	uint16_t offset;
	DSA *dsa;
	BIGNUM *Q; BIGNUM *P;
	BIGNUM *G; BIGNUM *Y;

	if(len == 0)
		return NULL;
	T = (uint8_t)key[0];
	length = (64 + T * 8);
	offset = 1;
	
	if (T > 8) {
		return NULL;
	}
	if(len < (size_t)1 + SHA_DIGEST_LENGTH + 3*length)
		return NULL;
	
	Q = BN_bin2bn(key+offset, SHA_DIGEST_LENGTH, NULL);
	offset += SHA_DIGEST_LENGTH;
	
	P = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	G = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	Y = BN_bin2bn(key+offset, (int)length, NULL);
	offset += length;
	
	/* create the key and set its properties */
	dsa = DSA_new();
	dsa->p = P;
	dsa->q = Q;
	dsa->g = G;
	dsa->pub_key = Y;

	return dsa;
}

RSA *
ldns_key_buf2rsa(ldns_buffer *key)
{
	return ldns_key_buf2rsa_raw((unsigned char*)ldns_buffer_begin(key),
						   ldns_buffer_position(key));
}

RSA *
ldns_key_buf2rsa_raw(unsigned char* key, size_t len)
{
	uint16_t offset;
	uint16_t exp;
	uint16_t int16;
	RSA *rsa;
	BIGNUM *modulus;
	BIGNUM *exponent;

	if (len == 0)
		return NULL;
	if (key[0] == 0) {
		if(len < 3)
			return NULL;
		/* need some smart comment here XXX*/
		/* the exponent is too large so it's places
		 * futher...???? */
		memmove(&int16, key+1, 2);
		exp = ntohs(int16);
		offset = 3;
	} else {
		exp = key[0];
		offset = 1;
	}

	/* key length at least one */
	if(len < (size_t)offset + exp + 1)
		return NULL;
	
	/* Exponent */
	exponent = BN_new();
	(void) BN_bin2bn(key+offset, (int)exp, exponent);
	offset += exp;

	/* Modulus */
	modulus = BN_new();
	/* length of the buffer must match the key length! */
	(void) BN_bin2bn(key+offset, (int)(len - offset), modulus);

	rsa = RSA_new();
	rsa->n = modulus;
	rsa->e = exponent;

	return rsa;
}

int
ldns_digest_evp(unsigned char* data, unsigned int len, unsigned char* dest,
	const EVP_MD* md)
{
	EVP_MD_CTX* ctx;
	ctx = EVP_MD_CTX_create();
	if(!ctx) 
		return false;
	if(!EVP_DigestInit_ex(ctx, md, NULL) ||
		!EVP_DigestUpdate(ctx, data, len) ||
		!EVP_DigestFinal_ex(ctx, dest, NULL)) {
		EVP_MD_CTX_destroy(ctx);
		return false;
	}
	EVP_MD_CTX_destroy(ctx);
	return true;
}
#endif /* HAVE_SSL */

ldns_rr *
ldns_key_rr2ds(const ldns_rr *key, ldns_hash h)
{
	ldns_rdf *tmp;
	ldns_rr *ds;
	uint16_t keytag;
	uint8_t  sha1hash;
	uint8_t *digest;
	ldns_buffer *data_buf;
#ifdef USE_GOST
	const EVP_MD* md = NULL;
#endif

	if (ldns_rr_get_type(key) != LDNS_RR_TYPE_DNSKEY) {
		return NULL;
	}

	ds = ldns_rr_new();
	if (!ds) {
		return NULL;
	}
	ldns_rr_set_type(ds, LDNS_RR_TYPE_DS);
	ldns_rr_set_owner(ds, ldns_rdf_clone(
								  ldns_rr_owner(key)));
	ldns_rr_set_ttl(ds, ldns_rr_ttl(key));
	ldns_rr_set_class(ds, ldns_rr_get_class(key));

	switch(h) {
	default:
	case LDNS_SHA1:
		digest = LDNS_XMALLOC(uint8_t, LDNS_SHA1_DIGEST_LENGTH);
		if (!digest) {
			ldns_rr_free(ds);
			return NULL;
		}
		break;
	case LDNS_SHA256:
		digest = LDNS_XMALLOC(uint8_t, LDNS_SHA256_DIGEST_LENGTH);
		if (!digest) {
			ldns_rr_free(ds);
			return NULL;
		}
		break;
	case LDNS_HASH_GOST94:
#ifdef USE_GOST
		(void)ldns_key_EVP_load_gost_id();
		md = EVP_get_digestbyname("md_gost94");
		if(!md) {
			ldns_rr_free(ds);
			return NULL;
		}
		digest = LDNS_XMALLOC(uint8_t, EVP_MD_size(md));
		if (!digest) {
			ldns_rr_free(ds);
			return NULL;
		}
#else
		/* not implemented */
		ldns_rr_free(ds);
		return NULL;
#endif
		break;
	}

	data_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!data_buf) {
		LDNS_FREE(digest);
		ldns_rr_free(ds);
		return NULL;
	}

	/* keytag */
	keytag = htons(ldns_calc_keytag((ldns_rr*)key));
	tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT16,
						   sizeof(uint16_t),
						   &keytag);
	ldns_rr_push_rdf(ds, tmp);

	/* copy the algorithm field */
	ldns_rr_push_rdf(ds, ldns_rdf_clone( ldns_rr_rdf(key, 2))); 

	/* digest hash type */
	sha1hash = (uint8_t)h;
	tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8,
						   sizeof(uint8_t),
						   &sha1hash);
	ldns_rr_push_rdf(ds, tmp);

	/* digest */
	/* owner name */
	tmp = ldns_rdf_clone(ldns_rr_owner(key));
	ldns_dname2canonical(tmp);
	if (ldns_rdf2buffer_wire(data_buf, tmp) != LDNS_STATUS_OK) {
		LDNS_FREE(digest);
		ldns_buffer_free(data_buf);
		ldns_rr_free(ds);
		ldns_rdf_deep_free(tmp);
		return NULL;
	}
	ldns_rdf_deep_free(tmp);

	/* all the rdata's */
	if (ldns_rr_rdata2buffer_wire(data_buf,
							(ldns_rr*)key) != LDNS_STATUS_OK) { 
		LDNS_FREE(digest);
		ldns_buffer_free(data_buf);
		ldns_rr_free(ds);
		return NULL;
	}
	switch(h) {
	case LDNS_SHA1:
		(void) ldns_sha1((unsigned char *) ldns_buffer_begin(data_buf),
		                 (unsigned int) ldns_buffer_position(data_buf),
		                 (unsigned char *) digest);

		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX,
		                            LDNS_SHA1_DIGEST_LENGTH,
		                            digest);
		ldns_rr_push_rdf(ds, tmp);

		break;
	case LDNS_SHA256:
		(void) ldns_sha256((unsigned char *) ldns_buffer_begin(data_buf),
		                   (unsigned int) ldns_buffer_position(data_buf),
		                   (unsigned char *) digest);
		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX,
		                            LDNS_SHA256_DIGEST_LENGTH,
		                            digest);
		ldns_rr_push_rdf(ds, tmp);
		break;
	case LDNS_HASH_GOST94:
#ifdef USE_GOST
		if(!ldns_digest_evp((unsigned char *) ldns_buffer_begin(data_buf),
				(unsigned int) ldns_buffer_position(data_buf),
				(unsigned char *) digest, md)) {
			LDNS_FREE(digest);
			ldns_buffer_free(data_buf);
			ldns_rr_free(ds);
			return NULL;
		}
		tmp = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_HEX,
		                            EVP_MD_size(md),
		                            digest);
		ldns_rr_push_rdf(ds, tmp);
#endif
		break;
	}

	LDNS_FREE(digest);
	ldns_buffer_free(data_buf);
	return ds;
}

ldns_rdf *
ldns_dnssec_create_nsec_bitmap(ldns_rr_type rr_type_list[],
                               size_t size,
                               ldns_rr_type nsec_type)
{
	size_t i;
	uint8_t *bitmap;
	uint16_t bm_len = 0;
	uint16_t i_type;
	ldns_rdf *bitmap_rdf;

	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	if (nsec_type != LDNS_RR_TYPE_NSEC &&
	    nsec_type != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	}

	/* the types in the list should be orders, lowest first,
	   so the last one contains the highest type */
	i_type = rr_type_list[size-1];
	if (i_type < nsec_type) {
		i_type = nsec_type;
	}
	bm_len = i_type / 8 + 2;
	bitmap = LDNS_XMALLOC(uint8_t, bm_len);
	for (i = 0; i < bm_len; i++) {
		bitmap[i] = 0;
	}

	for (i = 0; i < size; i++) {
		i_type = rr_type_list[i];
		ldns_set_bit(bitmap + (int) i_type / 8,
				   (int) (7 - (i_type % 8)),
				   true);
	}

	/* fold it into windows TODO: can this be done directly? */
	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data,
								 uint8_t,
								 cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2,
					  cur_data,
					  cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		}
		cur_data[i%32] = bitmap[i];
		if (bitmap[i] > 0) {
			cur_window_max = i%32;
		}
	}
	if (cur_window_max > 0 || cur_data[0] != 0) {
		/* this window has stuff, add it */
		data = LDNS_XREALLOC(data,
						 uint8_t,
						 cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}
	
	bitmap_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC,
								cur_data_size,
								data);

	LDNS_FREE(bitmap);
	LDNS_FREE(data);

	return bitmap_rdf;
}

int
ldns_dnssec_rrsets_contains_type(ldns_dnssec_rrsets *rrsets,
                                 ldns_rr_type type)
{
	ldns_dnssec_rrsets *cur_rrset = rrsets;
	while (cur_rrset) {
		if (cur_rrset->type == type) {
			return 1;
		}
		cur_rrset = cur_rrset->next;
	}
	return 0;
}

/* returns true if the current dnssec_rrset from the given list of rrsets
 * is glue */
static int
is_glue(ldns_dnssec_rrsets *cur_rrsets, ldns_dnssec_rrsets *orig_rrsets)
{
	/* only glue if a or aaaa if there are no ns, unless there is soa */
	return (cur_rrsets->type == LDNS_RR_TYPE_A ||
	        cur_rrsets->type ==  LDNS_RR_TYPE_AAAA) &&
	        (ldns_dnssec_rrsets_contains_type(orig_rrsets,
	              LDNS_RR_TYPE_NS) &&
	        !ldns_dnssec_rrsets_contains_type(orig_rrsets,
	              LDNS_RR_TYPE_SOA));
}

ldns_rr *
ldns_dnssec_create_nsec(ldns_dnssec_name *from,
                        ldns_dnssec_name *to,
                        ldns_rr_type nsec_type)
{
	ldns_rr *nsec_rr;
	ldns_rr_type types[1024];
	size_t type_count = 0;
	ldns_dnssec_rrsets *cur_rrsets;

	if (!from || !to || (nsec_type != LDNS_RR_TYPE_NSEC &&
					 nsec_type != LDNS_RR_TYPE_NSEC3)) {
		return NULL;
	}

	nsec_rr = ldns_rr_new();
	ldns_rr_set_type(nsec_rr, nsec_type);
	ldns_rr_set_owner(nsec_rr, ldns_rdf_clone(ldns_dnssec_name_name(from)));
	ldns_rr_push_rdf(nsec_rr, ldns_rdf_clone(ldns_dnssec_name_name(to)));

	cur_rrsets = from->rrsets;
	while (cur_rrsets) {
		if (is_glue(cur_rrsets, from->rrsets)) {
			cur_rrsets = cur_rrsets->next;
			continue;
		}
		types[type_count] = cur_rrsets->type;
		type_count++;
		cur_rrsets = cur_rrsets->next;
	}
	types[type_count] = LDNS_RR_TYPE_RRSIG;
	type_count++;
	types[type_count] = LDNS_RR_TYPE_NSEC;
	type_count++;

	ldns_rr_push_rdf(nsec_rr, ldns_dnssec_create_nsec_bitmap(types,
	                               type_count,
	                               nsec_type));

	return nsec_rr;
}

ldns_rr *
ldns_dnssec_create_nsec3(ldns_dnssec_name *from,
					ldns_dnssec_name *to,
					ldns_rdf *zone_name,
					uint8_t algorithm,
					uint8_t flags,
					uint16_t iterations,
					uint8_t salt_length,
					uint8_t *salt)
{
	ldns_rr *nsec_rr;
	ldns_rr_type types[1024];
	size_t type_count = 0;
	ldns_dnssec_rrsets *cur_rrsets;
	ldns_status status;

	flags = flags;

	if (!from) {
		return NULL;
	}

	nsec_rr = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_owner(nsec_rr,
	                  ldns_nsec3_hash_name(ldns_dnssec_name_name(from),
	                  algorithm,
	                  iterations,
	                  salt_length,
	                  salt));
	status = ldns_dname_cat(ldns_rr_owner(nsec_rr), zone_name);
	ldns_nsec3_add_param_rdfs(nsec_rr,
	                          algorithm,
	                          flags,
	                          iterations,
	                          salt_length,
	                          salt);

	cur_rrsets = from->rrsets;
	while (cur_rrsets) {
		if (is_glue(cur_rrsets, from->rrsets)) {
			cur_rrsets = cur_rrsets->next;
			continue;
		}
		types[type_count] = cur_rrsets->type;
		type_count++;
		cur_rrsets = cur_rrsets->next;
	}
	/* always add rrsig type if this is not an unsigned 
	 * delegation
	 */
	if (type_count > 0 &&
	    !(type_count == 1 && types[0] == LDNS_RR_TYPE_NS)) {
		types[type_count] = LDNS_RR_TYPE_RRSIG;
		type_count++;
	}
	
	/* leave next rdata empty if they weren't precomputed yet */
	if (to && to->hashed_name) {
		(void) ldns_rr_set_rdf(nsec_rr,
		                       ldns_rdf_clone(to->hashed_name),
		                       4);
	} else {
		(void) ldns_rr_set_rdf(nsec_rr, NULL, 4);
	}

	ldns_rr_push_rdf(nsec_rr,
	                 ldns_dnssec_create_nsec_bitmap(types,
	                 type_count,
	                 LDNS_RR_TYPE_NSEC3));

	return nsec_rr;
}

ldns_rr *
ldns_create_nsec(ldns_rdf *cur_owner, ldns_rdf *next_owner, ldns_rr_list *rrs)
{
	/* we do not do any check here - garbage in, garbage out */
	
	/* the the start and end names - get the type from the
	 * before rrlist */

	/* inefficient, just give it a name, a next name, and a list of rrs */
	/* we make 1 big uberbitmap first, then windows */
	/* todo: make something more efficient :) */
	uint16_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 2);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;

	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	nsec = ldns_rr_new();
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC);
	ldns_rr_set_owner(nsec, ldns_rdf_clone(cur_owner));
	ldns_rr_push_rdf(nsec, ldns_rdf_clone(next_owner));

	bitmap[0] = 0;
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);

		if (ldns_rdf_compare(cur_owner,
						 ldns_rr_owner(i_rr)) == 0) {
			/* add type to bitmap */
			i_type = ldns_rr_get_type(i_rr);
			if ((i_type / 8) + 1 > bm_len) {
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
				/* set to 0 */
				for (; bm_len <= i_type / 8; bm_len++) {
					bitmap[bm_len] = 0;
				}
			}
			ldns_set_bit(bitmap + (int) i_type / 8,
					   (int) (7 - (i_type % 8)),
					   true);
		}
	}
	/* add NSEC and RRSIG anyway */
	i_type = LDNS_RR_TYPE_RRSIG;
	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);
	i_type = LDNS_RR_TYPE_NSEC;

	if (i_type / 8 > bm_len) {
		bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 2);
		/* set to 0 */
		for (; bm_len <= i_type / 8; bm_len++) {
			bitmap[bm_len] = 0;
		}
	}
	ldns_set_bit(bitmap + (int) i_type / 8, (int) (7 - (i_type % 8)), true);

	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data,
								 uint8_t,
								 cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2,
					  cur_data,
					  cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		} else {
			cur_data[i%32] = bitmap[i];
			if (bitmap[i] > 0) {
				cur_window_max = i%32;
			}
		}
	}
	if (cur_window_max > 0) {
		/* this window has stuff, add it */
		data = LDNS_XREALLOC(data,
						 uint8_t,
						 cur_data_size + cur_window_max + 3);
		data[cur_data_size] = cur_window;
		data[cur_data_size + 1] = cur_window_max + 1;
		memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
		cur_data_size += cur_window_max + 3;
	}

	ldns_rr_push_rdf(nsec,
				  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC,
								    cur_data_size,
								    data));

	LDNS_FREE(bitmap);
	LDNS_FREE(data);
	return nsec;
}

ldns_rdf *
ldns_nsec3_hash_name(ldns_rdf *name,
				 uint8_t algorithm,
				 uint16_t iterations,
				 uint8_t salt_length,
				 uint8_t *salt)
{
	char *orig_owner_str;
	size_t hashed_owner_str_len;
	ldns_rdf *hashed_owner;
	unsigned char *hashed_owner_str;
	char *hashed_owner_b32;
	size_t hashed_owner_b32_len;
	uint32_t cur_it;
	/* define to contain the largest possible hash, which is
	 * sha1 at the moment */
	unsigned char hash[LDNS_SHA1_DIGEST_LENGTH];
	ldns_status status;
	
	/* prepare the owner name according to the draft section bla */
	orig_owner_str = ldns_rdf2str(name);
	
	/* TODO: mnemonic list for hash algs SHA-1, default to 1 now (sha1) */
	algorithm = algorithm;
	
	hashed_owner_str_len = salt_length + ldns_rdf_size(name);
	hashed_owner_str = LDNS_XMALLOC(unsigned char, hashed_owner_str_len);
	memcpy(hashed_owner_str, ldns_rdf_data(name), ldns_rdf_size(name));
	memcpy(hashed_owner_str + ldns_rdf_size(name), salt, salt_length);

	for (cur_it = iterations + 1; cur_it > 0; cur_it--) {
		(void) ldns_sha1((unsigned char *) hashed_owner_str,
		                 (unsigned int) hashed_owner_str_len, hash);

		LDNS_FREE(hashed_owner_str);
		hashed_owner_str_len = salt_length + LDNS_SHA1_DIGEST_LENGTH;
		hashed_owner_str = LDNS_XMALLOC(unsigned char, hashed_owner_str_len);
		if (!hashed_owner_str) {
			fprintf(stderr, "Memory error\n");
			abort();
		}
		memcpy(hashed_owner_str, hash, LDNS_SHA1_DIGEST_LENGTH);
		memcpy(hashed_owner_str + LDNS_SHA1_DIGEST_LENGTH, salt, salt_length);
		hashed_owner_str_len = LDNS_SHA1_DIGEST_LENGTH + salt_length;
	}

	LDNS_FREE(orig_owner_str);
	LDNS_FREE(hashed_owner_str);
	hashed_owner_str = hash;
	hashed_owner_str_len = LDNS_SHA1_DIGEST_LENGTH;

	hashed_owner_b32 = LDNS_XMALLOC(char,
							  ldns_b32_ntop_calculate_size(
							       hashed_owner_str_len) + 1);
	hashed_owner_b32_len =
		(size_t) ldns_b32_ntop_extended_hex((uint8_t *) hashed_owner_str,
									 hashed_owner_str_len,
									 hashed_owner_b32,
									 ldns_b32_ntop_calculate_size(
										 hashed_owner_str_len));
	if (hashed_owner_b32_len < 1) {
		fprintf(stderr, "Error in base32 extended hex encoding ");
		fprintf(stderr, "of hashed owner name (name: ");
		ldns_rdf_print(stderr, name);
		fprintf(stderr, ", return code: %u)\n",
		        (unsigned int) hashed_owner_b32_len);
		LDNS_FREE(hashed_owner_b32);
		return NULL;
	}
	hashed_owner_str_len = hashed_owner_b32_len;
	hashed_owner_b32[hashed_owner_b32_len] = '\0';

	status = ldns_str2rdf_dname(&hashed_owner, hashed_owner_b32);
	if (status != LDNS_STATUS_OK) {
		fprintf(stderr, "Error creating rdf from %s\n", hashed_owner_b32);
		LDNS_FREE(hashed_owner_b32);
		return NULL;
	}

	LDNS_FREE(hashed_owner_b32);
	return hashed_owner;
}

void
ldns_nsec3_add_param_rdfs(ldns_rr *rr,
					 uint8_t algorithm, 
					 uint8_t flags,
					 uint16_t iterations,
					 uint8_t salt_length,
					 uint8_t *salt)
{
	ldns_rdf *salt_rdf = NULL;
	uint8_t *salt_data = NULL;
	ldns_rdf *old;

	old = ldns_rr_set_rdf(rr,
	                      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8,
	                                            1, (void*)&algorithm),
	                      0);
	if (old) ldns_rdf_deep_free(old);

	old = ldns_rr_set_rdf(rr,
	                      ldns_rdf_new_frm_data(LDNS_RDF_TYPE_INT8,
	                                            1, (void*)&flags),
	                      1);
	if (old) ldns_rdf_deep_free(old);
	
	old = ldns_rr_set_rdf(rr,
                          ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16,
                                                iterations),
	                      2);
	if (old) ldns_rdf_deep_free(old);
	
	salt_data = LDNS_XMALLOC(uint8_t, salt_length + 1);
	salt_data[0] = salt_length;
	memcpy(salt_data + 1, salt, salt_length);
	salt_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC3_SALT,
							   salt_length + 1,
							   salt_data);

	old = ldns_rr_set_rdf(rr, salt_rdf, 3);
	if (old) ldns_rdf_deep_free(old);
	LDNS_FREE(salt_data);
}

static int
rr_list_delegation_only(ldns_rdf *origin, ldns_rr_list *rr_list)
{
	size_t i;
	ldns_rr *cur_rr;
	if (!origin || !rr_list) return 0;
	for (i = 0; i < ldns_rr_list_rr_count(rr_list); i++) {
		cur_rr = ldns_rr_list_rr(rr_list, i);
		if (ldns_dname_compare(ldns_rr_owner(cur_rr), origin) == 0) {
			return 0;
		}
		if (ldns_rr_get_type(cur_rr) != LDNS_RR_TYPE_NS) {
			return 0;
		}
	}
	return 1;
}

/* this will NOT return the NSEC3  completed, you will have to run the
   finalize function on the rrlist later! */
ldns_rr *
ldns_create_nsec3(ldns_rdf *cur_owner,
                  ldns_rdf *cur_zone,
                  ldns_rr_list *rrs,
                  uint8_t algorithm,
                  uint8_t flags,
                  uint16_t iterations,
                  uint8_t salt_length,
                  uint8_t *salt,
                  bool emptynonterminal)
{
	size_t i;
	ldns_rr *i_rr;

	uint8_t *bitmap = LDNS_XMALLOC(uint8_t, 1);
	uint16_t bm_len = 0;
	uint16_t i_type;

	ldns_rr *nsec = NULL;
	ldns_rdf *hashed_owner = NULL;
	
	uint8_t *data = NULL;
	uint8_t cur_data[32];
	uint8_t cur_window = 0;
	uint8_t cur_window_max = 0;
	uint16_t cur_data_size = 0;

	ldns_status status;

	
	hashed_owner = ldns_nsec3_hash_name(cur_owner,
								 algorithm,
								 iterations,
								 salt_length,
								 salt);
	status = ldns_dname_cat(hashed_owner, cur_zone);
	
	nsec = ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_type(nsec, LDNS_RR_TYPE_NSEC3);
	ldns_rr_set_owner(nsec, hashed_owner);
	
	ldns_nsec3_add_param_rdfs(nsec,
						 algorithm,
						 flags,
						 iterations,
						 salt_length,
						 salt);
	(void) ldns_rr_set_rdf(nsec, NULL, 4);

	bitmap[0] = 0;
	for (i = 0; i < ldns_rr_list_rr_count(rrs); i++) {
		i_rr = ldns_rr_list_rr(rrs, i);

		if (ldns_rdf_compare(cur_owner,
		                     ldns_rr_owner(i_rr)) == 0) {
			/* add type to bitmap */
			i_type = ldns_rr_get_type(i_rr);
			if ((i_type / 8) + 1 > bm_len) {
				bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
				/* set to 0 */
				for (; bm_len <= i_type / 8; bm_len++) {
					bitmap[bm_len] = 0;
				}
			}
			ldns_set_bit(bitmap + (int) i_type / 8,
					   (int) (7 - (i_type % 8)),
					   true);
		}
	}
	/* add NSEC and RRSIG anyway, but only if this is not an ENT or
	 * an unsigned delegation */
	if (!emptynonterminal && !rr_list_delegation_only(cur_zone, rrs)) {
		i_type = LDNS_RR_TYPE_RRSIG;
		if (i_type / 8 > bm_len) {
			bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
			/* set to 0 */
			for (; bm_len <= i_type / 8; bm_len++) {
				bitmap[bm_len] = 0;
			}
		}
		ldns_set_bit(bitmap + (int) i_type / 8,
				   (int) (7 - (i_type % 8)),
				   true);
	}

	/* and SOA if owner == zone */
	if (ldns_dname_compare(cur_zone, cur_owner) == 0) {
		i_type = LDNS_RR_TYPE_SOA;
		if (i_type / 8 > bm_len) {
			bitmap = LDNS_XREALLOC(bitmap, uint8_t, (i_type / 8) + 1);
			/* set to 0 */
			for (; bm_len <= i_type / 8; bm_len++) {
				bitmap[bm_len] = 0;
			}
		}
		ldns_set_bit(bitmap + (int) i_type / 8,
				   (int) (7 - (i_type % 8)),
				   true);
	}

	memset(cur_data, 0, 32);
	for (i = 0; i < bm_len; i++) {
		if (i / 32 > cur_window) {
			/* check, copy, new */
			if (cur_window_max > 0) {
				/* this window has stuff, add it */
				data = LDNS_XREALLOC(data,
								 uint8_t,
								 cur_data_size + cur_window_max + 3);
				data[cur_data_size] = cur_window;
				data[cur_data_size + 1] = cur_window_max + 1;
				memcpy(data + cur_data_size + 2,
					  cur_data,
					  cur_window_max+1);
				cur_data_size += cur_window_max + 3;
			}
			cur_window++;
			cur_window_max = 0;
			memset(cur_data, 0, 32);
		} else {
			cur_data[i%32] = bitmap[i];
			if (bitmap[i] > 0) {
				cur_window_max = i%32;
			}
		}
	}
	data = LDNS_XREALLOC(data,
					 uint8_t,
					 cur_data_size + cur_window_max + 3);
	data[cur_data_size] = cur_window;
	data[cur_data_size + 1] = cur_window_max + 1;
	memcpy(data + cur_data_size + 2, cur_data, cur_window_max+1);
	cur_data_size += cur_window_max + 3;

	ldns_rr_push_rdf(nsec,
	                 ldns_rdf_new_frm_data(LDNS_RDF_TYPE_NSEC,
	                                       cur_data_size,
	                                       data));

	LDNS_FREE(bitmap);
	LDNS_FREE(data);

	return nsec;
}

uint8_t
ldns_nsec3_algorithm(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 0)) > 0
	    ) {
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec3_rr, 0));
	}
	return 0;
}

uint8_t
ldns_nsec3_flags(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 1)) > 0
	    ) {
		return ldns_rdf2native_int8(ldns_rr_rdf(nsec3_rr, 1));
	}
	return 0;
}

bool
ldns_nsec3_optout(const ldns_rr *nsec3_rr)
{
	return (ldns_nsec3_flags(nsec3_rr) & LDNS_NSEC3_VARS_OPTOUT_MASK);
}

uint16_t
ldns_nsec3_iterations(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3 &&
	    ldns_rdf_size(ldns_rr_rdf(nsec3_rr, 2)) > 0
	    ) {
		return ldns_rdf2native_int16(ldns_rr_rdf(nsec3_rr, 2));
	}
	return 0;
	
}

ldns_rdf *
ldns_nsec3_salt(const ldns_rr *nsec3_rr)
{
	if (nsec3_rr && ldns_rr_get_type(nsec3_rr) == LDNS_RR_TYPE_NSEC3) {
		return ldns_rr_rdf(nsec3_rr, 3);
	}
	return NULL;
}

uint8_t
ldns_nsec3_salt_length(const ldns_rr *nsec3_rr)
{
	ldns_rdf *salt_rdf = ldns_nsec3_salt(nsec3_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
		return (uint8_t) ldns_rdf_data(salt_rdf)[0];
	}
	return 0;
}

/* allocs data, free with LDNS_FREE() */
uint8_t *
ldns_nsec3_salt_data(const ldns_rr *nsec3_rr)
{
	uint8_t salt_length;
	uint8_t *salt;

	ldns_rdf *salt_rdf = ldns_nsec3_salt(nsec3_rr);
	if (salt_rdf && ldns_rdf_size(salt_rdf) > 0) {
	    	salt_length = ldns_rdf_data(salt_rdf)[0];
		salt = LDNS_XMALLOC(uint8_t, salt_length);
		memcpy(salt, &ldns_rdf_data(salt_rdf)[1], salt_length);
		return salt;
	}
	return NULL;
}

ldns_rdf *
ldns_nsec3_next_owner(const ldns_rr *nsec3_rr)
{
	if (!nsec3_rr || ldns_rr_get_type(nsec3_rr) != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec3_rr, 4);
	}
}

ldns_rdf *
ldns_nsec3_bitmap(const ldns_rr *nsec3_rr)
{
	if (!nsec3_rr || ldns_rr_get_type(nsec3_rr) != LDNS_RR_TYPE_NSEC3) {
		return NULL;
	} else {
		return ldns_rr_rdf(nsec3_rr, 5);
	}
}

ldns_rdf *
ldns_nsec3_hash_name_frm_nsec3(const ldns_rr *nsec, ldns_rdf *name)
{
	uint8_t algorithm;
	uint16_t iterations;
	uint8_t salt_length;
	uint8_t *salt = 0;
	
	ldns_rdf *hashed_owner;

	algorithm = ldns_nsec3_algorithm(nsec);
	salt_length = ldns_nsec3_salt_length(nsec);
	salt = ldns_nsec3_salt_data(nsec);
	iterations = ldns_nsec3_iterations(nsec);
	
	hashed_owner = ldns_nsec3_hash_name(name,
								 algorithm,
								 iterations,
								 salt_length,
								 salt);
	
	LDNS_FREE(salt);
	return hashed_owner;
}

bool
ldns_nsec_bitmap_covers_type(const ldns_rdf *nsec_bitmap, ldns_rr_type type)
{
	uint8_t window_block_nr;
	uint8_t bitmap_length;
	uint16_t cur_type;
	uint16_t pos = 0;
	uint16_t bit_pos;
	uint8_t *data = ldns_rdf_data(nsec_bitmap);
	
	while(pos < ldns_rdf_size(nsec_bitmap)) {
		window_block_nr = data[pos];
		bitmap_length = data[pos + 1];
		pos += 2;
		
		for (bit_pos = 0; bit_pos < (bitmap_length) * 8; bit_pos++) {
			if (ldns_get_bit(&data[pos], bit_pos)) {
				cur_type = 256 * (uint16_t) window_block_nr + bit_pos;
				if (cur_type == type) {
					return true;
				}
			}
		}
		
		pos += (uint16_t) bitmap_length;
	}
	return false;
}

bool
ldns_nsec_covers_name(const ldns_rr *nsec, const ldns_rdf *name)
{
	ldns_rdf *nsec_owner = ldns_rr_owner(nsec);
	ldns_rdf *hash_next;
	char *next_hash_str;
	ldns_rdf *nsec_next = NULL;
	ldns_status status;
	ldns_rdf *chopped_dname;
	bool result;
	
	if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC) {
		nsec_next = ldns_rdf_clone(ldns_rr_rdf(nsec, 0));
	} else if (ldns_rr_get_type(nsec) == LDNS_RR_TYPE_NSEC3) {
		hash_next = ldns_nsec3_next_owner(nsec);
		next_hash_str = ldns_rdf2str(hash_next);
		nsec_next = ldns_dname_new_frm_str(next_hash_str);
		LDNS_FREE(next_hash_str);
		chopped_dname = ldns_dname_left_chop(nsec_owner);
		status = ldns_dname_cat(nsec_next, chopped_dname);
		ldns_rdf_deep_free(chopped_dname);
		if (status != LDNS_STATUS_OK) {
			printf("error catting: %s\n", ldns_get_errorstr_by_id(status));
		}
	} else {
		ldns_rdf_deep_free(nsec_next);
		return false;
	}
	
	/* in the case of the last nsec */
	if(ldns_dname_compare(nsec_owner, nsec_next) > 0) {
		result = (ldns_dname_compare(nsec_owner, name) <= 0 ||
				ldns_dname_compare(name, nsec_next) < 0);
	} else {
		result = (ldns_dname_compare(nsec_owner, name) <= 0 &&
		          ldns_dname_compare(name, nsec_next) < 0);
	}
	
	ldns_rdf_deep_free(nsec_next);
	return result;
}

#ifdef HAVE_SSL
/* sig may be null - if so look in the packet */
ldns_status
ldns_pkt_verify(ldns_pkt *p, ldns_rr_type t, ldns_rdf *o, 
			 ldns_rr_list *k, ldns_rr_list *s, ldns_rr_list *good_keys)
{
	ldns_rr_list *rrset;
	ldns_rr_list *sigs;
	ldns_rr_list *sigs_covered;
	ldns_rdf *rdf_t;
	ldns_rr_type t_netorder;

	if (!k) {
		return LDNS_STATUS_ERR;
		/* return LDNS_STATUS_CRYPTO_NO_DNSKEY; */
	}

	if (t == LDNS_RR_TYPE_RRSIG) {
		/* we don't have RRSIG(RRSIG) (yet? ;-) ) */
		return LDNS_STATUS_ERR;
	}
	
	if (s) {
		/* if s is not NULL, the sigs are given to use */
		sigs = s;
	} else {
		/* otherwise get them from the packet */
		sigs = ldns_pkt_rr_list_by_name_and_type(p, o, LDNS_RR_TYPE_RRSIG, 
									  LDNS_SECTION_ANY_NOQUESTION);
		if (!sigs) {
			/* no sigs */
			return LDNS_STATUS_ERR;
			/* return LDNS_STATUS_CRYPTO_NO_RRSIG; */
		}
	}

	/* rrsig are subtyped, so now we need to find the correct
	 * sigs for the type t
	 */
	t_netorder = htons(t); /* rdf are in network order! */
	/* a type identifier is a 16-bit number, so the size is 2 bytes */
	rdf_t = ldns_rdf_new(LDNS_RDF_TYPE_TYPE,
					 2,
					 &t_netorder);
	sigs_covered = ldns_rr_list_subtype_by_rdf(sigs, rdf_t, 0);
	
	rrset = ldns_pkt_rr_list_by_name_and_type(p,
									  o,
									  t,
									  LDNS_SECTION_ANY_NOQUESTION);

	if (!rrset) {
		return LDNS_STATUS_ERR;
	}

	if (!sigs_covered) {
		return LDNS_STATUS_ERR;
	}

	return ldns_verify(rrset, sigs, k, good_keys);
}
#endif /* HAVE_SSL */

ldns_status
ldns_dnssec_chain_nsec3_list(ldns_rr_list *nsec3_rrs)
{
	size_t i;
	char *next_nsec_owner_str;
	ldns_rdf *next_nsec_owner_label;
	ldns_rdf *next_nsec_rdf;
	ldns_status status = LDNS_STATUS_OK;

	for (i = 0; i < ldns_rr_list_rr_count(nsec3_rrs); i++) {
		if (i == ldns_rr_list_rr_count(nsec3_rrs) - 1) {
			next_nsec_owner_label = 
				ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs,
													  0)), 0);
			next_nsec_owner_str = ldns_rdf2str(next_nsec_owner_label);
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1]
			    == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1]
					= '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf,
									next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i),
							 next_nsec_rdf, 4)) {
				/* todo: error */
			}

			ldns_rdf_deep_free(next_nsec_owner_label);
			LDNS_FREE(next_nsec_owner_str);
		} else {
			next_nsec_owner_label = 
				ldns_dname_label(ldns_rr_owner(ldns_rr_list_rr(nsec3_rrs,
													  i + 1)),
							  0);
			next_nsec_owner_str = ldns_rdf2str(next_nsec_owner_label);
			if (next_nsec_owner_str[strlen(next_nsec_owner_str) - 1]
			    == '.') {
				next_nsec_owner_str[strlen(next_nsec_owner_str) - 1]
					= '\0';
			}
			status = ldns_str2rdf_b32_ext(&next_nsec_rdf,
									next_nsec_owner_str);
			ldns_rdf_deep_free(next_nsec_owner_label);
			LDNS_FREE(next_nsec_owner_str);
			if (!ldns_rr_set_rdf(ldns_rr_list_rr(nsec3_rrs, i),
							 next_nsec_rdf, 4)) {
				/* todo: error */
			}
		}
	}
	return status;
}

int
qsort_rr_compare_nsec3(const void *a, const void *b)
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
	return ldns_rdf_compare(ldns_rr_owner(rr1), ldns_rr_owner(rr2));
}

void
ldns_rr_list_sort_nsec3(ldns_rr_list *unsorted)
{
	qsort(unsorted->_rrs,
	      ldns_rr_list_rr_count(unsorted),
	      sizeof(ldns_rr *),
	      qsort_rr_compare_nsec3);
}

int
ldns_dnssec_default_add_to_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_LEAVE_ADD_NEW;
}

int
ldns_dnssec_default_leave_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_LEAVE_NO_ADD;
}

int
ldns_dnssec_default_delete_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_REMOVE_NO_ADD;
}

int
ldns_dnssec_default_replace_signatures(ldns_rr *sig, void *n)
{
	sig = sig;
	n = n;
	return LDNS_SIGNATURE_REMOVE_ADD_NEW;
}

#ifdef HAVE_SSL
ldns_rdf *
ldns_convert_dsa_rrsig_asn12rdf(const ldns_buffer *sig,
						  const long sig_len)
{
	ldns_rdf *sigdata_rdf;
	DSA_SIG *dsasig;
	unsigned char *dsasig_data = (unsigned char*)ldns_buffer_begin(sig);
	size_t byte_offset;

	dsasig = d2i_DSA_SIG(NULL,
					 (const unsigned char **)&dsasig_data,
					 sig_len);
	if (!dsasig) {
		return NULL;
	}

	dsasig_data = LDNS_XMALLOC(unsigned char, 41);
	dsasig_data[0] = 0;
	byte_offset = (size_t) (20 - BN_num_bytes(dsasig->r));
	if (byte_offset > 20) {
		return NULL;
	}
	memset(&dsasig_data[1], 0, byte_offset);
	BN_bn2bin(dsasig->r, &dsasig_data[1 + byte_offset]);
	byte_offset = (size_t) (20 - BN_num_bytes(dsasig->s));
	if (byte_offset > 20) {
		return NULL;
	}
	memset(&dsasig_data[21], 0, byte_offset);
	BN_bn2bin(dsasig->s, &dsasig_data[21 + byte_offset]);
	
	sigdata_rdf = ldns_rdf_new(LDNS_RDF_TYPE_B64, 41, dsasig_data);
	DSA_SIG_free(dsasig);

	return sigdata_rdf;
}

ldns_status
ldns_convert_dsa_rrsig_rdf2asn1(ldns_buffer *target_buffer,
						  const ldns_rdf *sig_rdf)
{
	/* the EVP api wants the DER encoding of the signature... */
	uint8_t t;
	BIGNUM *R, *S;
	DSA_SIG *dsasig;
	unsigned char *raw_sig = NULL;
	int raw_sig_len;
	
	/* extract the R and S field from the sig buffer */
	t = ldns_rdf_data(sig_rdf)[0];
	R = BN_new();
	(void) BN_bin2bn((unsigned char *) ldns_rdf_data(sig_rdf) + 1,
	                 SHA_DIGEST_LENGTH, R);
	S = BN_new();
	(void) BN_bin2bn((unsigned char *) ldns_rdf_data(sig_rdf) + 21,
	                 SHA_DIGEST_LENGTH, S);

	dsasig = DSA_SIG_new();
	if (!dsasig) {
		return LDNS_STATUS_MEM_ERR;
	}

	dsasig->r = R;
	dsasig->s = S;
	
	raw_sig_len = i2d_DSA_SIG(dsasig, &raw_sig);
	if (raw_sig_len < 0) {
		DSA_SIG_free(dsasig);
		free(raw_sig);
		return LDNS_STATUS_SSL_ERR;
	}
	if (ldns_buffer_reserve(target_buffer, (size_t) raw_sig_len)) {
		ldns_buffer_write(target_buffer, raw_sig, (size_t)raw_sig_len);
	}

	DSA_SIG_free(dsasig);
	free(raw_sig);

	return ldns_buffer_status(target_buffer);
}
#endif /* HAVE_SSL */
