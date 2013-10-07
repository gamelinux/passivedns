#include <ldns/config.h>

#include <ldns/ldns.h>

#include <ldns/dnssec.h>
#include <ldns/dnssec_sign.h>

#ifdef _MSC_VER
#include <string.h>
#else
#include <strings.h>
#endif
#include <time.h>

#ifdef HAVE_SSL
/* this entire file is rather useless when you don't have
 * crypto...
 */
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/md5.h>
#endif /* HAVE_SSL */

ldns_rr *
ldns_create_empty_rrsig(ldns_rr_list *rrset,
                        ldns_key *current_key)
{
	uint32_t orig_ttl;
	time_t now;
	ldns_rr *current_sig;
	uint8_t label_count;

	label_count = ldns_dname_label_count(ldns_rr_owner(ldns_rr_list_rr(rrset,
	                                                   0)));
	
	current_sig = ldns_rr_new_frm_type(LDNS_RR_TYPE_RRSIG);
	
	/* set the type on the new signature */
	orig_ttl = ldns_rr_ttl(ldns_rr_list_rr(rrset, 0));

	ldns_rr_set_ttl(current_sig, orig_ttl);
	ldns_rr_set_owner(current_sig, 
			  ldns_rdf_clone(
			       ldns_rr_owner(
				    ldns_rr_list_rr(rrset,
						    0))));

	/* fill in what we know of the signature */
	
	/* set the orig_ttl */
	(void)ldns_rr_rrsig_set_origttl(
		   current_sig, 
		   ldns_native2rdf_int32(LDNS_RDF_TYPE_INT32,
					 orig_ttl));
	/* the signers name */
	(void)ldns_rr_rrsig_set_signame(
			current_sig, 
			ldns_rdf_clone(ldns_key_pubkey_owner(current_key)));
	/* label count - get it from the first rr in the rr_list */
	(void)ldns_rr_rrsig_set_labels(
			current_sig, 
			ldns_native2rdf_int8(LDNS_RDF_TYPE_INT8,
			                     label_count));
	/* inception, expiration */
	now = time(NULL);
	if (ldns_key_inception(current_key) != 0) {
		(void)ldns_rr_rrsig_set_inception(
				current_sig,
				ldns_native2rdf_int32(
				    LDNS_RDF_TYPE_TIME, 
				    ldns_key_inception(current_key)));
	} else {
		(void)ldns_rr_rrsig_set_inception(
				current_sig,
				ldns_native2rdf_int32(LDNS_RDF_TYPE_TIME, now));
	}
	if (ldns_key_expiration(current_key) != 0) {
		(void)ldns_rr_rrsig_set_expiration(
				current_sig,
				ldns_native2rdf_int32(
				    LDNS_RDF_TYPE_TIME, 
				    ldns_key_expiration(current_key)));
	} else {
		(void)ldns_rr_rrsig_set_expiration(
			     current_sig,
				ldns_native2rdf_int32(
				    LDNS_RDF_TYPE_TIME, 
				    now + LDNS_DEFAULT_EXP_TIME));
	}

	(void)ldns_rr_rrsig_set_keytag(
		   current_sig,
		   ldns_native2rdf_int16(LDNS_RDF_TYPE_INT16, 
		                         ldns_key_keytag(current_key)));

	(void)ldns_rr_rrsig_set_algorithm(
			current_sig,
			ldns_native2rdf_int8(
			    LDNS_RDF_TYPE_ALG, 
			    ldns_key_algorithm(current_key)));

	(void)ldns_rr_rrsig_set_typecovered(
			current_sig,
			ldns_native2rdf_int16(
			    LDNS_RDF_TYPE_TYPE,
			    ldns_rr_get_type(ldns_rr_list_rr(rrset,
			                                     0))));
	return current_sig;
}

#ifdef HAVE_SSL
ldns_rdf *
ldns_sign_public_buffer(ldns_buffer *sign_buf, ldns_key *current_key)
{
	ldns_rdf *b64rdf = NULL;

	switch(ldns_key_algorithm(current_key)) {
	case LDNS_SIGN_DSA:
	case LDNS_DSA_NSEC3:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_dss1());
		break;
	case LDNS_SIGN_RSASHA1:
	case LDNS_SIGN_RSASHA1_NSEC3:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha1());
		break;
#ifdef USE_SHA2
	case LDNS_SIGN_RSASHA256:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha256());
		break;
	case LDNS_SIGN_RSASHA512:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_sha512());
		break;
#endif /* USE_SHA2 */
#ifdef USE_GOST
	case LDNS_SIGN_GOST:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_get_digestbyname("md_gost94"));
		break;
#endif /* USE_GOST */
	case LDNS_SIGN_RSAMD5:
		b64rdf = ldns_sign_public_evp(
				   sign_buf,
				   ldns_key_evp_key(current_key),
				   EVP_md5());
		break;
	default:
		/* do _you_ know this alg? */
		printf("unknown algorithm, ");
		printf("is the one used available on this system?\n");
		break;
	}
	
	return b64rdf;
}

/**
 * use this function to sign with a public/private key alg
 * return the created signatures
 */
ldns_rr_list *
ldns_sign_public(ldns_rr_list *rrset, ldns_key_list *keys)
{
	ldns_rr_list *signatures;
	ldns_rr_list *rrset_clone;
	ldns_rr *current_sig;
	ldns_rdf *b64rdf;
	ldns_key *current_key;
	size_t key_count;
	uint16_t i;
	ldns_buffer *sign_buf;
	ldns_rdf *new_owner;

	if (!rrset || ldns_rr_list_rr_count(rrset) < 1 || !keys) {
		return NULL;
	}
	
	new_owner = NULL;

	key_count = 0;
	signatures = ldns_rr_list_new();

	/* prepare a signature and add all the know data
	 * prepare the rrset. Sign this together.  */
	rrset_clone = ldns_rr_list_clone(rrset);
	if (!rrset_clone) {
		return NULL;
	}

	/* make it canonical */
	for(i = 0; i < ldns_rr_list_rr_count(rrset_clone); i++) {
		ldns_rr2canonical(ldns_rr_list_rr(rrset_clone, i));
	}
	/* sort */
	ldns_rr_list_sort(rrset_clone);
	
	for (key_count = 0;
		key_count < ldns_key_list_key_count(keys);
		key_count++) {
		if (!ldns_key_use(ldns_key_list_key(keys, key_count))) {
			continue;
		}
		sign_buf = ldns_buffer_new(LDNS_MAX_PACKETLEN);
		if (!sign_buf) {
			ldns_rr_list_free(rrset_clone);
			ldns_rr_list_free(signatures);
			ldns_rdf_free(new_owner);
			return NULL;
		}
		b64rdf = NULL;

		current_key = ldns_key_list_key(keys, key_count);
		/* sign all RRs with keys that have ZSKbit, !SEPbit.
		   sign DNSKEY RRs with keys that have ZSKbit&SEPbit */
		if (
		    ldns_key_flags(current_key) & LDNS_KEY_ZONE_KEY &&
		    (!(ldns_key_flags(current_key) & LDNS_KEY_SEP_KEY)
			|| ldns_rr_get_type(ldns_rr_list_rr(rrset, 0))
		        == LDNS_RR_TYPE_DNSKEY)
		    ) {
			current_sig = ldns_create_empty_rrsig(rrset_clone,
			                                      current_key);

			/* right now, we have: a key, a semi-sig and an rrset. For
			 * which we can create the sig and base64 encode that and
			 * add that to the signature */

			if (ldns_rrsig2buffer_wire(sign_buf, current_sig)
			    != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				/* ERROR */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}

			/* add the rrset in sign_buf */
			if (ldns_rr_list2buffer_wire(sign_buf, rrset_clone)
			    != LDNS_STATUS_OK) {
				ldns_buffer_free(sign_buf);
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}

			b64rdf = ldns_sign_public_buffer(sign_buf, current_key);

			if (!b64rdf) {
				/* signing went wrong */
				ldns_rr_list_deep_free(rrset_clone);
				return NULL;
			}

			ldns_rr_rrsig_set_sig(current_sig, b64rdf);

			/* push the signature to the signatures list */
			ldns_rr_list_push_rr(signatures, current_sig);
		}
		ldns_buffer_free(sign_buf); /* restart for the next key */
	}
	ldns_rr_list_deep_free(rrset_clone);

	return signatures;
}

/**
 * Sign data with DSA
 *
 * \param[in] to_sign The ldns_buffer containing raw data that is
 *                    to be signed
 * \param[in] key The DSA key structure to sign with
 * \return ldns_rdf for the RRSIG ldns_rr
 */
ldns_rdf *
ldns_sign_public_dsa(ldns_buffer *to_sign, DSA *key)
{
	unsigned char *sha1_hash;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	DSA_SIG *sig;
	uint8_t *data;
	size_t pad;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}
	
	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
				  ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}


	sig = DSA_do_sign(sha1_hash, SHA_DIGEST_LENGTH, key);

	data = LDNS_XMALLOC(uint8_t, 1 + 2 * SHA_DIGEST_LENGTH);

	data[0] = 1;
	pad = 20 - (size_t) BN_num_bytes(sig->r);
	if (pad > 0) {
		memset(data + 1, 0, pad);
	}
	BN_bn2bin(sig->r, (unsigned char *) (data + 1) + pad);

	pad = 20 - (size_t) BN_num_bytes(sig->s);
	if (pad > 0) {
		memset(data + 1 + SHA_DIGEST_LENGTH, 0, pad);
	}
	BN_bn2bin(sig->s, (unsigned char *) (data + 1 + SHA_DIGEST_LENGTH + pad));

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64,
								 1 + 2 * SHA_DIGEST_LENGTH,
								 data);

	ldns_buffer_free(b64sig);
	LDNS_FREE(data);

	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_evp(ldns_buffer *to_sign,
				 EVP_PKEY *key,
				 const EVP_MD *digest_type)
{
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	EVP_MD_CTX ctx;
	const EVP_MD *md_type;
	int r;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	/* initializes a signing context */
	md_type = digest_type;
	if(!md_type) {
		/* unknown message difest */
		ldns_buffer_free(b64sig);
		return NULL;
	}

	EVP_MD_CTX_init(&ctx);
	r = EVP_SignInit(&ctx, md_type);
	if(r == 1) {
		r = EVP_SignUpdate(&ctx, (unsigned char*)
					    ldns_buffer_begin(to_sign), 
					    ldns_buffer_position(to_sign));
	} else {
		ldns_buffer_free(b64sig);
		return NULL;
	}
	if(r == 1) {
		r = EVP_SignFinal(&ctx, (unsigned char*)
					   ldns_buffer_begin(b64sig), &siglen, key);
	} else {
		ldns_buffer_free(b64sig);
		return NULL;
	}
	if(r != 1) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	/* unfortunately, OpenSSL output is differenct from DNS DSA format */
	if (EVP_PKEY_type(key->type) == EVP_PKEY_DSA) {
		sigdata_rdf = ldns_convert_dsa_rrsig_asn12rdf(b64sig, siglen);
	} else {
		/* ok output for other types is the same */
		sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen,
									 ldns_buffer_begin(b64sig));
	}
	ldns_buffer_free(b64sig);
	EVP_MD_CTX_cleanup(&ctx);
	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsasha1(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *sha1_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;
	int result;

	siglen = 0;
	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}

	sha1_hash = SHA1((unsigned char*)ldns_buffer_begin(to_sign),
				  ldns_buffer_position(to_sign), NULL);
	if (!sha1_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	result = RSA_sign(NID_sha1, sha1_hash, SHA_DIGEST_LENGTH,
				   (unsigned char*)ldns_buffer_begin(b64sig),
				   &siglen, key);
	if (result != 1) {
		return NULL;
	}

	if (result != 1) {
		return NULL;
	}

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig); /* can't free this buffer ?? */
	return sigdata_rdf;
}

ldns_rdf *
ldns_sign_public_rsamd5(ldns_buffer *to_sign, RSA *key)
{
	unsigned char *md5_hash;
	unsigned int siglen;
	ldns_rdf *sigdata_rdf;
	ldns_buffer *b64sig;

	b64sig = ldns_buffer_new(LDNS_MAX_PACKETLEN);
	if (!b64sig) {
		return NULL;
	}
	
	md5_hash = MD5((unsigned char*)ldns_buffer_begin(to_sign),
				ldns_buffer_position(to_sign), NULL);
	if (!md5_hash) {
		ldns_buffer_free(b64sig);
		return NULL;
	}

	RSA_sign(NID_md5, md5_hash, MD5_DIGEST_LENGTH,
		    (unsigned char*)ldns_buffer_begin(b64sig),
		    &siglen, key);

	sigdata_rdf = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, siglen, 
								 ldns_buffer_begin(b64sig));
	ldns_buffer_free(b64sig);
	return sigdata_rdf;
}
#endif /* HAVE_SSL */

static int
ldns_dnssec_name_has_only_a(ldns_dnssec_name *cur_name)
{
	ldns_dnssec_rrsets *cur_rrset;
	cur_rrset = cur_name->rrsets;
	while (cur_rrset) {
		if (cur_rrset->type != LDNS_RR_TYPE_A &&
			cur_rrset->type != LDNS_RR_TYPE_AAAA) {
			return 0;
		} else {
			cur_rrset = cur_rrset->next;
		}
	}
	return 1;
}

ldns_status
ldns_dnssec_zone_mark_glue(ldns_dnssec_zone *zone)
{
	ldns_rbnode_t *cur_node;
	ldns_dnssec_name *cur_name;
	ldns_rdf *cur_owner, *cur_parent;

	cur_node = ldns_rbtree_first(zone->names);
	while (cur_node != LDNS_RBTREE_NULL) {
		cur_name = (ldns_dnssec_name *) cur_node->data;
		cur_node = ldns_rbtree_next(cur_node);
		if (ldns_dnssec_name_has_only_a(cur_name)) {
			/* assume glue XXX check for zone cur */
			cur_owner = ldns_rdf_clone(ldns_rr_owner(
					      cur_name->rrsets->rrs->rr));
			while (ldns_dname_label_count(cur_owner) >
				  ldns_dname_label_count(zone->soa->name)) {
				if (ldns_dnssec_zone_find_rrset(zone,
										  cur_owner,
										  LDNS_RR_TYPE_NS)) {
					/*
					fprintf(stderr, "[XX] Marking as glue: ");
					ldns_rdf_print(stderr, cur_name->name);
					fprintf(stderr, "\n");
					*/
					cur_name->is_glue = true;
				}
				cur_parent = ldns_dname_left_chop(cur_owner);
				ldns_rdf_deep_free(cur_owner);
				cur_owner = cur_parent;
			}
			ldns_rdf_deep_free(cur_owner);
		}
	}
	return LDNS_STATUS_OK;
}

ldns_rbnode_t *
ldns_dnssec_name_node_next_nonglue(ldns_rbnode_t *node)
{
	ldns_rbnode_t *next_node = NULL;
	ldns_dnssec_name *next_name = NULL;
	bool done = false;

	if (node == LDNS_RBTREE_NULL) {
		return NULL;
	}
	next_node = node;
	while (!done) {
		if (next_node == LDNS_RBTREE_NULL) {
			return NULL;
		} else {
			next_name = (ldns_dnssec_name *)next_node->data;
			if (!next_name->is_glue) {
				done = true;
			} else {
				next_node = ldns_rbtree_next(next_node);
			}
		}
	}
	return next_node;
}

ldns_status
ldns_dnssec_zone_create_nsecs(ldns_dnssec_zone *zone,
                              ldns_rr_list *new_rrs)
{

	ldns_rbnode_t *first_node, *cur_node, *next_node;
	ldns_dnssec_name *cur_name, *next_name;
	ldns_rr *nsec_rr;
	uint32_t nsec_ttl;
	ldns_dnssec_rrsets *soa;
	
	/* the TTL of NSEC rrs should be set to the minimum TTL of
	 * the zone SOA (RFC4035 Section 2.3)
	 */
	soa = ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA);
	
	/* did the caller actually set it? if not,
	 * fall back to default ttl
	 */
	if (soa && soa->rrs && soa->rrs->rr) {
		nsec_ttl = ldns_rdf2native_int32(ldns_rr_rdf(
		                                     soa->rrs->rr, 6));
	} else {
		nsec_ttl = LDNS_DEFAULT_TTL;
	}
	
	first_node = ldns_dnssec_name_node_next_nonglue(
			       ldns_rbtree_first(zone->names));
	cur_node = first_node;
	if (cur_node) {
		next_node = ldns_dnssec_name_node_next_nonglue(
			           ldns_rbtree_next(cur_node));
	} else {
		next_node = NULL;
	}

	while (cur_node && next_node) {
		cur_name = (ldns_dnssec_name *)cur_node->data;
		next_name = (ldns_dnssec_name *)next_node->data;
		nsec_rr = ldns_dnssec_create_nsec(cur_name,
		                                  next_name,
		                                  LDNS_RR_TYPE_NSEC);
		ldns_rr_set_ttl(nsec_rr, nsec_ttl);
		ldns_dnssec_name_add_rr(cur_name, nsec_rr);
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
		cur_node = next_node;
		if (cur_node) {
			next_node = ldns_dnssec_name_node_next_nonglue(
                               ldns_rbtree_next(cur_node));
		}
	}

	if (cur_node && !next_node) {
		cur_name = (ldns_dnssec_name *)cur_node->data;
		next_name = (ldns_dnssec_name *)first_node->data;
		nsec_rr = ldns_dnssec_create_nsec(cur_name,
		                                  next_name,
		                                  LDNS_RR_TYPE_NSEC);
		ldns_rr_set_ttl(nsec_rr, nsec_ttl);
		ldns_dnssec_name_add_rr(cur_name, nsec_rr);
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
	} else {
		printf("error\n");
	}

	return LDNS_STATUS_OK;
}

#ifdef HAVE_SSL
ldns_status
ldns_dnssec_zone_create_nsec3s(ldns_dnssec_zone *zone,
						 ldns_rr_list *new_rrs,
						 uint8_t algorithm,
						 uint8_t flags,
						 uint16_t iterations,
						 uint8_t salt_length,
						 uint8_t *salt)
{
	ldns_rbnode_t *first_name_node;
	ldns_rbnode_t *current_name_node;
	ldns_dnssec_name *current_name;
	ldns_status result = LDNS_STATUS_OK;
	ldns_rr *nsec_rr;
	ldns_rr_list *nsec3_list;
	uint32_t nsec_ttl;
	ldns_dnssec_rrsets *soa;
	
	if (!zone || !new_rrs || !zone->names) {
		return LDNS_STATUS_ERR;
	}
	
	/* the TTL of NSEC rrs should be set to the minimum TTL of
	 * the zone SOA (RFC4035 Section 2.3)
	 */
	soa = ldns_dnssec_name_find_rrset(zone->soa, LDNS_RR_TYPE_SOA);
	
	/* did the caller actually set it? if not,
	 * fall back to default ttl
	 */
	if (soa && soa->rrs && soa->rrs->rr) {
		nsec_ttl = ldns_rdf2native_int32(ldns_rr_rdf(
		                                     soa->rrs->rr, 6));
	} else {
		nsec_ttl = LDNS_DEFAULT_TTL;
	}

	nsec3_list = ldns_rr_list_new();

	first_name_node = ldns_dnssec_name_node_next_nonglue(
					  ldns_rbtree_first(zone->names));
	
	current_name_node = first_name_node;

	while (current_name_node &&
	       current_name_node != LDNS_RBTREE_NULL) {
		current_name = (ldns_dnssec_name *) current_name_node->data;
		nsec_rr = ldns_dnssec_create_nsec3(current_name,
		                                   NULL,
		                                   zone->soa->name,
		                                   algorithm,
		                                   flags,
		                                   iterations,
		                                   salt_length,
		                                   salt);
		/* by default, our nsec based generator adds rrsigs
		 * remove the bitmap for empty nonterminals */
		if (!current_name->rrsets) {
			ldns_rdf_deep_free(ldns_rr_pop_rdf(nsec_rr));
		}
		ldns_rr_set_ttl(nsec_rr, nsec_ttl);
		ldns_dnssec_name_add_rr(current_name, nsec_rr);
		ldns_rr_list_push_rr(new_rrs, nsec_rr);
		ldns_rr_list_push_rr(nsec3_list, nsec_rr);
		current_name_node = ldns_dnssec_name_node_next_nonglue(
		                   ldns_rbtree_next(current_name_node));
	}

	ldns_rr_list_sort_nsec3(nsec3_list);
	ldns_dnssec_chain_nsec3_list(nsec3_list);
	if (result != LDNS_STATUS_OK) {
		return result;
	}
	
	ldns_rr_list_free(nsec3_list);
	return result;
}
#endif /* HAVE_SSL */

ldns_dnssec_rrs *
ldns_dnssec_remove_signatures(ldns_dnssec_rrs *signatures,
						ldns_key_list *key_list,
						int (*func)(ldns_rr *, void *),
						void *arg)
{
	ldns_dnssec_rrs *base_rrs = signatures;
	ldns_dnssec_rrs *cur_rr = base_rrs;
	ldns_dnssec_rrs *prev_rr = NULL;
	ldns_dnssec_rrs *next_rr;

	uint16_t keytag;
	size_t i;
	int v;

	key_list = key_list;

	if (!cur_rr) {
		switch(func(NULL, arg)) {
		case LDNS_SIGNATURE_LEAVE_ADD_NEW:
		case LDNS_SIGNATURE_REMOVE_ADD_NEW:
		break;
		case LDNS_SIGNATURE_LEAVE_NO_ADD:
		case LDNS_SIGNATURE_REMOVE_NO_ADD:
		ldns_key_list_set_use(key_list, false);
		break;
		default:
			fprintf(stderr, "[XX] unknown return value from callback\n");
			break;
		}
		return NULL;
	}
	v = func(cur_rr->rr, arg);

	while (cur_rr) {
		next_rr = cur_rr->next;
		
		switch (func(cur_rr->rr, arg)) {
		case  LDNS_SIGNATURE_LEAVE_ADD_NEW:
			prev_rr = cur_rr;
			break;
		case LDNS_SIGNATURE_LEAVE_NO_ADD:
			keytag = ldns_rdf2native_int16(
					   ldns_rr_rrsig_keytag(cur_rr->rr));
			for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
				if (ldns_key_keytag(ldns_key_list_key(key_list, i)) ==
				    keytag) {
					ldns_key_set_use(ldns_key_list_key(key_list, i),
								  false);
				}
			}
			prev_rr = cur_rr;
			break;
		case LDNS_SIGNATURE_REMOVE_NO_ADD:
			keytag = ldns_rdf2native_int16(
					   ldns_rr_rrsig_keytag(cur_rr->rr));
			for (i = 0; i < ldns_key_list_key_count(key_list); i++) {
				if (ldns_key_keytag(ldns_key_list_key(key_list, i))
				    == keytag) {
					ldns_key_set_use(ldns_key_list_key(key_list, i),
								  false);
				}
			}
			if (prev_rr) {
				prev_rr->next = next_rr;
			} else {
				base_rrs = next_rr;
			}
			LDNS_FREE(cur_rr);
			break;
		case LDNS_SIGNATURE_REMOVE_ADD_NEW:
			if (prev_rr) {
				prev_rr->next = next_rr;
			} else {
				base_rrs = next_rr;
			}
			LDNS_FREE(cur_rr);
			break;
		default:
			fprintf(stderr, "[XX] unknown return value from callback\n");
			break;
		}
		cur_rr = next_rr;
	}

	return base_rrs;
}

#ifdef HAVE_SSL
ldns_status
ldns_dnssec_zone_create_rrsigs(ldns_dnssec_zone *zone,
                               ldns_rr_list *new_rrs,
                               ldns_key_list *key_list,
                               int (*func)(ldns_rr *, void*),
                               void *arg)
{
	ldns_status result = LDNS_STATUS_OK;

	ldns_rbnode_t *cur_node;
	ldns_rr_list *rr_list;

	ldns_dnssec_name *cur_name;
	ldns_dnssec_rrsets *cur_rrset;
	ldns_dnssec_rrs *cur_rr;

	ldns_rr_list *siglist;
	
	size_t i;

	ldns_rr_list *pubkey_list = ldns_rr_list_new();
	zone = zone;
	new_rrs = new_rrs;
	key_list = key_list;
	for (i = 0; i<ldns_key_list_key_count(key_list); i++) {
		ldns_rr_list_push_rr(pubkey_list,
						 ldns_key2rr(ldns_key_list_key(key_list, i)));
	}
	/* TODO: callback to see is list should be signed */
	/* TODO: remove 'old' signatures from signature list */
	cur_node = ldns_rbtree_first(zone->names);
	while (cur_node != LDNS_RBTREE_NULL) {
		cur_name = (ldns_dnssec_name *) cur_node->data;

		if (!cur_name->is_glue) {
			cur_rrset = cur_name->rrsets;
			while (cur_rrset) {
				/* reset keys to use */
				ldns_key_list_set_use(key_list, true);
				
				/* walk through old sigs, remove the old,
				   and mark which keys (not) to use) */
				cur_rrset->signatures =
					ldns_dnssec_remove_signatures(cur_rrset->signatures,
											key_list,
											func,
											arg);
				
				/* TODO: just set count to zero? */
				rr_list = ldns_rr_list_new();
				
				cur_rr = cur_rrset->rrs;
				while (cur_rr) {
					ldns_rr_list_push_rr(rr_list, cur_rr->rr);
					cur_rr = cur_rr->next;
				}
				
				/* only sign non-delegation RRsets */
				/* (glue should have been marked earlier) */
				if ((ldns_rr_list_type(rr_list) != LDNS_RR_TYPE_NS ||
					ldns_dname_compare(ldns_rr_list_owner(rr_list),
					zone->soa->name) == 0) &&
					/* OK, there is also the possibility that the record
					 * is glue, but at the same owner name as other records that
					 * are not NS nor A/AAAA. Bleh, our current data structure
					 * doesn't really support that... */
					!((ldns_rr_list_type(rr_list) == LDNS_RR_TYPE_A ||
					 ldns_rr_list_type(rr_list) == LDNS_RR_TYPE_AAAA) &&
					 !ldns_dname_compare(ldns_rr_list_owner(rr_list), zone->soa->name) == 0 &&
					 ldns_dnssec_zone_find_rrset(zone, ldns_rr_list_owner(rr_list), LDNS_RR_TYPE_NS)
					 )) {

					siglist = ldns_sign_public(rr_list, key_list);
					for (i = 0; i < ldns_rr_list_rr_count(siglist); i++) {
						if (cur_rrset->signatures) {
							ldns_dnssec_rrs_add_rr(cur_rrset->signatures,
											   ldns_rr_list_rr(siglist,
														    i));
						} else {
							cur_rrset->signatures = ldns_dnssec_rrs_new();
							cur_rrset->signatures->rr =
								ldns_rr_list_rr(siglist, i);
							ldns_rr_list_push_rr(new_rrs,
											 ldns_rr_list_rr(siglist,
														  i));
						}
					}
					ldns_rr_list_free(siglist);
				}
				
				ldns_rr_list_free(rr_list);
				
				cur_rrset = cur_rrset->next;
			}
			
			/* sign the nsec */
			cur_name->nsec_signatures =
				ldns_dnssec_remove_signatures(cur_name->nsec_signatures,
										key_list,
										func,
										arg);
			
			rr_list = ldns_rr_list_new();
			ldns_rr_list_push_rr(rr_list, cur_name->nsec);
			siglist = ldns_sign_public(rr_list, key_list);
			
			for (i = 0; i < ldns_rr_list_rr_count(siglist); i++) {
				if (cur_name->nsec_signatures) {
					ldns_dnssec_rrs_add_rr(cur_name->nsec_signatures,
									   ldns_rr_list_rr(siglist, i));
				} else {
					cur_name->nsec_signatures = ldns_dnssec_rrs_new();
					cur_name->nsec_signatures->rr =
						ldns_rr_list_rr(siglist, i);
					ldns_rr_list_push_rr(new_rrs,
									 ldns_rr_list_rr(siglist, i));
				}
			}
			
			ldns_rr_list_free(siglist);
			ldns_rr_list_free(rr_list);
		}
		cur_node = ldns_rbtree_next(cur_node);
	}

	ldns_rr_list_deep_free(pubkey_list);
	return result;
}

ldns_status
ldns_dnssec_zone_sign(ldns_dnssec_zone *zone,
				  ldns_rr_list *new_rrs,
				  ldns_key_list *key_list,
				  int (*func)(ldns_rr *, void *),
				  void *arg)
{
	ldns_status result = LDNS_STATUS_OK;

	if (!zone || !new_rrs || !key_list) {
		return LDNS_STATUS_ERR;
	}

	/* zone is already sorted */
	ldns_dnssec_zone_mark_glue(zone);
	
	/* check whether we need to add nsecs */
	if (zone->names && !((ldns_dnssec_name *)zone->names->root->data)->nsec) {
		result = ldns_dnssec_zone_create_nsecs(zone, new_rrs);
		if (result != LDNS_STATUS_OK) {
			return result;
		}
	}

	result = ldns_dnssec_zone_create_rrsigs(zone,
									new_rrs,
									key_list,
									func,
									arg);

	return result;
}

ldns_status
ldns_dnssec_zone_sign_nsec3(ldns_dnssec_zone *zone,
					   ldns_rr_list *new_rrs,
					   ldns_key_list *key_list,
					   int (*func)(ldns_rr *, void *),
					   void *arg,
					   uint8_t algorithm,
					   uint8_t flags,
					   uint16_t iterations,
					   uint8_t salt_length,
					   uint8_t *salt)
{
	ldns_rr *nsec3, *nsec3params;
	ldns_status result = LDNS_STATUS_OK;

	/* zone is already sorted */
	ldns_dnssec_zone_mark_glue(zone);

	/* TODO if there are already nsec3s presents and their
	 * parameters are the same as these, we don't have to recreate
	 */
	if (zone->names) {
		/* add empty nonterminals */
		ldns_dnssec_zone_add_empty_nonterminals(zone);

		nsec3 = ((ldns_dnssec_name *)zone->names->root->data)->nsec;
		if (nsec3 && ldns_rr_get_type(nsec3) == LDNS_RR_TYPE_NSEC3) {
			/* no need to recreate */
		} else {
			if (!ldns_dnssec_zone_find_rrset(zone,
									   zone->soa->name,
									   LDNS_RR_TYPE_NSEC3PARAMS)) {
				/* create and add the nsec3params rr */
				nsec3params =
					ldns_rr_new_frm_type(LDNS_RR_TYPE_NSEC3PARAMS);
				ldns_rr_set_owner(nsec3params,
							   ldns_rdf_clone(zone->soa->name));
				ldns_nsec3_add_param_rdfs(nsec3params,
									 algorithm,
									 flags,
									 iterations,
									 salt_length,
									 salt);
				/* always set bit 7 of the flags to zero, according to
				 * rfc5155 section 11 */
				ldns_set_bit(ldns_rdf_data(ldns_rr_rdf(nsec3params, 1)), 7, 0);
				ldns_dnssec_zone_add_rr(zone, nsec3params);
				ldns_rr_list_push_rr(new_rrs, nsec3params);
			}
			result = ldns_dnssec_zone_create_nsec3s(zone,
											new_rrs,
											algorithm,
											flags,
											iterations,
											salt_length,
											salt);
			if (result != LDNS_STATUS_OK) {
				return result;
			}
		}

		result = ldns_dnssec_zone_create_rrsigs(zone,
										new_rrs,
										key_list,
										func,
										arg);
	}
	
	return result;
}


ldns_zone *
ldns_zone_sign(const ldns_zone *zone, ldns_key_list *key_list)
{
	ldns_dnssec_zone *dnssec_zone;
	ldns_zone *signed_zone;
	ldns_rr_list *new_rrs;
	size_t i;

	signed_zone = ldns_zone_new();
	dnssec_zone = ldns_dnssec_zone_new();

	(void) ldns_dnssec_zone_add_rr(dnssec_zone, ldns_zone_soa(zone));
	ldns_zone_set_soa(signed_zone, ldns_zone_soa(zone));
	
	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(zone)); i++) {
		(void) ldns_dnssec_zone_add_rr(dnssec_zone,
								 ldns_rr_list_rr(ldns_zone_rrs(zone),
											  i));
		ldns_zone_push_rr(signed_zone, 
					   ldns_rr_clone(ldns_rr_list_rr(ldns_zone_rrs(zone),
											   i)));
	}

	new_rrs = ldns_rr_list_new();
	(void) ldns_dnssec_zone_sign(dnssec_zone,
						    new_rrs,
						    key_list,
						    ldns_dnssec_default_replace_signatures,
						    NULL);

    	for (i = 0; i < ldns_rr_list_rr_count(new_rrs); i++) {
		ldns_rr_list_push_rr(ldns_zone_rrs(signed_zone),
						 ldns_rr_clone(ldns_rr_list_rr(new_rrs, i)));
	}

	ldns_rr_list_deep_free(new_rrs);
	ldns_dnssec_zone_free(dnssec_zone);

	return signed_zone;
}

ldns_zone *
ldns_zone_sign_nsec3(ldns_zone *zone, ldns_key_list *key_list, uint8_t algorithm, uint8_t flags, uint16_t iterations, uint8_t salt_length, uint8_t *salt)
{
	ldns_dnssec_zone *dnssec_zone;
	ldns_zone *signed_zone;
	ldns_rr_list *new_rrs;
	size_t i;

	signed_zone = ldns_zone_new();
	dnssec_zone = ldns_dnssec_zone_new();

	(void) ldns_dnssec_zone_add_rr(dnssec_zone, ldns_zone_soa(zone));
	ldns_zone_set_soa(signed_zone, ldns_zone_soa(zone));
	
	for (i = 0; i < ldns_rr_list_rr_count(ldns_zone_rrs(zone)); i++) {
		(void) ldns_dnssec_zone_add_rr(dnssec_zone,
								 ldns_rr_list_rr(ldns_zone_rrs(zone),
											  i));
		ldns_zone_push_rr(signed_zone, 
					   ldns_rr_clone(ldns_rr_list_rr(ldns_zone_rrs(zone),
											   i)));
	}

	new_rrs = ldns_rr_list_new();
	(void) ldns_dnssec_zone_sign_nsec3(dnssec_zone,
								new_rrs,
								key_list,
								ldns_dnssec_default_replace_signatures,
								NULL,
								algorithm,
								flags,
								iterations,
								salt_length,
								salt);

    	for (i = 0; i < ldns_rr_list_rr_count(new_rrs); i++) {
		ldns_rr_list_push_rr(ldns_zone_rrs(signed_zone),
						 ldns_rr_clone(ldns_rr_list_rr(new_rrs, i)));
	}

	ldns_rr_list_deep_free(new_rrs);
	ldns_dnssec_zone_free(dnssec_zone);

	return signed_zone;
}
#endif /* HAVE_SSL */

