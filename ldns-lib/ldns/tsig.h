/*
 * tsig.h -- defines for TSIG [RFC2845]
 *
 * Copyright (c) 2005-2008, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#ifndef LDNS_TSIG_H
#define LDNS_TSIG_H

/**
 * \file
 *
 * Defines functions for TSIG usage
 */


/**
 * Contains credentials for TSIG
*/
typedef struct ldns_tsig_credentials_struct
{
    char *algorithm;
    char *keyname;
    char *keydata;
    /* XXX More eventually. */
} ldns_tsig_credentials;

char *ldns_tsig_algorithm(ldns_tsig_credentials *);
char *ldns_tsig_keyname(ldns_tsig_credentials *);
char *ldns_tsig_keydata(ldns_tsig_credentials *);
char *ldns_tsig_keyname_clone(ldns_tsig_credentials *);
char *ldns_tsig_keydata_clone(ldns_tsig_credentials *);

/**
 * verifies the tsig rr for the given packet and key.
 * The wire must be given too because tsig does not sign normalized packets.
 *
 * \return true if tsig is correct, false if not, or if tsig is not set
 */
bool ldns_pkt_tsig_verify(ldns_pkt *pkt, uint8_t *wire, size_t wire_size, const char *key_name, const char *key_data, ldns_rdf *mac);

/**
 * creates a tsig rr for the given packet and key.
 * \param[in] pkt the packet to sign
 * \param[in] key_name the name of the shared key
 * \param[in] key_data the key in base 64 format
 * \param[in] fudge seconds of error permitted in time signed
 * \param[in] algorithm_name the name of the algorithm used
 * \param[in] query_mac is added to the digest if not NULL (so NULL is for signing queries, not NULL is for signing answers)
 * \return status (OK if success)
 */
ldns_status ldns_pkt_tsig_sign(ldns_pkt *pkt, const char *key_name, const char *key_data, uint16_t fudge, const char *algorithm_name, ldns_rdf *query_mac);

#endif /* LDNS_TSIG_H */
