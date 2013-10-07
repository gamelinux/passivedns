/*
 * host2str.c
 *
 * conversion routines from the host format
 * to the presentation format (strings)
 *
 * a Net::DNS like library for C
 * 
 * (c) NLnet Labs, 2004-2006
 *
 * See the file LICENSE for the license
 */
#include <ldns/config.h>

#include <ldns/ldns.h>

#include <limits.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#include <time.h>
#ifndef _MSC_VER
#include <sys/time.h>
#endif

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN 16
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif

/* lookup tables for standard DNS stuff  */

/* Taken from RFC 2535, section 7.  */
ldns_lookup_table ldns_algorithms[] = {
        { LDNS_RSAMD5, "RSAMD5" },
        { LDNS_DH, "DH" },
        { LDNS_DSA, "DSA" },
        { LDNS_ECC, "ECC" },
        { LDNS_RSASHA1, "RSASHA1" },
        { LDNS_INDIRECT, "INDIRECT" },
        { LDNS_PRIVATEDNS, "PRIVATEDNS" },
        { LDNS_PRIVATEOID, "PRIVATEOID" },
        { 0, NULL }
};

/* Taken from RFC 2538  */
ldns_lookup_table ldns_cert_algorithms[] = {
        { LDNS_CERT_PKIX, "PKIX" },
	{ LDNS_CERT_SPKI, "SPKI" },
	{ LDNS_CERT_PGP, "PGP" },
	{ LDNS_CERT_URI, "URI" },
	{ LDNS_CERT_OID, "OID" },
        { 0, NULL }
};

/* classes  */
ldns_lookup_table ldns_rr_classes[] = {
        { LDNS_RR_CLASS_IN, "IN" },
        { LDNS_RR_CLASS_CH, "CH" },
        { LDNS_RR_CLASS_HS, "HS" },
        { LDNS_RR_CLASS_NONE, "NONE" },
        { LDNS_RR_CLASS_ANY, "ANY" },
        { 0, NULL }
};

/* if these are used elsewhere */
ldns_lookup_table ldns_rcodes[] = {
        { LDNS_RCODE_NOERROR, "NOERROR" },
        { LDNS_RCODE_FORMERR, "FORMERR" },
        { LDNS_RCODE_SERVFAIL, "SERVFAIL" },
        { LDNS_RCODE_NXDOMAIN, "NXDOMAIN" },
        { LDNS_RCODE_NOTIMPL, "NOTIMPL" },
        { LDNS_RCODE_REFUSED, "REFUSED" },
        { LDNS_RCODE_YXDOMAIN, "YXDOMAIN" },
        { LDNS_RCODE_YXRRSET, "YXRRSET" },
        { LDNS_RCODE_NXRRSET, "NXRRSET" },
        { LDNS_RCODE_NOTAUTH, "NOTAUTH" },
        { LDNS_RCODE_NOTZONE, "NOTZONE" },
        { 0, NULL }
};

ldns_lookup_table ldns_opcodes[] = {
        { LDNS_PACKET_QUERY, "QUERY" },
        { LDNS_PACKET_IQUERY, "IQUERY" },
        { LDNS_PACKET_STATUS, "STATUS" }, 
	{ LDNS_PACKET_NOTIFY, "NOTIFY" },
	{ LDNS_PACKET_UPDATE, "UPDATE" },
        { 0, NULL }
};

ldns_status
ldns_pkt_opcode2buffer_str(ldns_buffer *output, ldns_pkt_opcode opcode)
{
	ldns_lookup_table *lt = ldns_lookup_by_id(ldns_opcodes, opcode);
	if (lt && lt->name) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
		ldns_buffer_printf(output, "OPCODE%u", opcode);
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_pkt_rcode2buffer_str(ldns_buffer *output, ldns_pkt_rcode rcode)
{
	ldns_lookup_table *lt = ldns_lookup_by_id(ldns_rcodes, rcode);
	if (lt && lt->name) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
		ldns_buffer_printf(output, "RCODE%u", rcode);
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_algorithm2buffer_str(ldns_buffer *output,
                          ldns_algorithm algorithm)
{
	ldns_lookup_table *lt = ldns_lookup_by_id(ldns_algorithms,
	                                          algorithm);
	if (lt && lt->name) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
		ldns_buffer_printf(output, "ALG%u", algorithm);
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_cert_algorithm2buffer_str(ldns_buffer *output,
                               ldns_cert_algorithm cert_algorithm)
{
	ldns_lookup_table *lt = ldns_lookup_by_id(ldns_cert_algorithms,
	                                          cert_algorithm);
	if (lt && lt->name) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
		ldns_buffer_printf(output, "CERT_ALG%u",
		                   cert_algorithm);
	}
	return ldns_buffer_status(output);
}

char *
ldns_pkt_opcode2str(ldns_pkt_opcode opcode)
{
	char *str;
	ldns_buffer *buf;

	buf = ldns_buffer_new(12);
	str = NULL;

	if (ldns_pkt_opcode2buffer_str(buf, opcode) == LDNS_STATUS_OK) {
		str = ldns_buffer2str(buf);
	}

	ldns_buffer_free(buf);
	return str;
}

char *
ldns_pkt_rcode2str(ldns_pkt_rcode rcode)
{
	char *str;
	ldns_buffer *buf;

	buf = ldns_buffer_new(10);
	str = NULL;

	if (ldns_pkt_rcode2buffer_str(buf, rcode) == LDNS_STATUS_OK) {
		str = ldns_buffer2str(buf);
	}

	ldns_buffer_free(buf);
	return str;
}

char *
ldns_pkt_algorithm2str(ldns_algorithm algorithm)
{
	char *str;
	ldns_buffer *buf;

	buf = ldns_buffer_new(10);
	str = NULL;

	if (ldns_algorithm2buffer_str(buf, algorithm)
	    == LDNS_STATUS_OK) {
		str = ldns_buffer2str(buf);
	}

	ldns_buffer_free(buf);
	return str;
}

char *
ldns_pkt_cert_algorithm2str(ldns_cert_algorithm cert_algorithm)
{
	char *str;
	ldns_buffer *buf;

	buf = ldns_buffer_new(10);
	str = NULL;

	if (ldns_cert_algorithm2buffer_str(buf, cert_algorithm)
	    == LDNS_STATUS_OK) {
		str = ldns_buffer2str(buf);
	}

	ldns_buffer_free(buf);
	return str;
}


/* do NOT pass compressed data here :p */
ldns_status
ldns_rdf2buffer_str_dname(ldns_buffer *output, const ldns_rdf *dname)
{
	/* can we do with 1 pos var? or without at all? */
	uint8_t src_pos = 0;
	uint8_t len;
	uint8_t *data;
	uint8_t i;
	
	data = (uint8_t*)ldns_rdf_data(dname);
	len = data[src_pos];

	if (ldns_rdf_size(dname) > LDNS_MAX_DOMAINLEN) {
		/* too large, return */
		return LDNS_STATUS_DOMAINNAME_OVERFLOW;
	}

	/* special case: root label */
	if (1 == ldns_rdf_size(dname)) {
		ldns_buffer_printf(output, ".");
	} else {
		while ((len > 0) && src_pos < ldns_rdf_size(dname)) {
			src_pos++;
			for(i = 0; i < len; i++) {
				/* paranoia check for various 'strange' 
				   characters in dnames
				*/
				if (data[src_pos] == '.' ||
				    data[src_pos] == '(' || data[src_pos] == ')') {
					ldns_buffer_printf(output, "\\%c", 
							data[src_pos]);
				} else if (!isgraph((int) data[src_pos])) {
					ldns_buffer_printf(output, "\\%03u", 
							data[src_pos]);
				} else {
					ldns_buffer_printf(output, "%c", data[src_pos]);
				}
				src_pos++;
			}
			
			len = data[src_pos];
			ldns_buffer_printf(output, ".");
		}
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_int8(ldns_buffer *output, const ldns_rdf *rdf)
{
	uint8_t data = ldns_rdf_data(rdf)[0];
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_int16(ldns_buffer *output, const ldns_rdf *rdf)
{
	uint16_t data = ldns_read_uint16(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_int32(ldns_buffer *output, const ldns_rdf *rdf)
{
	uint32_t data = ldns_read_uint32(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%lu", (unsigned long) data);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_time(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* create a YYYYMMDDHHMMSS string if possible */
	uint32_t data = ldns_read_uint32(ldns_rdf_data(rdf));
	time_t data_time;
	struct tm tm;
	char date_buf[16];
	
	data_time = 0;
	memcpy(&data_time, &data, sizeof(uint32_t));

	memset(&tm, 0, sizeof(tm));

	if (gmtime_r(&data_time, &tm) && strftime(date_buf, 15, "%Y%m%d%H%M%S", &tm)) {
		ldns_buffer_printf(output, "%s", date_buf);
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_a(ldns_buffer *output, const ldns_rdf *rdf)
{
	char str[INET_ADDRSTRLEN];
	
	if (inet_ntop(AF_INET, ldns_rdf_data(rdf), str, INET_ADDRSTRLEN)) {
		ldns_buffer_printf(output, "%s", str);
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_aaaa(ldns_buffer *output, const ldns_rdf *rdf)
{
	char str[INET6_ADDRSTRLEN];

	if (inet_ntop(AF_INET6, ldns_rdf_data(rdf), str, INET6_ADDRSTRLEN)) {
		ldns_buffer_printf(output, "%s", str);
	}

	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_str(ldns_buffer *output, const ldns_rdf *rdf)
{
	const uint8_t *data = ldns_rdf_data(rdf);
	uint8_t length = data[0];
	size_t i;

	ldns_buffer_printf(output, "\"");
	for (i = 1; i <= length; ++i) {
		char ch = (char) data[i];
		if (isprint((int)ch) || ch=='\t') {
			ldns_buffer_printf(output, "%c", ch);
		} else {
			ldns_buffer_printf(output, "\\%03u", (unsigned) ch);
		}
	}
	ldns_buffer_printf(output, "\"");
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_b64(ldns_buffer *output, const ldns_rdf *rdf)
{
	size_t size = ldns_b64_ntop_calculate_size(ldns_rdf_size(rdf));
	char *b64 = LDNS_XMALLOC(char, size);
	if (ldns_b64_ntop(ldns_rdf_data(rdf), ldns_rdf_size(rdf), b64, size)) {
		ldns_buffer_printf(output, "%s", b64);
	}
	LDNS_FREE(b64);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_b32_ext(ldns_buffer *output, const ldns_rdf *rdf)
{
	size_t size = ldns_b32_ntop_calculate_size(ldns_rdf_size(rdf) - 1);
	char *b32 = LDNS_XMALLOC(char, size + 1);
	size = (size_t) ldns_b32_ntop_extended_hex(ldns_rdf_data(rdf) + 1,
									   ldns_rdf_size(rdf) - 1,
									   b32, size);
	if (size > 0) {
		ldns_buffer_printf(output, "%s", b32);
	}
	LDNS_FREE(b32);
	return ldns_buffer_status(output);
}	

ldns_status
ldns_rdf2buffer_str_hex(ldns_buffer *output, const ldns_rdf *rdf)
{
	size_t i;
	for (i = 0; i < ldns_rdf_size(rdf); i++) {
		ldns_buffer_printf(output, "%02x", ldns_rdf_data(rdf)[i]);
	}

	return ldns_buffer_status(output);
}	

ldns_status
ldns_rdf2buffer_str_type(ldns_buffer *output, const ldns_rdf *rdf)
{
        uint16_t data = ldns_read_uint16(ldns_rdf_data(rdf));
	const ldns_rr_descriptor *descriptor;

	descriptor = ldns_rr_descript(data);
	if (descriptor && descriptor->_name) {
		ldns_buffer_printf(output, "%s", descriptor->_name);
	} else {
		ldns_buffer_printf(output, "TYPE%u", data);
	}
	return ldns_buffer_status(output);
}	

ldns_status
ldns_rdf2buffer_str_class(ldns_buffer *output, const ldns_rdf *rdf)
{
	uint16_t data = ldns_read_uint16(ldns_rdf_data(rdf));
	ldns_lookup_table *lt;

 	lt = ldns_lookup_by_id(ldns_rr_classes, (int) data);
	if (lt) {
		ldns_buffer_printf(output, "\t%s", lt->name);
	} else {
		ldns_buffer_printf(output, "\tCLASS%d", data);
	}
	return ldns_buffer_status(output);
}	

ldns_status
ldns_rdf2buffer_str_cert_alg(ldns_buffer *output, const ldns_rdf *rdf)
{
        uint16_t data = ldns_read_uint16(ldns_rdf_data(rdf));
	ldns_lookup_table *lt;
 	lt = ldns_lookup_by_id(ldns_cert_algorithms, (int) data);
	if (lt) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
		ldns_buffer_printf(output, "%d", data);
	}
	return ldns_buffer_status(output);
}	

ldns_status
ldns_rdf2buffer_str_alg(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* don't use algorithm mnemonics in the presentation format
	   this kind of got sneaked into the rfc's */
        uint8_t data = ldns_rdf_data(rdf)[0];
/*

	ldns_lookup_table *lt;

 	lt = ldns_lookup_by_id(ldns_algorithms, (int) data);
	if (lt) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
*/
		ldns_buffer_printf(output, "%d", data);
/*
	}
*/
	return ldns_buffer_status(output);
}	

static void
loc_cm_print(ldns_buffer *output, uint8_t mantissa, uint8_t exponent)
{
	uint8_t i;
	/* is it 0.<two digits> ? */
	if(exponent < 2) {
		if(exponent == 1)
			mantissa *= 10;
		ldns_buffer_printf(output, "0.%02ld", (long)mantissa);
		return;
	}
	/* always <digit><string of zeros> */
	ldns_buffer_printf(output, "%d", (int)mantissa);
	for(i=0; i<exponent-2; i++)
		ldns_buffer_printf(output, "0");
}

ldns_status
ldns_rr_type2buffer_str(ldns_buffer *output, const ldns_rr_type type)
{
	const ldns_rr_descriptor *descriptor;

	descriptor = ldns_rr_descript(type);

	if (descriptor && descriptor->_name) {
		ldns_buffer_printf(output, "%s", descriptor->_name);
	} else {
		/* exceptions for pseudotypes */
		switch (type) {
			case LDNS_RR_TYPE_IXFR:
				ldns_buffer_printf(output, "IXFR");
				break;
			case LDNS_RR_TYPE_AXFR:
				ldns_buffer_printf(output, "AXFR");
				break;
			case LDNS_RR_TYPE_MAILA:
				ldns_buffer_printf(output, "MAILA");
				break;
			case LDNS_RR_TYPE_MAILB:
				ldns_buffer_printf(output, "MAILB");
				break;
			case LDNS_RR_TYPE_ANY:
				ldns_buffer_printf(output, "ANY");
				break;
			default:
				ldns_buffer_printf(output, "TYPE%u", type);
		}
	}
	return ldns_buffer_status(output);
}

char *
ldns_rr_type2str(const ldns_rr_type type)
{
	char *str;
	ldns_buffer *buf;

	buf = ldns_buffer_new(10);
	str = NULL;

	if (ldns_rr_type2buffer_str(buf, type) == LDNS_STATUS_OK) {
		str = ldns_buffer2str(buf);
	}

	ldns_buffer_free(buf);
	return str;
}


ldns_status
ldns_rr_class2buffer_str(ldns_buffer *output,
                         const ldns_rr_class klass)
{
	ldns_lookup_table *lt;

	lt = ldns_lookup_by_id(ldns_rr_classes, klass);
	if (lt) {
		ldns_buffer_printf(output, "%s", lt->name);
	} else {
		ldns_buffer_printf(output, "CLASS%d", klass);
	}
	return ldns_buffer_status(output);
}

char *
ldns_rr_class2str(const ldns_rr_class klass)
{
	ldns_buffer *buf;
	char *str;

	str = NULL;
	buf = ldns_buffer_new(10);
	if (ldns_rr_class2buffer_str(buf, klass) == LDNS_STATUS_OK) {
		str = ldns_buffer2str(buf);
	}
	ldns_buffer_free(buf);
	return str;
}

ldns_status
ldns_rdf2buffer_str_loc(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* we could do checking (ie degrees < 90 etc)? */
	uint8_t version = ldns_rdf_data(rdf)[0];
	uint8_t size;
	uint8_t horizontal_precision;
	uint8_t vertical_precision;
	uint32_t longitude;
	uint32_t latitude;
	uint32_t altitude;
	char northerness;
	char easterness;
	uint32_t h;
	uint32_t m;
	double s;
	
	uint32_t equator = (uint32_t) ldns_power(2, 31);

	if (version == 0) {
		size = ldns_rdf_data(rdf)[1];
		horizontal_precision = ldns_rdf_data(rdf)[2];
		vertical_precision = ldns_rdf_data(rdf)[3];
		
		latitude = ldns_read_uint32(&ldns_rdf_data(rdf)[4]);
		longitude = ldns_read_uint32(&ldns_rdf_data(rdf)[8]);
		altitude = ldns_read_uint32(&ldns_rdf_data(rdf)[12]);
		
		if (latitude > equator) {
			northerness = 'N';
			latitude = latitude - equator;
		} else {
			northerness = 'S';
			latitude = equator - latitude;
		}
		h = latitude / (1000 * 60 * 60);
		latitude = latitude % (1000 * 60 * 60);
		m = latitude / (1000 * 60);
		latitude = latitude % (1000 * 60);
		s = (double) latitude / 1000.0;
		ldns_buffer_printf(output, "%02u %02u %0.3f %c ", 
			h, m, s, northerness);

		if (longitude > equator) {
			easterness = 'E';
			longitude = longitude - equator;
		} else {
			easterness = 'W';
			longitude = equator - longitude;
		}
		h = longitude / (1000 * 60 * 60);
		longitude = longitude % (1000 * 60 * 60);
		m = longitude / (1000 * 60);
		longitude = longitude % (1000 * 60);
		s = (double) longitude / (1000.0);
		ldns_buffer_printf(output, "%02u %02u %0.3f %c ", 
			h, m, s, easterness);

		ldns_buffer_printf(output, "%ld", altitude/100 - 100000);
		if(altitude%100 != 0)
			ldns_buffer_printf(output, ".%02ld", altitude%100);
		ldns_buffer_printf(output, "m ");
		
		loc_cm_print(output, (size & 0xf0) >> 4, size & 0x0f);	
		ldns_buffer_printf(output, "m ");

		loc_cm_print(output, (horizontal_precision & 0xf0) >> 4, 
			horizontal_precision & 0x0f);	
		ldns_buffer_printf(output, "m ");

		loc_cm_print(output, (vertical_precision & 0xf0) >> 4, 
			vertical_precision & 0x0f);	
		ldns_buffer_printf(output, "m ");

		return ldns_buffer_status(output);
	} else {
		return ldns_rdf2buffer_str_hex(output, rdf);
	}
}

ldns_status
ldns_rdf2buffer_str_unknown(ldns_buffer *output, const ldns_rdf *rdf)
{
	ldns_buffer_printf(output, "\\# %u ", ldns_rdf_size(rdf));
	return ldns_rdf2buffer_str_hex(output, rdf);
}

ldns_status
ldns_rdf2buffer_str_nsap(ldns_buffer *output, const ldns_rdf *rdf)
{
	ldns_buffer_printf(output, "0x");
	return ldns_rdf2buffer_str_hex(output, rdf);
}

ldns_status
ldns_rdf2buffer_str_wks(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* protocol, followed by bitmap of services */
	struct protoent *protocol;
	char *proto_name = NULL;
	uint8_t protocol_nr;
	struct servent *service;
	uint16_t current_service;

	protocol_nr = ldns_rdf_data(rdf)[0];
	protocol = getprotobynumber((int) protocol_nr);
	if (protocol && (protocol->p_name != NULL)) {
		proto_name = protocol->p_name;
		ldns_buffer_printf(output, "%s ", protocol->p_name);
	} else {
		ldns_buffer_printf(output, "%u ", protocol_nr);
	}

#ifdef HAVE_ENDPROTOENT
	endprotoent();
#endif
	
	for (current_service = 0; 
	     current_service < ldns_rdf_size(rdf) * 7; current_service++) {
		if (ldns_get_bit(&(ldns_rdf_data(rdf)[1]), current_service)) {
			service = getservbyport((int) htons(current_service),
			                        proto_name);
			if (service && service->s_name) {
				ldns_buffer_printf(output, "%s ", service->s_name);
			} else {
				ldns_buffer_printf(output, "%u ", current_service);
			}
#ifdef HAVE_ENDSERVENT
			endservent();
#endif
		}
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_nsec(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* Note: this code is duplicated in higher.c in 
	 * ldns_nsec_type_check() function
	 */
	uint8_t window_block_nr;
	uint8_t bitmap_length;
	uint16_t type;
	uint16_t pos = 0;
	uint16_t bit_pos;
	uint8_t *data = ldns_rdf_data(rdf);
	const ldns_rr_descriptor *descriptor;
	
	while(pos < ldns_rdf_size(rdf)) {
		window_block_nr = data[pos];
		bitmap_length = data[pos + 1];
		pos += 2;
		
		for (bit_pos = 0; bit_pos < (bitmap_length) * 8; bit_pos++) {
			if (ldns_get_bit(&data[pos], bit_pos)) {
				type = 256 * (uint16_t) window_block_nr + bit_pos;
				descriptor = ldns_rr_descript(type);

				if (descriptor && descriptor->_name) {
					ldns_buffer_printf(output, "%s ", 
							descriptor->_name);
				} else {
					ldns_buffer_printf(output, "TYPE%u ", type);
				}
			}
		}
		
		pos += (uint16_t) bitmap_length;
	}
	
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_nsec3_salt(ldns_buffer *output, const ldns_rdf *rdf)
{
	uint8_t salt_length;
	uint8_t salt_pos;

	uint8_t *data = ldns_rdf_data(rdf);
	size_t pos;

	salt_length = data[0];
	/* todo: length check needed/possible? */
	/* from now there are variable length entries so remember pos */
	pos = 1;
	if (salt_length == 0) {
		ldns_buffer_printf(output, "- ");
	} else {
		for (salt_pos = 0; salt_pos < salt_length; salt_pos++) {
			ldns_buffer_printf(output, "%02x", data[1 + salt_pos]);
			pos++;
		}
		ldns_buffer_printf(output, " ");
	}
	
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_period(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* period is the number of seconds */
	uint32_t p = ldns_read_uint32(ldns_rdf_data(rdf));
	ldns_buffer_printf(output, "%u", p);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_tsigtime(ldns_buffer *output,const  ldns_rdf *rdf)
{
	/* tsigtime is 48 bits network order unsigned integer */
	uint64_t tsigtime = 0;
	uint8_t *data = ldns_rdf_data(rdf);

	if (ldns_rdf_size(rdf) != 6) {
		return LDNS_STATUS_ERR;
	}
	
	tsigtime = ldns_read_uint16(data);
	tsigtime *= 65536;
	tsigtime += ldns_read_uint16(data+2);
	tsigtime *= 65536;

	ldns_buffer_printf(output, "%llu ", tsigtime);

	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_apl(ldns_buffer *output, const ldns_rdf *rdf)
{
	uint8_t *data = ldns_rdf_data(rdf);
	uint16_t address_family = ldns_read_uint16(data);
	uint8_t prefix = data[2];
	bool negation;
	uint8_t adf_length;
	unsigned short i;
	unsigned int pos = 0;
	
	while (pos < (unsigned int) ldns_rdf_size(rdf)) {
		address_family = ldns_read_uint16(&data[pos]);
		prefix = data[pos + 2];
		negation = data[pos + 3] & LDNS_APL_NEGATION;
		adf_length = data[pos + 3] & LDNS_APL_MASK;
		if (address_family == LDNS_APL_IP4) {
			/* check if prefix < 32? */
			if (negation) {
				ldns_buffer_printf(output, "!");
			}
			ldns_buffer_printf(output, "%u:", address_family);
			/* address is variable length 0 - 4 */
			for (i = 0; i < 4; i++) {
				if (i > 0) {
					ldns_buffer_printf(output, ".");
				}
				if (i < (unsigned short) adf_length) {
					ldns_buffer_printf(output, "%d", 
					                   data[pos + i + 4]);
				} else {
					ldns_buffer_printf(output, "0");
				}
			}
			ldns_buffer_printf(output, "/%u ", prefix);
		} else if (address_family == LDNS_APL_IP6) {
			/* check if prefix < 128? */
			if (negation) {
				ldns_buffer_printf(output, "!");
			}
			ldns_buffer_printf(output, "%u:", address_family);
			/* address is variable length 0 - 16 */
			for (i = 0; i < 16; i++) {
				if (i % 2 == 0 && i > 0) {
					ldns_buffer_printf(output, ":");
				}
				if (i < (unsigned short) adf_length) {
					ldns_buffer_printf(output, "%02x", 
					                   data[pos + i + 4]);
				} else {
					ldns_buffer_printf(output, "00");
				}
			}
			ldns_buffer_printf(output, "/%u ", prefix);
		
		} else {
			/* unknown address family */
			ldns_buffer_printf(output, "Unknown address family: %u data: ", 
					address_family);
			for (i = 1; i < (unsigned short) (4 + adf_length); i++) {
				ldns_buffer_printf(output, "%02x", data[i]);
			}
		}
		pos += 4 + adf_length;
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_int16_data(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* Subtract the size (2) of the number that specifies the length */
	size_t size = ldns_b64_ntop_calculate_size(ldns_rdf_size(rdf) - 2);
	char *b64 = LDNS_XMALLOC(char, size);

	ldns_buffer_printf(output, "%u ", ldns_rdf_size(rdf) - 2);
	
	if (ldns_rdf_size(rdf) > 2 &&
	    ldns_b64_ntop(ldns_rdf_data(rdf) + 2,
				   ldns_rdf_size(rdf) - 2,
				   b64, size)) {
		ldns_buffer_printf(output, "%s", b64);
	}
	LDNS_FREE(b64);
	return ldns_buffer_status(output);
}

ldns_status
ldns_rdf2buffer_str_ipseckey(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* wire format from 
	   http://www.ietf.org/internet-drafts/draft-ietf-ipseckey-rr-12.txt
	*/
	uint8_t *data = ldns_rdf_data(rdf);
	uint8_t precedence;
	uint8_t gateway_type;
	uint8_t algorithm;
	
	ldns_rdf *gateway = NULL;
	uint8_t *gateway_data;
	
	size_t public_key_size;
	uint8_t *public_key_data;
	ldns_rdf *public_key;
	
	size_t offset = 0;
	ldns_status status;
	
	
	precedence = data[0];
	gateway_type = data[1];
	algorithm = data[2];
	offset = 3;
	
	switch (gateway_type) {
		case 0:
			/* no gateway */
			break;
		case 1:
			gateway_data = LDNS_XMALLOC(uint8_t, LDNS_IP4ADDRLEN);
			memcpy(gateway_data, &data[offset], LDNS_IP4ADDRLEN);
			gateway = ldns_rdf_new(LDNS_RDF_TYPE_A, LDNS_IP4ADDRLEN , gateway_data);
			break;
		case 2:
			gateway_data = LDNS_XMALLOC(uint8_t, LDNS_IP6ADDRLEN);
			memcpy(gateway_data, &data[offset], LDNS_IP6ADDRLEN);
			gateway = 
				ldns_rdf_new(LDNS_RDF_TYPE_AAAA, LDNS_IP6ADDRLEN, gateway_data);
			break;
		case 3:
			status = ldns_wire2dname(&gateway, data, ldns_rdf_size(rdf), &offset);
			break;
		default:
			/* error? */
			break;
	}

	public_key_size = ldns_rdf_size(rdf) - offset;
	public_key_data = LDNS_XMALLOC(uint8_t, public_key_size);
	memcpy(public_key_data, &data[offset], public_key_size);
	public_key = ldns_rdf_new(LDNS_RDF_TYPE_B64, public_key_size, public_key_data);
	
	ldns_buffer_printf(output, "%u %u %u ", precedence, gateway_type, algorithm);
	(void) ldns_rdf2buffer_str(output, gateway);
	ldns_buffer_printf(output, " ");
	(void) ldns_rdf2buffer_str(output, public_key);	

	ldns_rdf_free(gateway);
	ldns_rdf_free(public_key);
	
	return ldns_buffer_status(output);
}

ldns_status 
ldns_rdf2buffer_str_tsig(ldns_buffer *output, const ldns_rdf *rdf)
{
	/* TSIG RRs have no presentation format, make them #size <data> */
	return ldns_rdf2buffer_str_unknown(output, rdf);
}


ldns_status
ldns_rdf2buffer_str(ldns_buffer *buffer, const ldns_rdf *rdf)
{
	ldns_status res;

	/*ldns_buffer_printf(buffer, "%u:", ldns_rdf_get_type(rdf));*/
	if (rdf) {
		switch(ldns_rdf_get_type(rdf)) {
		case LDNS_RDF_TYPE_NONE:
			break;
		case LDNS_RDF_TYPE_DNAME:
			res = ldns_rdf2buffer_str_dname(buffer, rdf); 
			break;
		case LDNS_RDF_TYPE_INT8:
			res = ldns_rdf2buffer_str_int8(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_INT16:
			res = ldns_rdf2buffer_str_int16(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_INT32:
			res = ldns_rdf2buffer_str_int32(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_PERIOD:
			res = ldns_rdf2buffer_str_period(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_TSIGTIME:
			res = ldns_rdf2buffer_str_tsigtime(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_A:
			res = ldns_rdf2buffer_str_a(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_AAAA:
			res = ldns_rdf2buffer_str_aaaa(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_STR:
			res = ldns_rdf2buffer_str_str(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_APL:
			res = ldns_rdf2buffer_str_apl(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_B32_EXT:
			res = ldns_rdf2buffer_str_b32_ext(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_B64:
			res = ldns_rdf2buffer_str_b64(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_HEX:
			res = ldns_rdf2buffer_str_hex(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_NSEC: 
			res = ldns_rdf2buffer_str_nsec(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_NSEC3_SALT:
			res = ldns_rdf2buffer_str_nsec3_salt(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_TYPE: 
			res = ldns_rdf2buffer_str_type(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_CLASS:
			res = ldns_rdf2buffer_str_class(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_CERT_ALG:
			res = ldns_rdf2buffer_str_cert_alg(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_ALG:
			res = ldns_rdf2buffer_str_alg(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_UNKNOWN:
			res = ldns_rdf2buffer_str_unknown(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_TIME:
			res = ldns_rdf2buffer_str_time(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_LOC:
			res = ldns_rdf2buffer_str_loc(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_WKS:
		case LDNS_RDF_TYPE_SERVICE:
			res = ldns_rdf2buffer_str_wks(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_NSAP:
			res = ldns_rdf2buffer_str_nsap(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_IPSECKEY:
			res = ldns_rdf2buffer_str_ipseckey(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_TSIG:
			res = ldns_rdf2buffer_str_tsig(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_INT16_DATA:
			res = ldns_rdf2buffer_str_int16_data(buffer, rdf);
			break;
		case LDNS_RDF_TYPE_NSEC3_NEXT_OWNER:
			res = ldns_rdf2buffer_str_b32_ext(buffer, rdf);
			break;
		}
	} else {
		ldns_buffer_printf(buffer, "(null) ");
	}
	return LDNS_STATUS_OK;
}

ldns_status
ldns_rr2buffer_str(ldns_buffer *output, const ldns_rr *rr)
{
	uint16_t i, flags;
	ldns_status status = LDNS_STATUS_OK;
	if (!rr) {
		ldns_buffer_printf(output, "(null)\n");
	} else {
		if (ldns_rr_owner(rr)) {
			status = ldns_rdf2buffer_str_dname(output, ldns_rr_owner(rr)); 
		}
		if (status != LDNS_STATUS_OK) {
			return status;
		}

		/* TTL should NOT be printed if it is a question, 
		 * but we don't know that anymore... (do we?)
		 * if the rd count is 0 we deal with a question sec. RR 
		 */
		if (ldns_rr_rd_count(rr) > 0) {
			ldns_buffer_printf(output, "\t%d", ldns_rr_ttl(rr));
		}

		ldns_buffer_printf(output, "\t");
		status = ldns_rr_class2buffer_str(output, ldns_rr_get_class(rr));
		if (status != LDNS_STATUS_OK) {
			return status;
		}
		ldns_buffer_printf(output, "\t");

		status = ldns_rr_type2buffer_str(output, ldns_rr_get_type(rr));
		if (status != LDNS_STATUS_OK) {
			return status;
		}
		
		if (ldns_rr_rd_count(rr) > 0) {
			ldns_buffer_printf(output, "\t");
		}
		for (i = 0; i < ldns_rr_rd_count(rr); i++) {
			status = ldns_rdf2buffer_str(output, ldns_rr_rdf(rr, i));
			if (i < ldns_rr_rd_count(rr) - 1) {
				ldns_buffer_printf(output, " ");
			}
		}
		/* per RR special comments - handy for DNSSEC types */
		/* check to prevent question sec. rr from
		 * getting here */
		if (ldns_rr_rd_count(rr) > 0) {
			switch (ldns_rr_get_type(rr)) {
				case LDNS_RR_TYPE_DNSKEY:
					if (ldns_rr_rdf(rr, 0)) {
						flags = ldns_rdf2native_int16(ldns_rr_rdf(rr, 0));
						if (flags == 256 || flags == 384) {
							ldns_buffer_printf(output, 
									" ;{id = %d (zsk), size = %db}", 
									ldns_calc_keytag(rr),
									ldns_rr_dnskey_key_size(rr)); 
							break;
						} 
						if (flags == 257 || flags == 385) {
							ldns_buffer_printf(output, 
									" ;{id = %d (ksk), size = %db}", 
									ldns_calc_keytag(rr),
									ldns_rr_dnskey_key_size(rr)); 
							break;
						} 
						ldns_buffer_printf(output, " ;{id = %d, size = %db}", 
								ldns_calc_keytag(rr),
								ldns_rr_dnskey_key_size(rr)); 
					}
					break;
				case LDNS_RR_TYPE_RRSIG:
					ldns_buffer_printf(output, " ;{id = %d}", 
							ldns_rdf2native_int16(ldns_rr_rdf(rr, 6)));
					break;
				case LDNS_RR_TYPE_DS:
					{
						uint8_t *data = ldns_rdf_data(ldns_rr_rdf(rr, 3));
						size_t len = ldns_rdf_size(ldns_rr_rdf(rr, 3));
						char *babble = ldns_bubblebabble(data, len);
						ldns_buffer_printf(output, " ; %s", babble);
						LDNS_FREE(babble);
					}
					break;
				case LDNS_RR_TYPE_NSEC3:
					if (ldns_nsec3_optout(rr)) {
						ldns_buffer_printf(output, " ; flags: optout");
					}
					break;
				default:
					break;

			}
		}
		/* last */
		ldns_buffer_printf(output, "\n");
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_rr_list2buffer_str(ldns_buffer *output, const ldns_rr_list *list)
{
	uint16_t i;

	for(i = 0; i < ldns_rr_list_rr_count(list); i++) {
		(void) ldns_rr2buffer_str(output, ldns_rr_list_rr(list, i));
	}
	return ldns_buffer_status(output);
}

ldns_status
ldns_pktheader2buffer_str(ldns_buffer *output, const ldns_pkt *pkt)
{
	ldns_lookup_table *opcode = ldns_lookup_by_id(ldns_opcodes,
			                    (int) ldns_pkt_get_opcode(pkt));
	ldns_lookup_table *rcode = ldns_lookup_by_id(ldns_rcodes,
			                    (int) ldns_pkt_get_rcode(pkt));

	ldns_buffer_printf(output, ";; ->>HEADER<<- ");
	if (opcode) {
		ldns_buffer_printf(output, "opcode: %s, ", opcode->name);
	} else {
		ldns_buffer_printf(output, "opcode: ?? (%u), ", 
				ldns_pkt_get_opcode(pkt));
	}
	if (rcode) {
		ldns_buffer_printf(output, "rcode: %s, ", rcode->name);
	} else {
		ldns_buffer_printf(output, "rcode: ?? (%u), ", ldns_pkt_get_rcode(pkt));
	}
	ldns_buffer_printf(output, "id: %d\n", ldns_pkt_id(pkt));
	ldns_buffer_printf(output, ";; flags: ");

	if (ldns_pkt_qr(pkt)) {
		ldns_buffer_printf(output, "qr ");
	}
	if (ldns_pkt_aa(pkt)) {
		ldns_buffer_printf(output, "aa ");
	}
	if (ldns_pkt_tc(pkt)) {
		ldns_buffer_printf(output, "tc ");
	}
	if (ldns_pkt_rd(pkt)) {
		ldns_buffer_printf(output, "rd ");
	}
	if (ldns_pkt_cd(pkt)) {
		ldns_buffer_printf(output, "cd ");
	}
	if (ldns_pkt_ra(pkt)) {
		ldns_buffer_printf(output, "ra ");
	}
	if (ldns_pkt_ad(pkt)) {
		ldns_buffer_printf(output, "ad ");
	}
	ldns_buffer_printf(output, "; ");
	ldns_buffer_printf(output, "QUERY: %u, ", ldns_pkt_qdcount(pkt));
	ldns_buffer_printf(output, "ANSWER: %u, ", ldns_pkt_ancount(pkt));
	ldns_buffer_printf(output, "AUTHORITY: %u, ", ldns_pkt_nscount(pkt));
	ldns_buffer_printf(output, "ADDITIONAL: %u ", ldns_pkt_arcount(pkt));
	return ldns_buffer_status(output);
}

ldns_status
ldns_pkt2buffer_str(ldns_buffer *output, const ldns_pkt *pkt)
{
	uint16_t i;
	ldns_status status = LDNS_STATUS_OK;
	char *tmp;
	struct timeval time;
	time_t time_tt;

	if (!pkt) {
		ldns_buffer_printf(output, "null");
		return LDNS_STATUS_OK;
	}

	if (ldns_buffer_status_ok(output)) {
		status = ldns_pktheader2buffer_str(output, pkt);
		if (status != LDNS_STATUS_OK) {
			return status;
		}

		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; QUESTION SECTION:\n;; ");


		for (i = 0; i < ldns_pkt_qdcount(pkt); i++) {
			status = ldns_rr2buffer_str(output, 
				       ldns_rr_list_rr(ldns_pkt_question(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}
		}
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; ANSWER SECTION:\n");
		for (i = 0; i < ldns_pkt_ancount(pkt); i++) {
			status = ldns_rr2buffer_str(output, 
				       ldns_rr_list_rr(ldns_pkt_answer(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

		}
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; AUTHORITY SECTION:\n");

		for (i = 0; i < ldns_pkt_nscount(pkt); i++) {
			status = ldns_rr2buffer_str(output, 
				       ldns_rr_list_rr(ldns_pkt_authority(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}
		}
		ldns_buffer_printf(output, "\n");
		
		ldns_buffer_printf(output, ";; ADDITIONAL SECTION:\n");
		for (i = 0; i < ldns_pkt_arcount(pkt); i++) {
			status = ldns_rr2buffer_str(output, 
				       ldns_rr_list_rr(ldns_pkt_additional(pkt), i));
			if (status != LDNS_STATUS_OK) {
				return status;
			}

		}
		ldns_buffer_printf(output, "\n");
		/* add some futher fields */
		ldns_buffer_printf(output, ";; Query time: %d msec\n", 
				ldns_pkt_querytime(pkt));
		if (ldns_pkt_edns(pkt)) {
			ldns_buffer_printf(output,
				   ";; EDNS: version %u; flags:", 
				   ldns_pkt_edns_version(pkt));
			if (ldns_pkt_edns_do(pkt)) {
				ldns_buffer_printf(output, " do");
			}
			/* the extended rcode is the value set, shifted four bits,
			 * and or'd with the original rcode */
			if (ldns_pkt_edns_extended_rcode(pkt)) {
				ldns_buffer_printf(output, " ; ext-rcode: %d",
					(ldns_pkt_edns_extended_rcode(pkt) << 4 | ldns_pkt_get_rcode(pkt)));
			}
			ldns_buffer_printf(output, " ; udp: %u\n",
					   ldns_pkt_edns_udp_size(pkt));
			
			if (ldns_pkt_edns_data(pkt)) {
				ldns_buffer_printf(output, ";; Data: ");
				(void)ldns_rdf2buffer_str(output, 
							  ldns_pkt_edns_data(pkt));
				ldns_buffer_printf(output, "\n");
			}
		}
		if (ldns_pkt_tsig(pkt)) {
			ldns_buffer_printf(output, ";; TSIG:\n;; ");
			(void) ldns_rr2buffer_str(output, ldns_pkt_tsig(pkt));
			ldns_buffer_printf(output, "\n");
		}
		if (ldns_pkt_answerfrom(pkt)) {
			tmp = ldns_rdf2str(ldns_pkt_answerfrom(pkt));
			ldns_buffer_printf(output, ";; SERVER: %s\n", tmp);
			LDNS_FREE(tmp);
		}
		time = ldns_pkt_timestamp(pkt);
		time_tt = (time_t)time.tv_sec;
		ldns_buffer_printf(output, ";; WHEN: %s", 
				(char*)ctime(&time_tt));

		ldns_buffer_printf(output, ";; MSG SIZE  rcvd: %d\n", 
				(int)ldns_pkt_size(pkt));
	} else {
		return ldns_buffer_status(output);
	}
	return status;
}

#ifdef HAVE_SSL
static ldns_status
ldns_hmac_key2buffer_str(ldns_buffer *output, const ldns_key *k)
{
	ldns_status status;
	size_t i;
	ldns_rdf *b64_bignum;
	
	ldns_buffer_printf(output, "Key: ");

 	i = ldns_key_hmac_size(k);
	b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, ldns_key_hmac_key(k));
	status = ldns_rdf2buffer_str(output, b64_bignum);
	ldns_rdf_deep_free(b64_bignum);
	ldns_buffer_printf(output, "\n");
	return status;
}
#endif

#if defined(HAVE_SSL) && defined(USE_GOST)
static ldns_status
ldns_gost_key2buffer_str(ldns_buffer *output, EVP_PKEY *p)
{
	unsigned char* pp = NULL;
	int ret;
	ldns_rdf *b64_bignum;
	ldns_status status;

	ret = i2d_PrivateKey(p, &pp);
	b64_bignum = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, ret, pp);
	status = ldns_rdf2buffer_str(output, b64_bignum);

	ldns_rdf_deep_free(b64_bignum);
	OPENSSL_free(pp);
	ldns_buffer_printf(output, "\n");
	return status;
}
#endif

ldns_status
ldns_key2buffer_str(ldns_buffer *output, const ldns_key *k)
{
	ldns_status status = LDNS_STATUS_OK;
	unsigned char  *bignum;
	
#ifdef HAVE_SSL
	/* not used when ssl is not defined */
	ldns_rdf *b64_bignum = NULL;
	uint16_t i;
	
	RSA *rsa;
	DSA *dsa;
#endif /* HAVE_SSL */

	if (!k) {
		return LDNS_STATUS_ERR;
	}

	bignum = LDNS_XMALLOC(unsigned char, LDNS_MAX_KEYLEN);
	if (!bignum) {
		return LDNS_STATUS_ERR;
	}
	
	if (ldns_buffer_status_ok(output)) {
#ifdef HAVE_SSL
		switch(ldns_key_algorithm(k)) {
			case LDNS_SIGN_RSASHA1:
			case LDNS_SIGN_RSASHA1_NSEC3:
			case LDNS_SIGN_RSASHA256:
			case LDNS_SIGN_RSASHA512:
			case LDNS_SIGN_RSAMD5:
				/* copied by looking at dnssec-keygen output */
				/* header */
				rsa = ldns_key_rsa_key(k);

				ldns_buffer_printf(output,"Private-key-format: v1.2\n");
				switch(ldns_key_algorithm(k)) {
				case LDNS_SIGN_RSAMD5:
					ldns_buffer_printf(output,
								    "Algorithm: %u (RSA)\n",
								    LDNS_RSAMD5);
					break;
				case LDNS_SIGN_RSASHA1:
					ldns_buffer_printf(output,
								    "Algorithm: %u (RSASHA1)\n",
								    LDNS_RSASHA1);
					break;
				case LDNS_SIGN_RSASHA1_NSEC3:
					ldns_buffer_printf(output,
								    "Algorithm: %u (RSASHA1_NSEC3)\n",
								    LDNS_RSASHA1_NSEC3);
					break;
#ifdef USE_SHA2
				case LDNS_SIGN_RSASHA256:
					ldns_buffer_printf(output,
								    "Algorithm: %u (RSASHA256)\n",
								    LDNS_RSASHA256);
					break;
				case LDNS_SIGN_RSASHA512:
					ldns_buffer_printf(output,
								    "Algorithm: %u (RSASHA512)\n",
								    LDNS_RSASHA512);
					break;
#endif
				default:
					fprintf(stderr, "Warning: unknown signature ");
					fprintf(stderr,
						   "algorithm type %u\n", 
						   ldns_key_algorithm(k));
					ldns_buffer_printf(output,
								    "Algorithm: %u (Unknown)\n",
								    ldns_key_algorithm(k));
					break;
				}
				


				/* print to buf, convert to bin, convert to b64,
				 * print to buf */
				ldns_buffer_printf(output, "Modulus: "); 
				i = (uint16_t)BN_bn2bin(rsa->n, bignum);
				if (i > LDNS_MAX_KEYLEN) {
					goto error;
				}
				b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
				if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
					goto error;
				}
				ldns_rdf_deep_free(b64_bignum);
				ldns_buffer_printf(output, "\n"); 
				ldns_buffer_printf(output, "PublicExponent: "); 
				i = (uint16_t)BN_bn2bin(rsa->e, bignum);
				if (i > LDNS_MAX_KEYLEN) {
					goto error;
				}
				b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
				if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
					goto error;
				}
				ldns_rdf_deep_free(b64_bignum);
				ldns_buffer_printf(output, "\n"); 

				ldns_buffer_printf(output, "PrivateExponent: "); 
				if (rsa->d) {
					i = (uint16_t)BN_bn2bin(rsa->d, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					ldns_buffer_printf(output, "(Not available)\n");
				}
				
				ldns_buffer_printf(output, "Prime1: "); 
				if (rsa->p) {
					i = (uint16_t)BN_bn2bin(rsa->p, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					ldns_buffer_printf(output, "(Not available)\n");
				}

				ldns_buffer_printf(output, "Prime2: ");
				if (rsa->q) {
					i = (uint16_t)BN_bn2bin(rsa->q, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					ldns_buffer_printf(output, "(Not available)\n");
				}

				ldns_buffer_printf(output, "Exponent1: ");
				if (rsa->dmp1) {
					i = (uint16_t)BN_bn2bin(rsa->dmp1, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					ldns_buffer_printf(output, "(Not available)\n");
				}

				ldns_buffer_printf(output, "Exponent2: "); 
				if (rsa->dmq1) {
					i = (uint16_t)BN_bn2bin(rsa->dmq1, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					ldns_buffer_printf(output, "(Not available)\n");
				}

				ldns_buffer_printf(output, "Coefficient: "); 
				if (rsa->iqmp) {
					i = (uint16_t)BN_bn2bin(rsa->iqmp, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					ldns_buffer_printf(output, "(Not available)\n");
				}
				
				RSA_free(rsa);
				break;
			case LDNS_SIGN_DSA:
			case LDNS_SIGN_DSA_NSEC3:
				dsa = ldns_key_dsa_key(k);
			
				ldns_buffer_printf(output,"Private-key-format: v1.2\n");
				if (ldns_key_algorithm(k) == LDNS_SIGN_DSA) {
					ldns_buffer_printf(output,"Algorithm: 3 (DSA)\n");
				} else if (ldns_key_algorithm(k) == LDNS_SIGN_DSA_NSEC3) {
					ldns_buffer_printf(output,"Algorithm: 6 (DSA_NSEC3)\n");
				}

				/* print to buf, convert to bin, convert to b64,
				 * print to buf */
				ldns_buffer_printf(output, "Prime(p): "); 
				if (dsa->p) {
					i = (uint16_t)BN_bn2bin(dsa->p, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					printf("(Not available)\n");
				}

				ldns_buffer_printf(output, "Subprime(q): "); 
				if (dsa->q) {
					i = (uint16_t)BN_bn2bin(dsa->q, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					printf("(Not available)\n");
				}

				ldns_buffer_printf(output, "Base(g): "); 
				if (dsa->g) {
					i = (uint16_t)BN_bn2bin(dsa->g, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					printf("(Not available)\n");
				}

				ldns_buffer_printf(output, "Private_value(x): "); 
				if (dsa->priv_key) {
					i = (uint16_t)BN_bn2bin(dsa->priv_key, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					printf("(Not available)\n");
				}

				ldns_buffer_printf(output, "Public_value(y): "); 
				if (dsa->pub_key) {
					i = (uint16_t)BN_bn2bin(dsa->pub_key, bignum);
					if (i > LDNS_MAX_KEYLEN) {
						goto error;
					}
					b64_bignum =  ldns_rdf_new_frm_data(LDNS_RDF_TYPE_B64, i, bignum);
					if (ldns_rdf2buffer_str(output, b64_bignum) != LDNS_STATUS_OK) {
						goto error;
					}
					ldns_rdf_deep_free(b64_bignum);
					ldns_buffer_printf(output, "\n"); 
				} else {
					printf("(Not available)\n");
				}
				break;
			case LDNS_SIGN_GOST:
				/* no format defined, use blob */
#if defined(HAVE_SSL) && defined(USE_GOST)
				ldns_buffer_printf(output, "Private-key-format: v1.2\n");
				ldns_buffer_printf(output, "Algorithm: 211 (GOST)\n");
				status = ldns_gost_key2buffer_str(output, k->_key.key);
#endif
				break;
			case LDNS_SIGN_HMACMD5:
				/* there's not much of a format defined for TSIG */
				/* It's just a binary blob, Same for all algorithms */
                ldns_buffer_printf(output, "Private-key-format: v1.2\n");
                ldns_buffer_printf(output, "Algorithm: 157 (HMAC_MD5)\n");
				status = ldns_hmac_key2buffer_str(output, k);
				break;
			case LDNS_SIGN_HMACSHA1:
		        ldns_buffer_printf(output, "Private-key-format: v1.2\n");
		        ldns_buffer_printf(output, "Algorithm: 158 (HMAC_SHA1)\n");
				status = ldns_hmac_key2buffer_str(output, k);
				break;
			case LDNS_SIGN_HMACSHA256:
		        ldns_buffer_printf(output, "Private-key-format: v1.2\n");
		        ldns_buffer_printf(output, "Algorithm: 159 (HMAC_SHA256)\n");
				status = ldns_hmac_key2buffer_str(output, k);
				break;
		}
#endif /* HAVE_SSL */
	} else {
#ifdef HAVE_SSL
		LDNS_FREE(b64_bignum);
#endif
		LDNS_FREE(bignum);
		return ldns_buffer_status(output);
	}
	LDNS_FREE(bignum);
	return status;

#ifdef HAVE_SSL
	/* compiles warn the label isn't used */
error:
	LDNS_FREE(bignum);
	return LDNS_STATUS_ERR;
#endif /* HAVE_SSL */
	
}

/*
 * Zero terminate the buffer and fix it to the size of the string.
 */
char *
ldns_buffer2str(ldns_buffer *buffer)
{
	char *tmp_str;
	char *str;
	
	/* check if buffer ends with \0, if not, and 
	   if there is space, add it */
	if (*(ldns_buffer_at(buffer, ldns_buffer_position(buffer))) != 0) {
		if (!ldns_buffer_reserve(buffer, 1)) {
			return NULL;
		}
		ldns_buffer_write_u8(buffer, (uint8_t) '\0');
		if (!ldns_buffer_set_capacity(buffer, ldns_buffer_position(buffer))) {
			return NULL;
		}
	}

	tmp_str = ldns_buffer_export(buffer);
	str = LDNS_XMALLOC(char, strlen(tmp_str) + 1);
	memcpy(str, tmp_str, strlen(tmp_str) + 1);

	return str;
}

char *
ldns_rdf2str(const ldns_rdf *rdf)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(LDNS_MIN_BUFLEN);

	if (ldns_rdf2buffer_str(tmp_buffer, rdf) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = ldns_buffer2str(tmp_buffer);
	}
	
	ldns_buffer_free(tmp_buffer);
	return result;
}

char *
ldns_rr2str(const ldns_rr *rr)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(LDNS_MIN_BUFLEN);

	if (ldns_rr2buffer_str(tmp_buffer, rr) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = ldns_buffer2str(tmp_buffer);
	}
	ldns_buffer_free(tmp_buffer);
	return result;
}

char *
ldns_pkt2str(const ldns_pkt *pkt)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(LDNS_MAX_PACKETLEN);

	if (ldns_pkt2buffer_str(tmp_buffer, pkt) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = ldns_buffer2str(tmp_buffer);
	}

	ldns_buffer_free(tmp_buffer);
	return result;
}

char *
ldns_key2str(const ldns_key *k)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(LDNS_MIN_BUFLEN);
	if (ldns_key2buffer_str(tmp_buffer, k) == LDNS_STATUS_OK) {
		/* export and return string, destroy rest */
		result = ldns_buffer2str(tmp_buffer);
	}
	ldns_buffer_free(tmp_buffer);
	return result;
}

char *
ldns_rr_list2str(const ldns_rr_list *list)
{
	char *result = NULL;
	ldns_buffer *tmp_buffer = ldns_buffer_new(LDNS_MIN_BUFLEN); 

	if (list) {
		if (ldns_rr_list2buffer_str(tmp_buffer, list) == LDNS_STATUS_OK) {
		}
	} else {
		ldns_buffer_printf(tmp_buffer, "(null)\n");
	}

	/* export and return string, destroy rest */
	result = ldns_buffer2str(tmp_buffer);
	ldns_buffer_free(tmp_buffer);
	return result;
}

void
ldns_rdf_print(FILE *output, const ldns_rdf *rdf)
{
	char *str = ldns_rdf2str(rdf);
	if (str) {
		fprintf(output, "%s", str);
	} else {
		fprintf(output, "Unable to convert rdf to string\n");
	}
	LDNS_FREE(str);
}

void
ldns_rr_print(FILE *output, const ldns_rr *rr)
{
	char *str = ldns_rr2str(rr);
	if (str) {
		fprintf(output, "%s", str);
	} else {
		fprintf(output, "Unable to convert rr to string\n");
	}
	LDNS_FREE(str);
}

void
ldns_pkt_print(FILE *output, const ldns_pkt *pkt)
{
	char *str = ldns_pkt2str(pkt);
	if (str) {
		fprintf(output, "%s", str);
	} else {
		fprintf(output, "Unable to convert packet to string\n");
	}
	LDNS_FREE(str);
}

void
ldns_rr_list_print(FILE *output, const ldns_rr_list *lst)
{
	size_t i;
	for (i = 0; i < ldns_rr_list_rr_count(lst); i++) {
		ldns_rr_print(output, ldns_rr_list_rr(lst, i));
	}
}

void
ldns_resolver_print(FILE *output, const ldns_resolver *r)
{
	uint16_t i;
	ldns_rdf **n;
	ldns_rdf **s;
	size_t *rtt;
	if (!r) {
		return;
	}
	n = ldns_resolver_nameservers(r);
	s = ldns_resolver_searchlist(r);
	rtt = ldns_resolver_rtt(r);

	fprintf(output, "port: %d\n", (int)ldns_resolver_port(r));
	fprintf(output, "edns0 size: %d\n", (int)ldns_resolver_edns_udp_size(r));
	fprintf(output, "use ip6: %d\n", (int)ldns_resolver_ip6(r));

	fprintf(output, "recursive: %d\n", ldns_resolver_recursive(r));
	fprintf(output, "usevc: %d\n", ldns_resolver_usevc(r));
	fprintf(output, "igntc: %d\n", ldns_resolver_igntc(r));
	fprintf(output, "fail: %d\n", ldns_resolver_fail(r));
	fprintf(output, "retry: %d\n", (int)ldns_resolver_retry(r));
	fprintf(output, "timeout: %d\n", (int)ldns_resolver_timeout(r).tv_sec);
	
	fprintf(output, "default domain: ");
	ldns_rdf_print(output, ldns_resolver_domain(r)); 
	fprintf(output, "\n");

	fprintf(output, "searchlist:\n");
	for (i = 0; i < ldns_resolver_searchlist_count(r); i++) {
		fprintf(output, "\t");
		ldns_rdf_print(output, s[i]);
		fprintf(output, "\n");
	}

	fprintf(output, "nameservers:\n");
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		fprintf(output, "\t");
		ldns_rdf_print(output, n[i]);

		switch ((int)rtt[i]) {
			case LDNS_RESOLV_RTT_MIN:
			fprintf(output, " - reachable\n");
			break;
			case LDNS_RESOLV_RTT_INF:
			fprintf(output, " - unreachable\n");
			break;
		}
	}
}

void
ldns_zone_print(FILE *output, const ldns_zone *z)
{
	ldns_rr_print(output, ldns_zone_soa(z));
	ldns_rr_list_print(output, ldns_zone_rrs(z));
}
