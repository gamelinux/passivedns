/*
 * net.c
 *
 * Network implementation
 * All network related functions are grouped here
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
#elif HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef _MSC_VER
#include <sys/time.h>
#else
#include <compat/gettimeofday.h>
#endif

#ifdef _MSC_VER
#define close(X) closesocket(X)
#endif

#include <errno.h>

ldns_status
ldns_send(ldns_pkt **result_packet, ldns_resolver *r, const ldns_pkt *query_pkt)
{
	ldns_buffer *qb;
	ldns_status result;
	ldns_rdf *tsig_mac = NULL;

	qb = ldns_buffer_new(LDNS_MIN_BUFLEN);

	if (query_pkt && ldns_pkt_tsig(query_pkt)) {
		tsig_mac = ldns_rr_rdf(ldns_pkt_tsig(query_pkt), 3);
	}


	if (!query_pkt ||
	    ldns_pkt2buffer_wire(qb, query_pkt) != LDNS_STATUS_OK) {
		result = LDNS_STATUS_ERR;
	} else {
        	result = ldns_send_buffer(result_packet, r, qb, tsig_mac);
	}

	ldns_buffer_free(qb);
	
	return result;
}

ldns_status
ldns_send_buffer(ldns_pkt **result, ldns_resolver *r, ldns_buffer *qb, ldns_rdf *tsig_mac)
{
	uint8_t i;
	
	struct sockaddr_storage *ns;
	size_t ns_len;
	struct timeval tv_s;
	struct timeval tv_e;

	ldns_rdf **ns_array;
	size_t *rtt;
	ldns_pkt *reply;
	bool all_servers_rtt_inf;
	uint8_t retries;

	uint8_t *reply_bytes = NULL;
	size_t reply_size = 0;
	ldns_status status, send_status;

	assert(r != NULL);

	status = LDNS_STATUS_OK;
	rtt = ldns_resolver_rtt(r);
	ns_array = ldns_resolver_nameservers(r);
	reply = NULL; 
	ns_len = 0;

	all_servers_rtt_inf = true;

	if (ldns_resolver_random(r)) {
		ldns_resolver_nameservers_randomize(r);
	}

	/* loop through all defined nameservers */
	for (i = 0; i < ldns_resolver_nameserver_count(r); i++) {
		if (rtt[i] == LDNS_RESOLV_RTT_INF) {
			/* not reachable nameserver! */
			continue;
		}
		all_servers_rtt_inf = false;

		/* maybe verbosity setting?
		printf("Sending to ");
		ldns_rdf_print(stdout, ns_array[i]);
		printf("\n");
		*/
		ns = ldns_rdf2native_sockaddr_storage(ns_array[i],
				ldns_resolver_port(r), &ns_len);
		
		if ((ns->ss_family == AF_INET) && 
				(ldns_resolver_ip6(r) == LDNS_RESOLV_INET6)) {
			continue;
		}

		if ((ns->ss_family == AF_INET6) &&
				 (ldns_resolver_ip6(r) == LDNS_RESOLV_INET)) {
			continue;
		}

		gettimeofday(&tv_s, NULL);

		send_status = LDNS_STATUS_ERR;

		/* reply_bytes implicitly handles our error */
		if (1 == ldns_resolver_usevc(r)) {
			for (retries = ldns_resolver_retry(r); retries > 0; retries--) {
				send_status = 
					ldns_tcp_send(&reply_bytes, qb, ns, 
					(socklen_t)ns_len, ldns_resolver_timeout(r), 
					&reply_size);
				if (send_status == LDNS_STATUS_OK) {
					break;
				}
			}
		} else {
			for (retries = ldns_resolver_retry(r); retries > 0; retries--) {
				/* ldns_rdf_print(stdout, ns_array[i]); */
				send_status = 
					ldns_udp_send(&reply_bytes, qb, ns, 
							(socklen_t)ns_len, ldns_resolver_timeout(r), 
							&reply_size);
				
				if (send_status == LDNS_STATUS_OK) {
					break;
				}
			}
		}

		if (send_status != LDNS_STATUS_OK) {
			ldns_resolver_set_nameserver_rtt(r, i, LDNS_RESOLV_RTT_INF);
			status = send_status;
		}
		
		/* obey the fail directive */
		if (!reply_bytes) {
			/* the current nameserver seems to have a problem, blacklist it */
			if (ldns_resolver_fail(r)) {
				LDNS_FREE(ns);
				return LDNS_STATUS_ERR;
			} else {
				LDNS_FREE(ns);
				continue;
			}
		} 
		
		status = ldns_wire2pkt(&reply, reply_bytes, reply_size);
		if (status != LDNS_STATUS_OK) {
			LDNS_FREE(reply_bytes);
			LDNS_FREE(ns);
			return status;
		}
		
		LDNS_FREE(ns);
		gettimeofday(&tv_e, NULL);

		if (reply) {
			ldns_pkt_set_querytime(reply, (uint32_t)
				((tv_e.tv_sec - tv_s.tv_sec) * 1000) +
				(tv_e.tv_usec - tv_s.tv_usec) / 1000);
			ldns_pkt_set_answerfrom(reply, ns_array[i]);
			ldns_pkt_set_timestamp(reply, tv_s);
			ldns_pkt_set_size(reply, reply_size);
			break;
		} else {
			if (ldns_resolver_fail(r)) {
				/* if fail is set bail out, after the first
				 * one */
				break;
			}
		}

		/* wait retrans seconds... */
		sleep((unsigned int) ldns_resolver_retrans(r));
	}

	if (all_servers_rtt_inf) {
		LDNS_FREE(reply_bytes);
		return LDNS_STATUS_RES_NO_NS;
	}
#ifdef HAVE_SSL
	if (tsig_mac && reply_bytes) {
		if (!ldns_pkt_tsig_verify(reply,
		                          reply_bytes,
					  reply_size,
		                          ldns_resolver_tsig_keyname(r),
		                          ldns_resolver_tsig_keydata(r), tsig_mac)) {
			status = LDNS_STATUS_CRYPTO_TSIG_BOGUS;
		}
	}
#else
	(void)tsig_mac;
#endif /* HAVE_SSL */
	
	LDNS_FREE(reply_bytes);
	if (result) {
		*result = reply;
	}

	return status;
}

ldns_status
ldns_udp_send(uint8_t **result, ldns_buffer *qbin, const struct sockaddr_storage *to, 
		socklen_t tolen, struct timeval timeout, size_t *answer_size)
{
	int sockfd;
	uint8_t *answer;

	sockfd = ldns_udp_bgsend(qbin, to, tolen, timeout);

	if (sockfd == 0) {
		return LDNS_STATUS_SOCKET_ERROR;
	}

	/* wait for an response*/
	answer = ldns_udp_read_wire(sockfd, answer_size, NULL, NULL);
	close(sockfd);

	if (*answer_size == 0) {
		/* oops */
		return LDNS_STATUS_NETWORK_ERR;
	}

	*result = answer;
	return LDNS_STATUS_OK;
}

int
ldns_udp_bgsend(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, 
		struct timeval timeout)
{
	int sockfd;

	sockfd = ldns_udp_connect(to, timeout);

	if (sockfd == 0) {
		return 0;
	}

	if (ldns_udp_send_query(qbin, sockfd, to, tolen) == 0) {
		return 0;
	}
	return sockfd;
}

int
ldns_udp_connect(const struct sockaddr_storage *to, struct timeval timeout)
{
	int sockfd;
	
	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_DGRAM, 
					IPPROTO_UDP)) 
			== -1) {
                return 0;
        }
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout,
				(socklen_t)sizeof(timeout))) {
                /* might fail, in that case, use default for now */
		/*
		close(sockfd);
		return 0;
		*/
        }
	return sockfd;
}

int
ldns_tcp_connect(const struct sockaddr_storage *to, socklen_t tolen, 
		struct timeval timeout)
{
	int sockfd;
	
	if ((sockfd = socket((int)((struct sockaddr*)to)->sa_family, SOCK_STREAM, 
					IPPROTO_TCP)) == -1) {
		return 0;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (void*)&timeout,
				(socklen_t) sizeof(timeout))) {
		close(sockfd);
		return 0;
	}
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (void*)&timeout,
				(socklen_t) sizeof(timeout))) {
		close(sockfd);
		return 0;
	}

	if (connect(sockfd, (struct sockaddr*)to, tolen) == -1) {
 		close(sockfd);
		return 0;
	}

	return sockfd;
}

ssize_t
ldns_tcp_send_query(ldns_buffer *qbin, int sockfd, 
                    const struct sockaddr_storage *to, socklen_t tolen)
{
	uint8_t *sendbuf;
	ssize_t bytes;

	/* add length of packet */
	sendbuf = LDNS_XMALLOC(uint8_t, ldns_buffer_position(qbin) + 2);
	ldns_write_uint16(sendbuf, ldns_buffer_position(qbin));
	memcpy(sendbuf + 2, ldns_buffer_export(qbin), ldns_buffer_position(qbin));

	bytes = sendto(sockfd, (void*)sendbuf,
			ldns_buffer_position(qbin) + 2, 0, (struct sockaddr *)to, tolen);

        LDNS_FREE(sendbuf);

	if (bytes == -1 || (size_t) bytes != ldns_buffer_position(qbin) + 2 ) {
		return 0;
	}
	return bytes;
}

/* don't wait for an answer */
ssize_t
ldns_udp_send_query(ldns_buffer *qbin, int sockfd, const struct sockaddr_storage *to, 
		socklen_t tolen)
{
	ssize_t bytes;

	bytes = sendto(sockfd, (void*)ldns_buffer_begin(qbin),
			ldns_buffer_position(qbin), 0, (struct sockaddr *)to, tolen);

	if (bytes == -1 || (size_t)bytes != ldns_buffer_position(qbin)) {
		return 0;
	}
	if ((size_t) bytes != ldns_buffer_position(qbin)) {
		return 0;
	}
	return bytes;
}

uint8_t *
ldns_udp_read_wire(int sockfd, size_t *size, struct sockaddr_storage *from,
		socklen_t *fromlen)
{
	uint8_t *wire;
	ssize_t wire_size;

	wire = LDNS_XMALLOC(uint8_t, LDNS_MAX_PACKETLEN);
	if (!wire) {
		*size = 0;
		return NULL;
	}

	wire_size = recvfrom(sockfd, (void*)wire, LDNS_MAX_PACKETLEN, 0, 
			(struct sockaddr *)from, fromlen);

	/* recvfrom can also return 0 */
	if (wire_size == -1 || wire_size == 0) {
		*size = 0;
		LDNS_FREE(wire);
		return NULL;
	}

	*size = (size_t)wire_size;
	wire = LDNS_XREALLOC(wire, uint8_t, (size_t)wire_size);

	return wire;
}

uint8_t *
ldns_tcp_read_wire(int sockfd, size_t *size)
{
	uint8_t *wire;
	uint16_t wire_size;
	ssize_t bytes = 0;

	wire = LDNS_XMALLOC(uint8_t, 2);
	if (!wire) {
		*size = 0;
		return NULL;
	}
	
	while (bytes < 2) {
		bytes = recv(sockfd, (void*)wire, 2, 0);
		if (bytes == -1 || bytes == 0) {
			*size = 0;
			LDNS_FREE(wire);
			return NULL;
		}
	}

	wire_size = ldns_read_uint16(wire);
	
	LDNS_FREE(wire);
	wire = LDNS_XMALLOC(uint8_t, wire_size);
	bytes = 0;

	while (bytes < (ssize_t) wire_size) {
		bytes += recv(sockfd, (void*) (wire + bytes), 
				(size_t) (wire_size - bytes), 0);
		if (bytes == -1 || bytes == 0) {
			LDNS_FREE(wire);
			*size = 0;
			return NULL;
		}
	}
	
	*size = (size_t) bytes;
	return wire;
}

/* keep in mind that in DNS tcp messages the first 2 bytes signal the
 * amount data to expect
 */
ldns_status
ldns_tcp_send(uint8_t **result,  ldns_buffer *qbin, const struct sockaddr_storage *to, 
		socklen_t tolen, struct timeval timeout, size_t *answer_size)
{
	int sockfd;
	uint8_t *answer;
	
	sockfd = ldns_tcp_bgsend(qbin, to, tolen, timeout);
	
	if (sockfd == 0) {
		return LDNS_STATUS_ERR;
	}
	
	answer = ldns_tcp_read_wire(sockfd, answer_size);
	close(sockfd);

	if (*answer_size == 0) {
		/* oops */
		return LDNS_STATUS_NETWORK_ERR;
	}

	/* resize accordingly */
	answer = (uint8_t*)LDNS_XREALLOC(answer, uint8_t *, (size_t)*answer_size);
	*result = answer;
	return LDNS_STATUS_OK;
}

int
ldns_tcp_bgsend(ldns_buffer *qbin, const struct sockaddr_storage *to, socklen_t tolen, 
		struct timeval timeout)
{
	int sockfd;
	
	sockfd = ldns_tcp_connect(to, tolen, timeout);
	
	if (sockfd == 0) {
		return 0;
	}
	
	if (ldns_tcp_send_query(qbin, sockfd, to, tolen) == 0) {
		return 0;
	}
	
	return sockfd;
}

/* code from rdata.c */
struct sockaddr_storage *
ldns_rdf2native_sockaddr_storage(const ldns_rdf *rd, uint16_t port, size_t *size)
{
        struct sockaddr_storage *data;
        struct sockaddr_in  *data_in;
        struct sockaddr_in6 *data_in6;

        data = LDNS_MALLOC(struct sockaddr_storage);
        if (!data) {
                return NULL;
        }
        if (port == 0) {
                port =  LDNS_PORT;
        }

        switch(ldns_rdf_get_type(rd)) {
                case LDNS_RDF_TYPE_A:
                        data->ss_family = AF_INET;
                        data_in = (struct sockaddr_in*) data;
                        data_in->sin_port = (in_port_t)htons(port);
                        memcpy(&(data_in->sin_addr), ldns_rdf_data(rd), ldns_rdf_size(rd));
                        *size = sizeof(struct sockaddr_in);
                        return data;
                case LDNS_RDF_TYPE_AAAA:
                        data->ss_family = AF_INET6;
                        data_in6 = (struct sockaddr_in6*) data;
                        data_in6->sin6_port = (in_port_t)htons(port);
                        memcpy(&data_in6->sin6_addr, ldns_rdf_data(rd), ldns_rdf_size(rd));
                        *size = sizeof(struct sockaddr_in6);
                        return data;
                default:
                        LDNS_FREE(data);
                        return NULL;
        }
}

ldns_rdf *
ldns_sockaddr_storage2rdf(struct sockaddr_storage *sock, uint16_t *port)
{
        ldns_rdf *addr;
        struct sockaddr_in *data_in;
        struct sockaddr_in6 *data_in6;

        switch(sock->ss_family) {
                case AF_INET:
                        data_in = (struct sockaddr_in*)sock;
                        if (port) {
                                *port = ntohs((uint16_t)data_in->sin_port);
                        }
                        addr = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_A,
                                        LDNS_IP4ADDRLEN, &data_in->sin_addr);
                        break;
                case AF_INET6:
                        data_in6 = (struct sockaddr_in6*)sock;
                        if (port) {
                                *port = ntohs((uint16_t)data_in6->sin6_port);
                        }
                        addr = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_AAAA,
                                        LDNS_IP6ADDRLEN, &data_in6->sin6_addr);
                        break;
                default:
                        if (port) {
                                *port = 0;
                        }
                        return NULL;
        }
        return addr;
}

/* code from resolver.c */
ldns_status
ldns_axfr_start(ldns_resolver *resolver, ldns_rdf *domain, ldns_rr_class class) 
{
        ldns_pkt *query;
        ldns_buffer *query_wire;

        struct sockaddr_storage *ns = NULL;
        size_t ns_len = 0;
        size_t ns_i;
        ldns_status status;

        if (!resolver || ldns_resolver_nameserver_count(resolver) < 1) {
                return LDNS_STATUS_ERR;
        }

        query = ldns_pkt_query_new(ldns_rdf_clone(domain), LDNS_RR_TYPE_AXFR, class, 0);

        if (!query) {
                return LDNS_STATUS_ADDRESS_ERR;
        }
        /* For AXFR, we have to make the connection ourselves */
        /* try all nameservers (which usually would mean v4 fallback if 
         * @hostname is used */
        for (ns_i = 0;
             ns_i < ldns_resolver_nameserver_count(resolver) &&
             resolver->_socket == 0;
             ns_i++) {
	        ns = ldns_rdf2native_sockaddr_storage(
	        	resolver->_nameservers[ns_i],
			ldns_resolver_port(resolver), &ns_len);
	
		resolver->_socket = ldns_tcp_connect(ns, (socklen_t)ns_len, 
				ldns_resolver_timeout(resolver));
	}

	if (resolver->_socket == 0) {
		ldns_pkt_free(query);
		LDNS_FREE(ns);
		return LDNS_STATUS_NETWORK_ERR;
	}

#ifdef HAVE_SSL
	if (ldns_resolver_tsig_keyname(resolver) && ldns_resolver_tsig_keydata(resolver)) {
		status = ldns_pkt_tsig_sign(query,
		                            ldns_resolver_tsig_keyname(resolver),
		                            ldns_resolver_tsig_keydata(resolver),
		                            300, ldns_resolver_tsig_algorithm(resolver), NULL);
		if (status != LDNS_STATUS_OK) {
			return LDNS_STATUS_CRYPTO_TSIG_ERR;
		}
	}
#endif /* HAVE_SSL */

        /* Convert the query to a buffer          * Is this necessary?
         */
        query_wire = ldns_buffer_new(LDNS_MAX_PACKETLEN);
        status = ldns_pkt2buffer_wire(query_wire, query);
        if (status != LDNS_STATUS_OK) {
                ldns_pkt_free(query);
                LDNS_FREE(ns);
                return status;
        }
        /* Send the query */
        if (ldns_tcp_send_query(query_wire, resolver->_socket, ns, 
				(socklen_t)ns_len) == 0) {
                ldns_pkt_free(query);
                ldns_buffer_free(query_wire);
                LDNS_FREE(ns);
                return LDNS_STATUS_NETWORK_ERR;
        }

        ldns_pkt_free(query);
        ldns_buffer_free(query_wire);
        LDNS_FREE(ns);

        /*
         * The AXFR is done once the second SOA record is sent
         */
        resolver->_axfr_soa_count = 0;
        return LDNS_STATUS_OK;
}
