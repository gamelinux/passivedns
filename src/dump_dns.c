/* dump_dns.c - library function to emit decoded dns message on a FILE.
 *
 */

#include <sys/types.h>
#include <stdio.h>
#include "dump_dns.h"

/* Define to 1 if you have the `ns_initparse' function. */
#define HAVE_NS_INITPARSE 1

/* Define to 1 if you have the `ns_parserr' function. */
#define HAVE_NS_PARSERR 1

#if HAVE_NS_INITPARSE && HAVE_NS_PARSERR

/*
 * Copyright (c) 2007 by Internet Systems Consortium, Inc. ("ISC")
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifdef __linux__
# define _GNU_SOURCE
#ifndef __USE_POSIX199309
# define __USE_POSIX199309
#endif
#endif

#ifdef __SVR4
# define u_int32_t uint32_t
# define u_int16_t uint16_t
#endif

#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern const char *_res_opcodes[];
extern const char *_res_sectioncodes[];
#define p_rcode __p_rcode
extern const char *p_rcode(int rcode);

static void dump_dns_sect(ns_msg *, ns_sect, FILE *, const char *);
static void dump_dns_rr(ns_msg *, ns_rr *, ns_sect, FILE *);
void dump_payload(u_char* xdata, uint16_t dlen);
char *fasthex(u_char *xdata, u_int16_t length);
void printchars(char buf[NS_MAXDNAME], u_char *cdata, u_int16_t dlen);

#define MY_GET16(s, cp) do { \
	register const u_char *t_cp = (const u_char *)(cp); \
	(s) = ((u_int16_t)t_cp[0] << 8) \
	    | ((u_int16_t)t_cp[1]) \
	    ; \
	(cp) += INT16SZ; \
} while (0)

#define MY_GET32(l, cp) do { \
	register const u_char *t_cp = (const u_char *)(cp); \
	(l) = ((u_int32_t)t_cp[0] << 24) \
	    | ((u_int32_t)t_cp[1] << 16) \
	    | ((u_int32_t)t_cp[2] << 8) \
	    | ((u_int32_t)t_cp[3]) \
	    ; \
	(cp) += INT32SZ; \
} while (0)

//#include "dump_dns.h"

void
dump_dns(const u_char *payload, size_t paylen,
	  const char *src_ip, time_t ts)
{
	u_int opcode, rcode, id;
	const char *sep;
	ns_msg msg;
        FILE *trace = stdout;
        const char *endline = "\n";

	/*fprintf(trace, "%sdns ", endline);*/
	if (ns_initparse(payload, paylen, &msg) < 0) {
		fputs(strerror(errno), trace);
		return;
	}
	opcode = ns_msg_getflag(msg, ns_f_opcode);
        //if ( opcode != 0 ) return; // Only QUERY are processed
	rcode = ns_msg_getflag(msg, ns_f_rcode);
        //if ( rcode == 3 ) return; // Skip NXDOMAIN
        fprintf(trace,"%ld||hostname||%s||",ts,src_ip);
	id = ns_msg_id(msg);
	fprintf(trace, "%s,%s,%u", _res_opcodes[opcode], p_rcode(rcode), id);
        
//printf("%u,%u,%u\n", opcode, rcode, id);
//return;
	sep = ",";
#define FLAG(t,f) if (ns_msg_getflag(msg, f)) { \
			fprintf(trace, "%s%s", sep, t); \
			sep = "|"; \
		  }
	FLAG("qr", ns_f_qr);
	FLAG("aa", ns_f_aa);
	FLAG("tc", ns_f_tc);
	FLAG("rd", ns_f_rd);
	FLAG("ra", ns_f_ra);
	FLAG("z", ns_f_z);
	FLAG("ad", ns_f_ad);
	FLAG("cd", ns_f_cd);
#undef FLAG 

	dump_dns_sect(&msg, ns_s_qd, trace, endline);
	dump_dns_sect(&msg, ns_s_an, trace, endline);
	dump_dns_sect(&msg, ns_s_ns, trace, endline);
	dump_dns_sect(&msg, ns_s_ar, trace, endline);
        fprintf(trace, "\n");
}

static void
dump_dns_sect(ns_msg *msg, ns_sect sect, FILE *trace, const char *endline) {
	int rrnum, rrmax;
	const char *sep;
	ns_rr rr;

        fprintf(trace, "||");
	rrmax = ns_msg_count(*msg, sect);
	if (rrmax == 0) {
		fputs("0", trace);
		return;
	}
        fprintf(trace, "%d",rrmax);
	//fprintf(trace, "%s%d", endline, rrmax);
        //fprintf(trace, "%s", endline);
	sep = "";
	for (rrnum = 0; rrnum < rrmax; rrnum++) {
		if (ns_parserr(msg, sect, rrnum, &rr)) {
			fputs(strerror(errno), trace);
			return;
		}
		//fprintf(trace, " %s", sep);
                fprintf(trace,"||");
		dump_dns_rr(msg, &rr, sect, trace);
		sep = endline;
	}
}

static void
dump_dns_rr(ns_msg *msg, ns_rr *rr, ns_sect sect, FILE *trace) {
	char buf[NS_MAXDNAME];
        char *ahex;
	u_int class, type;
	const u_char *rd;
	u_int32_t soa[5];
	u_int16_t mx;
	int n;
        uint8_t  i;

	class = ns_rr_class(*rr);
	type = ns_rr_type(*rr);
	fprintf(trace, "%s,%s,%s",
		ns_rr_name(*rr),
		p_class(class),
		p_type(type));
	if (sect == ns_s_qd)
		return;
	fprintf(trace, ",%lu", (u_long)ns_rr_ttl(*rr));
	rd = ns_rr_rdata(*rr);
	switch (type) {
	case ns_t_soa:
		n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
				       rd, buf, sizeof buf);
		if (n < 0)
			goto error;
		putc(',', trace);
		fputs(buf, trace);
		rd += n;
		n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
				       rd, buf, sizeof buf);
		if (n < 0)
			goto error;
		putc(',', trace);
		fputs(buf, trace);
		rd += n;
		if (ns_msg_end(*msg) - rd < 5*NS_INT32SZ)
			goto error;
		for (n = 0; n < 5; n++)
			MY_GET32(soa[n], rd);
		sprintf(buf, "%u,%u,%u,%u,%u",
			soa[0], soa[1], soa[2], soa[3], soa[4]);
		break;
	case ns_t_a:
		inet_ntop(AF_INET, rd, buf, sizeof buf);
		break;
	case ns_t_aaaa:
		inet_ntop(AF_INET6, rd, buf, sizeof buf);
		break;
	case ns_t_mx:
		MY_GET16(mx, rd);
		fprintf(trace, ",%u", mx);
		/* FALLTHROUGH */
	case ns_t_ns:
        case ns_t_txt:
	case ns_t_ptr:
	case ns_t_cname:
		n = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg),
				       rd, buf, sizeof buf);
		if (n < 0)
			goto error;
		break;
	default:
 error:
		//sprintf(buf, "[%u]", ns_rr_rdlen(*rr));
                //fprintf(stderr, ",[%u],", ns_rr_rdlen(*rr));
                fprintf(trace, ",");
                for (i=1;i<ns_rr_rdlen(*rr);i++) {
                    if ( 31 < rd[i] && rd[i] < 127) {
                        fprintf(trace, "%c", rd[i]);
                    } else {
                        fprintf(trace, ".");
                    }
                }
	}
	if (buf[0] != '\0') {
		putc(',', trace);
		fputs(buf, trace);
	}
}

void print_only(char* in) 
{ 
    while(*in++) {
        if (isprint(*in)) putchar(*in);
    }
}

void printchars(char buf[NS_MAXDNAME], u_char *cdata, u_int16_t dlen) {
    uint8_t  i;

    printf("[");
    for (i=0;i<dlen;i++) {
        if ( 31 < cdata[i] && cdata[i] < 127) {
            printf("%c", cdata[i]);
        }
    }
    printf("]");
}

#else

void
dump_dns(const u_char *payload, size_t paylen,
          FILE *trace, const char *endline)
{
	(void) payload;
	(void) paylen;
        fprintf(trace, "NO BINDLIB\n");
}

#endif
