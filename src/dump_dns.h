/* dump_dns.c - library function to emit decoded dns message on a FILE.
 *
 * By: Paul Vixie, ISC, October 2007
 */

//void
//dump_dns(const u_char *payload, size_t paylen,
//	  FILE *trace, const char *endline);

void
dump_dns(const u_char *payload, size_t paylen,
          FILE *trace, const char *endline,
          const char *src_ip, time_t ts);

