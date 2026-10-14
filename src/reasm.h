#ifndef REASM_H
#define REASM_H

/* Fragment reassembly and TCP DNS stream reassembly.
 * Callers must already have rejected a short or wrapped header.
 * Completed datagrams are handed back through reasm_continue().
 */

int ip4_defrag(packetinfo *pi);
int ip6_defrag(packetinfo *pi, const uint8_t *unfrag, uint16_t unfrag_len,
               uint16_t nh_at, uint8_t frag_next, uint32_t id,
               uint16_t off_bytes, int more,
               const uint8_t *frag, uint16_t fraglen);
void tcp_reassemble(packetinfo *pi);
void tcp_buf_free(tcp_buf *tb);
void reasm_expire(time_t now);
void reasm_shutdown(void);
void reasm_continue(packetinfo *parent, int is_v6, uint8_t *buf, uint32_t len);

#endif
