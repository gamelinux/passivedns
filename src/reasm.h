/*
** This file is a part of PassiveDNS.
**
** Copyright (C) 2010-2026, Edward Fjellskål <edwardfjellskaal@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

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
