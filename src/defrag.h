
#ifndef DEFRAG_H
#define DEFRAG_H

#define FRAG_HASH4(src,dst,ip_id) (( src + dst + ip_id) % 11)

typedef struct _single_frag {
   uint16_t            ip_off;  /* IP frag offset */
   const uint8_t       *fdata;  /* Pointer to payload */
   uint16_t            fdlen;   /* Payload length */
   struct _single_frag *prev;   /* Prev frag */
   struct _single_frag *next;   /* Next frag */
} single_frag;

typedef struct _frag_stream {
   uint16_t            ip_id;    /* Keep the IP ID here */
   uint16_t            tfsize;   /* Total size of frags payload in stream */
   uint32_t            lfsize;   /* Last frag indicated size of frag stream */
   struct _ip4_header  *ip4;     /* IP-header from first fragment */
   struct _frag_stream *prev;    /* Prev frag stream */
   struct _frag_stream *next;    /* Next frag stream */
   struct _single_frag *sfprev;  /* Prev single frag */
   struct _single_frag *sfnext;  /* Next single frag */
} frag_stream;


void process_frag(packetinfo *pi);
void update_frag(packetinfo *pi, frag_stream *frags);
void ip_defrag(packetinfo *pi, frag_stream *frags);

#endif //DEFRAG_H

