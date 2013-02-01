
//#include <stdio.h>
#include <stdlib.h>

#include <string.h>
//#include <time.h>
#include <sys/types.h>
//#include <ldns/ldns.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap.h>
#include "passivedns.h"

#include <ldns/ldns.h>
#include "dns.h"


#include "defrag.h"

globalconfig config;
frag_stream *fbucket[11];

// Functions that are needed in further handling of payload as pdns data
// pi->plen pi->af pi->ip4->ip_p pi->ip6->next pi->payload pi->sc pi->cxt->s_total_pkts pi->cxt->plid pi->cxt->last_pkt_time pi->cxt->start_time pi->pheader->ts pi->cxt->s_ip pi->cxt->d_ip pi->cxt->af pi->ip4->ip_p

void process_frag(packetinfo *pi)
{
   olog("Processing Frag with IP ID:%d\n",pi->ip4->ip_id);
   frag_stream *frags = NULL;
   frag_stream *head = NULL;
   uint32_t frag_hash;
   frag_hash = FRAG_HASH4(pi->ip4->ip_src,pi->ip4->ip_dst,pi->ip4->ip_id);
   olog("frag_hash:%d\n",frag_hash);
   frags = fbucket[frag_hash];
   head = frags;

   /* Check if we have a frag_stream->id (dupe), if not add */
   /* look for frag packets with same ID */
   while (frags != NULL) {
      if (frags->ip_id == pi->ip4->ip_id) {
         /* We got a match */
         olog("ID Match!\n");
         update_frag(pi,frags);
         return;
      }
      olog("No ID Match!\n");
      frags = frags->next;
   }

   if (frags == NULL) { /* We got our first frag stream or a new frag stream */
      frags = (frag_stream *) calloc(1,sizeof(frag_stream));
      frags->ip_id = pi->ip4->ip_id;
      olog("New Frag Stream allocated for IP id:%d\n",frags->ip_id);
   }
   /* Push new frags on top */
   if (head != NULL) {
       head->prev  = frags;
       frags->next = head;
       olog("Check1:%d\n",frags->ip_id);
   }
   fbucket[frag_hash] = frags;

   update_frag(pi,frags);
}

void update_frag(packetinfo *pi, frag_stream *frags)
{
    olog("update_frag\n");
    single_frag *sfrag    = NULL;
    single_frag *head = NULL;
    single_frag *tail = NULL;
    sfrag = frags->sfnext;
    head = sfrag;
    tail = sfrag;

    /* If we dont have copied the IP header from the first fragment */
    /* and if this is the first fragment - copy it... */
    if ( pi->frag == FRAG_FIRST && frags->ip4 == NULL ) {
        olog("New Frag Stream\n");
        frags->ip4 = (ip4_header *) calloc(1,72);
        memcpy(frags->ip4, pi->ip4, IP_HL(pi->ip4)*4);
    }

    /* spool to the last frag in linked list, add new frag... */
    while (sfrag != NULL ) {
        olog("Stepping once to get to the last frag in linked list...\n");
        if (sfrag->ip_off == (ntohs(pi->ip4->ip_off) & IP_OFFMASK) ) {
            olog("Huston - we have a offset duped single frag\n");
            return;
        }
        tail = sfrag;
        sfrag = sfrag->next;
    }

    /* tail should be lined up, but first we need to prepare the new sfrag */
    single_frag *new_sfrag = NULL;
    new_sfrag = (single_frag *) calloc(1,sizeof(single_frag));
    new_sfrag->fdlen = pi->packet_bytes;
    new_sfrag->fdata = (const uint8_t *) calloc(1,new_sfrag->fdlen);
    new_sfrag->ip_off = (ntohs(pi->ip4->ip_off) & IP_OFFMASK);
    memcpy((uint8_t *) new_sfrag->fdata, (pi->ip4 + IP_HL(pi->ip4)*4), new_sfrag->fdlen);
    if (frags->sfnext == NULL) { /* We are at head, and this is the first frag */
        frags->sfnext = new_sfrag;
    } else {
        tail->next = new_sfrag;
        new_sfrag->prev = tail;
    } 
    /* Update the total fragstream size */
    frags->tfsize += pi->packet_bytes;
    olog("ip_len:%d\n",pi->packet_bytes);
    olog("tfsize:%d\n",frags->tfsize);

    /* if we have the last fragment at hand...:
        1: Update the lfsize
        2: try to reass the frag stream */
    if ( pi->frag == FRAG_LAST ) {
       frags->lfsize = ((ntohs(pi->ip4->ip_off) & IP_OFFMASK) *8) + pi->packet_bytes;
    }
    olog("lfsize:%d\n",frags->lfsize);

    if (frags->ip4 != NULL && frags->lfsize != 0 && frags->tfsize >= frags->lfsize ) {
       /* We should now have the first and the last frag (and a buffer that is full) - try to reassemble*/
       ip_defrag(pi,frags);
    }

    return;
}

void ip_defrag(packetinfo *pi, frag_stream *frags)
{
    single_frag *sfrag    = NULL;
    //single_frag *tmpsfrag = NULL;
    sfrag = frags->sfnext;
    //uint16_t fssize = 0;
    ldns_status   status;
    ldns_pkt     *dns_pkt;


    if (frags->tfsize > frags->lfsize) {
       olog("Total fragsize is bigger than the last frag+len - bailing:%d vs %d\n",frags->tfsize,frags->lfsize);
       // Free this frag stream
       return;
    }
    olog("DEFRAGING!\n");
    const uint8_t *defdata;
    defdata = (const uint8_t *) calloc(1,frags->lfsize);
    while (sfrag != NULL ) {
        olog("defrag ip_off:%d, %d\n",sfrag->ip_off,sfrag->fdlen);
        if ((sfrag->ip_off *8) + sfrag->fdlen > frags->lfsize) {
            olog("Frag_offset+Frag_len is beyond fragment size!\n");
        } else {
            olog("Added frag with offset:%d\n",sfrag->ip_off);
            memcpy(((uint8_t *) defdata + (sfrag->ip_off * 8 )), sfrag->fdata, sfrag->fdlen);
            dump_payload(sfrag->fdata,sfrag->fdlen);
        }
        sfrag = sfrag->next;
    }
    frags->ip4->ip_off = 0;
    pi->ip4 = frags->ip4;
    pi->udph = (udp_header *) (pi->ip4 + (IP_HL(pi->ip4) * 4));
    pi->plen = frags->lfsize;
    pi->payload = defdata;
    status = ldns_wire2pkt(&dns_pkt,pi->payload, pi->plen);
    olog("Status:%d\n",status);
    dump_payload(pi->payload,pi->plen);
    //dns_parser(pi);
    parse_ip4 (pi);
    pi->frag = FRAG_NO;
    /* Walk the linked list and try to defrag */
    // FRAG:1 - MF:1, OS:0         (total-fragstream-mem +185*8)
    // FRAG:2 - MF:1, OS:185       (total-fragstream-mem +185*8)
    // FRAG:4 - MF:0, OS:370       (total-fragstream-mem +32*8)
    // Say last fragment has size 32, total fragstream size is 402*8 = 3216
    // Total length of fragment stream should be Last Frag Offsett + (pi->packet_bytes - IP_HL()*4)
    /* if total-fragstream-mem >= Total lengt calculated from last frag
       we can now walk the linked list, memcpy the parts into the right place...
       Overlaps are brutally handled :) */
    /* 5 main fifferent methods: */
    // First (Windows, SUN, MacOS, HPUX) - (Walk the raw linkedlist reversed)
    // Last/RFC791 (Cisco)               - (Walk the raw linkedlist)
    // Linux                             - (Sort the linked list, then walk the linkedlist Reversed)
    // BSD (AIX, FreeBSD, HPUX, VMS)     - sorted(fragmentsin, key=lambda x:x[IP].frag)[::-1]:
    // BSD-Right (HP Jet Direct)         - sorted(fragmentsin, key= lambda x:x[IP].frag):

    //while (sfrag != NULL ) {
    //    fssize += sfrag->fdlen;
    //    sfrag = sfrag->next;
    //}
    //frags->

    // When defragged - pass to upper layer (tcp/udp)

    // Delete the frag stream and all its frags 
}

void dump_payload(const uint8_t* data,uint32_t dlen);

void dump_payload(const uint8_t* data,uint32_t dlen) {
  uint16_t  tbuf[PKT_MAXPAY+2];
  uint8_t* t = tbuf;
  uint16_t  i;
  uint16_t  max = dlen > PKT_MAXPAY ? PKT_MAXPAY : dlen;

  if (!dlen) return;

  for (i=0;i<max;i++) {
    if (isprint(*data)) *(t++) = *data;
      else if (!*data)  *(t++) = '?';
      else *(t++) = '.';
    data++;
  }

  *t = 0;

  plog( "  # Payload: \"%s\"%s",tbuf,dlen > PKT_MAXPAY ? "...\n" : "\n");
}

