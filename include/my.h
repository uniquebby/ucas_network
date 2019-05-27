#ifndef _MY_H_
#define _MY_H_

#include "tcp_sock.h"
#include "ip.h"
#include "ether.h"
#include "list.h"
#include "tcp.h"
#include "log.h"

#include <stdlib.h>

#define MSS ETH_FRAME_LEN - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE


//the node for send_buf
struct packet_link_node{
   char *packet;
   struct list_head list;
   u32 len;
   u32 tcp_data_len;
   u32 seq;
};

static inline void resend(struct tcp_sock *tsk) {
    struct packet_link_node *pkt_node = list_entry(tsk->send_buf.next, struct packet_link_node, list);
		struct iphdr *ip = packet_to_ip_hdr(pkt_node->packet);
		log(DEBUG, "resend: resend a packet with ip %u", ntohl(ip->daddr));

    tsk->inflight += pkt_node->tcp_data_len;
    ip_send_packet(pkt_node->packet, pkt_node->len);
}

static inline void update_snd_buf(struct tcp_sock *tsk, struct tcp_cb *cb) {
	log(DEBUG, "update_snd_buf");
    struct packet_link_node *pkt, *q;
    //delete pkt from send_buf which has been ack by peer
		int i = 0;
    list_for_each_entry_safe(pkt, q, &tsk->send_buf, list) {
			i++;
			log(DEBUG, "updata_snd_buf: list_for_each_entry: number %d", i);
  	  if (pkt->seq < cb->ack) {
					log(DEBUG, "updata_snd_buf: delete a link packet");
   	      list_delete_entry(&pkt->list);
   		}
		}
    //reset timer if there are any pkt hasn't been acked
  //  if (!list_empty(&tsk->send_buf))
//        tcp_set_retrans_timer(tsk);
}

#endif
