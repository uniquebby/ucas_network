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
struct packet_link_node 
{
   char *packet;
   struct list_head list;
   u32 len;
   u32 tcp_data_len;
   u32 seq;
};

static inline struct packet_link_node* alloc_packet_link_node(int len)
{
   	char *link_packet = (char *)malloc(len);
	if (!link_packet) 
	{
		log(ERROR, "malloc link_packet failed."); 	
		return NULL;
	}
   struct packet_link_node *pkt_node = (struct packet_link_node*)malloc(sizeof(struct packet_link_node));

   pkt_node->packet = link_packet;

   return pkt_node;
}


static inline void free_packet_link_node(struct packet_link_node *pkt_node) 
{
	free(pkt_node->packet);
	free(pkt_node);
}

static inline void resend(struct tcp_sock *tsk) 
{
	log(DEBUG, "resend: resnd a link packet start send_buf=%p and next =%p 1111111111",&tsk->send_buf, tsk->send_buf.next);
	if (list_empty(&tsk->send_buf))
		return;

	log(DEBUG, "resend: resnd a link packet start send_buf=%p and next =%p2222222222222222",&tsk->send_buf, tsk->send_buf.next);
    struct packet_link_node *pkt_node = list_entry(tsk->send_buf.next, struct packet_link_node, list);

    struct packet_link_node *pkt = alloc_packet_link_node(pkt_node->len);
	log(DEBUG, "resend: resnd a link packet start send_buf=%p and next =%p55555555555",&tsk->send_buf, tsk->send_buf.next);
	memcpy(pkt->packet, pkt_node->packet, pkt_node->len);
	log(DEBUG, "resend: resnd a link packet start send_buf=%p and next =%p6666666666666666",&tsk->send_buf, tsk->send_buf.next);

    tsk->inflight += pkt_node->tcp_data_len;
	log(DEBUG, "resend: resnd a link packet start send_buf=%p and next =%p77777777777777",&tsk->send_buf, tsk->send_buf.next);

//   	struct tcphdr *link_node_tcp = packet_to_tcp_hdr(pkt->packet);
   	struct iphdr *ip = packet_to_ip_hdr(pkt->packet);
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

    tcp->checksum = tcp_checksum(ip, tcp);
    
    ip->checksum = ip_checksum(ip);

	log(DEBUG, "resend: resend a packet with seq %u and ack %u", ntohl(tcp->seq),ntohl(tcp->ack));
    ip_send_packet(pkt->packet, pkt_node->len);
	log(DEBUG, "resen: resnd a link packet done with seq %u and len %u",pkt_node->seq, pkt_node->len);
}

static inline void update_snd_buf(struct tcp_sock *tsk, struct tcp_cb *cb) 
{
    struct packet_link_node *pkt_node, *q;
    //delete pkt from send_buf which has been ack by peer
    list_for_each_entry_safe(pkt_node, q, &tsk->send_buf, list) 
	{
  		if (pkt_node->seq < cb->ack) 
		{
			log(DEBUG, "updata_snd_buf: delete a link packet with seq %u and len %u",pkt_node->seq, pkt_node->len);
   	    	list_delete_entry(&pkt_node->list);
			free(pkt_node);
   		}
	}
}

#endif
