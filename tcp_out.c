#include "tcp.h"
#include "tcp_sock.h"
#include "ip.h"
#include "ether.h"

#include "log.h"
#include "list.h"

#include "my.h"

#include <stdlib.h>
#include <string.h>

// initialize tcp header according to the arguments
static void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
		u8 flags, u16 rwnd)
{
	memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off = TCP_HDR_OFFSET;
	tcp->flags = flags;
	tcp->rwnd = htons(rwnd);
}

// send a tcp packet
//
// Given that the payload of the tcp packet has been filled, initialize the tcp 
// header and ip header (remember to set the checksum in both header), and emit 
// the packet by calling ip_send_packet.
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len) 
{   
    struct iphdr *ip = packet_to_ip_hdr(packet); 
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);
    
    int ip_tot_len = len - ETHER_HDR_SIZE;
    int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;
    
    u32 saddr = tsk->sk_sip;
    u32 daddr = tsk->sk_dip;
    u16 sport = tsk->sk_sport;
    u16 dport = tsk->sk_dport;
    
    u32 seq = tsk->snd_nxt;
    u32 ack = tsk->rcv_nxt;
    u16 rwnd = tsk->rcv_wnd;
    
    tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH|TCP_ACK, rwnd);
    ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP);
    
    tcp->checksum = tcp_checksum(ip, tcp);
    
    ip->checksum = ip_checksum(ip);

	  
    //把发送的包加入到send_buf中
    struct packet_link_node *pkt_node = alloc_packet_link_node(len); 
	memcpy(pkt_node->packet, packet, len);
    pkt_node->len = len;
    pkt_node->tcp_data_len = tcp_data_len;
    pkt_node->seq = tsk->snd_nxt;
    list_add_tail(&pkt_node->list, &tsk->send_buf);

//   	struct iphdr *link_node_ip = packet_to_ip_hdr(pkt_node->packet);
//	log(DEBUG, "tcp_sent_packet: buffer a packet with ip %u and seq1 %u ", ntohl(link_node_ip->daddr), tsk->snd_nxt);


    tsk->snd_nxt += tcp_data_len;
	log(DEBUG, "tcp_sent_packet: send a data pkt with len %d tsk->snd_nxt %u!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",tcp_data_len, tsk->snd_nxt);
    //tsk->snd_wnd -= tcp_data_len;             源代码中有的，觉得有问题所以注释掉
    
    //开启定时器
    if (!tsk->retrans_timer.enable) 
	{
        tcp_set_retrans_timer(tsk);
		log(DEBUG, "tcp_send_packet: tcp_set_retrans_timer successed.");
	}
    
//	log(DEBUG, "tcp_send_packet: is ip——send——packet 's problem？.");
    ip_send_packet(packet, len);
	++tsk->inflight;
	log(DEBUG, "tcp_send_packet: inflight is %d ######################################################################.", tsk->inflight);
	log(DEBUG, "tcp_send_packet: send a data pkt successed.");
}


// send a tcp control packet
//
// The control packet is like TCP_ACK, TCP_SYN, TCP_FIN (excluding TCP_RST).
// All these packets do not have payload and the only difference among these is 
// the flags.
void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags)
{
    int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
    char *packet = (char *)malloc(pkt_size);

    if (!packet) 
	{
        log(ERROR, "malloc tcp control packet failed.");
        return ;
    }

    log(DEBUG, "malloc tcp control packet successed.");
    struct iphdr *ip = packet_to_ip_hdr(packet);
    struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

    u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

    ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);
    tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, tsk->snd_nxt, \
            tsk->rcv_nxt, flags, tsk->rcv_wnd);


    tcp->checksum = tcp_checksum(ip, tcp);
    log(DEBUG, "tcp_send_control_packet: tcp_checsum done.");


	log(DEBUG, "tcp_set_control_packet: send a packet with ip %u and seq= %u,ack=%u and flags %hu and rcv_wnd %hu,inflight%d", ntohl(ip->daddr), tsk->snd_nxt,tsk->rcv_nxt,flags, tsk->rcv_wnd, tsk->inflight);
    if (flags & (TCP_SYN|TCP_FIN)) 
	{
  		char *link_packet = (char*)malloc(pkt_size);
		if (!link_packet) 
		{
			log(ERROR, "malloc link_packet failed."); 	
			return;
		}
		memcpy(link_packet, packet, pkt_size);
		

	    //把发送的包加入到send_buf中
 	    struct packet_link_node *pkt_node = (struct packet_link_node *)malloc(sizeof(struct packet_link_node));
		if (!pkt_node)
        	log(ERROR, "tcp_send_control_packet: malloc pkt_node failed.");
    	pkt_node->packet = link_packet;
       	log(DEBUG, "tcp_send_control_packet: malloc pkt_node successed.");
   	    pkt_node->len = pkt_size;
    	pkt_node->seq = tsk->snd_nxt;
//       	log(DEBUG, "tcp_send_control_packet: malloc pkt_node successed 1.");
    	list_add_tail(&pkt_node->list, &tsk->send_buf);
 //      	log(DEBUG, "tcp_send_control_packet: malloc pkt_node successed 2.");
//		struct iphdr *link_node_ip = packet_to_ip_hdr(pkt_node->packet);

        tsk->snd_nxt += 1;

    	//开启定时器
  //     	log(DEBUG, "tcp_send_control_packet: malloc pkt_node successed 3.");
    	if (!(tsk->retrans_timer.enable)) 
		{
       		tcp_set_retrans_timer(tsk);
			log(DEBUG, "tcp_send_control_packet: tcp_set_retrans_timer successed.");
		}

	}

    ip_send_packet(packet, pkt_size);
	log(DEBUG, "tcp_send_control_packet: send a control packet successed.");
}

// send tcp reset packet
//
// Different from tcp_send_control_packet, the fields of reset packet is 
// from tcp_cb instead of tcp_sock.
void tcp_send_reset(struct tcp_cb *cb)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet) 
	{
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	ip_init_hdr(ip, cb->daddr, cb->saddr, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, cb->dport, cb->sport, 0, cb->seq_end, TCP_RST|TCP_ACK, 0);
	tcp->checksum = tcp_checksum(ip, tcp);

	ip_send_packet(packet, pkt_size);
}
