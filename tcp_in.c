#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "my.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
void tcp_listen_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_syn_recv_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_established_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet);
void tcp_syn_sent_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet); 
void tcp_cc_in(struct tcp_sock *tsk, struct tcp_cb *cb); 

static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
    u16 old_snd_wnd = tsk->snd_wnd;
	//  tsk->snd_wnd = cb->rwnd;        //modified
    tsk->adv_wnd = cb->rwnd;
    tsk->snd_wnd = min(tsk->adv_wnd, tsk->cwnd);

    if (old_snd_wnd == 0 && tsk->snd_wnd != 0)
        wake_up(tsk->wait_send);
	log(DEBUG, "tcp_update_window: successed to update_window.");
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
//	fprintf(stdout, "TODO: implement %s please.\ndf, __FUNCTION__);
	if (!tsk) {
		log(ERROR, "tcp_process: can't find a tsk that fit to packet'");
		return;
	} 

	if (!is_tcp_seq_valid(tsk, cb)) return;
	if (!(cb->flags & TCP_SYN) && !(cb->flags & TCP_ACK)) {
		log(ERROR, "tcp_process: recv a invalid packet that have no ack.");
		return;//除了SYN之外的所有包都必须有TCP_ACK
	}

	switch (tsk->state) {
		//被动建立和关闭连接
		case TCP_CLOSED:
			log(DEBUG, "tcp_process: process a CLOSED state packet.");
			tcp_send_reset(cb);
			return;
		case TCP_LISTEN: 
			tcp_listen_process(tsk, cb, packet);
			log(DEBUG, "tcp_process: process a LISTEN state packet.");
			return;		//LISTEN的sock不应该处理其他的包,比如RST，FIN.所以直接return
			break;
		case TCP_SYN_RECV: 
			log(DEBUG, "tcp_process: process a SYN_RECV state packet.");
			tcp_syn_recv_process(tsk, cb, packet);
			break;
		case TCP_ESTABLISHED: 
			log(DEBUG, "tcp_process: process a ESTABLISHED state packet.");
			tcp_established_process(tsk, cb, packet);
			break;
		case TCP_LAST_ACK:
			log(DEBUG, "tcp_process: process a LAST_ACK state packet.");
			if (cb->flags == TCP_ACK) {
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unhash(tsk);
				return;
			}
			break;
		//主动建立和关闭连接
		case TCP_SYN_SENT:
			log(DEBUG, "tcp_process: process a SYN_SENT state packet.");
			tcp_syn_sent_process(tsk, cb, packet);
			break;
		
		case TCP_FIN_WAIT_1:
			log(DEBUG, "tcp_process: process a FIN_WAIT_1 state packet.");
			if (cb->flags == TCP_ACK) {
				tcp_set_state(tsk, TCP_FIN_WAIT_2);

				tsk->rcv_nxt = cb->seq_end;

				return;
			}
			break;
		case TCP_FIN_WAIT_2:
			log(DEBUG, "tcp_process: process a FIN_WAIT_2 state packet.");
			if (cb->flags == TCP_FIN) {
				tcp_set_state(tsk, TCP_TIME_WAIT);

				tsk->rcv_nxt = cb->seq_end;
				tcp_send_control_packet(tsk, TCP_ACK);

				tcp_set_timewait_timer(tsk);

				return;
			}
			break;
	}

	//拥塞控制
	if (tsk->state != TCP_CLOSED && 
		tsk->state != TCP_LISTEN && 
		tsk->state != TCP_SYN_RECV) {
		tcp_cc_in(tsk, cb);
	}


	if (cb->flags & TCP_RST) {
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return;
	}

	if (cb->flags & TCP_SYN) {
		tcp_send_reset(cb);
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return;
	}

		
}

//congestion control with tcp_in
void tcp_cc_in(struct tcp_sock *tsk, struct tcp_cb *cb) {
	if (cb->ack > tsk->snd_una) { 	//收到新数据的确认
		log(DEBUG, "tcp_cc_in:  recv a new ack.");
		switch(tsk->cstate) {
			case TCP_COPEN:
				//slow start
				if (tsk->cwnd < tsk->ssthresh) 
					tsk->cwnd += MSS;
				else
					tsk->cwnd += (MSS / tsk->cwnd);
						
				tsk->snd_una = cb->ack;
				update_snd_buf(tsk, cb);
				break;

			case TCP_CRECOVERY:
				update_snd_buf(tsk, cb);
				if (cb->ack < tsk->rp)	
					resend(tsk);	
				else
					tsk->cstate = TCP_COPEN;
				break;
		}

		tcp_set_retrans_timer(tsk);
	}

	else if (cb->ack == tsk->snd_una){ 	//没有新数据确认
		log(DEBUG, "tcp_cc_in:  recv a old ack.");
		switch(tsk->cstate) {
			case TCP_COPEN:
				tsk->cstate = TCP_CDISORDER;
				break;
			case TCP_CDISORDER:
				tsk->ssthresh = tsk->cwnd / 2;
				tsk->cwnd = tsk->ssthresh;
				tsk->cstate = TCP_CRECOVERY;
				break;
			case TCP_CRECOVERY:
			default:
				break;
		} 
		tsk->inflight -= MSS;

		tcp_set_retrans_timer(tsk);
	}
	else
		log(DEBUG, "tcp_cc_in: recv dupack of previous pkt that already be acked.");
}

void tcp_listen_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	if (cb->flags == TCP_SYN) {
   		struct tcp_sock *csk = alloc_tcp_sock();

		csk->sk_sip = tsk->sk_sip;
		csk->sk_sport = tsk->sk_sport;
		csk->sk_dip = cb->saddr;
		csk->sk_dport = cb->sport;
		csk->parent = tsk;
		list_add_tail(&csk->list, &tsk->listen_queue);
		csk->rcv_nxt = cb->seq_end;
				
		tcp_set_state(csk, TCP_SYN_RECV);
		if (tcp_hash(csk) != 0)
			log(ERROR,"tcp_process:failed to process on listen state.");
		tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
	}
}

void tcp_syn_recv_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	if (cb->flags == TCP_ACK){
		tcp_set_state(tsk, TCP_ESTABLISHED);	 
		tsk->cwnd = 1;
		tcp_sock_accept_enqueue(tsk);
		tsk->rcv_nxt = cb->seq_end;
		wake_up(tsk->parent->wait_accept); 
		log(DEBUG, "tcp_syn_recv_process: wake up a wait_accept.");

		return;
	}
}
void tcp_established_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	if (!(cb->flags & (TCP_RST|TCP_SYN))) {
		tcp_update_window_safe(tsk, cb);	

		if (cb->pl_len) { 
			tsk->rcv_wnd -= cb->pl_len;
			if (cb->seq > tsk->rcv_nxt) { 
				log(DEBUG, "tcp_established_process: recv a data packet out of order.");
				list_add_tail(&cb->list, &tsk->rcv_ofo_buf);	 
			}
			else{
				log(DEBUG, "tcp_established_process: recv a data packet in order.");
				write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
				tsk->rcv_nxt = cb->seq_end;
				
				//把ofo buffer中能连续上的包送到rcv buf
				struct tcp_cb *ofo_cb, *q;
				int flag = 1; 	//有没有形成连续的包
				while (flag) {
					flag = 0;
					list_for_each_entry_safe(ofo_cb, q, &tsk->rcv_ofo_buf, list) {
						if (ofo_cb->seq_end == tsk->rcv_nxt) {
							flag = 1;
							list_delete_entry(&ofo_cb->list);
							write_ring_buffer(tsk->rcv_buf, ofo_cb->payload, ofo_cb->pl_len);
						}		
					}
				}
				wake_up(tsk->wait_recv);
				log(DEBUG, "tcp_established_process: wake up a wait_recv.");
			}
		}
		
	}
	if (cb->flags == (TCP_FIN | TCP_ACK)) {
		tcp_set_state(tsk, TCP_CLOSE_WAIT);
		tcp_send_control_packet(tsk, TCP_ACK);
		tcp_sock_close(tsk);
		
		return;	
	} 
	if (cb->flags != TCP_ACK) { 	//处理数据包
		tcp_send_control_packet(tsk, TCP_ACK);
	}
}
void tcp_syn_sent_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	if (cb->flags == (TCP_SYN | TCP_ACK)) {
				tcp_set_state(tsk, TCP_ESTABLISHED);

				tsk->rcv_nxt = cb->seq_end;
				tcp_send_control_packet(tsk, TCP_ACK);
				wake_up(tsk->wait_connect);
				log(DEBUG, "tcp_syn_sent_process: wake up a wait_connect.");

				return;
			}
			else {
				tcp_send_reset(cb);
				return;
			}
}

	
