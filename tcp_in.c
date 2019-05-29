#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "my.h"
#include "synch_wait.h"

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
	//  tsk->snd_wnd = cb->rwnd;        //modified

	int old_allowed_send = tsk->allowed_send;
	int new_allowed_send;
    tsk->adv_wnd = cb->rwnd;
    tsk->snd_wnd = min(tsk->adv_wnd, (int)tsk->cwnd * MSS);
	new_allowed_send = tsk->snd_wnd - tsk->inflight;

    if (old_allowed_send <= 0 && new_allowed_send > 0 )
    	wake_up(tsk->wait_send);
	log(DEBUG, "tcp_update_window: successed to update_window with adv_wnd %u cwnd= %f packets and snd_wnd %u.", \
	tsk->adv_wnd, tsk->cwnd, tsk->snd_wnd);
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
	//if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
	if (less_than_32b(cb->seq, tsk->rcv_nxt) || less_or_equal_32b(rcv_end, cb->seq_end)) {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
	else {
		return 1;
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
//	fprintf(stdout, "TODO: implement %s please.\ndf, __FUNCTION__);
	if (!tsk) 
	{
		log(ERROR, "tcp_process: can't find a tsk that fit to packet'");
		return;
	} 
	log(DEBUG, "tcp_process: successed to find a tsk that fit to packet'");
	log(DEBUG, "tcp_process: recv a packet with seq %u with flags=%d,ack=%u and my rcv_nxt is %u", cb->seq,cb->flags,cb->ack,tsk->rcv_nxt);

	if (!is_tcp_seq_valid(tsk, cb)) 
	{ 
		log(ERROR, "tcp_process: recv a packet with invalid seq.");
		tcp_send_control_packet(tsk, TCP_ACK);		//如果收到重复的包，可能是ack丢了，重新发送
		return;
	}
	if (!(cb->flags & (TCP_SYN|TCP_FIN)) && !(cb->flags & TCP_ACK)) 
	{
		log(ERROR, "tcp_process: recv a invalid packet that have no ack.");
		return;//除了SYN和FIN之外的所有包都必须有TCP_ACK
	}

	tcp_set_retrans_timer(tsk);
	tcp_update_window_safe(tsk, cb);	

	switch (tsk->state) 
	{
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
			if (cb->flags == TCP_ACK) 
			{
				tcp_unset_retrans_timer(tsk);
				wake_up(tsk->wait_recv);				//唤醒server进程
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unhash(tsk);
				return;
			}
			break;
		//主动建立和关闭连接
		case TCP_SYN_SENT:
			log(DEBUG, "tcp_process: process a SYN_SENT state packet.");
			tcp_syn_sent_process(tsk, cb, packet);
			return;
			break;
		
		case TCP_FIN_WAIT_1:
			log(DEBUG, "tcp_process: process a FIN_WAIT_1 state packet.cb->ack= %u, tsk->snd_nxt = %u",cb->ack, tsk->snd_nxt);
			if (cb->ack == tsk->snd_nxt) 
			{
//				tcp_set_retrans_timer(tsk);
				update_snd_buf(tsk, cb);
				tcp_set_state(tsk, TCP_FIN_WAIT_2);

				tsk->rcv_nxt = cb->seq_end ;
				return;
			}
			break;
		case TCP_FIN_WAIT_2:
//			log(DEBUG, "tcp_process: process a FIN_WAIT_2 state packet.");
			if (cb->flags == TCP_FIN ) 
			{			//所有的数据都确认才能关连接
//				log(DEBUG, "tcp_process: process a FIN_WAIT_2 state packet.");
				if (list_empty(&tsk->send_buf)) 
				{
//				log(DEBUG, "tcp_process: process a FIN_WAIT_2 state packet.");
				tcp_unset_retrans_timer(tsk);
				tcp_set_state(tsk, TCP_TIME_WAIT);

				tsk->rcv_nxt = cb->seq_end ;
				tcp_send_control_packet(tsk, TCP_ACK);

				tcp_set_timewait_timer(tsk);
				}
				return;
			}
			break;
	}

	//拥塞控制
	if (tsk->state != TCP_CLOSED && tsk->state != TCP_LISTEN && 
										tsk->state != TCP_SYN_RECV) 
		tcp_cc_in(tsk, cb);


	if (cb->flags & TCP_RST) 
	{
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return;
	}

	if (cb->flags & TCP_SYN) 
	{
		tcp_send_reset(cb);
		tcp_set_state(tsk, TCP_CLOSED);
		tcp_unhash(tsk);
		return;
	}

		
}

//congestion control with tcp_in
void tcp_cc_in(struct tcp_sock *tsk, struct tcp_cb *cb) {
	if (cb->ack > tsk->snd_una) { 	//收到新数据的确认
//		tcp_set_retrans_timer(tsk);
		log(DEBUG, "tcp_cc_in:  recv a new ack.");
		switch(tsk->cstate) 
		{
			case TCP_COPEN:
				log(DEBUG, "tcp_cc_in:  recv a new ack.468512357465132156123.0456132156123.15643120.545612315468541321315646541321y");
			case TCP_CDISORDER:
				log(DEBUG, "tcp_cc_in:  recv a new ack.468512357465132156123.0456132156123.15643120.545612315468541321315646541321y");
				//slow start
				if ((int)tsk->cwnd < tsk->ssthresh) 
					++tsk->cwnd;
				else
					tsk->cwnd += (1/tsk->cwnd);
				
				tsk->snd_una = cb->ack;
				tsk->inflight = tsk->snd_nxt - tsk->snd_una;			//update inflight
				if (tsk->cstate == TCP_CDISORDER)
					tsk->cstate = TCP_COPEN;
				
				
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
	}

	else if (cb->ack == tsk->snd_una && cb->flags != (TCP_PSH|TCP_ACK))
	{ 	//没有新数据确认
		log(DEBUG, "tcp_cc_in:  ##############################$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$@@@@@@@@@@@@@@@@@@@@@@@@");
		if (cb->flags == TCP_ACK) 
		{
			log(DEBUG, "tcp_cc_in:  recv a ack ack ack ack ack ack ack only.");
			//return;
		}
			
		log(DEBUG, "tcp_cc_in:  recv a old ack.");

		switch(tsk->cstate) 
		{
			case TCP_COPEN:
				tsk->cstate = TCP_CDISORDER;
				break;
			case TCP_CDISORDER:
				tsk->ssthresh = (int)tsk->cwnd / 2;
				tsk->cwnd = tsk->ssthresh;
				tsk->cstate = TCP_CRECOVERY;
				break;
			case TCP_CRECOVERY:
				default:
				break;
		} 
		tsk->inflight -= MSS;			//update inflight

	}
	else if (cb->ack < tsk->snd_una)
		log(DEBUG, "tcp_cc_in: recv dupack of previous pkt that already be acked.");
	else
		log(DEBUG, "tcp_cc_in: recv a psh|ack pkt.");

	tcp_update_window_safe(tsk, cb);	
}

void tcp_listen_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) 
{
	if (cb->flags == TCP_SYN) 
	{
   		struct tcp_sock *csk = alloc_tcp_sock();

		csk->sk_sip = cb->daddr;
//		log(DEBUG, "tcp_listen_process: csk->sk_sip: %u.", csk->sk_sip);
		csk->sk_sport = cb->dport;
//		log(DEBUG, "tcp_listen_process: csk->sk_sport: %hu.", csk->sk_sport);
		csk->sk_dip = cb->saddr;
//		log(DEBUG, "tcp_listen_process: csk->sk_dip: %u.", csk->sk_dip);
		csk->sk_dport = cb->sport;
//		log(DEBUG, "tcp_listen_process: csk->sk_dport: %hu.", csk->sk_dport);
		csk->parent = tsk;
		list_add_tail(&csk->list, &tsk->listen_queue);
		csk->rcv_nxt = cb->seq_end ;
				
		tcp_set_state(csk, TCP_SYN_RECV);
		if (tcp_hash(csk) != 0)
			log(ERROR,"tcp_process:failed to process on listen state.");
		tcp_send_control_packet(csk, TCP_SYN | TCP_ACK);
	}
}

void tcp_syn_recv_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	if (cb->flags == TCP_ACK){
		tcp_set_state(tsk, TCP_ESTABLISHED);	 
//		tsk->cwnd = MSS;
		tcp_sock_accept_enqueue(tsk);
		wake_up(tsk->parent->wait_accept); 
		log(DEBUG, "tcp_syn_recv_process: wake up a wait_accept.");

		return;
	}
}
void tcp_established_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) {
	if (!(cb->flags & (TCP_RST|TCP_SYN))) {

		if (cb->pl_len) { 
			tsk->rcv_wnd -= cb->pl_len;
			if (cb->seq > tsk->rcv_nxt) { 
				log(DEBUG, "tcp_established_process: recv a data packet out of order.*******************************************************************************************************************************************************************");
				struct tcp_cb *ofo_cb, *q;
				list_for_each_entry_safe(ofo_cb, q, &tsk->rcv_ofo_buf, list) {
					if (ofo_cb->seq == cb->seq)
						return;
				}
				list_add_tail(&ofo_cb->list, &tsk->rcv_ofo_buf);	 
				log(DEBUG, "tcp_established_process: add a out of order pkt to rcv_ofo_buf.");
			}
			else{
				log(DEBUG, "tcp_established_process: recv a data packet in order.#########################################################################################################################################################################");

			//	pthread_mutex_lock(&tsk->wait_recv->lock);
				write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);
				if (! ring_buffer_empty(tsk->rcv_buf)) {			//buffer 为空说明刚刚写入的数据被读线程读完了
					wake_up(tsk->wait_recv);
					//log(DEBUG, "write_ring_buffer: wake up a wait_recv.1");
				}
			 //	pthread_mutex_unlock(&tsk->wait_recv->lock);
		
				tsk->rcv_nxt = cb->seq_end ;
//				log(DEBUG, "write_ring_buffer: wake up a wait_recv.2");
				
				//把ofo buffer中能连续上的包送到rcv buf
				struct tcp_cb *ofo_cb, *q;
//				log(DEBUG, "write_ring_buffer: wake up a wait_recv.3");
				int flag = 1; 	//有没有形成连续的包
				while (!list_empty(&tsk->rcv_ofo_buf) && flag) {
					flag = 0;
//					log(DEBUG, "write_ring_buffer: wake up a wait_recv.4");
					list_for_each_entry_safe(ofo_cb, q, &tsk->rcv_ofo_buf, list) {
//						log(DEBUG, "write_ring_buffer: wake up a wait_recv.5");
						if (ofo_cb->seq_end == tsk->rcv_nxt - 1) {
//						log(DEBUG, "write_ring_buffer: wake up a wait_recv.6");
							flag = 1;
//						log(DEBUG, "write_ring_buffer: wake up a wait_recv.7");
							list_delete_entry(&ofo_cb->list);
//						log(DEBUG, "write_ring_buffer: wake up a wait_recv.8");

				//			pthread_mutex_lock(&tsk->wait_recv->lock);
							write_ring_buffer(tsk->rcv_buf, ofo_cb->payload, ofo_cb->pl_len);
//						log(DEBUG, "write_ring_buffer: wake up a wait_recv.");
							if (! ring_buffer_empty(tsk->rcv_buf)) {			//buffer 为空说明刚刚写入的数据被读线程读完了
								wake_up(tsk->wait_recv);
								log(DEBUG, "write_ring_buffer: wake up a wait_recv.");
							}
			 	//			pthread_mutex_unlock(&tsk->wait_recv->lock);
						}		
					}
				}
			}
		}
		
	}
	if (cb->flags == TCP_FIN) 
	{
		if (tsk->rcv_nxt == cb->seq) 
		{
			tsk->rcv_nxt = cb->seq_end ;
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			tcp_send_control_packet(tsk, TCP_ACK);
			tcp_sock_close(tsk);
		}
		return;	
	} 
	if (cb->flags != TCP_ACK) 
		//处理数据包
		tcp_send_control_packet(tsk, TCP_ACK);
	
}
void tcp_syn_sent_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet) 
{
	if (cb->flags == (TCP_SYN | TCP_ACK)) 
	{
		update_snd_buf(tsk, cb);
		tcp_set_state(tsk, TCP_ESTABLISHED);

		tsk->rcv_nxt = cb->seq_end ;
		log(DEBUG, "tcp_syn_sent_process: cb->seq_end %u.", cb->seq_end);
		tcp_send_control_packet(tsk, TCP_ACK);
		wake_up(tsk->wait_connect);
		log(DEBUG, "tcp_syn_sent_process: wake up a wait_connect.");

		return;
	}
	else 
	{
		tcp_send_reset(cb);
		return;
	}
}

	
