#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include "my.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    struct tcp_sock *tsk;
    struct tcp_timer *t, *q;
    
    list_for_each_entry_safe(t, q, &timer_list, list) {
        t->timeout -= TCP_TIMER_SCAN_INTERVAL;
        if (t->timeout <= 0) {
			log(DEBUG, "tcp_scan_timer_list: timeout at a timewait timer.");
            if (t->type == 0) { //等待定时
                list_delete_entry(&t->list);
                tsk = timewait_to_tcp_sock(t);
                if (!tsk->parent)
                    tcp_bind_unhash(tsk);
                tcp_set_state(tsk, TCP_CLOSED);
                free_tcp_sock(tsk);
            }
            else {  //超时重传
				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.");
                if (t->enable >= 3) {
                    tsk = retranstimer_to_tcp_sock(t);
                    list_delete_entry(&t->list);
                    if (!tsk->parent)
                        tcp_bind_unhash(tsk);
                    tcp_set_state(tsk, TCP_CLOSED);
                    free_tcp_sock(tsk);
                    return;
//                  struct packet_link_node *pkt_node = list_entry(&tsk->send_buf.next, typ    eof(pkt_node), list);
//                  ip_send_packet(pkt_node->packet, pkt_node->len);    
                }

                tsk->inflight -= MSS;   //丢包时在网络中的包减一

                tsk->ssthresh = tsk->cwnd / 2;
                tsk->cwnd = TCP_DEFAULT_WINDOW;
                tsk->cstate = TCP_COPEN;

           		//     t->timeout = (int)pow(TCP_RETRANS_INTERVAL_INITIAL, (t->enable));        //定时器翻倍
                resend(tsk);
				//记录重传次数
                t->enable++; 
    			//定时器翻倍
				for (int i = t->enable; i > 1; i--)
					t->timeout *= t->timeout; 
            }
        }
    }
}
// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	log(DEBUG, "tcp_timer.c,,,tcp_set_timewait_timer .");
    tsk->timewait.type = 0;
    tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
    tsk->timewait.enable = 1;
    list_add_tail(&tsk->timewait.list, &timer_list);
}

// set the retrans timer of a tcp sock, by adding the timer into timer_list
void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .");
    tsk->retrans_timer.type = 1;
    tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
    tsk->retrans_timer.enable = 1;  //重传次数
    list_add_tail(&tsk->retrans_timer.list, &timer_list);
}

// unset the retrans timer of a tcp sock, by removing the timer from timer_list
void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	log(DEBUG, "tcp_timer.c,,,tcp_unset_retrans_timer .");
    list_delete_entry(&tsk->retrans_timer.list);
}


// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}
