#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include "my.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

static struct list_head timer_list;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
    struct tcp_sock *tsk = NULL;
    struct tcp_timer *t = NULL, *q= NULL;
    
    list_for_each_entry_safe(t, q, &timer_list, list) 
	{
        t->timeout -= TCP_TIMER_SCAN_INTERVAL;
        if (t->timeout <= 0) 
		{
            if (t->type == 0) 
			{ //等待定时
                tsk = timewait_to_tcp_sock(t);
				log(DEBUG, "tcp_scan_timer_list: timeout at a timewait timer parent == null? %d tsk->ref_cnt = %d.", !tsk->parent, tsk->ref_cnt);
                list_delete_entry(&t->list);
                if (!tsk->parent)
                    tcp_bind_unhash(tsk);
                tcp_set_state(tsk, TCP_CLOSED);
                free_tcp_sock(tsk);
            }
            else 
			{  //超时重传
                tsk = retranstimer_to_tcp_sock(t);
				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.");
				if (list_empty(&tsk->send_buf))
				{		//disable timer if there is no packet in send_buf
					t->enable = 0;
               		list_delete_entry(&t->list);
					return;
				}
										

                if (t->enable > 6) 
				{
					log(DEBUG, "tcp_scan_timer_list: timeout at a timewait timer parent == null? %d tsk->ref_cnt = %d.", !tsk->parent, tsk->ref_cnt);
                    list_delete_entry(&t->list);
                    if (!tsk->parent)
                        tcp_bind_unhash(tsk);
                    tcp_set_state(tsk, TCP_CLOSED);
                    free_tcp_sock(tsk);
                    return;
//                  struct packet_link_node *pkt_node = list_entry(&tsk->send_buf.next, typ    eof(pkt_node), list);
//                  ip_send_packet(pkt_node->packet, pkt_node->len);    
                }
//				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.11111111111111");
				tsk->inflight = 0;
//				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.22222222222222");
           	    tsk->ssthresh = max(((u32)(tsk->cwnd / 2)), 1);
//				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.33333333333333");
               	tsk->cwnd = 1;
//				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.44444444444444");
                tsk->cstate = TCP_COPEN;
//				log(DEBUG, "tcp_scan_timer_list: timeout at a retranstimer.55555555555555");

                resend(tsk);
				//记录重传次数
                t->enable++; 
    			//定时器翻倍
				t->timeout = TCP_RETRANS_INTERVAL_INITIAL;
				for (int i = t->enable; i > 1; i--) 
				{
					log(DEBUG, "tcp_scan_timer_list: i = %d", i);
					t->timeout *= 2; 
				}
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
		if (tsk->timewait.enable == 0)
    		list_add_tail(&tsk->timewait.list, &timer_list);
    tsk->timewait.enable = 1;
}

// set the retrans timer of a tcp sock, by adding the timer into timer_list
void tcp_set_retrans_timer(struct tcp_sock *tsk)
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .");
    tsk->retrans_timer.type = 1;
//	log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .1");
    tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
//	log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .2");
		if (tsk->retrans_timer.enable == 0 && !list_empty(&tsk->send_buf)) {
			log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .timer->list = %p and timer_list = %p start", tsk->retrans_timer.list.next, timer_list.next);
    		list_add_tail(&tsk->retrans_timer.list, &timer_list);
			log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .222222222222222222222222222222222222222222222222 done");
		}
	log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .3");
    tsk->retrans_timer.enable = 1;  //重传次数
	log(DEBUG, "tcp_timer.c,,,tcp_set_retrans_timer .4");
}

// unset the retrans timer of a tcp sock, by removing the timer from timer_list
void tcp_unset_retrans_timer(struct tcp_sock *tsk)
{
//  fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	log(DEBUG, "tcp_timer.c,,,tcp_unset_retrans_timer .");
	log(DEBUG, "tcp_timer.c,,,tcp_unset_retrans_timer .1");
	log(DEBUG, "tcp_unset_retrans_timer: &tsk= %p", (&tsk->retrans_timer.list)->next);
	if (tsk->retrans_timer.enable >= 0)
    	list_delete_entry(&tsk->retrans_timer.list);
  	tsk->retrans_timer.enable = 0;  //0表示关闭，非零表示重传次数
	log(DEBUG, "tcp_timer.c,,,tcp_unset_retrans_timer .2");
}


// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	log(DEBUG, "tcp_timer_thred: init a timer: %p", &timer_list);
	while (1) 
	{
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

//parse the cwnd  
void *tcp_cwnd_plot_thread(void *arg)
{
	struct tcp_sock *tsk = (struct tcp_sock *)arg;
	FILE *file = fopen("cwnd.dat", "w");

	float i = 0;
//	float time = 1;	//取cwnd的间隔，单位为ms
	while (tsk->state != TCP_TIME_WAIT) 
	{
		usleep(1000);
		++i;
		fprintf(file, "%f:%f\n",i/1000, tsk->cwnd);
//		fprintf(file, "%d:(%d,%u) ",i,(int)tsk->cwnd, tsk->ssthresh);
//		if (i % 30 == 0)
//		fprintf(file, "\n");
	}
	fclose(file);

	return NULL;
}


void init_timer(struct tcp_timer *timer, int type) 
{
	init_list_head(&timer->list);	
	timer->type = type;
	timer->enable = 0;
}
