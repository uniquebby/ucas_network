#include "tcp_sock.h"

#include "log.h"

#include <unistd.h>

#define BUF_SIZE 1000

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);
	log(DEBUG, "accept a connection.");

	char rbuf[BUF_SIZE];
	FILE *file = fopen("server-output.dat", "wb");
	while (1) {
		int rlen = tcp_sock_read(csk, rbuf, BUF_SIZE);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			fwrite(rbuf, 1, rlen, file);
		}
	}

	fclose(file);
	log(DEBUG, "close this connection.");
	printf("server: close tsk.\n");
	tcp_sock_close(csk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), and
// send file to it.
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}
	char buf[BUF_SIZE];
	FILE *file = fopen("client-input.dat", "rb");
	while (!feof(file)) {
        int ret_size = fread(buf, 1, BUF_SIZE, file);
        tcp_sock_write(tsk, buf, ret_size);

        if (ret_size < BUF_SIZE) break;
		//usleep(500000);
    }

    fclose(file);
    printf("client: close tsk.\n");
	tcp_sock_close(tsk);

	return NULL;
}
