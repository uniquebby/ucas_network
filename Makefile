TARGET = tcp_stack

all: $(TARGET)

CC = gcc
LD = gcc

CFLAGS = -g -Wall -Iinclude
LDFLAGS = -L.

LIBS = -lipstack -lpthread -lm 			#-lm 连接math库

HDRS = ./include/*.h

SRCS = ip.c main.c tcp.c tcp_apps.c tcp_in.c tcp_out.c tcp_sock.c tcp_timer.c

OBJS = $(patsubst %.c,%.o,$(SRCS))

$(OBJS) : %.o : %.c include/*.h
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJS)
	$(LD) $(LDFLAGS) $(OBJS) -o $(TARGET) $(LIBS) 

clean:
	rm -f *.o $(TARGET)
