CC=gcc

LIBS=-lpcap

CFLAGS=-Wall -Wextra -Ofast
LFLAGS=-s $(LIBS)

OBJS=main.o ethernet.o indent.o ip.o tcp.c udp.c pppoe.o ppp.c
DEPS=ethernet.h indent.h ip.h tcp.h udp.h pppoe.h ppp.h

BIN=pcap_test

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(BIN): $(OBJS)
	$(CC) -o $@ $^ $(LFLAGS)
