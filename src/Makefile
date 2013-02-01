#Makefile
UNAME := $(shell uname -s)

OCFLAGS=-O3
#DCFLAGS=-Wall -Wextra -Werror -g -DDEBUG
DCFLAGS=-Wall -g -DDEBUG
PCFLAGS=-g -pg
LDFLAGS=-lpcap -lldns

ifeq ($(UNAME), FreeBSD)
    OCFLAGS=-I/usr/local/include -O3
    LDFLAGS=-L/usr/local/lib -lpcap -lldns
endif

all:
	gcc $(OCFLAGS) -c dns.c
	gcc $(OCFLAGS) -c defrag.c
	gcc $(OCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o defrag.o passivedns.o $(LDFLAGS)

static:
	gcc -static $(OCFLAGS) -c dns.c
	gcc -static $(OCFLAGS) -c defrag.c
	gcc -static $(OCFLAGS) -c passivedns.c
	gcc -static -o passivedns dns.o defrag.o passivedns.o $(LDFLAGS) -lc -lnsl -lcrypto -lz

debug: 
	gcc $(DCFLAGS) -c dns.c
	gcc $(DCFLAGS) -c defrag.c
	gcc $(DCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o defrag.o passivedns.o $(LDFLAGS)

profile:
	gcc $(PCFLAGS) -c dns.c
	gcc $(PCFLAGS) -c defrag.c
	gcc $(PCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o defrag.o passivedns.o $(LDFLAGS)

clean:
	-rm -v passivedns passivedns.o dns.o defrag.o

