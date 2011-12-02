#Makefile
UNAME := $(shell uname -s)

OCFLAGS=-O3
DCFLAGS=-Wall -g -DDEBUG
PCFLAGS=-g -pg
LDFLAGS=-lpcap -lldns
# dump_dns.o -lresolv
# gcc $(OCFLAGS) -c dump_dns.c
LDFLAGS=-lpcap -lldns

ifeq ($(UNAME), FreeBSD)
    LDFLAGS=-lpcap
endif

all:
	gcc $(OCFLAGS) -c dns.c
	gcc $(OCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o passivedns.o $(LDFLAGS)

debug: 
	gcc $(DCFLAGS) -c dns.c
	gcc $(DCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o passivedns.o $(LDFLAGS)

profile:
	gcc $(PCFLAGS) -c dns.c
	gcc $(PCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o passivedns.o $(LDFLAGS)

clean:
	-rm -v passivedns passivedns.o dns.o

