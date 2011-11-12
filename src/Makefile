#Makefile
UNAME := $(shell uname -s)

OCFLAGS=-O3
DCFLAGS=-Wall -g
PCFLAGS=-g -pg
LDFLAGS=-lpcap -lresolv

ifeq ($(UNAME), FreeBSD)
    LDFLAGS=-lpcap
endif

all:
	gcc $(OCFLAGS) -c dump_dns.c
	gcc $(OCFLAGS) -c passivedns.c
	gcc -o passivedns  passivedns.o dump_dns.o $(LDFLAGS) 

debug: 
	gcc $(DCFLAGS) -c dump_dns.c
	gcc $(DCFLAGS) -c passivedns.c
	gcc -o passivedns passivedns.o dump_dns.o $(LDFLAGS) 

profile:
	gcc $(PCFLAGS) -c dump_dns.c
	gcc $(PCFLAGS) -c passivedns.c
	gcc -o passivedns passivedns.o dump_dns.o $(LDFLAGS) 

clean:
	-rm -v passivedns passivedns.o dump_dns.o

