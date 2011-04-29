#Makefile

OCFLAGS=-O3
DCFLAGS=-Wall -g
PCFLAGS=-g -pg
LDFLAGS=-lpcap

all:
	gcc $(OCFLAGS) -c dump_dns.c
	gcc $(OCFLAGS) -c passivedns.c
	gcc -o passivedns  passivedns.o dump_dns.o -lpcap -lresolv

debug: 
	gcc $(DCFLAGS) -c dump_dns.c
	gcc $(DCFLAGS) -c passivedns.c
	gcc -o passivedns passivedns.o dump_dns.o -lpcap -lresolv

profile:
	gcc $(PCFLAGS) -c dump_dns.c
	gcc $(PCFLAGS) -c passivedns.c
	gcc -o passivedns passivedns.o dump_dns.o -lpcap -lresolv

clean:
	-rm -v passivedns passivedns.o dump_dns.o

