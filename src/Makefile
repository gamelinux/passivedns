#Makefile

OCFLAGS=-O3
DCFLAGS=-Wall -g -DDEBUG
PCFLAGS=-g -pg
LDFLAGS=-lpcap -lldns
# dump_dns.o -lresolv
# gcc $(OCFLAGS) -c dump_dns.c

all:
	gcc $(OCFLAGS) -c dns.c
	gcc $(OCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o passivedns.o -lpcap -lldns

debug: 
	gcc $(DCFLAGS) -c dns.c
	gcc $(DCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o passivedns.o -lpcap -lldns

profile:
	gcc $(PCFLAGS) -c dns.c
	gcc $(PCFLAGS) -c passivedns.c
	gcc -o passivedns dns.o passivedns.o -lpcap -lldns

clean:
	-rm -v passivedns passivedns.o dns.o

