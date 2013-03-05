#Makefile
UNAME := $(shell uname -s)

OCFLAGS=-O3
#DCFLAGS=-Wall -Wextra -Werror -g -DDEBUG
DCFLAGS=-Wall -g -DDEBUG
PCFLAGS=-g -pg
LDFLAGS=-lpcap -lldns

OBJECTS=$(patsubst %.c,%.o,$(wildcard *.c))
DOBJECTS=$(patsubst %.o,%_dbg.o,$(OBJECTS))
POBJECTS=$(patsubst %.o,%_pfl.o,$(OBJECTS))
BINARY=passivedns

ifeq ($(UNAME), FreeBSD)
    OCFLAGS=-I/usr/local/include -O3
    LDFLAGS=-L/usr/local/lib -lpcap -lldns
endif

all: $(BINARY)

%_dbg.o: %.c
	gcc $(DCFLAGS) -c $< -o $@

%_pfl.o: %.c
	gcc $(PCFLAGS) -c $< -o $@

%.o: %.c
	gcc $(OCFLAGS) -c $< -o $@

passivedns: $(OBJECTS)
	gcc -o passivedns $(OBJECTS) $(LDFLAGS)

static: $(OBJECTS)
	gcc -static -o passivedns dns.o passivedns.o $(LDFLAGS) -lc -lnsl -lcrypto -lz

debug: $(DOBJECTS)
	gcc -o passivedns $(DOBJECTS) $(LDFLAGS)

profile: $(POBJECTS)
	gcc -o passivedns $(POBJECTS) $(LDFLAGS)

clean:
	-rm -v passivedns *.o 2>/dev/null || true

