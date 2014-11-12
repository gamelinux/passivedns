#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

OCFLAGS=-O3
PCFLAGS=-g -pg

OBJECTS=$(patsubst %.c,%.o,$(wildcard *.c))
DOBJECTS=$(patsubst %.o,%_dbg.o,$(OBJECTS))
POBJECTS=$(patsubst %.o,%_pfl.o,$(OBJECTS))
BINARY=passivedns

all: $(BINARY)

%_pfl.o: %.c
	gcc $(PCFLAGS) $(CPPFLAGS) -c $< -o $@

%.o: %.c
	gcc $(OCFLAGS) $(CPPFLAGS) -c $< -o $@

passivedns: $(OBJECTS)
	gcc -o passivedns $(OBJECTS) $(LDFLAGS)

static: $(OBJECTS)
	gcc -static -o passivedns dns.o passivedns.o $(LDFLAGS) -lc -lnsl -lcrypto -lz

profile: $(POBJECTS)
	gcc -o passivedns $(POBJECTS) $(LDFLAGS)

clean:
	-rm -v passivedns *.o 2>/dev/null || true

