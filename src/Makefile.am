#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

OCFLAGS=-O3

OBJECTS=$(patsubst %.c,%.o,$(wildcard *.c))
BINARY=passivedns

all: $(BINARY)

%.o: %.c
	gcc $(OCFLAGS) $(CPPFLAGS) -c $< -o $@

passivedns: $(OBJECTS)
	gcc -o passivedns $(OBJECTS) $(LDFLAGS)

static: $(OBJECTS)
	gcc -static -o passivedns dns.o passivedns.o $(LDFLAGS) -lc -lnsl -lcrypto -lz

clean:
	-rm -v passivedns *.o 2>/dev/null || true

