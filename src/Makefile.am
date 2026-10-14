#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

OBJECTS=passivedns.o dns.o reasm.o
bin_PROGRAMS=passivedns
passivedns_SOURCES=passivedns.c dns.c reasm.c

all: $(bin_PROGRAMS)

%.o: %.c
	$(CC) $(CFLAGS) -O3 $(CPPFLAGS) -c $< -o $@

passivedns$(EXEEXT): $(OBJECTS)
	$(CC) $(CFLAGS) -o passivedns $(OBJECTS) $(LDFLAGS)

clean:
	-rm -v passivedns *.o 2>/dev/null || true

