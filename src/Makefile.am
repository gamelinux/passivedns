#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

OBJECTS=passivedns.o dns.o
bin_PROGRAMS=passivedns

all: $(bin_PROGRAMS)

%.o: %.c
	$(CC) -O3 $(CPPFLAGS) -c $< -o $@

passivedns: $(OBJECTS)
	$(CC) -o passivedns $(OBJECTS) $(LDFLAGS)

clean:
	-rm -v passivedns *.o 2>/dev/null || true

