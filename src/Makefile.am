#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

OBJECTS=passivedns.o dns.o
bin_PROGRAMS=passivedns

all: $(bin_PROGRAMS)

%.o: %.c
	gcc -O3 $(CPPFLAGS) -c $< -o $@

passivedns: $(OBJECTS)
	gcc -o passivedns $(OBJECTS) $(LDFLAGS)

clean:
	-rm -v passivedns *.o 2>/dev/null || true

