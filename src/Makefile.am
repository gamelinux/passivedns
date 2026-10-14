#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

OBJECTS=passivedns.o dns.o reasm.o
bin_PROGRAMS=passivedns
passivedns_SOURCES=passivedns.c dns.c reasm.c

# Hardening stays on this hand rule. configure may also add
# -fstack-protector-strong; repeating it is harmless.
HARDEN_CFLAGS = -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2
HARDEN_LDFLAGS = -pie -Wl,-z,relro,-z,now,-z,noexecstack

all: $(bin_PROGRAMS)

%.o: %.c
	$(CC) $(HARDEN_CFLAGS) $(CFLAGS) -O3 $(CPPFLAGS) -c $< -o $@

passivedns$(EXEEXT): $(OBJECTS)
	$(CC) $(HARDEN_CFLAGS) $(CFLAGS) -o passivedns $(OBJECTS) $(HARDEN_LDFLAGS) $(LDFLAGS)

clean:
	-rm -v passivedns *.o 2>/dev/null || true

