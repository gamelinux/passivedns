#Makefile
AUTOMAKE_OPTIONS = -Wno-portability

bin_PROGRAMS = passivedns
passivedns_SOURCES = passivedns.c dns.c passivedns.h dns.h

# Security hardening compiler flags
HARDENING_CFLAGS = -fstack-protector-strong \
                   -fstack-clash-protection \
                   -fcf-protection=full \
                   -D_FORTIFY_SOURCE=2 \
                   -fPIE \
                   -Wformat \
                   -Wformat-security \
                   -Werror=format-security \
                   -Wall \
                   -Wextra \
                   -Wconversion \
                   -Wsign-conversion \
                   -Wcast-align \
                   -Wcast-qual \
                   -Wshadow \
                   -Wstrict-overflow=5 \
                   -fno-strict-aliasing

HARDENING_LDFLAGS = -pie \
                    -Wl,-z,relro \
                    -Wl,-z,now \
                    -Wl,-z,noexecstack \
                    -Wl,--as-needed

AM_CFLAGS = -O2 -g $(HARDENING_CFLAGS)
AM_LDFLAGS = $(HARDENING_LDFLAGS)

