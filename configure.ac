#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([passivedns], [1.1.3])
AM_INIT_AUTOMAKE
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([src/passivedns.h])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libpcap.
AC_ARG_WITH(libpcap_includes,
    [  --with-libpcap-includes=DIR   libpcap include directory],
    [with_libcap_includes="$withval"],[with_libcap_includes="no"])

AC_ARG_WITH(libpcap_libraries,
    [  --with-libpcap-libraries=DIR  libpcap library directory],
    [with_libpcap_libraries="$withval"],[with_libpcap_libraries="no"])

if test "$with_libpcap_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libpcap_includes}"
fi

if test "$with_libpcap_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_libpcap_libraries}"
fi

LDFLAGS="${LDFLAGS} -lpcap"

# Check for libpcap headers
AC_CHECK_HEADER(pcap.h,,LIBPCAP_H="no")

if test "$LIBPCAP_H" = "no"; then
    echo -e "\n  ERROR! libpcap headers not found\n"
    exit 1
fi

# Check for libpcap library
AC_CHECK_LIB(pcap,pcap_loop,,LIBPCAP_L="no")

if test "$LIBPCAP_L" = "no"; then
    echo -e "\n  ERROR! libpcap library not found\n"
    exit 1
fi

# Checks for ldns.
AC_ARG_WITH(ldns_includes,
    [  --with-ldns-includes=DIR      ldns include directory],
    [with_ldns_includes="$withval"],[with_ldns_includes="no"])

AC_ARG_WITH(ldns_libraries,
    [  --with-ldns-libraries=DIR     ldns library directory],
    [with_ldns_libraries="$withval"],[with_ldns_libraries="no"])

if test "$with_ldns_includes" != "no"; then
    CPPFLAGS="${CPPFLAGS} -I${with_ldns_includes}"
fi

if test "$with_ldns_libraries" != "no"; then
    LDFLAGS="${LDFLAGS} -L${with_ldns_libraries}"
fi

LDFLAGS="${LDFLAGS} -lldns"

# Check or ldns headers
AC_CHECK_HEADER(ldns/ldns.h,,LIBLDNS_H="no")

if test "$LIBLDNS_H" = "no"; then
    echo -e "\n  ERROR! ldns headers not found\n"
    exit 1
fi

# Check for ldns library
AC_CHECK_LIB(ldns,ldns_pkt_get_rcode,,LIBLDNS_L="no")

if test "$LIBLDNS_L" = "no"; then
    echo -e "\n  ERROR! ldns library not found\n"
    exit 1
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([alarm dup2 endgrent endpwent ftruncate getcwd memset strdup strerror strtol strtoul])

AC_OUTPUT(Makefile src/Makefile)

