#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([passivedns], [1.2.0])
AM_INIT_AUTOMAKE
AC_USE_SYSTEM_EXTENSIONS
AC_CONFIG_SRCDIR([src/passivedns.h])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs.
AC_PROG_CC

# Enable debug output.
AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug], [Enable debug output]))

AS_IF([test "x$enable_debug" = "xyes"], [
    CPPFLAGS="${CPPFLAGS} -Wall -g -DDEBUG"
])

# Enable gcc profile info.
AC_ARG_ENABLE(gccprofile,
    AS_HELP_STRING([--enable-gccprofile], [Enable gcc profile info (set -pg flag)]))

AS_IF([test "x$enable_gccprofile" = "xyes"], [
    CPPFLAGS="${CPPFLAGS} -g -pg"
])

# Checks for libpcap.
AC_ARG_WITH(libpcap_includes,
    [  --with-libpcap-includes=DIR   libpcap include directory],
    [with_libpcap_includes="$withval"],[with_libpcap_includes="no"])

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

# Checks for OpenSSL (newer versions of ldns require OpenSSL).
AC_ARG_ENABLE(openssl,
    AS_HELP_STRING([--disable-openssl],
                   [Requires ldns library compiled without OpenSSL]),
    [enable_openssl=no], [enable_openssl=yes])

AC_ARG_WITH(openssl_includes,
    [  --with-openssl-includes=DIR   OpenSSL include directory],
    [with_openssl_includes="$withval"],[with_openssl_includes="no"])

AC_ARG_WITH(openssl_libraries,
    [  --with-openssl-libraries=DIR  OpenSSL library directory],
    [with_openssl_libraries="$withval"],[with_openssl_libraries="no"])

AS_IF([test "x$enable_openssl" = "xyes"], [
    if test "$with_openssl_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_openssl_includes}"
    fi

    if test "$with_openssl_libraries" != "no"; then
        LDFLAGS="${LDFLAGS} -L${with_openssl_libraries}"
    fi

    # Check for OpenSSL headers
    AC_CHECK_HEADER(openssl/ssl.h,,LIBOPENSSL_H="no")

    if test "$LIBOPENSSL_H" = "no"; then
        echo -e "\n  ERROR! OpenSSL headers not found\n"
        exit 1
    fi
])

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

# Checks for PF_RING.
AC_ARG_ENABLE(pfring,
    AS_HELP_STRING([--enable-pfring], [Enable PF_RING support]))

AC_ARG_WITH(pfring_includes,
    [  --with-pfring-includes=DIR    PF_RING include directory],
    [with_pfring_includes="$withval"],[with_pfring_includes="no"])

AC_ARG_WITH(pfring_libraries,
    [  --with-pfring-libraries=DIR   PF_RING library directory],
    [with_pfring_libraries="$withval"],[with_pfring_libraries="no"])

AS_IF([test "x$enable_pfring" = "xyes"], [
    AC_DEFINE([HAVE_PFRING],[1],[PF_RING support enabled])

    if test "$with_pfring_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_pfring_includes}"
    fi

    if test "$with_pfring_libraries" != "no"; then
        LDFLAGS="${LDFLAGS} -L${with_pfring_libraries}"
    fi

    LDFLAGS="${LDFLAGS} -lpfring -lnuma -lrt"

    # Checks for libnuma
    AC_CHECK_HEADER(numa.h,,LIBNUMA="no")
    AC_CHECK_LIB(numa,numa_available,,LIBNUMA="no")

    if test "$LIBNUMA" = "no"; then
        echo -e "\n  ERROR! libnuma not found (PF_RING requirement)\n"
        exit 1
    fi

    # Check for PF_RING headers
    AC_CHECK_HEADER(pfring.h,,LIBPFRING_H="no")

    if test "$LIBPFRING_H" = "no"; then
        echo -e "\n  ERROR! PF_RING headers not found\n"
        exit 1
    fi

    # Check for PF_RING library
    AC_CHECK_LIB(pfring,pfring_stats,,LIBPFRING_L="no")

    if test "$LIBPFRING_L" = "no"; then
        echo -e "\n  ERROR! PF_RING library not found\n"
        exit 1
    fi

    # Check for PF_RING BPF support
    AC_CHECK_LIB(pfring,pfring_set_bpf_filter,,LIBPFRING_BPF="no")

    if test "$LIBPFRING_BPF" != "no"; then
        AC_DEFINE([HAVE_PFRING_BPF],[1],[PF_RING BPF support])
    fi
])

# Checks for libjansson.
AC_ARG_ENABLE(json,
    AS_HELP_STRING([--enable-json], [Enable JSON support]))

AC_ARG_WITH(jansson_includes,
    [  --with-jansson-includes=DIR   libjansson include directory],
    [with_jansson_includes="$withval"],[with_jansson_includes="no"])

AC_ARG_WITH(jansson_libraries,
    [  --with-jansson-libraries=DIR  libjansson library directory],
    [with_jansson_libraries="$withval"],[with_jansson_libraries="no"])

AS_IF([test "x$enable_json" = "xyes"], [
    AC_DEFINE([HAVE_JSON],[1],[JSON support enabled])

    if test "$with_jansson_includes" != "no"; then
        CPPFLAGS="${CPPFLAGS} -I${with_jansson_includes}"
    fi

    if test "$with_jansson_libraries" != "no"; then
        LDFLAGS="${LDFLAGS} -L${with_jansson_libraries}"
    fi

    LDFLAGS="${LDFLAGS} -ljansson"

    # Check for jansson headers
    AC_CHECK_HEADER(jansson.h,,LIBJANSSON_H="no")

    if test "$LIBJANSSON_H" = "no"; then
        echo -e "\n  ERROR! Jansson headers not found\n"
        exit 1
    fi

    # Check for jansson library
    AC_CHECK_LIB(jansson,json_delete,,LIBJANSSON_L="no")

    if test "$LIBJANSSON_L" = "no"; then
        echo -e "\n  ERROR! Jansson library not found\n"
        exit 1
    fi
])

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

