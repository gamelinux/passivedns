dnl Process this file with autoconf to produce a configure script
m4_include([version.m4])
AC_PREREQ([2.59])
AC_INIT([passivedns], VERSION_NUMBER)
AC_CONFIG_SRCDIR(src/passivedns.c)
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([1.11])
AC_USE_SYSTEM_EXTENSIONS

dnl Checks for programs
AC_PROG_CC

dnl make /usr/local as the default install dir
AC_PREFIX_DEFAULT(/usr/local)

CFLAGS="${CFLAGS} -I. -I.. -I../include `getconf LFS64_CFLAGS`"
LDFLAGS="${LDFLAGS} `getconf LFS64_LDFLAGS` `getconf LFS64_LIBS`"

SPLINT="no"
AC_ARG_ENABLE(splint,
    [  --enable-splint         Debug the code with splint],
	SPLINT="yes"      
	CC="splint -D -I"
    ,)

DEBUG="no"
AC_ARG_ENABLE(debug,
    [  --enable-debug          Enable debugging],
    [ if test "$GCC" = yes; then
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG -ggdb"
      else
          DEBUG="yes"
          CFLAGS="${CFLAGS} -DDEBUG"
      fi
    ],)

MEM_DEBUG="no"
AC_ARG_ENABLE(memdebug,
    [  --enable-memdebug       Enable memory debugging],
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG"
    ,)

SHOW_MEM_DEBUG="no"
AC_ARG_ENABLE(showmemdebug,
    [  --enable-showmemdebug   Enable verbose memory debugging],
      SHOW_MEM_DEBUG="yes"
      MEM_DEBUG="yes"
      CFLAGS="${CFLAGS} -DMEM_DEBUG -DSHOW_MEM_DEBUG"
    ,)

GPROF="no"
AC_ARG_ENABLE(gprof,
    [  --enable-gprof          Enable profiler],
    [ if test "$GCC" = yes; then
          GPROF="yes"
          CFLAGS="${CFLAGS} -DGPROF -pg"
      else
          GPROF="yes"
          CFLAGS="${CFLAGS} -DGPROF"
      fi
    ],)

dnl ############# System Dependencies

AC_MSG_CHECKING([for special system dependencies])

AC_CANONICAL_HOST
AC_C_CONST
AC_PROG_GCC_TRADITIONAL

dnl Checks for OS type.
case "$host" in
    *-freebsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([FREEBSD],1,FREEBSD)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-netbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([NETBSD],1,NETBSD)
        ;;
    *-openbsd*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([OPENBSD],1,OPENBSD)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-apple*)
        AC_DEFINE([BSD_DERIVED],1,BSD_DERIVED)
        AC_DEFINE([MACOS],1,MACOS)
        LDFLAGS="${LDFLAGS}"
        ;;
    *-linux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([LINUX],1,LINUX)
        AC_SUBST(more_incl)
        more_incl="-I/usr/include/pcap"
	AC_DEFINE([__USE_BSD],1,__USE_BSD)
	AC_DEFINE([__FAVOR_BSD],1,__FAVOR_BSD)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-solaris2.10)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([SOLARIS],1,SOLARIS)
	AC_DEFINE([SOLARIS10],1,SOLARIS10)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-solaris*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([SOLARIS],1,SOLARIS)
	LDFLAGS="${LDFLAGS}"
        ;;
    *-aix*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([AIX],1,AIX)
        ;;
    *-hpux*)
        AC_DEFINE([SYSV_DERIVED],1,SYSV_DERIVED)
        AC_DEFINE([HPUX],1,HPUX)
        ;;
esac

dnl ############## Header Checks
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([paths.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/param.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([syslog.h])
AC_CHECK_HEADERS([libgen.h])

dnl ############## Function checks
AC_CHECK_FUNCS([alarm])
AC_CHECK_FUNCS([dup2])
AC_CHECK_FUNCS([endgrent])
AC_CHECK_FUNCS([endpwent])
AC_CHECK_FUNCS([ftruncate])
AC_CHECK_FUNCS([getcwd])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([strerror])
AC_CHECK_FUNCS([strtol])
AC_CHECK_FUNCS([strtoul])
AC_CHECK_FUNCS([dirname])
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_STRNLEN

dnl ############## Type checks
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

dnl ############# Checks for libpcap.
AC_ARG_WITH(libpcap,
[  --with-libpcap=PATH        Specify path to libpcap library.],
    [
        AC_MSG_CHECKING(for --with-libpcap option)
        case "$withval" in
          yes|no)
            AC_MSG_ERROR(PATH required with libpcap option)
            ;;
          *)
            if test '!' -d "$withval"; then
                AC_MSG_ERROR($withval does not exist!)
            else
                AC_MSG_RESULT($withval)
                if test -d "$withval/include"; then
                  CFLAGS="${CFLAGS} -I$withval/include"
                  CPPFLAGS="${CPPFLAGS} -I$withval/include"
                else
                  CFLAGS="${CFLAGS} -I$withval"
                  CPPFLAGS="${CPPFLAGS} -I$withval"
                fi
                if test -d "$withval/lib"; then
                  LDFLAGS="${LDFLAGS} -L$withval/lib"
                else
                  LDFLAGS="${LDFLAGS} -L$withval"
                fi
            fi
            ;;
          esac
    ]
)

dnl #############  Check for libpcap headers
AC_CHECK_HEADERS(pcap.h,, LIBPCAP="no")
if test "$LIBPCAP" = "no"; then
   echo ""
   echo "Error: Can't find Libpcap. Visit http://www.tcpdump.org for the latest version."
   exit;
fi

dnl #############  Check for libpcap library
AC_CHECK_LIB(pcap, pcap_open_live,, LIBPCAP="no")
if test "$LIBPCAP" = "no"; then
    echo ""
    echo "Error: Can't find Libpcap. Visit http://www.tcpdump.org for the latest version."
    exit;
else
   AC_CHECK_LIB(pcap, pcap_setnonblock,, SETNONBLOCK="no")
   if test "$SETNONBLOCK" = "no"; then
       echo "compensating for lack of pcap_setnonblock()"
   else
       AC_DEFINE([HAVE_SETNONBLOCK],1,HAVE_SETNONBLOCK)
   fi

   AC_CHECK_LIB(pcap, pcap_freecode,, FREECODE="no")
   if test "$FREECODE" = "no"; then
       echo "compensating for lack of pcap_freecode()"
   else
       AC_DEFINE([HAVE_FREECODE],1,HAVE_FREECODE)
   fi
fi

dnl #############  Check for libpcap bpf
AC_MSG_CHECKING(for bpf)
if test -r /dev/bpf0 ; then
    AC_DEFINE([HAVE_BPF],1,HAVE_BPF)
    AC_MSG_RESULT(yes)
elif test -c /dev/bpf0 ; then
    AC_DEFINE([HAVE_BPF],1,HAVE_BPF)
    AC_MSG_RESULT(yes)
else
    AC_MSG_RESULT(no)
fi

dnl #############  Checks for ldns.
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

dnl #############  Check or ldns headers
AC_CHECK_HEADERS(ldns/ldns.h,,LIBLDNS_H="no")

if test "$LIBLDNS_H" = "no"; then
    echo -e "\n  ERROR! ldns headers not found\n"
    exit 1
fi

dnl #############  Check for ldns library
AC_CHECK_LIB(ldns,ldns_pkt_get_rcode,,LIBLDNS_L="no")

if test "$LIBLDNS_L" = "no"; then
    echo -e "\n  ERROR! ldns library not found\n"
    exit 1
fi

dnl #############  Checks for PF_RING.
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

    dnl #############  Checks for libnuma
    AC_CHECK_HEADER(numa.h,,LIBNUMA="no")
    AC_CHECK_LIB(numa,numa_available,,LIBNUMA="no")

    if test "$LIBNUMA" = "no"; then
        echo -e "\n  ERROR! libnuma not found (PF_RING requirement)\n"
        exit 1
    fi

    dnl #############  Check for PF_RING headers
    AC_CHECK_HEADER(pfring.h,,LIBPFRING_H="no")

    if test "$LIBPFRING_H" = "no"; then
        echo -e "\n  ERROR! PF_RING headers not found\n"
        exit 1
    fi

    dnl #############  Check for PF_RING library
    AC_CHECK_LIB(pfring,pfring_stats,,LIBPFRING_L="no")

    if test "$LIBPFRING_L" = "no"; then
        echo -e "\n  ERROR! PF_RING library not found\n"
        exit 1
    fi

    dnl #############  Check for PF_RING BPF support
    AC_CHECK_LIB(pfring,pfring_set_bpf_filter,,LIBPFRING_BPF="no")

    if test "$LIBPFRING_BPF" != "no"; then
        AC_DEFINE([HAVE_PFRING_BPF],[1],[PF_RING BPF support])
    fi
])

dnl #############  Checks for libjansson.
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

    dnl #############  Check for jansson headers
    AC_CHECK_HEADER(jansson.h,,LIBJANSSON_H="no")

    if test "$LIBJANSSON_H" = "no"; then
        echo -e "\n  ERROR! Jansson headers not found\n"
        exit 1
    fi

    dnl #############  Check for jansson library
    AC_CHECK_LIB(jansson,json_delete,,LIBJANSSON_L="no")

    if test "$LIBJANSSON_L" = "no"; then
        echo -e "\n  ERROR! Jansson library not found\n"
        exit 1
    fi
])

AC_CONFIG_HEADER(include/config.h)
AC_PROG_INSTALL
AC_OUTPUT(Makefile src/Makefile passivedns.1)

BINDIR=`eval echo ${bindir}`; BINDIR=`eval echo ${BINDIR}`;
MANDIR=`eval echo ${mandir}/${mansubdir}`; MANDIR=`eval echo ${MANDIR}`;

echo ""
echo "-----------------------------------------------"
echo "Host type             : ${host}"
echo "Compiler              : ${CC}"
echo "Compiler flags        : ${CFLAGS}"
echo "Linker flags          : ${LDFLAGS}"
echo "Libraries             : ${LIBS}"
echo ""
echo "Binary                : ${BINDIR}"
echo "Manual pages          : ${MANDIR}"
echo ""
echo "Enable debugging      : ${DEBUG}"
echo "Enable mem debugging  : ${MEM_DEBUG}"
echo "Show mem debugging    : ${SHOW_MEM_DEBUG}"
echo "-----------------------------------------------"
echo ""
