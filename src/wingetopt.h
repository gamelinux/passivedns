/*
POSIX getopt for Windows

AT&T Public License

Code given out at the 1985 UNIFORUM conference in Dallas.  
*/

#ifdef __GNUC__
#include <getopt.h>
#else
#ifndef _WINGETOPT_H_
#define _WINGETOPT_H_

#include <tchar.h>
#include <strsafe.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int opterr;
extern int optind;
extern int optopt;
extern const TCHAR *optarg;
extern int getopt(const int argc, const TCHAR **argv, TCHAR *opts);

#ifdef __cplusplus
}
#endif

#endif  /* _GETOPT_H_ */
#endif  /* __GNUC__ */
