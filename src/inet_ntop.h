#ifndef INET_NTOP_H
#define INET_NTOP_H

#if defined(NTDDI_VISTA) && (NTDDI_VERSION >= NTDDI_VISTA)	//If Windows version is before Vista
#define INET_NTOP	inet_ntop
#else
#define INET_NTOP	__inet_ntop
const char * __inet_ntop(int af, const void *src, char *dst, size_t size);
#endif

#endif	//end INET_NTOP_H