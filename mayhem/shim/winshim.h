/* Minimal Windows type shim so Sandboxie's OS-independent parsers in
 * Sandboxie/common compile natively on Linux. Force-included (-include)
 * before every upstream TU; it defines types and CRT aliases only, no logic. */
#ifndef MAYHEM_WINSHIM_H
#define MAYHEM_WINSHIM_H
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>
typedef wchar_t WCHAR, *PWCHAR, *PWSTR;
typedef const wchar_t *PCWSTR;
typedef unsigned char UCHAR, BOOLEAN, BYTE, *PUCHAR;
typedef uint32_t ULONG, DWORD, *PULONG;
typedef int32_t LONG, NTSTATUS;
typedef uint16_t USHORT, WORD, *PUSHORT;
typedef int16_t SHORT;
typedef void VOID, *PVOID, *HANDLE;
typedef uint64_t ULONG64, ULONGLONG;
typedef uintptr_t ULONG_PTR, UINT_PTR;
typedef intptr_t LONG_PTR;
typedef int64_t LONGLONG, LONG64;
typedef size_t SIZE_T;
typedef int BOOL;
typedef char CHAR;
typedef unsigned int UINT;
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif
#define __declspec(x)
#define FAR
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#define _wcsnicmp wcsncasecmp
#define _wcsicmp wcscasecmp
#define _wcsnicmp wcsncasecmp
#define _wtoi(s) ((int)wcstol((s), 0, 10))
#define _Check_return_
#define _CRTIMP
#define __cdecl
#define _In_z_
#define _Out_opt_
#define _Deref_post_z_
#ifdef __cplusplus
extern "C" {
#endif
/* MSVC wcsncpy_s: copies at most count chars and NUL-terminates; a
 * destination that is too small invokes the CRT invalid-parameter handler,
 * whose default terminates the process — mirrored here with abort(). */
static inline int wcsncpy_s(wchar_t *dst, size_t dstsz, const wchar_t *src, size_t count)
{
    size_t n = 0;
    if (!dst || dstsz == 0) abort();
    while (n < count && src[n]) n++;
    if (n >= dstsz) { dst[0] = 0; abort(); }
    memcpy(dst, src, n * sizeof(wchar_t));
    dst[n] = 0;
    return 0;
}
static inline wchar_t *mayhem_wcslwr(wchar_t *s) { wchar_t *p; for (p = s; *p; p++) *p = (wchar_t)towlower(*p); return s; }
#ifdef __cplusplus
}
#endif
#define _wcslwr mayhem_wcslwr
#ifndef __cplusplus
/* Headers the MSVC build reaches through its include order before
 * pattern.h/netfw.h (which use LIST, struct in_addr and struct sockaddr
 * in prototypes without including them). */
#include "common/list.h"
#include <inaddr.h>
#include <in6addr.h>
struct sockaddr;
#endif
#endif
