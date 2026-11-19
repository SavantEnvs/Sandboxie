/* Fake <windows.h> so SandboxieTools/Common/helpers.cpp (and its Win32
 * dirent.h emulation) compile on Linux. Only types and inert stubs of the
 * OS calls those files reference: every file-system / version call reports
 * failure. The fuzzed code (GetArguments, wildcmp, Trimm) touches none. */
#ifndef MAYHEM_FAKE_WINDOWS_H
#define MAYHEM_FAKE_WINDOWS_H
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <wchar.h>
#include <wctype.h>
#include <errno.h>
typedef uint32_t DWORD, ULONG;
typedef int32_t LONG, NTSTATUS;
typedef int BOOL;
typedef void *HANDLE, *HMODULE;
typedef wchar_t WCHAR;
typedef char CHAR;
typedef intptr_t (*FARPROC)(void);
#define WINAPI
#define __inline inline
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define FILE_ATTRIBUTE_DEVICE 0x40
#define FILE_ATTRIBUTE_REPARSE_POINT 0x400
#define ERROR_FILE_NOT_FOUND 2
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
typedef struct _OSVERSIONINFOW {
    DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion, dwBuildNumber, dwPlatformId;
    WCHAR szCSDVersion[128];
} OSVERSIONINFOW, *LPOSVERSIONINFOW;
typedef struct _FILETIME { DWORD dwLowDateTime, dwHighDateTime; } FILETIME;
typedef struct _WIN32_FIND_DATAA {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime, ftLastAccessTime, ftLastWriteTime;
    DWORD nFileSizeHigh, nFileSizeLow, dwReserved0, dwReserved1;
    CHAR cFileName[MAX_PATH];
    CHAR cAlternateFileName[14];
} WIN32_FIND_DATAA;
static inline FARPROC GetProcAddress(HMODULE m, const char *n) { (void)m; (void)n; return 0; }
static inline HMODULE GetModuleHandleA(const char *n) { (void)n; return 0; }
static inline BOOL GetVersionExW(LPOSVERSIONINFOW v) { (void)v; return FALSE; }
static inline DWORD GetLastError(void) { return ERROR_FILE_NOT_FOUND; }
static inline DWORD GetFileAttributesW(const WCHAR *p) { (void)p; return INVALID_FILE_ATTRIBUTES; }
#define GetFileAttributes GetFileAttributesW
static inline void OutputDebugStringW(const WCHAR *s) { (void)s; }
#define _vsnwprintf vswprintf
static inline HANDLE FindFirstFileA(const char *p, WIN32_FIND_DATAA *d) { (void)p; (void)d; return INVALID_HANDLE_VALUE; }
static inline BOOL FindNextFileA(HANDLE h, WIN32_FIND_DATAA *d) { (void)h; (void)d; return FALSE; }
static inline BOOL FindClose(HANDLE h) { (void)h; return TRUE; }
static inline DWORD GetFullPathNameA(const char *p, DWORD n, char *b, char **f) { (void)p; (void)n; (void)b; (void)f; return 0; }
#endif
