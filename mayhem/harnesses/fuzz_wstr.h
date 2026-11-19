/* Turn fuzzer bytes into NUL-terminated wide strings (one byte -> one
 * WCHAR, Latin-1 widening), split on '\n' when a harness needs several. */
#ifndef FUZZ_WSTR_H
#define FUZZ_WSTR_H
#include <stdlib.h>
#include <stddef.h>
#include <wchar.h>
static wchar_t *fuzz_wstr(const unsigned char *data, size_t size)
{
    wchar_t *w = (wchar_t *)malloc((size + 1) * sizeof(wchar_t));
    size_t i, n = 0;
    if (!w) return NULL;
    for (i = 0; i < size; i++) {
        if (data[i] == 0) break;   /* the C string ends at the first NUL */
        w[n++] = (wchar_t)data[i];
    }
    w[n] = 0;
    return w;
}
#endif
