/* Wildcard path-pattern compiler/matcher (Sandboxie/common/pattern.c) shared
 * by the driver and SbieDll for OpenFilePath/ClosedFilePath-style rules.
 * Input lines: every line but the last is a pattern (as read from
 * Sandboxie.ini); the last line is the path being matched. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_wstr.h"
#include "common/pattern.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    POOL *pool = Pool_Create();
    LIST list;
    const uint8_t *p = data, *end = data + size, *nl;
    WCHAR *path = NULL;
    ULONG level = 0;
    if (!pool) return 0;
    List_Init(&list);
    while ((nl = memchr(p, '\n', (size_t)(end - p))) != NULL) {
        WCHAR *src = fuzz_wstr(p, (size_t)(nl - p));
        /* Patterns come from Sandboxie.ini values, and the driver's reader
         * (core/drv/conf.c Conf_Read_Line) rejects an empty value with
         * STATUS_INVALID_PARAMETER, so Pattern_Create never sees "". */
        if (src && src[0]) {
            /* Pattern_Create(lower=TRUE) as config.c/dllpath.c call it */
            PATTERN *pat = Pattern_Create(pool, src, TRUE, level++ % 4);
            if (pat) List_Insert_After(&list, NULL, pat);
            free(src);
        }
        p = nl + 1;
    }
    path = fuzz_wstr(p, (size_t)(end - p));
    if (path) {
        /* Pattern_MatchPathList appends a '\\' in place of the NUL (pattern.c),
         * so callers hand it spare room: dns_filter.c allocates path_len + 4
         * WCHARs. Mirror that here. */
        size_t n = wcslen(path);
        WCHAR *big = (WCHAR *)calloc(n + 4, sizeof(WCHAR));
        if (!big) { free(path); path = NULL; goto out; }
        wmemcpy(big, path, n);
        free(path);
        path = big;
    }
    if (path) {
        /* pattern.h: with lower=TRUE the string matched must be lowercase */
        int len = (int)wcslen(_wcslwr(path));
        PATTERN *pat, *found = NULL;
        ULONG lvl = (ULONG)-1, flags = 0;
        USHORT wildc = 0;
        int mlen = 0;
        const WCHAR *patsrc = NULL;
        for (pat = List_Head(&list); pat; pat = List_Next(pat)) {
            (void)Pattern_Match(pat, path, len);
            (void)Pattern_MatchX(pat, path, len);
            (void)Pattern_Source(pat);
            (void)Pattern_Wildcards(pat);
            (void)Pattern_Exact(pat);
        }
        /* reads path[len - 1]; Pattern_MatchPathListEx guards len == 0 */
        if (len > 0)
            Pattern_MatchPathList(path, (ULONG)len, &list, &lvl, &flags, &wildc, &found);
        lvl = (ULONG)-1; flags = 0; wildc = 0;
        Pattern_MatchPathListEx(path, (ULONG)len, &list, &lvl, &mlen, &flags, &wildc, &patsrc);
        free(path);
    }
out:
    while ((list.head) != NULL) {
        PATTERN *pat = List_Head(&list);
        List_Remove(&list, pat);
        Pattern_Free(pat);
    }
    Pool_Delete(pool);
    return 0;
}
