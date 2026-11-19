/* 'Tag=Value;Tag=Value' setting-string tokenizer (Sandboxie/common/str_util.c)
 * used for NetworkAccess, proxy, DNS and other rule values.
 * Input: first line = tag name to look up, rest = the setting string. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_wstr.h"
#include "common/str_util.h"

static BOOLEAN enum_cb(const WCHAR *name, ULONG name_len, const WCHAR *value, ULONG value_len, void *param)
{
    size_t *acc = (size_t *)param;
    ULONG i;
    for (i = 0; i < name_len; i++) *acc += name[i];
    for (i = 0; i < value_len; i++) *acc += value[i];
    return TRUE;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const uint8_t *nl = memchr(data, '\n', size);
    size_t nlen = nl ? (size_t)(nl - data) : 0;
    const uint8_t *rest = nl ? nl + 1 : data;
    size_t rlen = nl ? size - nlen - 1 : size;
    WCHAR *name = fuzz_wstr(data, nlen);
    WCHAR *str = fuzz_wstr(rest, rlen);
    size_t acc = 0;
    if (name && str) {
        static const WCHAR seps[][2] = { { L'=', L';' }, { L':', L',' } };
        size_t k;
        for (k = 0; k < 2; k++) {
            ULONG vsize = (ULONG)((wcslen(str) + 1) * sizeof(WCHAR));
            WCHAR *val = (WCHAR *)malloc(vsize);
            const WCHAR *vp; ULONG vl;
            SbieDll_EnumTagValues(str, enum_cb, &acc, seps[k][0], seps[k][1]);
            if (val) {
                SbieDll_FindTagValue(str, name, val, vsize, seps[k][0], seps[k][1]);
                free(val);
            }
            SbieDll_FindTagValuePtr(str, name, &vp, &vl, seps[k][0], seps[k][1]);
        }
        if (*name) (void)wcsistr(str, name);
    }
    free(name);
    free(str);
    return (int)(acc & 0);
}
