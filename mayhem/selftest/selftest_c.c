/* Known-answer checks for the Sandboxie/common C parsers. Built with the
 * project's normal flags (no sanitizers) by build.sh; run by test.sh. */
#include <stdio.h>
#include <string.h>
#include "common/pattern.h"
#include "common/netfw.h"
#include "common/str_util.h"
size_t b64_encoded_size(size_t inlen);
int b64_encode(const unsigned char *in, size_t inlen, wchar_t *out, size_t outlen);
size_t b64_decoded_size(const wchar_t *in);
int b64_decode(const wchar_t *in, unsigned char *out, size_t outlen);

typedef void (*report_fn)(const char *name, int ok);

static int pat_match(const WCHAR *src, const WCHAR *path)
{
    POOL *pool = Pool_Create();
    PATTERN *pat = Pattern_Create(pool, src, TRUE, 0);
    int r = pat ? Pattern_Match(pat, path, (int)wcslen(path)) : -1;
    if (pat) Pattern_Free(pat);
    Pool_Delete(pool);
    return r;
}

static int fw_block(const WCHAR *rule_str, const WCHAR *ip4, USHORT port, int proto, int *parsed)
{
    POOL *pool = Pool_Create();
    LIST list;
    IP_ADDRESS ip;
    NETFW_RULE *rule;
    int r;
    List_Init(&list);
    memset(&ip, 0, sizeof(ip));
    _inet_xton(ip4, (ULONG)wcslen(ip4), &ip, NULL);
    rule = NetFw_AllocRule(pool, 2);
    *parsed = NetFw_ParseRule(rule, rule_str);
    if (*parsed) NetFw_AddRule(&list, rule); else NetFw_FreeRule(rule);
    r = NetFw_BlockTraffic(&list, &ip, port, proto);
    while (list.head) { NETFW_RULE *x = List_Head(&list); List_Remove(&list, x); NetFw_FreeRule(x); }
    Pool_Delete(pool);
    return r;
}

void c_checks(report_fn report)
{
    unsigned char buf[64];
    wchar_t wbuf[64];
    int parsed = 0;
    IP_ADDRESS ip;

    /* base64 */
    memset(buf, 0, sizeof(buf));
    report("b64_decoded_size", b64_decoded_size(L"SGVsbG8=") == 5);
    report("b64_decode_hello", b64_decode(L"SGVsbG8=", buf, 5) == 1 && memcmp(buf, "Hello", 5) == 0);
    report("b64_decode_reject_len", b64_decoded_size(L"SGVsbG8") == 0);
    report("b64_decode_reject_char", b64_decode(L"SGV$bG8=", buf, 5) == 0);
    memset(wbuf, 0, sizeof(wbuf));
    report("b64_encode_hello", b64_encode((const unsigned char *)"Hello", 5, wbuf, 8) == 1 && wcsncmp(wbuf, L"SGVsbG8=", 8) == 0);

    /* tag strings */
    report("tag_find_address", SbieDll_FindTagValue(L"Port=80;Address=1.2.3.4;Protocol=TCP", L"Address", wbuf, sizeof(wbuf), L'=', L';') && wcscmp(wbuf, L"1.2.3.4") == 0);
    report("tag_find_missing", !SbieDll_FindTagValue(L"Port=80;Address=1.2.3.4", L"Proto", wbuf, sizeof(wbuf), L'=', L';'));
    report("wcsistr", wcsistr(L"C:\\Windows\\System32", L"windows") != NULL && wcsistr(L"abc", L"x") == NULL);

    /* patterns */
    report("pattern_star_match", pat_match(L"*\\windows\\*", L"c:\\windows\\system32") == 1);
    report("pattern_star_nomatch", pat_match(L"*\\windows\\*", L"c:\\temp\\file") == 0);
    report("pattern_exact", pat_match(L"c:\\temp\\a.txt", L"c:\\temp\\a.txt") == 1 && pat_match(L"c:\\temp\\a.txt", L"c:\\temp\\b.txt") == 0);
    report("pattern_qmark", pat_match(L"c:\\a?c", L"c:\\abc") == 1);

    /* network firewall rules */
    report("netfw_block_port", fw_block(L"Block;Port=80;Protocol=TCP", L"1.2.3.4", 80, 6, &parsed) == 1 && parsed);
    report("netfw_other_port", fw_block(L"Block;Port=80;Protocol=TCP", L"1.2.3.4", 81, 6, &parsed) == 0);
    report("netfw_other_proto", fw_block(L"Block;Port=80;Protocol=TCP", L"1.2.3.4", 80, 17, &parsed) == 0);
    report("netfw_ip_range", fw_block(L"Block;Address=10.0.0.1-10.0.0.9", L"10.0.0.5", 443, 6, &parsed) == 1
                             && fw_block(L"Block;Address=10.0.0.1-10.0.0.9", L"10.0.0.10", 443, 6, &parsed) == 0);
    memset(&ip, 0, sizeof(ip));
    report("inet_xton_v4", _inet_xton(L"192.168.1.2", 11, &ip, NULL) == 1 && ip.Data[15] == 2 && ip.Data[12] == 192);
}
