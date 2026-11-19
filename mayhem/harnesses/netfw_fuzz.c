/* NetworkAccess firewall rules (Sandboxie/common/netfw.c): rule parser
 * (ports, IPv4/IPv6 ranges, protocol), rule merge and traffic match.
 * Input: 16 bytes IP, 2 bytes port, 1 byte protocol selector, then one
 * rule per line in the Sandboxie.ini value form
 * ("Allow;Port=80,443;Address=10.0.0.1-10.0.0.9;Protocol=TCP"). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "fuzz_wstr.h"
#include "common/netfw.h"

#define HDR 19

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static const int protos[] = { 6 /*TCP*/, 17 /*UDP*/, 1 /*ICMP*/, 256 /*any*/ };
    IP_ADDRESS ip;
    USHORT port;
    int proto;
    POOL *pool;
    LIST list;
    const uint8_t *p, *end, *nl;
    int level = 0;
    if (size < HDR) return -1;
    memcpy(ip.Data, data, 16);
    port = (USHORT)(data[16] | (data[17] << 8));
    proto = protos[data[18] & 3];
    pool = Pool_Create();
    if (!pool) return 0;
    List_Init(&list);
    p = data + HDR;
    end = data + size;
    while (p < end) {
        WCHAR *s;
        nl = memchr(p, '\n', (size_t)(end - p));
        if (!nl) nl = end;
        s = fuzz_wstr(p, (size_t)(nl - p));
        if (s) {
            NETFW_RULE *rule = NetFw_AllocRule(pool, level++ % 4);
            if (rule) {
                if (NetFw_ParseRule(rule, s))
                    NetFw_AddRule(&list, rule);
                else
                    NetFw_FreeRule(rule);
            }
            free(s);
        }
        p = nl + 1;
    }
    (void)NetFw_BlockTraffic(&list, &ip, port, proto);
    while (list.head) {
        NETFW_RULE *rule = (NETFW_RULE *)List_Head(&list);
        List_Remove(&list, rule);
        NetFw_FreeRule(rule);
    }
    Pool_Delete(pool);
    return 0;
}
