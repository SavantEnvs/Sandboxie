/* Windows <in6addr.h> layout (IN6_ADDR), for Sandboxie/common/my_wsa.h. */
#ifndef MAYHEM_IN6ADDR_H
#define MAYHEM_IN6ADDR_H
typedef struct in6_addr {
    union {
        UCHAR Byte[16];
        USHORT Word[8];
    } u;
} IN6_ADDR, *PIN6_ADDR;
#define in_addr6 in6_addr
#define _S6_un u
#define _S6_u8 Byte
#define s6_addr _S6_un._S6_u8
#define s6_bytes u.Byte
#define s6_words u.Word
#endif
