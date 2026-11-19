/*
 * Malloc-backed stand-in for Sandboxie/common/pool.c (POOL API from pool.h).
 * The upstream user-mode pool carves 64K pages out of VirtualAlloc /
 * NtAllocateVirtualMemory with a Win32 spin lock; neither exists on Linux.
 * Every Pool_Alloc here is a separate malloc so ASan sees each object's real
 * bounds, and Pool_Delete frees whatever the pool still owns (pool.c semantics).
 */
#include <stdlib.h>
#include "common/pool.h"

typedef struct HDR { struct HDR *prev, *next; struct POOL *pool; ULONG size; ULONG pad; } HDR;
struct POOL { HDR head; };

POOL *Pool_Create(void)
{
    POOL *p = (POOL *)calloc(1, sizeof(POOL));
    if (!p) return NULL;
    p->head.prev = p->head.next = &p->head;
    return p;
}

POOL *Pool_CreateTagged(ULONG tag) { (void)tag; return Pool_Create(); }

void *Pool_Alloc(POOL *pool, ULONG size)
{
    HDR *h = (HDR *)malloc(sizeof(HDR) + size);
    if (!h) return NULL;
    h->pool = pool; h->size = size;
    h->next = pool->head.next; h->prev = &pool->head;
    pool->head.next->prev = h; pool->head.next = h;
    return h + 1;
}

void Pool_Free(void *ptr, ULONG size)
{
    HDR *h;
    if (!ptr) return;
    h = (HDR *)ptr - 1;
    if (h->size != size) abort(); /* pool.c frees by caller-supplied size */
    h->prev->next = h->next; h->next->prev = h->prev;
    free(h);
}

ULONG Pool_Delete(POOL *pool)
{
    HDR *h = pool->head.next;
    while (h != &pool->head) { HDR *n = h->next; free(h); h = n; }
    free(pool);
    return 0;
}
