#ifndef __ONLOAD_OO_SHMBUF_H__
#define __ONLOAD_OO_SHMBUF_H__

#include <ci/driver/internal.h>

/* Shared memory buffers are allocated as distinct chunks of virtual memory
 * areas.  They are mapped to UL in a continuous way, but in-kernel
 * addressess are not continuous.
 */
struct oo_shmbuf {
  int max;
  int order;

  /* Number of chunks allocated */
  int num;

  /* Number of continuous chank allocated initially */
  int init_num;

  void** addrs;
#define OO_SHMBUF_INIT_CHUNK ((void*)1UL)

  /* Lock for the num field above */
  struct mutex lock;
};


static inline unsigned long oo_shmbuf_chunk_size(const struct oo_shmbuf* sh) {
  return 1ULL << sh->order << PAGE_SHIFT;
}

static inline char*
oo_shmbuf_idx2ptr(const struct oo_shmbuf* sh, int idx)
{
  if( idx > 0 && idx < sh->init_num ) {
    ci_assert_equal(sh->addrs[idx], OO_SHMBUF_INIT_CHUNK);
    return (char*)sh->addrs[0] + oo_shmbuf_chunk_size(sh) * idx;
  }
  return sh->addrs[idx];
}

static inline void*
oo_shmbuf_off2ptr(const struct oo_shmbuf* sh, unsigned long off)
{
  return oo_shmbuf_idx2ptr(sh, off >> sh->order >> PAGE_SHIFT) +
         (off & ((1UL << sh->order << PAGE_SHIFT) - 1));
}

extern unsigned long __oo_shmbuf_ptr2off(const struct oo_shmbuf* sh, char* ptr);
static inline unsigned long
oo_shmbuf_ptr2off(const struct oo_shmbuf* sh, char* ptr)
{
  unsigned long off;

  /* Fast path: is it in the initial chunk? */
  off = ptr - oo_shmbuf_idx2ptr(sh, 0);
  if( off >= 0 && off < oo_shmbuf_chunk_size(sh) * sh->init_num )
    return off;

  /* Slow path: find the pointer in non-continuous chunks */
  return __oo_shmbuf_ptr2off(sh, ptr);
}

static inline long oo_shmbuf_size(struct oo_shmbuf* sh)
{
  return sh->max * oo_shmbuf_chunk_size(sh);
}

extern int oo_shmbuf_alloc(struct oo_shmbuf* sh, int order,
                           int max, int init_num);
extern void oo_shmbuf_free(struct oo_shmbuf* sh);
extern int oo_shmbuf_add(struct oo_shmbuf* sh);
extern int oo_shmbuf_fault(struct oo_shmbuf* sh, struct vm_area_struct* vma,
                           unsigned long off);


#endif /* __ONLOAD_OO_SHMBUF_H__ */
