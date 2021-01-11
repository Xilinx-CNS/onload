#include <onload/debug.h>
#include <onload/oo_shmbuf.h>


int oo_shmbuf_alloc(struct oo_shmbuf* sh, int order, int max, int init_num)
{
  int i;

  sh->max = max;
  sh->order = order;
  sh->num = init_num;
  sh->init_num = init_num;

  sh->addrs = kzalloc(sizeof(sh->addrs[0]) * max, GFP_KERNEL);
  if( sh->addrs == NULL )
    return -ENOMEM;

  sh->addrs[0] = vmalloc_user((unsigned long)init_num << PAGE_SHIFT << order);
  if( sh->addrs[0] == 0 ) {
    ci_log("%s: failed to allocate a virtually-continuous buffer of size %ld",
           __func__, (unsigned long)init_num << PAGE_SHIFT << order);
    return -ENOMEM;
  }

  for( i = 1; i < init_num; i++ )
    sh->addrs[i] = OO_SHMBUF_INIT_CHUNK;
  return 0;
}

void oo_shmbuf_free(struct oo_shmbuf* sh)
{
  int i;

  if( sh->addrs[0] )
    vfree(sh->addrs[0]);

  for( i = sh->init_num; i < sh->num && sh->addrs[i] != 0; i++ )
    vfree(sh->addrs[i]);

  kfree(sh->addrs);
}

int oo_shmbuf_add(struct oo_shmbuf* sh)
{
  int i;

  i = sh->num++;
  /* Fixme implement locking */

  sh->addrs[i] = vmalloc_user(PAGE_SIZE << sh->order);
  if( sh->addrs[i] == 0 ) {
    sh->num--;
    return -ENOMEM;
  }


  /* Fixme add to hash table */

  return i;
}

unsigned long oo_shmbuf_ptr2off(const struct oo_shmbuf* sh, char* ptr)
{
  int i;

  ci_assert_lt(sh->num, 10);
  /* Fixme implement hash table */

  for(i = 0; i < sh->num; i++) {
    unsigned long off = ptr - oo_shmbuf_idx2ptr(sh, i);

    if( off >= 0 && off < oo_shmbuf_chunk_size(sh) )
      return (i << sh->order << PAGE_SHIFT) + off;
  }
  ci_assert(0);
  return -1;
}

int oo_shmbuf_fault(struct oo_shmbuf* sh, struct vm_area_struct* vma,
                    unsigned long off)
{
  int i = off >> sh->order >> PAGE_SHIFT;
  unsigned long start_off = (unsigned long)i << sh->order << PAGE_SHIFT;
  unsigned long size = oo_shmbuf_chunk_size(sh);

  if( sh->addrs[i] == 0 )
    return -EFAULT;

  if( i < sh->init_num ) {
    start_off = 0;
    i = 0;
    size *= sh->init_num;
  }

  return remap_vmalloc_range_partial(vma, vma->vm_start + start_off,
                                     (void*)sh->addrs[i], 0, size);
}
