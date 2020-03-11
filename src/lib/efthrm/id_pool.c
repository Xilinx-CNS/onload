/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver */
 
#include <onload/id_pool.h>


int
ci_id_pool_ctor(ci_id_pool_t* idp, int max_num_ids, int init_size)
{
  int fifo_size;

  ci_assert(idp);
  ci_assert(init_size >= 0);
  ci_assert(max_num_ids == -1 || init_size <= max_num_ids);

  if( init_size == 0 )  fifo_size = 5;
  else                  fifo_size = ci_log2_le(init_size) + 1;
  fifo_size = ci_pow2(fifo_size);

  idp->next_id = 0;
  idp->max_num_ids = max_num_ids;

  /* Want [free_ids] to be 2^x in size, as more efficient that way. */
  idp->free_ids.fifo = (int*) ci_vmalloc(fifo_size * sizeof(int));
  ci_fifo2_init(&idp->free_ids, fifo_size);

  while( init_size-- ) {
    ci_assert(!ci_fifo2_is_full(&idp->free_ids));
    ci_fifo2_put(&idp->free_ids, (int) idp->next_id++);
  }

  return 0;
}


void
ci_id_pool_dtor(ci_id_pool_t* idp)
{
  ci_vfree(idp->free_ids.fifo);
}


#if defined(CI_HAVE_SPINLOCKS)

int
ci_id_pool_free(ci_id_pool_t* idp, unsigned id, ci_irqlock_t* lock)
{
  ci_irqlock_state_t lock_flags;
  unsigned current_size;
  int rc;

  while( 1 ) {
    ci_irqlock_lock(lock, &lock_flags);

    if( !ci_fifo2_is_full(&idp->free_ids) ) {
      ci_fifo2_put(&idp->free_ids, (int) id);
      ci_irqlock_unlock(lock, &lock_flags);
      return 0;
    }

    current_size = ci_fifo2_buf_size(&idp->free_ids);
    ci_irqlock_unlock(lock, &lock_flags);

    if (ci_in_atomic()) {
      ci_log("ci_id_pool: ci_in_atomic in ci_id_pool_free()");
      return -ENOMEM;
    }

    ci_fifo2_grow_lock_a(&idp->free_ids, current_size, lock, ci_vmalloc_fn,
			 ci_vfree, &rc);
    if( rc < 0 )  return rc;
  }
}

#endif


/*! \cidoxg_end */

