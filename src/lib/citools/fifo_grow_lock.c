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
 
/*! \cidoxg_lib_citools */
 
#include "citools_internal.h"


void ci_fifo_grow_lock_helper(void* pfifo_a, unsigned elemsize,
			unsigned* psize, unsigned size_off,
			unsigned* rd_i, unsigned* wr_i,
			unsigned current_size, ci_irqlock_t* lock,
			void* (*alloc_fn)(size_t), void (*free_fn)(void*),
			int* prc)
{
  ci_irqlock_state_t lock_flags;
  void* newfifo, *oldfifo;
  void** pfifo = (void**) pfifo_a;
  unsigned num, n, newsize, size;

  ci_assert(pfifo != NULL);
  ci_assert(*pfifo != NULL);
  ci_assert(elemsize > 0);
  ci_assert(psize != NULL);
  ci_assert(*psize + size_off > 0);
  ci_assert(rd_i != NULL);
  ci_assert(wr_i != NULL);
  ci_assert(lock != NULL);

  *prc = 0;

  while( 1 ) {
    ci_irqlock_lock(lock, &lock_flags);
    ci_assert(*wr_i - *rd_i <= *psize + size_off);

    size = *psize + size_off;
    newsize = size * 2u;

    ci_irqlock_unlock(lock, &lock_flags);
    newfifo = alloc_fn(newsize * elemsize);
    ci_irqlock_lock(lock, &lock_flags);

    /* We unlocked, so anything could have happened... */
    size = *psize + size_off;
    num = *wr_i - *rd_i;

    if( num < size ) {
      /* Someone else made space in the fifo. */
      ci_irqlock_unlock(lock, &lock_flags);
      if( newfifo )
        free_fn(newfifo);
      return;
    }
    if( newfifo == NULL ) {
      ci_irqlock_unlock(lock, &lock_flags);
      *prc = -ENOMEM;
      return;
    }

    if( newsize > size )
      break;

    /* The buffer we allocated does not make fifo bigger, so try again.
     * (This can happen because someone else got in and grew the fifo (and
     * it filled again) while the lock was dropped).
     */
    ci_irqlock_unlock(lock, &lock_flags);
    free_fn(newfifo);
  }

  /* Copy in the old data, starting at the beginning. */
  n = size - (*rd_i % size);
  if( n > num )  n = num;
  memcpy(newfifo, (char*) *pfifo + (*rd_i % size) * elemsize, n * elemsize);
  memcpy((char*) newfifo + n * elemsize, *pfifo, (num - n) * elemsize);

  oldfifo = *pfifo;
  *pfifo = newfifo;
  *psize = newsize - size_off;
  *rd_i = 0;
  *wr_i = num;

  ci_irqlock_unlock(lock, &lock_flags);
  free_fn(oldfifo);
}

/*! \cidoxg_end */
