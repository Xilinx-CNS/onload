/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  
**  \brief External interface for id management in the resource library 
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_efrm  */

#ifndef __CI_TOOLS_ID_POOL_H__
#define __CI_TOOLS_ID_POOL_H__

#include <ci/tools/fifos.h>

#define CI_ID_POOL_ID_NONE ((unsigned)(-1))

/*
** Maintains a pool of unique integers.  They are allocated starting from
** zero, and freed ids are reused in fifo order.
*/

typedef struct ci_id_pool_s {
  ci_int_fifo2_t  free_ids;
  unsigned        next_id;
  unsigned        max_num_ids;
} ci_id_pool_t;


extern int ci_id_pool_ctor(ci_id_pool_t* idp, int max_ids, int init_size);
  /*!< Pass -1 for [max_ids] if the number is unlimited. */

/*! Destructor */
extern void ci_id_pool_dtor(ci_id_pool_t* idp);


/*! Comment? */
/*! Comment?
 * Returns CI_ID_POOL_ID_NONE on failure
 */
ci_inline unsigned ci_id_pool_alloc(ci_id_pool_t* idp) {
  unsigned id;
  if( ci_fifo2_is_empty(&idp->free_ids) ) {
    id = idp->next_id == idp->max_num_ids ?
            CI_ID_POOL_ID_NONE : idp->next_id++;
  }
  else {
    ci_fifo2_get(&idp->free_ids, &id);
  }
  return id;
}


#if defined(CI_HAVE_SPINLOCKS)

/*! Comment? */
extern int ci_id_pool_free(ci_id_pool_t* idp, unsigned id,
			   ci_irqlock_t* lock);

#endif


#endif  /* __CI_TOOLS_ID_POOL_H__ */

/*! \cidoxg_end */
