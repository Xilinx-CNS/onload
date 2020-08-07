/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
#include "efch.h"


#ifdef __KERNEL__

extern int
efch_resource_id_lookup(efch_resource_id_t id, ci_resource_table_t *rt,
                        efch_resource_t **out)
{
  uint32_t index = id.index;
  efch_resource_t *rs;

  ci_assert(rt);
  ci_assert(out);

  if( id.index >= rt->resource_table_highwater )
    return -EINVAL;

  /* NB. This needs no lock because resources cannot be detached from
   * a ci_resource_table_t.  They can only go away when 
   * the ci_resource_table_t is destroyed. */
  if ((rs = rt->resource_table[index]) == NULL || rs->rs_base == NULL)
    return -ENOENT;

  EFRM_RESOURCE_ASSERT_VALID(rs->rs_base, 0);
  *out = rs;
  return 0;
}

#endif


/* We put the ci_private ctor/ctor here as ci_resource_table_t is as much to do 
 * with resource management as anything else. 
 */

#if CI_CFG_PRIVATE_T_DEBUG_LIST
static struct list_head priv_list;
static ci_lock_t priv_list_lock;
#endif

/* Set up the resource_table_t; assumes that p addresses an allocated piece of memory
 * of size sizeof(ci_resource_table_t); also associates the new private_t to nic n
 */
void
ci_resource_table_ctor(ci_resource_table_t *rt, unsigned access)
{
  rt->access = access;

  rt->resource_table = rt->resource_table_static;
  rt->resource_table_size = CI_DEFAULT_RESOURCE_TABLE_SIZE;

#if CI_CFG_PRIVATE_T_DEBUG_LIST
  {
    static int initialized_list = 0;
    
    if (!initialized_list) {
      initialized_list = 1;
      ci_lock_ctor(&priv_list_lock);
      INIT_LIST_HEAD(&priv_list);
    }
    ci_lock_lock(&priv_list_lock);
    list_add_tail(&priv_list, &(rt->priv_list));
    ci_lock_unlock(&priv_list_lock);
  }
#endif
}


/*! Tear down a private_t */
void
ci_resource_table_dtor( ci_resource_table_t *rt )
{
  efch_resource_t *rs;
  unsigned i;

  ci_assert(rt);

#if CI_CFG_PRIVATE_T_DEBUG_LIST
  ci_lock_lock(&priv_list_lock);
  list_del(&(rt->priv_list));
  ci_lock_unlock(&priv_list_lock);
#endif

  for( i = 0; i < rt->resource_table_highwater; i++ ) {
    rs = rt->resource_table[i];
    ci_assert(rs != NULL);
    efch_resource_free(rs);
    CI_DEBUG(rt->resource_table[i] = NULL);
  }
  if( rt->resource_table != rt->resource_table_static )
    ci_free(rt->resource_table);
  CI_DEBUG_ZERO(rt);
}
