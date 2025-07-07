/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2019 Xilinx, Inc. */
#include "efch.h"


#ifdef __KERNEL__

extern int
efch_resource_id_lookup(efch_resource_id_t id, ci_resource_table_t *rt,
                        efch_resource_t **out)
{
  efch_resource_t *rs;

  ci_assert(rt);
  ci_assert(out);

  /* Ensure that efch_resource_free does not free the resource between
   * reading the table and taking a reference to the resource */
  rcu_read_lock();

  rs = xa_load(&rt->table, id.index);
  if( rs == NULL || rs->rs_base == NULL ) {
    rcu_read_unlock();
    return -ENOENT;
  }

  refcount_inc(&rs->ref_count);
  rcu_read_unlock();

  EFRM_RESOURCE_ASSERT_VALID(rs->rs_base, 0);
  *out = rs;
  return 0;
}

#endif


#if CI_CFG_PRIVATE_T_DEBUG_LIST
static struct list_head priv_list;
static ci_lock_t priv_list_lock;
#endif

/* Set up the ci_resource_table_t */
void
ci_resource_table_ctor(ci_resource_table_t *rt, unsigned access)
{
  rt->access = access;

  xa_init_flags(&rt->table, XA_FLAGS_ALLOC);

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


/*! Tear down a ci_resource_table_t */
void
ci_resource_table_dtor( ci_resource_table_t *rt )
{
  ci_assert(rt);

#if CI_CFG_PRIVATE_T_DEBUG_LIST
  ci_lock_lock(&priv_list_lock);
  list_del(&(rt->priv_list));
  ci_lock_unlock(&priv_list_lock);
#endif

  efch_resource_free_all(rt);
  CI_DEBUG_ZERO(rt);
}
