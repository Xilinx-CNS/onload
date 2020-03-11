/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  Alexandra.Kossovsky@oktetlabs.ru
**  \brief  Non-linux-kernel sysdep file
**   \date  2007/11/20
**    \cop  (c) Solarflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_efrm  */

#ifndef __CI_EFRM_SYSDEP_CI2LINUX_H__
#define __CI_EFRM_SYSDEP_CI2LINUX_H__


#include <ci/compat.h>
#include <ci/tools/config.h>
#include <ci/tools/debug.h>
#include <ci/tools/log.h>
#include <ci/tools/sysdep.h>
#include <ci/tools/dllist.h>
#include <ci/tools/fifos.h>

/* 
 * Keep it compatible to ci_dllink & ci_dllist!
 * It should contain next and prev fields, which are used in the code
 * directly.
 */
#define list_head ci_dllink_s
#define LIST_HEAD_TO_LIST(l_) ((ci_dllist*)(l_))
#define LIST_HEAD_TO_LINK(l_) (l_)
#define LIST_HEAD CI_DLLIST_DECLARE


#undef INIT_LIST_HEAD
#undef list_for_each_entry
#undef list_for_each_entry_safe
#define INIT_LIST_HEAD(l_) ci_dllist_init(LIST_HEAD_TO_LIST(l_))
#define list_for_each(p_,l_)                            \
    CI_DLLIST_FOR_EACH(p_,LIST_HEAD_TO_LIST(l_))
#define list_for_each_safe(p_,temp_,l_)                 \
    CI_DLLIST_FOR_EACH4(p_,LIST_HEAD_TO_LIST(l_),temp_)

#define list_add(new_, l_) \
    ci_dllist_push(LIST_HEAD_TO_LIST(l_),LIST_HEAD_TO_LINK(new_))
#define list_add_tail(new_, l_) \
    ci_dllist_push_tail(LIST_HEAD_TO_LIST(l_),LIST_HEAD_TO_LINK(new_))
#define list_del(l_) ci_dllist_remove(LIST_HEAD_TO_LINK(l_))
#define list_pop(l_) ci_dllist_pop(LIST_HEAD_TO_LIST(l_))
#define list_pop_tail(l_) ci_dllist_pop_tail(LIST_HEAD_TO_LIST(l_))
#define list_empty(l_) ci_dllist_is_empty(LIST_HEAD_TO_LIST(l_))
#define list_replace_init(old_,new_) \
    ci_dllist_rehome(LIST_HEAD_TO_LIST(new_),LIST_HEAD_TO_LIST(old_))



#undef container_of
#undef list_entry
#undef offsetof
#define container_of(p_,t_,f_) CI_CONTAINER(t_,f_,p_)
#define list_entry(p_,t_,f_) CI_CONTAINER(t_,f_,p_)
#define offsetof(t_,m_) CI_MEMBER_OFFSET(t_,m_)



#define in_atomic ci_in_atomic
#define in_interrupt ci_in_interrupt


#define GFP_KERNEL 0
#define GFP_ATOMIC 1

typedef unsigned gfp_t;

ci_inline void *kmalloc(size_t size, gfp_t flags)
{
  switch (flags) {
    case GFP_KERNEL:
      return ci_alloc(size);
    case GFP_ATOMIC:
      return ci_atomic_alloc(size);
    default:
      ci_assert(0);
      return NULL;
  }
}
ci_inline void *kcalloc(size_t n, size_t size, gfp_t flags)
{
  void* p;
  ci_assert_equal(flags, GFP_KERNEL);
  p = ci_alloc(n * size);
  memset(p, 0, n * size);
  return p;
}
#define kfree(p)  do{ if ((p) != NULL)  ci_free(p); }while(0)


#define CI_MAX_ERRNO 1024
#define IS_ERR(ptr) \
  CI_UNLIKELY((uintptr_t)(ptr) >= (uintptr_t)-CI_MAX_ERRNO)
#define PTR_ERR(ptr) ((long)((uintptr_t)(ptr)))
#define ERR_PTR(err) ((void*)(uintptr_t)(long)(err))



#define roundup_pow_of_two(n) (1 << ci_log2_ge(n,0))
#define is_power_of_2(N) CI_IS_POW2(N)



#define smp_rmb ci_rmb
#define smp_mb  ci_mb
#define smp_wmb ci_wmb



#define atomic_t ci_atomic_t
#define atomic_dec_and_test ci_atomic_dec_and_test
#define atomic_inc ci_atomic_inc
#define atomic_dec ci_atomic_dec
#define atomic_set ci_atomic_set
#define atomic_read ci_atomic_read



ci_inline ci_uint64
get_jiffies_64(void)
{
  ci_uint64 ret;
  ci_frc64(&ret);
  return ret;
}
ci_inline ci_uint32
get_jiffies_32(void)
{
  ci_uint32 ret;
  ci_frc32(&ret);
  return ret;
}
#define jiffies get_jiffies_32()


#ifndef inline
#define inline __inline
#endif

#endif /* __CI_EFRM_SYSDEP_CI2LINUX_H__ */
