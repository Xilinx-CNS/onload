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

#ifndef __CI_EFHW_SYSDEP_CI2LINUX_H__
#define __CI_EFHW_SYSDEP_CI2LINUX_H__


#include <ci/tools/sysdep.h>
#include <ci/tools/utils.h>
#include <ci/tools/spinlock.h>
#include <ci/tools/fifos.h>


#include <ci/driver/internal.h>


typedef ci_irqlock_t        spinlock_t;
typedef ci_irqlock_state_t  irq_flags_t;

#define spin_lock_irqsave(l_,f_)        ci_irqlock_lock((l_),&(f_))
#define spin_unlock_irqrestore(l_,f_)   ci_irqlock_unlock((l_),&(f_))
#define spin_lock_init(l_)              ci_irqlock_ctor((l_))
#define spin_lock_destroy(l_)           ci_irqlock_dtor((l_))


#define vmalloc ci_vmalloc_fn
#define vfree ci_vfree


#define fls(n) ci_log2_ge((n) + 1,0)
#define get_order(n) (ci_log2_ge(n, CI_PAGE_SHIFT) - CI_PAGE_SHIFT)
#define roundup(x,y) CI_ALIGN_FWD(x,y)


#ifndef PAGE_SIZE
#define PAGE_SIZE CI_PAGE_SIZE
#endif
#ifndef PAGE_SHIFT
#define PAGE_SHIFT CI_PAGE_SHIFT
#endif


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif
#ifndef ETH_HLEN
#define ETH_HLEN 14
#endif


#ifndef likely
# define likely CI_LIKELY
#endif
#ifndef unlikely
# define unlikely CI_UNLIKELY
#endif

#define EXPORT_SYMBOL(x)

#define cmpxchg(ptr,o,n)\
  (__cmpxchg((ptr),(unsigned long)(o),                  \
             (unsigned long)(n),sizeof(*(ptr))))

ci_inline unsigned long
__cmpxchg(volatile void *ptr, unsigned long old,
          unsigned long new, int size)
{
  ci_assert(size == 4 || size == 8);
  switch(size) {
    case 4:
      return ci_cas32_succeed(ptr, old, new) ? old : new;
    case 8:
#ifndef __i386__
      return ci_cas64_succeed(ptr, old, new) ? old : new;
#else
      ci_assert(0);
#endif
  }
  return old;
}


ci_inline int
test_and_set_bit(int nr, volatile void * addr)
{
  ci_int32 old, new;
  ci_assert(nr < 32);

  do {
    old = *(ci_int32*)addr;
    new = old | (1 << nr);
  } while (old != new && !ci_cas32_succeed(addr, old, new));
  return (old >> nr) & 1;
}

ci_inline int
test_and_clear_bit(int nr, volatile void * addr)
{
  ci_int32 old, new;
  ci_assert(nr < 32);

  do {
    old = *(ci_int32*)addr;
    new = old & ~(1 << nr);
  } while (old != new && !ci_cas32_succeed(addr, old, new));
  return (old >> nr) & 1;
}


#include <ci/net/ipv4.h>
#define NIPQUAD_FMT CI_IP_PRINTF_FORMAT
#define NIPQUAD(addr) CI_IP_PRINTF_ARGS(addr)


#ifndef min
# define min(a,b) CI_MIN(a,b)
#endif
#ifndef max
# define max(a,b) CI_MAX(a,b)
#endif
#ifndef min_t
# define min_t(t,a,b) CI_MIN((t)a,(t)b)
#endif
#ifndef max_t
# define max_t(t,a,b) CI_MAX((t)a,(t)b)
#endif

#ifndef ntohl
# define ntohl(v) CI_BSWAP_BE32(v)
#endif
#ifndef htonl
# define htonl(v) CI_BSWAP_BE32(v)
#endif
#ifndef ntohs
# define ntohs(v) CI_BSWAP_BE16(v)
#endif
#ifndef htons
# define htons(v) CI_BSWAP_BE16(v)
#endif


#endif /* __CI_EFHW_SYSDEP_CI2LINUX_H__ */
