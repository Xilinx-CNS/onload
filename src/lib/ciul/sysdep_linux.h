/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/*
 * \author  stg
 *  \brief  System dependent support for ef vi lib
 *   \date  2007/05/10
 */

/*! \cidoxg_include_ci_ul */
#ifndef __CI_CIUL_SYSDEP_LINUX_H__
#define __CI_CIUL_SYSDEP_LINUX_H__

#include <asm/io.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/nodemask.h>


typedef dma_addr_t ef_vi_dma_addr_t;


#define EF_VI_HF __attribute__((visibility("hidden")))
#define EF_VI_HV __attribute__((visibility("hidden")))


#if defined(__i386__) || defined(__x86_64__)
# define wmb_wc()  __asm__ __volatile__("sfence": : :"memory")
#elif defined(__aarch64__)
# define wmb_wc()  __asm__ __volatile__ ("dsb oshst" : : : "memory")
#elif defined(__PPC__)
# define wmb_wc()  __asm__ __volatile__("sync" : : :"memory")
#else
# error Unknown processor architecture
#endif


#ifndef __printf
# define __printf(fmt, arg)  __attribute__((format(printf, fmt, arg)))
#endif


/* We don't worry much about optimising these in kernel. */
#define unordered_writel(data, addr)  __raw_writel(cpu_to_le32(data), (addr))
#define noswap_writel(data, addr)     writel(le32_to_cpu(data), (addr))


static inline int sys_is_numa(void)
{
  return num_online_nodes() > 1;
}


#ifndef mmiowb
/* Kernels from 5.2 onwards no longer have mmiowb(), because it is now
 * implied by spin_unlock() on architectures that require it.
 *
 * NB Sasha
 * I am a bit afraid of this, because it looks that we use mmiowb() without
 * spin_unlock().  I guess it was already wrong before linux changed its
 * internal API.
 * See also EFX_HAVE_MMIOWB
 */
#define mmiowb()
#endif

#endif  /* __CI_CIUL_SYSDEP_LINUX_H__ */
