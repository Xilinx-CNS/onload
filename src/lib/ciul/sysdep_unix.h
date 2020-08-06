/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  stg
**  \brief  System dependent support for ef vi lib
**   \date  2007/05/10
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __CI_CIUL_SYSDEP_UNIX_H__
#define __CI_CIUL_SYSDEP_UNIX_H__

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <endian.h>
#include <byteswap.h>


/**********************************************************************
 * Processor/architecture
 */

#if defined(__i386__) || defined(__x86_64__)
# define PAGE_SHIFT            12u
# define PAGE_SIZE             (1lu << PAGE_SHIFT)
#elif defined(__PPC__)
# define PAGE_SHIFT            16u
# define PAGE_SIZE             (1lu << PAGE_SHIFT)
#elif defined(__aarch64__)
#define PAGE_SIZE              (AARCH64_PAGE_SIZE)
/* There is no simple way to do ffs at compile time,
 * and sysconf returns PAGE_SIZE, not page shift, so just
 * check the sizes that are known to be supported on Linux/arm64
 */
#if PAGE_SIZE == (4 * 1024)
#define PAGE_SHIFT             12u
#elif PAGE_SIZE == (16 * 1024)
#define PAGE_SHIFT             14u
#elif PAGE_SIZE == (64 * 1024)
#define PAGE_SHIFT             16u
#else
#error "Unsupported PAGE_SIZE"
#endif

#endif


typedef uint64_t ef_vi_dma_addr_t;


/**********************************************************************
 * Compiler/processor dependencies.
 *
 * The following describes how we are using these primitives:
 *
 * wmb: Ensure ordering between writes to device, or write to memory and
 *      write to device.
 *
 * wmb_wc: Ensure WC write completes before uncached write to device.
 *
 * mmiowb: Ensure write to device is flushed out promptly.
 */

#define __printf(fmt, arg)  __attribute__((format(printf, fmt, arg)))

#if defined(__GNUC__)

#  define likely(t)    __builtin_expect((t), 1)
#  define unlikely(t)  __builtin_expect((t), 0)

#  define EF_VI_HF __attribute__((visibility("hidden")))
#  define EF_VI_HV __attribute__((visibility("hidden")))

# if defined(__i386__) || defined(__x86_64__)  /* GCC x86/x64 */
#  define wmb()       __asm__ __volatile__("": : :"memory")
#  define wmb_wc()    __builtin_ia32_sfence()
#  define mmiowb()    do{}while(0)
#  define dma_wmb()   __asm__ __volatile__("": : :"memory")
#  define smp_rmb()   __asm__ __volatile__("lfence": : :"memory")

# elif defined(__PPC__)
#  define wmb()       __asm__ __volatile__("sync" : : :"memory")
#  define wmb_wc()    __asm__ __volatile__("sync" : : :"memory")
#  define mmiowb()    __asm__ __volatile__("sync" : : :"memory")
#  define dma_wmb()   __asm__ __volatile__("sync" : : :"memory")
#  define smp_rmb()   __asm__ __volatile__("lwsync": : :"memory")

# elif defined(__aarch64__)
#  define wmb()      __asm__ __volatile__ ("dsb st" : : : "memory")
#  define wmb_wc()   __asm__ __volatile__ ("dsb oshst" : : : "memory")
#  define mmiowb()    do{}while(0)
#  define dma_wmb()   __asm__ __volatile__ ("dsb oshst" : : : "memory")
#  define smp_rmb()  __asm__ __volatile__ ("dmb ishld" : : : "memory")


# else
#  error Unknown processor architecture
# endif

#else
# error Unknown compiler.
#endif


/*
 * Defaults for anything left undefined.
 */
#ifndef  EF_VI_HF
# define  EF_VI_HF
# define  EF_VI_HV
#endif

#ifndef likely
# define likely(t)    (t)
# define unlikely(t)  (t)
#endif

#if EF_VI_LITTLE_ENDIAN
# define cpu_to_le16(v)   (v)
# define le16_to_cpu(v)   (v)
# define cpu_to_le32(v)   (v)
# define le32_to_cpu(v)   (v)
# define cpu_to_le64(v)   (v)
# define le64_to_cpu(v)   (v)
#else
# define cpu_to_le16(v)   bswap_16(v)
# define le16_to_cpu(v)   bswap_16(v)
# define cpu_to_le32(v)   bswap_32(v)
# define le32_to_cpu(v)   bswap_32(v)
# define cpu_to_le64(v)   bswap_64(v)
# define le64_to_cpu(v)   bswap_64(v)
#endif


/* __raw_writel: No byte-swap and no ordering. */
ef_vi_inline void __raw_writel(uint32_t data, volatile void *addr)
{
  *((volatile uint32_t *) addr) = data;
}


#if defined(__PPC__)

ef_vi_inline void noswap_writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("sync; stwx %1,0,%2"
                       : "=m" (*(uint32_t*)addr)
                       : "r" (data), "r" (addr)
                       : "memory");
}

# if EF_VI_LITTLE_ENDIAN
ef_vi_inline void unordered_writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("stwx %1,0,%2"
                       : "=m" (*(uint32_t*)addr)
                       : "r" (data), "r" (addr));
}
# define writel  noswap_writel
# else
ef_vi_inline void unordered_writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("stwbrx %1,0,%2"
                       : "=m" (*(uint32_t*)addr)
                       : "r" (data), "r" (addr));
}
ef_vi_inline void writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("sync; stwbrx %1,0,%2"
                       : "=m" (*(uint32_t*)addr)
                       : "r" (data), "r" (addr)
                       : "memory");
}
# endif

#elif defined(__x86_64__) || defined(__i386__)

ef_vi_inline void unordered_writel(uint32_t data, volatile void *addr)
{
  __raw_writel(cpu_to_le32(data), addr);
}
ef_vi_inline void writel(uint32_t data, volatile void *addr)
{
  __asm__ __volatile__("movl %0,%1"
                       :
                       : "r" (data), "m" (*(volatile uint32_t*)addr)
                       : "memory");
}
#define noswap_writel  writel

#elif defined(__aarch64__)

#define writel(data, addr)  do{dma_wmb(); __raw_writel(cpu_to_le32(data), addr);}while(0)
#define unordered_writel(data, addr)  __raw_writel(cpu_to_le32(data), (addr))
#define noswap_writel(data, addr)     writel(le32_to_cpu(data), (addr))

#else

# error "Need to define writel, unordered_writel and noswap_writel"

#endif


#define BUG_ON(exp)  assert(!(exp))


#include <sys/stat.h>

static inline int sys_is_numa_(void)
{
  struct stat s;
  return stat("/sys/devices/system/node/node1", &s) == 0;
}


static inline int sys_is_numa(void)
{
  static int result;
  if( ! result )
    result = sys_is_numa_() + 1;
  return result - 1;
}


#endif  /* __CI_CIUL_SYSDEP_UNIX_H__ */
