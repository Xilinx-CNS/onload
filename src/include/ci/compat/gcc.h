/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*! \cidoxg_include_ci_compat  */

#ifndef __CI_COMPAT_GCC_H__
#define __CI_COMPAT_GCC_H__


#define CI_HAVE_INT64


#ifdef __KERNEL__

# include <linux/types.h>

typedef __u64                 ci_uint64;
typedef __s64                 ci_int64;
# if BITS_PER_LONG == 32
typedef __s32                 ci_ptr_arith_t;
typedef __u32                 ci_uintptr_t;
# else
typedef __s64                 ci_ptr_arith_t;
typedef __u64                 ci_uintptr_t;
# endif


# define CI_PRId64            "lld"
# define CI_PRIi64            "lli"
# define CI_PRIo64            "llo"
# define CI_PRIu64            "llu"
# define CI_PRIx64            "llx"
# define CI_PRIX64            "llX"

# define CI_PRId32            "d"
# define CI_PRIi32            "i"
# define CI_PRIo32            "o"
# define CI_PRIu32            "u"
# define CI_PRIx32            "x"
# define CI_PRIX32            "X"

#else

# include <stdint.h>
# ifndef __STDC_FORMAT_MACROS
#  define __STDC_FORMAT_MACROS
# endif
# include <inttypes.h>

typedef uint64_t              ci_uint64;
typedef int64_t               ci_int64;
typedef intptr_t              ci_ptr_arith_t;
typedef uintptr_t             ci_uintptr_t;

# define CI_PRId64            PRId64
# define CI_PRIi64            PRIi64
# define CI_PRIo64            PRIo64
# define CI_PRIu64            PRIu64
# define CI_PRIx64            PRIx64
# define CI_PRIX64            PRIX64

# define CI_PRId32            PRId32
# define CI_PRIi32            PRIi32
# define CI_PRIo32            PRIo32
# define CI_PRIu32            PRIu32
# define CI_PRIx32            PRIx32
# define CI_PRIX32            PRIX32

#endif


typedef ci_uint64                       ci_fixed_descriptor_t;

#define from_fixed_descriptor(desc) ((ci_uintptr_t)(desc))
#define to_fixed_descriptor(desc) ((ci_fixed_descriptor_t)(ci_uintptr_t)(desc))


#if !defined(__cplusplus)
/*
** Checks that [p_mbr] has the same type as [&c_type::mbr_name].
*/
# define CI_CONTAINER(c_type, mbr_name, p_mbr)				\
   __builtin_choose_expr(						\
     __builtin_types_compatible_p(__typeof__(&((c_type*)0)->mbr_name),	\
				 __typeof__(p_mbr)),			\
     __CI_CONTAINER(c_type, mbr_name, p_mbr), (void)0)

# define ci_restrict  __restrict__
#endif


#define CI_LIKELY(t)    __builtin_expect(!!(t), 1)
#define CI_UNLIKELY(t)  __builtin_expect((t), 0)


#define OO_ACCESS_ONCE(p) (*(volatile __typeof__(p) *)&(p))
#define CI_WRITE_ONCE(x, v) (OO_ACCESS_ONCE((x)) = (v))
#define CI_READ_ONCE(x) OO_ACCESS_ONCE((x))


#define ci_unreachable  __builtin_unreachable


/**********************************************************************
 * Attributes
 */
#if defined(NDEBUG)
# define CI_HF __attribute__((visibility("hidden")))
# define CI_HV __attribute__((visibility("hidden")))
# define CI_DV __attribute__((visibility("default")))
# define CI_USE_GCC_VISIBILITY
#else
# define CI_HF
# define CI_HV
# define CI_DV
#endif

/* (Linux 2.6 defines its own "noinline", so we use the "__noinline__" form) */
# define ci_noinline  static __attribute__((__noinline__))

#define CI_ALIGN(x) __attribute__ ((aligned (x)))

#define CI_PRINTF_LIKE(a,b) __attribute__((format(printf,a,b)))
#define CI_UNUSED __attribute__((__unused__))

/* gcc <5 does not have __has_attribute macro.  It also does not have any
 * attribute we'd like to check for, including __fallthrough__. */
#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#if __has_attribute(__fallthrough__)
#define ci_fallthrough __attribute__((__fallthrough__))
#else
#define ci_fallthrough do{}while(0) /*fallthrough*/
#endif

# define ci_bswapc16  __builtin_bswap16
# define ci_bswap16   ci_bswapc16

/* Explicit cast is necessary on older versions of gcc to satisfy printf
 * argument checking warning */
#define ci_bswap32(v)  ((unsigned)__builtin_bswap32(v))
#define ci_bswap64  __builtin_bswap64

/* Compiler barrier: prevent compiler from reordering.  (Does nothing to
 * prevent the processor or platform from reordering).
 */
#define ci_compiler_barrier()    __asm__ __volatile__ ("": : :"memory")


#endif  /* __CI_COMPAT_GCC_H__ */
/*! \cidoxg_end */
