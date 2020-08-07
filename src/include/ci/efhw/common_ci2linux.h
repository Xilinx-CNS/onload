/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */

#ifndef __CI_EFHW_COMMON_CI2LINUX_H__
#define __CI_EFHW_COMMON_CI2LINUX_H__

#include <ci/compat.h>

#if defined(__KERNEL__)
# error ci/efhw/common_ci2linux.h should not be included for Linux modules
#endif
#include <stdbool.h>

#if ! (defined bool) && ! (defined __cplusplus)
#undef false
#undef true
typedef enum {
  false = 0,
  true = 1
} bool;
#endif

#ifndef uint64_t
#define uint64_t ci_uint64
#endif
#ifndef uint32_t
#define uint32_t ci_uint32
#endif
#ifndef uint16_t
#define uint16_t ci_uint16
#endif
#ifndef uint8_t
#define uint8_t  ci_uint8 
#endif

#ifndef int64_t
#define int64_t ci_int64 
#endif
#ifndef int32_t
#define int32_t ci_int32 
#endif
#ifndef int16_t
#define int16_t ci_int16 
#endif
#ifndef int8_t 
#define int8_t  ci_int8 
#endif

#endif /* __CI_EFHW_COMMON_CI2LINUX_H__ */
