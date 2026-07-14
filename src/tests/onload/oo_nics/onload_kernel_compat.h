/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef __OO_NICS_TEST_ONLOAD_KERNEL_COMPAT_H__
#define __OO_NICS_TEST_ONLOAD_KERNEL_COMPAT_H__

#include <ci/kcompat.h>
#include <stdlib.h>
#include <string.h>

/* Kernel memory allocation stubs */
#define GFP_KERNEL 0

static inline char* kstrdup(const char* s, int gfp)
{
  (void)gfp;
  return strdup(s);
}

/* ci/kcompat.h already provides kfree */

/* Kernel network locking */
static inline void rtnl_lock(void) {}
static inline void rtnl_unlock(void) {}

/* Kernel net_device lookup */
struct net;

struct net_device {
  int ifindex;
  char name[16];
};

/* EFRM_DEV_GET_BY_NAME_TAKES_NS is expected in our test environment */
#define EFRM_DEV_GET_BY_NAME_TAKES_NS

extern struct net_device* dev_get_by_name(struct net* ns, const char* name);
static inline void dev_put(struct net_device* dev) { (void)dev; }


#endif /* __OO_NICS_TEST_ONLOAD_KERNEL_COMPAT_H__ */
