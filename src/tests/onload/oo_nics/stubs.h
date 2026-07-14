/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#ifndef __OO_NICS_TEST_STUBS_H__
#define __OO_NICS_TEST_STUBS_H__

#include "oo_nics_deps.h"

/* efrm_client stub — maps client to mock efhw_nic */
struct efrm_client {
  struct efhw_nic* nic;
};

/* Test setup functions */
extern void test_set_cplane_hwports(cicp_hwport_mask_t mask);
extern void test_add_interface(const char* name, int ifindex,
                               cicp_hwport_mask_t rx_hwports);
extern void test_add_hwport(int hwport, int is_llct,
                            struct net_device* net_dev);
extern void test_cleanup(void);

#endif /* __OO_NICS_TEST_STUBS_H__ */
