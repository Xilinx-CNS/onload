/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc. */

#ifndef CI_DRIVER_CI_EF10_H
#define CI_DRIVER_CI_EF10_H

#include <ci/driver/ci_aux.h>

#if CI_HAVE_SFC
#include <../driver/linux_net/include/linux/sfc/efx_auxbus.h>
#include <../driver/linux_net/drivers/net/ethernet/sfc/filter.h>
#endif

struct efhw_buddy_allocator;
struct efx_auxdev_dl_vi_resources;
struct ef10_aux_arch_extra {
  struct efhw_buddy_allocator *vi_allocator;
  struct efx_auxdev_dl_vi_resources *dl_res;
};

#endif /* CI_DRIVER_CI_EF10_H */

