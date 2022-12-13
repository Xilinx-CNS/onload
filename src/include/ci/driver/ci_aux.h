/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef CI_DRIVER_CI_AUX_H
#define CI_DRIVER_CI_AUX_H
#include <driver/linux_resource/autocompat.h>

/* There are three options here, native kernel aux bus support, support
 * through the out of tree cns aux bus repo for older kernels, or no aux bus
 * support at all, in that order of preference.
 *
 * If we have an aux bus available we use the appropriate header and indicate
 * aux bus availability through CI_HAVE_AUX_BUS.
 */
#if defined (EFRM_HAS_AUXBUS_H) || CI_HAVE_CNS_AUX
  #include <linux/auxiliary_bus.h>
  #define CI_HAVE_AUX_BUS 1
#else
  #define CI_HAVE_AUX_BUS 0
#endif

#endif /* CI_DRIVER_CI_AUX_H */

