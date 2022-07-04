/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */

#ifndef CI_DRIVER_CI_EFCT_H
#define CI_DRIVER_CI_EFCT_H

#include <ci/driver/ci_aux.h>

#if CI_HAVE_AUX_BUS
#ifdef EFRM_HAS_XLNX_EFCT_H
  #include <linux/net/xilinx/xlnx_efct.h>
  #define CI_HAVE_EFCT_AUX 1
#elif CI_HAVE_X3_NET
  #include CI_XLNX_EFCT_HEADER
  #define CI_HAVE_EFCT_AUX 1
#else
  #define CI_HAVE_EFCT_AUX 0
#endif
#else
  #define CI_HAVE_EFCT_AUX 0
#endif

#endif /* CI_DRIVER_CI_EFCT_H */

