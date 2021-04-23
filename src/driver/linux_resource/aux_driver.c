/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#include "linux_resource_internal.h"
#include <ci/driver/ci_efct.h>

int efrm_auxbus_register(void)
{
#if CI_HAVE_EFCT_AUX
  return auxiliary_driver_register(&efct_drv);
#else
  return 0;
#endif
}

void efrm_auxbus_unregister(void)
{
#if CI_HAVE_EFCT_AUX
  auxiliary_driver_unregister(&efct_drv);
#endif
}

