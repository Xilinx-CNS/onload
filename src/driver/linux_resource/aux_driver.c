/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */

#include "linux_resource_internal.h"
#include <ci/driver/ci_efct.h>
#include <ci/driver/ci_ef10ct.h>

int efrm_auxbus_register(void)
{
  int rc = 0;

#if CI_HAVE_SFC
  rc = auxiliary_driver_register(&ef10_drv);
  if( rc < 0 ) {
    EFRM_ERR("WARNING: Failed to register ef10 driver with auxbus, rc %d", rc);
    goto fail_sfc;
  }
#endif

#if CI_HAVE_EFCT_AUX
  rc = auxiliary_driver_register(&efct_drv);
  if( rc < 0 ) {
    EFRM_ERR("WARNING: Failed to register efct driver with auxbus, rc %d", rc);
    goto fail_efct;
  }
#endif

#if CI_HAVE_EF10CT
  rc = auxiliary_driver_register(&ef10ct_drv);
  if( rc < 0 ) {
    EFRM_ERR("WARNING: Failed to register ef10ct driver with auxbus, rc %d", rc);
    goto fail_ef10ct;
  }
#endif

  goto out;

#if CI_HAVE_EF10CT
 fail_ef10ct:
 #if CI_HAVE_EFCT_AUX
  auxiliary_driver_unregister(&efct_drv);
 #endif
#endif
#if CI_HAVE_EFCT_AUX
 fail_efct:
 #if CI_HAVE_SFC
  auxiliary_driver_unregister(&ef10_drv);
 #endif
#endif
#if CI_HAVE_SFC
 fail_sfc:
#endif
 out:
  return rc;
}

void efrm_auxbus_unregister(void)
{
#if CI_HAVE_SFC
  auxiliary_driver_unregister(&ef10_drv);
#endif

#if CI_HAVE_EFCT_AUX
  auxiliary_driver_unregister(&efct_drv);
#endif

#if CI_HAVE_EF10CT
  auxiliary_driver_unregister(&ef10ct_drv);
#endif
}

