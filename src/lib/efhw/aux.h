/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2024 Advanced Micro Devices, Inc. */

#ifndef LIB_EFHW_AUX_H
#define LIB_EFHW_AUX_H

static inline struct efx_auxdev_client*
efhw_nic_acquire_auxdev(struct efhw_nic* nic)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF10 ||
              nic->devtype.arch == EFHW_ARCH_EF10CT);
  return efhw_nic_acquire_drv_device(nic);
}

static inline void
efhw_nic_release_auxdev(struct efhw_nic* nic, struct efx_auxdev_client* cli)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF10 ||
              nic->devtype.arch == EFHW_ARCH_EF10CT);
  efhw_nic_release_drv_device(nic, cli);
}

#define AUX_PRE(dev, auxdev, auxcli, nic, rc) \
{ \
  (dev) = efhw_nic_get_dev(nic); \
  (auxdev) = to_efx_auxdev(to_auxiliary_dev(dev)); \
  (auxcli) = efhw_nic_acquire_auxdev((nic));\
  EFHW_ASSERT(!in_atomic()); \
  \
  if (!dev) { \
    rc = -ENETDOWN; \
  } \
  else if ((nic)->resetting || (auxcli) == NULL) { \
    /* [nic->resetting] means we have detected that we are in a reset.
     * There is potentially a period after [nic->resetting] is cleared
     * but before the aux client is re-enabled, during which time [auxcli]
     * will be NULL. */ \
    rc = -ENETDOWN; \
  } \
  else { \
    /* Aux client handle is valid and we're not resetting, so issue
     * the call. */ \

#define AUX_POST(dev, auxdev, auxcli, nic, rc) \
  \
    /* If we see ENETDOWN here, we must be in the window between
     * hardware being removed and being informed about this fact by
     * the kernel. */ \
    if ((rc) == -ENETDOWN) \
      ci_atomic32_or(&(nic)->resetting, NIC_RESETTING_FLAG_VANISHED); \
  } \
  \
  /* This is safe even if [auxcli] is NULL. */ \
  efhw_nic_release_auxdev((nic), (auxcli)); \
  put_device((dev)); \
}

#endif

