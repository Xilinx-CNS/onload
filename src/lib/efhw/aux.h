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

#define AUX_PRE_CHECK(dev, auxdev, auxcli, nic, rc, check_reset) \
{ \
  (dev) = efhw_nic_get_dev(nic); \
  (auxdev) = to_efx_auxdev(to_auxiliary_dev(dev)); \
  (auxcli) = efhw_nic_acquire_auxdev((nic));\
  EFHW_ASSERT(!in_atomic()); \
  \
  if (!dev) { \
    rc = -ENETDOWN; \
  } \
  else if ((check_reset && (nic)->resetting) || (auxcli) == NULL) { \
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

#define AUX_PRE_ALLOW_RESET(dev, auxdev, auxcli, nic, rc) \
        AUX_PRE_CHECK(dev, auxdev, auxcli, nic, rc, false)
#define AUX_PRE(dev, auxdev, auxcli, nic, rc) \
        AUX_PRE_CHECK(dev, auxdev, auxcli, nic, rc, true)

static inline int
efhw_check_aux_abi_version(const struct efx_auxdev *edev,
                           const struct auxiliary_device_id *id) {
  if ( !efx_aux_abi_version_is_compat(edev->abi_version) ) {
    EFHW_ERR("Auxbus ABI version mismatch. %s requires %u.%u. %s has %u.%u.",
             KBUILD_MODNAME, EFX_AUX_ABI_VERSION_MAJOR_GET(edev->abi_version),
             EFX_AUX_ABI_VERSION_MINOR_GET(edev->abi_version),
             id->name, EFX_AUX_ABI_VERSION_MAJOR,
             EFX_AUX_ABI_VERSION_MINOR);
    return -EPROTO;
  }

  return 0;
}

#endif

