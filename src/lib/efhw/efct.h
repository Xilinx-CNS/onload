/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#ifndef LIB_EFHW_EFCT_H
#define LIB_EFHW_EFCT_H

struct xlnx_efct_client;
static inline struct xlnx_efct_client*
efhw_nic_acquire_efct_device(struct efhw_nic* nic)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EFCT);
  return efhw_nic_acquire_drv_device(nic);
}

static inline void
efhw_nic_release_efct_device(struct efhw_nic* nic,
                             struct xlnx_efct_client* cli)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EFCT);
  efhw_nic_release_drv_device(nic, cli);
}

#define EFCT_PRE(dev, efct_dev, efct_cli, nic, rc) \
{ \
  (dev) = efhw_nic_get_dev(nic); \
  (efct_dev) = to_xlnx_efct_device(to_auxiliary_dev(dev)); \
  (efct_cli) = efhw_nic_acquire_efct_device((nic));\
  EFHW_ASSERT(!in_atomic()); \
  \
  if (!dev) { \
    rc = -ENODEV; \
  } \
  else if ((efct_cli) == NULL) { \
    /* This means the NIC has been removed. We don't have hotplug support
     * for efct, so need to report the error. */ \
    rc = -ENETDOWN; \
  } \
  else { \
    /* Driverlink handle is valid and we're not resetting, so issue
     * the call. */ \

#define EFCT_POST(dev, efct_dev, efct_cli, nic, rc) \
  \
    /* If we see ENETDOWN here, we must be in the window between
     * hardware being removed and being informed about this fact by
     * the kernel. */ \
    if ((rc) == -ENETDOWN) \
      ci_atomic32_or(&(nic)->resetting, NIC_RESETTING_FLAG_VANISHED); \
  } \
  \
  /* This is safe even if [efct_cli] is NULL. */ \
  efhw_nic_release_efct_device((nic), (efct_cli)); \
  put_device((dev)); \
}

void efct_provide_bind_memfd(struct file* memfd, off_t memfd_off);
void efct_unprovide_bind_memfd(off_t *final_off);

#endif

