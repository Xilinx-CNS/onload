/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */

#ifndef EFHW_EF10_EF100_H
#define EFHW_EF10_EF100_H

/* We base owner ids from 1 within Onload so that we can use owner id 0 as
 * as easy check whether a pd is using physical addressing mode.  However, we
 * don't want to use up part of our actual owner id space, which is 0 based,
 * so subtract back to 0 based when talking to the firmware.
 */
#define REAL_OWNER_ID(owner_id) ((owner_id) ? ((owner_id) - 1) : 0)

struct ef10_ef100_alloc_vi_constraints {
	struct efhw_nic *nic;
	struct efhw_vi_constraints *evc;
};

struct tlp_state {
  unsigned relaxed;
  unsigned inorder;
  unsigned snoop;
  unsigned tph;
  unsigned data;
  uint8_t tag1;
  uint8_t tag2;
};

static inline struct efx_auxdev_client*
efhw_nic_acquire_auxdev(struct efhw_nic* nic)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF10);
  return efhw_nic_acquire_drv_device(nic);
}

static inline void
efhw_nic_release_auxdev(struct efhw_nic* nic, struct efx_auxdev_client* cli)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF10);
  efhw_nic_release_drv_device(nic, cli);
}

#define EF10_EF100_RSS_INDIRECTION_TABLE_LEN 128
#define EF10_EF100_RSS_KEY_LEN 40

#endif /* EFHW_EF10_EF100_H */
