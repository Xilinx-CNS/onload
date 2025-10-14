/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include "tph.h"

#include <ci/efhw/debug.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/tph.h>

#include <ci/driver/efab/hardware.h>

#include <ci/efhw/mc_driver_pcol.h>
#include "mcdi_common.h"

void
efhw_populate_get_vi_tlp_processing_mcdi_cmd(ci_dword_t *buf,
                                             unsigned instance)
{
  EFHW_MCDI_SET_DWORD(buf, GET_VI_TLP_PROCESSING_IN_INSTANCE, instance);
}

void
efhw_extract_get_vi_tlp_processing_mcdi_cmd_result(ci_dword_t *buf,
                                                   struct tlp_state *tlp)
{
  tlp->data = EFHW_MCDI_DWORD(buf, GET_VI_TLP_PROCESSING_OUT_DATA);

  tlp->tag1 = EFHW_MCDI_BYTE(buf, GET_VI_TLP_PROCESSING_OUT_TPH_TAG1_RX);
  tlp->tag2 = EFHW_MCDI_BYTE(buf, GET_VI_TLP_PROCESSING_OUT_TPH_TAG2_EV);
  tlp->relaxed = tlp->data &
            (1u << MC_CMD_GET_VI_TLP_PROCESSING_OUT_RELAXED_ORDERING_LBN);
  tlp->inorder = tlp->data &
            (1u << MC_CMD_GET_VI_TLP_PROCESSING_OUT_ID_BASED_ORDERING_LBN);
  tlp->snoop = tlp->data &
            (1u << MC_CMD_GET_VI_TLP_PROCESSING_OUT_NO_SNOOP_LBN);
  tlp->tph = tlp->data &
            (1u << MC_CMD_GET_VI_TLP_PROCESSING_OUT_TPH_ON_LBN);
}

void
efhw_populate_set_vi_tlp_processing_mcdi_cmd(ci_dword_t *buf,
                                             uint instance,
                                             struct tlp_state *tlp)
{
  /* The mcdi headers have awkward definitions of these values so do it
   * manually */
  EFHW_MCDI_SET_DWORD(buf, SET_VI_TLP_PROCESSING_IN_INSTANCE, instance);
  tlp->data = (unsigned)tlp->tag1 | ((unsigned)tlp->tag2 << (8));
  if (tlp->relaxed)
    tlp->data |= 1u <<
                (MC_CMD_SET_VI_TLP_PROCESSING_IN_RELAXED_ORDERING_LBN-32);
  if (tlp->inorder)
    tlp->data |= 1u <<
                (MC_CMD_SET_VI_TLP_PROCESSING_IN_ID_BASED_ORDERING_LBN-32);
  if (tlp->snoop)
    tlp->data |= 1u << (MC_CMD_SET_VI_TLP_PROCESSING_IN_NO_SNOOP_LBN-32);
  if (tlp->tph)
    tlp->data |= 1u << (MC_CMD_SET_VI_TLP_PROCESSING_IN_TPH_ON_LBN-32);
  EFHW_MCDI_SET_DWORD(buf, SET_VI_TLP_PROCESSING_IN_DATA, tlp->data);
}

int
efhw_set_tph_steering(struct efhw_nic *nic, uint instance, int set,
                      int tag_mode)
{
#if CI_HAVE_SDCI
  uint16_t tag = 0;
  int rc;

  if( tag_mode != 0 ) {
    struct pci_dev *nic_pci_dev = efhw_nic_get_pci_dev(nic);

    if( nic_pci_dev ) {
      /* TODO verify that raw_smp_processor_id() returns the right value */
      rc = pcie_tph_get_cpu_st(nic_pci_dev, TPH_MEM_TYPE_VM,
                               raw_smp_processor_id(), &tag);
      pci_dev_put(nic_pci_dev);
    } else {
      rc = -ENODEV;
    }

    if( rc != 0 )
      EFHW_WARN_LIMITED("Failed to read steering tag (error %d), continuing without it",
                        rc);
  }

  rc = efhw_nic_set_vi_tlp_processing(nic, instance, set, tag);
  if( rc != 0 )
    EFHW_WARN_LIMITED("Failed to set steering tag (error %d), continuing without it",
                      rc);

  return rc;
#else /* CI_HAVE_SDCI */
  return -EOPNOTSUPP;
#endif /* CI_HAVE_SDCI */
}
