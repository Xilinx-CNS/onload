/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#ifndef EFHW_TPH_H
#define EFHW_TPH_H

#include <ci/efhw/efhw_types.h>
#include "mcdi_common.h"

#define DEBUG_TLP 0

struct tlp_state {
  unsigned relaxed;
  unsigned inorder;
  unsigned snoop;
  unsigned tph;
  unsigned data;
  uint8_t tag1;
  uint8_t tag2;
};

void
efhw_populate_get_vi_tlp_processing_mcdi_cmd(ci_dword_t *buf,
                                             unsigned instance);

void
efhw_extract_get_vi_tlp_processing_mcdi_cmd_result(ci_dword_t *buf,
                                                   struct tlp_state *tlp);

void
efhw_populate_set_vi_tlp_processing_mcdi_cmd(ci_dword_t *buf,
                                             uint instance,
                                             struct tlp_state *tlp);

int
efhw_set_tph_steering(struct efhw_nic *nic, uint instance, int set,
                      int tag_mode);

#endif /* EFHW_TPH_H */
