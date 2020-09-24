/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

#ifndef __CI_EFHW_EF100_H__
#define __CI_EFHW_EF100_H__

struct efhw_nic;

extern struct efhw_func_ops ef100_char_functional_units;

/* Size of RX user buffer for EF100 */
#define EF100_RX_USR_BUF_SIZE 2048 - 256

/* Slice plugins are so EF100-specific that there's no point in using the
 * abstraction layer for these functions. */

extern int ef100_nic_ext_alloc(struct efhw_nic* nic,
                               const unsigned char* service_guid,
                               bool flag_info_only,
                               uint32_t* out_mc_handle);

extern int ef100_nic_ext_free(struct efhw_nic* nic, uint32_t mc_handle);

extern int ef100_nic_ext_get_meta_global(struct efhw_nic* nic,
                                         uint32_t mc_handle,
                                         uint8_t* uuid, uint16_t* minor_ver,
                                         uint16_t* patch_ver, uint32_t* nmsgs,
                                         uint16_t* mapped_csr_offset,
                                         uint16_t* mapped_csr_size,
                                         uint8_t* mapped_csr_flags,
                                         uint8_t* admin_group);

extern int ef100_nic_ext_get_meta_msg(struct efhw_nic* nic, uint32_t mc_handle,
                                      uint32_t msg_id, uint32_t* index,
                                      char* name, size_t name_len,
                                      uint32_t* mcdi_param_size);

extern int ef100_nic_ext_msg(struct efhw_nic* nic, uint32_t mc_handle,
                             uint32_t msg_id, void* payload, size_t len);

extern int ef100_nic_ext_destroy_rsrc(struct efhw_nic* nic, uint32_t mc_handle,
                                      uint32_t clas, uint32_t id);

#endif /* __CI_EFHW_EF100_H__ */
