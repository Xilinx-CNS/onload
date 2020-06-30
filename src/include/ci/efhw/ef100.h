#ifndef __CI_EFHW_EF100_H__
#define __CI_EFHW_EF100_H__

extern struct efhw_func_ops ef100_char_functional_units;

/* Slice plugins are so EF100-specific that there's no point in using the
 * abstraction layer for these functions. */

extern int ef100_nic_ext_alloc(struct efhw_nic* nic,
                               const unsigned char* service_guid,
                               uint32_t* out_mc_handle);

extern int ef100_nic_ext_free(struct efhw_nic* nic, uint32_t mc_handle);

extern int ef100_nic_ext_get_meta_global(struct efhw_nic* nic,
                                         uint32_t mc_handle,
                                         uint8_t* uuid, uint16_t* minor_ver,
                                         uint16_t* patch_ver, uint32_t* nmsgs,
                                         uint32_t* nrsrc_classes);

extern int ef100_nic_ext_get_meta_rc(struct efhw_nic* nic, uint32_t mc_handle,
                                     uint32_t clas,
                                     uint32_t* max, uint32_t* kern_extra);

extern int ef100_nic_ext_get_meta_msg(struct efhw_nic* nic, uint32_t mc_handle,
                                      uint32_t msg_id, uint32_t* index,
                                      char* name, size_t name_len,
                                      uint32_t* ef_vi_param_size,
                                      uint32_t* mcdi_param_size,
                                      uint32_t* ninsns);

extern int ef100_nic_ext_get_meta_msg_prog(struct efhw_nic* nic,
                                           uint32_t mc_handle, uint32_t msg_id,
                                           void* prog, size_t prog_bytes);

extern int ef100_nic_ext_msg(struct efhw_nic* nic, uint32_t mc_handle,
                             uint32_t msg_id, void* payload, size_t len);

extern int ef100_nic_ext_destroy_rsrc(struct efhw_nic* nic, uint32_t mc_handle,
                                      uint32_t clas, uint32_t id);

#endif /* __CI_EFHW_EF100_H__ */
