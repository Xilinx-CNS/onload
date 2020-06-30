/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#ifndef __CI_EFRM_SLICE_EXT_H__
#define __CI_EFRM_SLICE_EXT_H__

struct efrm_resource;
struct efrm_resource_manager;

int efrm_create_ext_resource_manager(struct efrm_resource_manager **rm_out);

extern int efrm_ext_alloc(struct efrm_resource *rs,
                          const unsigned char* ext_guid,
                          uint32_t* out_mc_handle);

extern int efrm_ext_alloc_rs(struct efrm_resource *pd_rs,
                             struct efrm_resource *ext_rs,
                            const unsigned char* ext_guid);

extern int efrm_ext_free(struct efrm_resource *rs, uint32_t mc_handle);

extern void efrm_ext_release(struct efrm_resource *rs);

struct efrm_ext_svc_meta {
    uint8_t uuid[16];
    uint16_t minor_ver;
    uint16_t patch_ver;
    uint32_t nmsgs;
    uint16_t mapped_csr_offset;
    uint16_t mapped_csr_size;
    uint8_t mapped_csr_flags;
    uint8_t admin_group;
};

extern int efrm_ext_get_meta_global(struct efrm_resource *rs,
                                    uint32_t mc_handle,
                                    struct efrm_ext_svc_meta *out);

struct efrm_ext_msg_meta {
    uint32_t id;
    uint32_t ix;
    char name[32];
    uint32_t mcdi_param_size;
};

extern int efrm_ext_get_meta_msg(struct efrm_resource *rs,
                                 uint32_t mc_handle, uint32_t msg_id,
                                 struct efrm_ext_msg_meta *out);

extern int efrm_ext_msg(struct efrm_resource *rs, uint32_t mc_handle,
                        uint32_t msg_id, void *buf, size_t len);

extern int efrm_ext_destroy_rsrc(struct efrm_resource *rs, uint32_t mc_handle,
                                 uint32_t clas, uint32_t id);

#endif
