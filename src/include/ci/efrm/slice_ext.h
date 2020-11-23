/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#ifndef __CI_EFRM_SLICE_EXT_H__
#define __CI_EFRM_SLICE_EXT_H__

struct efrm_resource;
struct efrm_resource_manager;
struct efrm_pd;
struct efrm_ext;

int efrm_create_ext_resource_manager(struct efrm_resource_manager **rm_out);

extern struct efrm_resource* efrm_ext_to_resource(struct efrm_ext *ext);
extern struct efrm_ext* efrm_ext_from_resource(struct efrm_resource *rs);

extern int efrm_ext_alloc_rs(struct efrm_pd* pd, const unsigned char* ext_guid,
                             struct efrm_ext **ext_out);

extern void efrm_ext_release(struct efrm_ext *ext);

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

extern int efrm_ext_get_meta_global(struct efrm_ext *ext,
                                    struct efrm_ext_svc_meta *out);

struct efrm_ext_msg_meta {
    uint32_t id;
    uint32_t ix;
    char name[32];
    uint32_t mcdi_param_size;
};

extern int efrm_ext_get_meta_msg(struct efrm_ext *ext, uint32_t msg_id,
                                 struct efrm_ext_msg_meta *out);

extern int efrm_ext_msg(struct efrm_ext *ext, uint32_t msg_id, void *buf,
                        size_t len);

#endif
