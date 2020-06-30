/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __CI_EFRM_SLICE_EXT_H__
#define __CI_EFRM_SLICE_EXT_H__

struct efrm_resource;

extern int efrm_ext_alloc(struct efrm_resource *rs,
                          const unsigned char* service_guid,
                          uint32_t* out_mc_handle);

extern int efrm_ext_free(struct efrm_resource *rs, uint32_t mc_handle);

struct efrm_ext_svc_meta {
    uint8_t uuid[16];
    uint16_t minor_ver;
    uint16_t patch_ver;
    uint32_t nmsgs;
    uint32_t nrsrc_classes;
};

extern int efrm_ext_get_meta_global(struct efrm_resource *rs,
                                    uint32_t mc_handle,
                                    struct efrm_ext_svc_meta *out);

struct efrm_ext_rc_meta {
    uint32_t max;
    uint32_t kern_extra;
};

extern int efrm_ext_get_meta_rc(struct efrm_resource *rs,
                                uint32_t mc_handle, uint32_t clas,
                                struct efrm_ext_rc_meta *out);

struct efrm_ext_msg_meta {
    uint32_t id;
    uint32_t ix;
    char name[32];
    uint32_t ef_vi_param_size;
    uint32_t mcdi_param_size;
    uint32_t ninsns;
};

extern int efrm_ext_get_meta_msg(struct efrm_resource *rs,
                                 uint32_t mc_handle, uint32_t msg_id,
                                 struct efrm_ext_msg_meta *out);

extern int efrm_ext_get_meta_msg_prog(struct efrm_resource *rs,
                                      uint32_t mc_handle, uint32_t msg_id,
                                      void* prog, size_t prog_bytes);

extern int efrm_ext_msg(struct efrm_resource *rs, uint32_t mc_handle,
                        uint32_t msg_id, void *buf, size_t len);

extern int efrm_ext_destroy_rsrc(struct efrm_resource *rs, uint32_t mc_handle,
                                 uint32_t clas, uint32_t id);

#endif
