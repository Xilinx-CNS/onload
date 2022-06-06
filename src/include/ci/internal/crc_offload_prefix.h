/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright Xilinx, Inc. */
#ifndef __CI_INTERNAL_CRC_OFFLOAD_PREFIX_H__
#define __CI_INTERNAL_CRC_OFFLOAD_PREFIX_H__

/*
 * NOTE: This struct defines the API that we use to send TCP offload
 * metadata to the hardware for processing. Any changes here must be
 * matched by corresponding changes in the plugin or hardware.
 */

/* TODO: the layout of this struct is provisional. It will need
 * updating based on the outcome of VIRTBLK-1759. */
#define CI_TCP_OFFLOAD_ZC_SEND_PREFIX_TYPE_ACCUM 1
#define CI_TCP_OFFLOAD_ZC_SEND_PREFIX_TYPE_INSERT 2
struct ci_tcp_offload_zc_send_prefix {
  uint32_t type : 8;
  uint32_t plugin_context_id : 24;
  uint16_t data_offset;
  union {
    struct {
      uint16_t data_len;
    } accum_crc;
    struct {
      uint8_t first_byte;
      uint8_t n_bytes;
    } insert_crc;
  };
};


#endif  /* __CI_INTERNAL_CRC_OFFLOAD_PREFIX_H__ */
