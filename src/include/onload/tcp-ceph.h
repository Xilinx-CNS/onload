#ifndef INCLUDED_XSMARTNIC_TCP_CEPH_H_
#define INCLUDED_XSMARTNIC_TCP_CEPH_H_
#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

static const uint8_t XSN_TCP_CEPH_PLUGIN[] = {
  0x5c, 0x6f, 0xf2, 0x1d, 0xf1, 0x28, 0x4e, 0xa0,
  0x9a, 0xe9, 0x4d, 0x7a, 0x60, 0xbc, 0x5c, 0x68};

struct xsn_tcp_create_app {
  uint16_t in_vi_id;
  uint32_t out_app_id;
};

struct xsn_tcp_create_stream {
  uint32_t in_app_id;
  uint32_t in_user_mark;
  uint8_t in_synchronised;
  uint32_t in_seq;
  uint32_t out_conn_id;
};

struct xsn_tcp_sync_stream {
  uint32_t in_conn_id;
  uint32_t in_seq;
};

struct xsn_ceph_create_app {
  struct xsn_tcp_create_app tcp;
  uint16_t in_meta_vi_id;
  uint16_t in_meta_buflen;
  uint64_t out_reg_addr __attribute__((aligned(8)));
};

struct xsn_ceph_create_stream {
  struct xsn_tcp_create_stream tcp;
  uint64_t in_data_buf_capacity __attribute__((aligned(8)));
  uint64_t out_addr_spc_id;
  uint64_t out_data_buf_base;
  uint64_t out_data_buf_capacity;
};

#define XSN_CEPH_CREATE_APP 0
#define XSN_CEPH_CREATE_STREAM 1
#define XSN_CEPH_SYNC_STREAM 2

#define XSN_CEPH_RSRC_CLASS_APP     0
#define XSN_CEPH_RSRC_CLASS_STREAM  1

union ceph_control_pkt {
  uint8_t cmd;
  struct {
    uint8_t cmd;  /* 0 */
    uint8_t unused1[3];
    uint32_t credit;
  } add_credit;
  struct {
    uint8_t cmd;  /* 1 */
    uint8_t unused[3];
    uint32_t stream_id;
    uint64_t buf_head;
  } consume_payload;
};

#define XSN_CEPH_CTRL_ADD_CREDIT       0
#define XSN_CEPH_CTRL_CONSUME_PAYLOAD  1

#endif
