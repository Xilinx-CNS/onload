/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2010-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Interface between sfc_char driver and userland.
**   \date  2010/09/01
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*
** README!!!!
**
** This header defines a stable interface between userlevel code and the
** sfc_char driver.  DO NOT make any changes that break backwards
** compatibility.
*/

#ifndef __CI_EFCH_OP_TYPES_H__
#define __CI_EFCH_OP_TYPES_H__

#include <ci/efch/resource_id.h>

/* Needed for definition of in6_addr */
#ifdef __KERNEL__
#include <linux/in6.h>
#else
#include <netinet/in.h>
#endif


/* We use an md5sum over certain headers to check that userland and kernel
 * drivers are built against a compatible interface.
 */
enum { EFCH_INTF_VER_LEN = 32 };


struct efch_timeval {
  int32_t tv_sec;
  int32_t tv_usec;
};


/**********************************************************************
 *
 * Allocating resources.
 *
 */

struct efch_vi_alloc_in {
  int32_t             ifindex;            /* only used if no pd or vi_set */
  int32_t             pd_or_vi_set_fd;    /* -1 if not specified */
  efch_resource_id_t  pd_or_vi_set_rs_id;
  int32_t             vi_set_instance;
  int32_t             evq_fd;
  efch_resource_id_t  evq_rs_id;
  int32_t             evq_capacity;
  int32_t             txq_capacity;
  int32_t             rxq_capacity;
  uint32_t            flags;  /* EFAB_VI_* flags */
  uint8_t             tx_q_tag;
  uint8_t             rx_q_tag;
  uint16_t            ps_buf_size_kb;
};


struct efch_vi_alloc_out {
  int32_t             evq_capacity;
  int32_t             txq_capacity;
  int32_t             rxq_capacity;
  uint8_t             nic_arch;
  uint8_t             nic_variant;
  uint8_t             nic_revision;
  uint8_t             nic_flags;
  uint32_t            mem_mmap_bytes;
  uint32_t            io_mmap_bytes;
  int32_t             instance;
  uint32_t            rx_prefix_len;
  uint32_t            out_flags; /* EFAB_VI_* flags */
  uint32_t            ps_buf_size;
  uint32_t            abs_idx;
};


struct efch_vi_set_alloc {
  int32_t             in_ifindex;         /* only used if pd_fd < 0 */
  int32_t             in_n_vis;
  uint32_t            in_flags;
  int32_t             in_pd_fd;           /* -1 if not specified */
  efch_resource_id_t  in_pd_rs_id;
};


struct efch_memreg_alloc {
  int32_t             in_vi_or_pd_fd;
  efch_resource_id_t  in_vi_or_pd_id;
  uint64_t            in_mem_ptr CI_ALIGN(8);
  uint64_t            in_mem_bytes;
  uint64_t            in_addrs_out_ptr;
  uint64_t            in_addrs_out_stride;
};


struct efch_pio_alloc {
  int32_t             in_pd_fd;
  efch_resource_id_t  in_pd_id;
};


#define EFCH_PD_FLAG_VF               0x1
#define EFCH_PD_FLAG_VF_OPTIONAL      0x2
#define EFCH_PD_FLAG_PHYS_ADDR        0x4
#define EFCH_PD_FLAG_RX_PACKED_STREAM 0x8
#define EFCH_PD_FLAG_VPORT            0x10
#define EFCH_PD_FLAG_MCAST_LOOP       0x20
#define EFCH_PD_FLAG_IGNORE_BLACKLIST 0x40
#define EFCH_PD_FLAG_LLCT             0x80


struct efch_pd_alloc {
  int32_t             in_ifindex;
  uint32_t            in_flags;
  int16_t             in_vlan_id;
};


struct efch_ext_alloc {
  efch_resource_id_t  in_pd_rs_id;
  unsigned char       in_ext_id[16];
  uint32_t            in_flags;
};


struct efch_efct_rxq_alloc {
  efch_resource_id_t  in_vi_rs_id;
  uint32_t            in_flags;  /* none currently defined */
  uint32_t            in_abi_version;
  uint8_t             in_qid;
  uint8_t             in_shm_ix;
  /*bool*/uint8_t     in_timestamp_req;
  uint32_t            in_n_hugepages;
  int32_t             in_memfd;
};


typedef struct ci_resource_alloc_s {
  char               intf_ver[EFCH_INTF_VER_LEN];
  uint32_t           ra_type;
  efch_resource_id_t out_id;
  union {
    struct efch_vi_alloc_in    vi_in;
    struct efch_vi_alloc_out   vi_out;
    struct efch_vi_set_alloc   vi_set;
    struct efch_memreg_alloc   memreg;
    struct efch_pd_alloc       pd;
    struct efch_pio_alloc      pio;
    struct efch_ext_alloc      ext;
    struct efch_efct_rxq_alloc rxq;
  } u;
} ci_resource_alloc_t;


/**********************************************************************
 *
 * Resource OPs.
 *
 */

typedef struct ci_resource_op_s {
  efch_resource_id_t    id;
  uint32_t              op;
# define                CI_RSOP_VI_GET_MAC              0x49
# define                CI_RSOP_EVENTQ_PUT              0x51
# define                CI_RSOP_EVENTQ_WAIT             0x54
# define                CI_RSOP_VI_GET_MTU              0x55
# define                CI_RSOP_DUMP                    0x58
# define                CI_RSOP_EVQ_REGISTER_POLL       0x59
# define                CI_RSOP_PT_ENDPOINT_FLUSH       0x5a
# define                CI_RSOP_FILTER_ADD_IP4          0x63
# define                CI_RSOP_FILTER_ADD_MAC          0x64
# define                CI_RSOP_FILTER_ADD_ALL_UNICAST  0x65
# define                CI_RSOP_FILTER_ADD_ALL_MULTICAST 0x66
# define                CI_RSOP_FILTER_DEL              0x67
# define                CI_RSOP_PIO_LINK_VI             0x68
# define                CI_RSOP_PIO_UNLINK_VI           0x69
# define                CI_RSOP_FILTER_ADD_IP4_VLAN     0x70
/* 0x71 and 0x72 removed - do not reuse */
# define                CI_RSOP_FILTER_ADD_MISMATCH_UNICAST        0x73
# define                CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST      0x74
# define                CI_RSOP_FILTER_ADD_MISMATCH_UNICAST_VLAN   0x75
# define                CI_RSOP_FILTER_ADD_MISMATCH_MULTICAST_VLAN 0x76
# define                CI_RSOP_VI_GET_RX_TS_CORRECTION            0x77
# define                CI_RSOP_PT_SNIFF                0x78
/* CI_RSOP_FILTER_BLOCK_KERNEL is legace, kept for backward compatibility */
# define                CI_RSOP_FILTER_BLOCK_KERNEL     0x79
# define                CI_RSOP_FILTER_ADD_BLOCK_KERNEL 0x7A
# define                CI_RSOP_FILTER_ADD_BLOCK_KERNEL_UNICAST   0x7B
# define                CI_RSOP_FILTER_ADD_BLOCK_KERNEL_MULTICAST 0x7C
# define                CI_RSOP_TX_PT_SNIFF             0x7D
# define                CI_RSOP_VI_GET_RX_ERROR_STATS   0x7E
# define                CI_RSOP_FILTER_ADD_MAC_IP_PROTO 0x7F
# define                CI_RSOP_FILTER_ADD_MAC_ETHER_TYPE         0x80
# define                CI_RSOP_FILTER_ADD_IP_PROTO_VLAN          0x81
# define                CI_RSOP_FILTER_ADD_ETHER_TYPE_VLAN        0x82
# define                CI_RSOP_FILTER_ADD_IP_PROTO     0x83
# define                CI_RSOP_FILTER_ADD_ETHER_TYPE   0x84
# define                CI_RSOP_VI_GET_TS_CORRECTION    0x85
# define                CI_RSOP_VI_TX_ALT_ALLOC         0x86
# define                CI_RSOP_VI_TX_ALT_FREE          0x87
# define                CI_RSOP_VI_GET_TS_FORMAT        0x88
# define                CI_RSOP_EXT_FREE                0x89
# define                CI_RSOP_EXT_MSG                 0x8A
# define                CI_RSOP_RXQ_REFRESH             0x8B
# define                CI_RSOP_FILTER_QUERY            0x8C
# define                CI_RSOP_VI_DESIGN_PARAMETERS    0x8D

  union {
    struct {
      uint32_t          current_ptr;
      struct efch_timeval timeout;
      uint32_t          nic_index;
    } evq_wait;
    struct {
      uint64_t          ev;
    } evq_put;
    struct {
      ci_uint16         out_mtu;
    } vi_get_mtu;
    struct {
      uint8_t           out_mac[6];
    } vi_get_mac;
    struct {
      int32_t           pace;
    } pt;
    struct {
      int32_t            in_vi_fd;
      efch_resource_id_t in_vi_id;
    } pio_link_vi;
    struct {
      int32_t            in_vi_fd;
      efch_resource_id_t in_vi_id;
    } pio_unlink_vi;
    struct {
      struct {
        uint8_t         protocol;
        ci_int16        port_be16;
        ci_int16        rport_be16;
        uint32_t        host_be32;
        uint32_t        rhost_be32;
        /* On NICs that require VLAN field as well, we use the field
         * from struct mac below. */
      } ip4;
      struct {
        ci_int16        vlan_id;
        uint8_t         mac[6];
      } mac;
#     define            CI_RSOP_FILTER_ADD_FLAG_REPLACE            1
#     define            CI_RSOP_FILTER_ADD_FLAG_MCAST_LOOP_RECEIVE 2
/* New flags here must match those defined for the new filter interface, and
 * are used as placeholders solely to avoid adding new clashing flags. */
#     define            CI_RSOP_FILTER_ADD_FLAG_EXCLUSIVE_RXQ      4
#     define            CI_RSOP_FILTER_ADD_FLAG_PREF_RXQ           8
#     define            CI_RSOP_FILTER_ADD_FLAG_ANY_RXQ            0x10
      union {
        struct {
          int32_t       flags;
          uint16_t      ether_type_be16;
        } in;
        struct {
          uint32_t      rxq;
          int32_t       filter_id;
        } out;
      } u;
    } filter_add;
    struct {
      int32_t           filter_id;
    } filter_del;
    struct {
      int32_t           filter_id;
      int32_t           out_rxq;
      int32_t           out_hw_id;
      int32_t           out_flags;
    } filter_query;
    struct {
      int32_t           out_rx_ts_correction;
    } vi_rx_ts_correction;
    struct {
      int32_t           out_rx_ts_correction;
      int32_t           out_tx_ts_correction;
    } vi_ts_correction;
    struct {
      uint8_t           enable;
      uint8_t           promiscuous;
    } pt_sniff;
    struct {
      /* MCDI op has 32 bit flags field, of which enable is the bottom one,
       * so make this pass all 32 bits for future compatibility, even if we
       * only ever set enable at the moment.
       */
      uint32_t          enable;
    } tx_pt_sniff;
    struct {
      uint8_t           block;
    } block_kernel;
    struct {
      uint64_t          data_ptr;
      uint32_t          data_len;
      uint8_t           do_reset;
    } vi_stats;
    struct {
      uint32_t          num_alts;
      uint32_t          buf_space_32b;
    } vi_tx_alt_alloc_in;
    struct {
      uint8_t           alt_ids[32];
    } vi_tx_alt_alloc_out;
    struct {
      /* enum ef_timestamp_format */
      uint32_t          out_ts_format;
    } vi_ts_format;
    struct {
      uint32_t          msg_id;
      uint64_t          payload_ptr;
      uint64_t          payload_len;
      uint32_t          flags;
    } ext_msg;
    struct {
      uint64_t          superbufs;
      uint64_t          current_mappings;
      uint32_t          max_superbufs;
    } rxq_refresh;
    struct {
      uint64_t          data_ptr; /* struct efab_nic_design_parameters */
      uint64_t          data_len;
    } design_parameters;
  } u CI_ALIGN(8);
} ci_resource_op_t;


typedef union ci_filter_add_u {
  struct {
    uint16_t            in_len;
    uint16_t            out_size;
    efch_resource_id_t  res_id;
    uint32_t            fields;
#define CI_FILTER_FIELD_REM_MAC        0x0001
#define CI_FILTER_FIELD_REM_HOST       0x0002
#define CI_FILTER_FIELD_REM_PORT       0x0004
#define CI_FILTER_FIELD_LOC_MAC        0x0008
#define CI_FILTER_FIELD_LOC_HOST       0x0010
#define CI_FILTER_FIELD_LOC_PORT       0x0020
#define CI_FILTER_FIELD_ETHER_TYPE     0x0040
#define CI_FILTER_FIELD_OUTER_VID      0x0080
#define CI_FILTER_FIELD_IP_PROTO       0x0100
#define CI_FILTER_FIELD_RXQ            0x0200
    uint32_t            opt_fields;
    uint32_t            flags;
#define CI_FILTER_FLAG_MCAST_LOOP          0x0001
#define CI_FILTER_FLAG_RSS                 0x0002
#define CI_FILTER_FLAG_EXCLUSIVE_RXQ       0x0004
#define CI_FILTER_FLAG_PREF_RXQ            0x0008
#define CI_FILTER_FLAG_ANY_RXQ             0x0010

    struct {
      struct {
        uint8_t  dhost[6];
        uint8_t  shost[6];
        uint16_t type;
        uint16_t vid;
        uint16_t reserved[2];
      } l2;
      struct {
        uint8_t  protocol;
        uint8_t  reserved[3];
        union {
          struct {
            uint32_t saddr;
            uint32_t daddr;
            uint32_t reserved[2];
          } ipv4;
          struct {
            struct in6_addr saddr CI_ALIGN(4);
            struct in6_addr daddr CI_ALIGN(4);
            uint32_t reserved[2];
          } ipv6;
        } u;
      } l3;
      struct {
        union {
          struct {
            uint16_t source;
            uint16_t dest;
          } ports;
          struct {
            uint32_t pad[8];
          } pad;
        };
      } l4;
    } spec;
    union {
      uint32_t            rxq_no;
    };
  } in;
  struct {
    uint16_t  out_len;
    uint8_t   rxq;
    uint64_t  filter_id;
  } out;
} ci_filter_add_t;


/**********************************************************************
 *
 * Priming resources
 *
 */
typedef struct ci_resource_prime_op_s {
  efch_resource_id_t crp_id;
  uint32_t           crp_current_ptr;
} ci_resource_prime_op_t;

typedef struct ci_resource_prime_qs_op_s {
  efch_resource_id_t crp_id;
  uint32_t           n_rxqs;
  uint32_t           n_txqs;
  struct {
    efch_resource_id_t rxq_id;
    uint32_t           sbseq;
    uint32_t           pktix;
  } rxq_current[8];
  uint32_t           txq_current;
} ci_resource_prime_qs_op_t;


/**********************************************************************
 *
 * Checking capabilities
 *
 */

struct efch_capabilities_in {
  uint32_t cap;
  int32_t ifindex;
  int32_t pd_fd;
  efch_resource_id_t pd_id;
};

struct efch_capabilities_out {
  int32_t support_rc;
  uint64_t val CI_ALIGN(8);
};

typedef struct ci_capabilities_op_s {
  union {
    struct efch_capabilities_in cap_in;
    struct efch_capabilities_out cap_out;
  };
} ci_capabilities_op_t;


#define CI_IOC_CHAR_BASE       81

#define CI_RESOURCE_OP      (CI_IOC_CHAR_BASE+ 0)  /* ioctls for resources */
#define CI_RESOURCE_ALLOC   (CI_IOC_CHAR_BASE+ 1)  /* allocate resources   */
#define CI_LICENSE_CHALLENGE (CI_IOC_CHAR_BASE+ 2) /* license challenge   */
#define CI_RESOURCE_PRIME   (CI_IOC_CHAR_BASE+ 3)  /* prime resource */
#define CI_FILTER_ADD       (CI_IOC_CHAR_BASE+ 4)  /* filter insertion */
#define CI_CAPABILITIES_OP  (CI_IOC_CHAR_BASE+ 5)  /* capabilities check */
#define CI_V3_LICENSE_CHALLENGE (CI_IOC_CHAR_BASE+ 6) /* V3 license challenge */
#define CI_IOC_CHAR_MAX     (CI_IOC_CHAR_BASE+ 7)
#define CI_RESOURCE_PRIME_QS (CI_IOC_CHAR_BASE+ 8)  /* prime VI queues (efct) */


/**********************************************************************
 *
 * Memory mappings.
 *
 */

/* mmap offsets must be page aligned, hence the bottom PAGE_SHIFT bits must
** be zero.  To be conservative we should assume 8k pages and 32-bit
** offset.  That leaves is with 19 bits to play with.  We current use 5 for
** the resource id, and 12 for the map_id (total 17).
*/
#define EFAB_MMAP_OFFSET_MAP_ID_BITS  (19u - EFRM_RESOURCE_MAX_PER_FD_BITS)
#define EFAB_MMAP_OFFSET_MAP_ID_MASK  ((1u << EFAB_MMAP_OFFSET_MAP_ID_BITS)-1u)
#define EFAB_MMAP_OFFSET_ID_MASK      (EFRM_RESOURCE_MAX_PER_FD - 1u)

static inline off_t
EFAB_MMAP_OFFSET_MAKE(efch_resource_id_t id, unsigned map_id) {
  return (id.index | (map_id << EFRM_RESOURCE_MAX_PER_FD_BITS))
         << CI_PAGE_SHIFT;
}

static inline efch_resource_id_t
EFAB_MMAP_OFFSET_TO_RESOURCE_ID(off_t offset) {
  efch_resource_id_t id;
  id.index = (offset >> CI_PAGE_SHIFT) & EFAB_MMAP_OFFSET_ID_MASK;
  return id;
}

static inline unsigned
EFAB_MMAP_OFFSET_TO_MAP_ID(off_t offset)
{ return offset >> (CI_PAGE_SHIFT + EFRM_RESOURCE_MAX_PER_FD_BITS); }


#endif  /* __CI_EFCH_OP_TYPES_H__ */
