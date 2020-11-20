/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
/* This file contains description of the Onload ioctls used by the Control
 * Plane server.  Any change in this file is likely to result in
 * misfunctioning cplane server. */

#ifndef __CPLANE_IOCTL_H__
#define __CPLANE_IOCTL_H__

#include <cplane/mib.h>

struct oo_op_cplane_ipmod {
  ci_addr_sh_t addr;
  ci_ifid_t ifindex;
  ci_int8/*bool*/ add;
  ci_int8 af;
};

struct oo_op_cplane_llapmod {
  ci_ifid_t ifindex;
  ci_uint16 flags; /* 0x1 means interface is up */
  ci_uint32 hwport_mask;
  ci_uint16 vlan_id;
  ci_mac_addr_t mac;
};

/* Parameter to OO_OP_CP_SELECT_INSTANCE, specifying which instance of the
 * cplane to select. */
enum oo_op_cp_select_instance {
  CP_SELECT_INSTANCE_LOCAL,
  CP_SELECT_INSTANCE_INIT_NET,
};

struct oo_op_cplane_arp_resolve {
  cicp_verinfo_t verinfo;
  cp_fwd_table_id fwd_table_id;  /* Respected only for the cplane server. */
};

struct oo_op_cplane_dnat_add {
  ci_addr_sh_t orig_addr;
  ci_addr_sh_t xlated_addr;
  ci_uint16    orig_port;
  ci_uint16    xlated_port;
};

struct oo_op_cplane_dnat_del {
  ci_addr_sh_t orig_addr;
  ci_uint16    orig_port;
};

#include <onload/ioctl_base.h>

/* This is the first part of a large enum defined in
 * include/onload/ioctl.h.
 * It MUST be synchronised with the oo_operations table! */
enum {
  OO_OP_GET_CPU_KHZ,
#define OO_IOC_GET_CPU_KHZ        OO_IOC_R(GET_CPU_KHZ, ci_uint32)

  OO_OP_CP_DUMP_HWPORTS,
#define OO_IOC_CP_DUMP_HWPORTS    OO_IOC_W(CP_DUMP_HWPORTS, ci_ifid_t)

#ifdef CP_SYSUNIT
#define cp_set_hwport_t \
  typeof(((struct cp_helper_msg*)NULL)->u.set_hwport)
  OO_OP_CP_SYSUNIT_MAKE_NIC,
#define OO_IOC_CP_SYSUNIT_MAKE_NIC OO_IOC_W(CP_SYSUNIT_MAKE_NIC, \
                                            cp_set_hwport_t)
#endif

  OO_OP_CP_MIB_SIZE,
#define OO_IOC_CP_MIB_SIZE        OO_IOC_R(CP_MIB_SIZE, ci_uint32)

  OO_OP_CP_FWD_RESOLVE,
#define OO_IOC_CP_FWD_RESOLVE     OO_IOC_W(CP_FWD_RESOLVE, struct cp_fwd_key)

  OO_OP_CP_FWD_RESOLVE_COMPLETE,
#define OO_IOC_CP_FWD_RESOLVE_COMPLETE     OO_IOC_W(CP_FWD_RESOLVE_COMPLETE, \
                                                    ci_uint32)
  OO_OP_CP_ARP_RESOLVE,
#define OO_IOC_CP_ARP_RESOLVE     OO_IOC_W(CP_ARP_RESOLVE, \
                                           struct oo_op_cplane_arp_resolve)

  OO_OP_CP_ARP_CONFIRM,
#define OO_IOC_CP_ARP_CONFIRM     OO_IOC_W(CP_ARP_CONFIRM, cicp_verinfo_t)

  OO_OP_CP_WAIT_FOR_SERVER,
#define OO_IOC_CP_WAIT_FOR_SERVER OO_IOC_W(CP_WAIT_FOR_SERVER, ci_uint32)
  OO_OP_CP_LINK,
#define OO_IOC_CP_LINK            OO_IOC_NONE(CP_LINK)
  OO_OP_CP_READY,
#define OO_IOC_CP_READY           OO_IOC_NONE(CP_READY)
  OO_OP_CP_CHECK_VERSION,
#define OO_IOC_CP_CHECK_VERSION   OO_IOC_W(CP_CHECK_VERSION, \
                                           oo_cp_version_check_t)

  OO_OP_OOF_CP_IP_MOD,
#define OO_IOC_OOF_CP_IP_MOD      OO_IOC_W(OOF_CP_IP_MOD, \
                                           struct oo_op_cplane_ipmod)

  OO_OP_OOF_CP_LLAP_MOD,
#define OO_IOC_OOF_CP_LLAP_MOD    OO_IOC_W(OOF_CP_LLAP_MOD, \
                                           struct oo_op_cplane_llapmod)

  OO_OP_OOF_CP_LLAP_UPDATE_FILTERS,
#define OO_IOC_OOF_CP_LLAP_UPDATE_FILTERS OO_IOC_W(OOF_CP_LLAP_UPDATE_FILTERS, \
                                                   struct oo_op_cplane_llapmod)

  OO_OP_OOF_CP_DNAT_ADD,
#define OO_IOC_OOF_CP_DNAT_ADD    OO_IOC_W(OOF_CP_DNAT_ADD, \
                                           struct oo_op_cplane_dnat_add)

  OO_OP_OOF_CP_DNAT_DEL,
#define OO_IOC_OOF_CP_DNAT_DEL    OO_IOC_W(OOF_CP_DNAT_DEL, \
                                           struct oo_op_cplane_dnat_del)

  OO_OP_OOF_CP_DNAT_RESET,
#define OO_IOC_OOF_CP_DNAT_RESET  OO_IOC_NONE(OOF_CP_DNAT_RESET)

  OO_OP_CP_NOTIFY_LLAP_MONITORS,
#define OO_IOC_CP_NOTIFY_LLAP_MONITORS OO_IOC_NONE(CP_NOTIFY_LLAP_MONITORS)

  OO_OP_CP_CHECK_VETH_ACCELERATION,
#define OO_IOC_CP_CHECK_VETH_ACCELERATION OO_IOC_W(CP_CHECK_VETH_ACCELERATION, \
                                                   ci_uint32)

  /* Defined as taking a ci_uint32.  Admissible values are in the
   * oo_op_cp_select_instance enum. */
  OO_OP_CP_SELECT_INSTANCE,
#define OO_IOC_CP_SELECT_INSTANCE OO_IOC_W(CP_SELECT_INSTANCE, ci_uint32)

  OO_OP_CP_INIT_KERNEL_MIBS,
#define OO_IOC_CP_INIT_KERNEL_MIBS OO_IOC_R(CP_INIT_KERNEL_MIBS, ci_uint32)

  OO_OP_CP_XDP_PROG_CHANGE,
#define OO_IOC_CP_XDP_PROG_CHANGE OO_IOC_W(CP_XDP_PROG_CHANGE, ci_hwport_id_t)

  OO_OP_CP_END  /* This had better be last! */
};

#endif /*__CPLANE_IOCTL_H__*/

