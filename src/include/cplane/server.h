/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
/* This header describes the interface between the open source parts
 * of Onload and the binary-only control plane server.
 *
 * We use an md5sum over certain headers to ensure that userland and
 * kernel drivers are built against a compatible interface. The
 * control plane server and its clients will verify this hash against
 * the kernel module and refuse to start if there is a version
 * mismatch.
 *
 * Users should therefore not modify these headers because the
 * supplied control plane server will refuse to operate with the
 * resulting module.
 */

#ifndef __ONLOAD_CPLANE_SERVER_H__
#define __ONLOAD_CPLANE_SERVER_H__

/* onload_cp_server can be spawned by the kernel, so the kernel needs to know
 * some things about the command line arguments that the server takes.  We
 * define such things here. */
#define CPLANE_SERVER_NS_CMDLINE_OPT "network-namespace-file"
#define CPLANE_SERVER_DAEMONISE_CMDLINE_OPT "daemonise"
#define CPLANE_SERVER_HWPORT_NUM_OPT "hwport-max"
#define CPLANE_SERVER_IPADDR_NUM_OPT "ipif-max"
#define CPLANE_SERVER_BOOTSTRAP "bootstrap"
#define CPLANE_SERVER_NO_IPV6 "no-ipv6"
#define CPLANE_SERVER_IPV6_NO_SOURCE "ipv6-no-source"
#define CPLANE_SERVER_UID "uid"
#define CPLANE_SERVER_GID "gid"
#define CPLANE_SERVER_PREFSRC_AS_LOCAL "preferred-source-as-local"
#ifndef NDEBUG
#define CPLANE_SERVER_CORE_SIZE "core_size"
#endif

/* Mask for forward request id, as used between server and module. */
#define CP_FWD_FLAG_REQ_MASK 0x01ffffff


#include <cplane/cplane.h> /* for cp_fwd_table_id */
#include <cplane/mib.h> /* for cp_fwd_key */

enum cp_helper_msg_type {
  CP_HMSG_FWD_REQUEST,
  CP_HMSG_VETH_SET_FWD_TABLE_ID,
  CP_HMSG_SET_HWPORT,
};

/* message from in-kernel cplane helper to the cplane server */
struct cp_helper_msg {
  enum cp_helper_msg_type hmsg_type;
  union {
    struct {
      struct cp_fwd_key key;
      ci_uint32 id;
      cp_fwd_table_id fwd_table_id;
    } fwd_request;
    struct {
      ci_ifid_t veth_ifindex;
      cp_fwd_table_id fwd_table_id;
    } veth_set_fwd_table_id;
    struct {
      ci_ifid_t ifindex;
      ci_hwport_id_t hwport;
      cp_nic_flags_t nic_flags;
    } set_hwport;
  } u;
};

#endif /* defined(__ONLOAD_CPLANE_SERVER_H__) */
