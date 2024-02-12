/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <cplane/cplane.h>
#include <cplane/server.h>

extern int cplane_ioctl(int, long unsigned int, void* );

int (* ci_sys_ioctl)(int, long unsigned int, ...) = (void*) cplane_ioctl;


/* avoid python's special treatment of double underscores */
int py_oo_cp_route_resolve(struct oo_cplane_handle* cp,
                           cicp_verinfo_t* verinfo,
                           struct cp_fwd_key* key,
                           int/*bool*/ ask_server,
                           struct cp_fwd_data* data)
{
  return __oo_cp_route_resolve(cp, verinfo, key, ask_server, data,
                               CP_FWD_TABLE_ID_INVALID /* Unused at UL */);
}

int cp_unit_cplane_ioctl(int fd, long unsigned int op, ...);
int py_oo_cp_set_hwport(struct oo_cplane_handle* cp,
                        ci_ifid_t ifindex, ci_hwport_id_t hwport)
{
  cp_set_hwport_t arg;
  arg.ifindex = ifindex;
  arg.hwport = hwport;
  return cplane_ioctl(cp->fd, OO_IOC_CP_SYSUNIT_MAKE_NIC, &arg);
}

int py_oo_cp_get_hwport_ifindex(struct oo_cplane_handle* cp,
                                ci_hwport_id_t hwport)
{
  return oo_cp_get_hwport_ifindex(cp, hwport);
}
