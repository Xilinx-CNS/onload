/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
/* Declarations common to apps in the efsend suite.
 *
 * CUSTOMER NOTE: This code is not intended to be used outside of the efsend
 * suite!
 */

#ifndef __SENDCOMMON_H__
#define __SENDCOMMON_H__


#include "utils.h"

#include <etherfabric/vi.h>
#include <ci/tools.h>
#include <ci/tools/ipcsum_base.h>
#include <ci/tools/ippacket.h>
#include <ci/net/ipv4.h>

extern void usage(void);

#define CL_CHK(x)                               \
  do{                                           \
    if( ! (x) )                                 \
      usage();                                  \
  }while(0)

extern int init_udp_pkt(void* pkt_buf, int paylen, ef_vi *vi,
                        ef_driver_handle dh, int vlan, int ip_checksum);
extern void common_usage(void);
extern void parse_args(char *argv[], int *ifindex, int local_port, int vlan);

#endif
