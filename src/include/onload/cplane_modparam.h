/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2021 Xilinx, Inc. */
#ifndef __ONLOAD_CPLANE_MODPARAM_H__
#define __ONLOAD_CPLANE_MODPARAM_H__

/* Tell Onload what kind of addresses are considered to be "local" */
extern bool cplane_use_prefsrc_as_local;

/* Do we track XDP programs? */
extern bool cplane_track_xdp;

#endif
