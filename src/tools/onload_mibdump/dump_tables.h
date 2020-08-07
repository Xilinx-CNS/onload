/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
#include <ci/tools.h>
#include <cplane/mib.h>

void cp_dump_hwport_table(struct cp_mibs*);
void cp_dump_llap_table(struct cp_mibs*);
void cp_dump_ipif_table(struct cp_mibs*);
void cp_dump_ip6if_table(struct cp_mibs*);
void cp_dump_fwd_table(struct cp_mibs*, ci_uint32 khz);
void cp_dump_services(struct cp_mibs*);
