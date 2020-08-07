/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2020 Xilinx, Inc. */

#ifndef __TOOLS_CPLANE_PRINT_H__
#define __TOOLS_CPLANE_PRINT_H__

struct cp_session;

void cp_print(struct cp_session* s, const char* format, ...);
void cp_print_nonewline(struct cp_session* s, const char* format, ...);

void cp_llap_print(struct cp_session* s);
void cp_team_print(struct cp_session* s);
void cp_mac_print(struct cp_session* s);
void cp_mac6_print(struct cp_session* s);
void cp_fwd_print(struct cp_session* s);
void cp_session_print_state(struct cp_session* s, int kind);

#endif /* __TOOLS_CPLANE_PRINT_H__ */
