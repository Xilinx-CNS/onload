/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */
#ifndef __OO_NICS_H__
#define __OO_NICS_H__

struct tcp_helper_resource_s;

extern int oo_get_nics(struct tcp_helper_resource_s* trs, int ifindices_len);

#endif /* __OO_NICS_H__ */
