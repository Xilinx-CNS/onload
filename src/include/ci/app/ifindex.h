/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  An interface to translate between ifindex and interface name.
**   \date  2008/12/18
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_IFINDEX_H__
#define __CI_APP_IFINDEX_H__


extern int ci_net_interface_ifindex_to_name(int ifindex, char* name_buf,
                                            int name_buf_len);

/* Translates [name] to an ifindex.  [name] may either be an integer (which
 * is returned) or an interface name such as "eth2".  Returns a -ve error
 * code on failure.
 */
extern int ci_net_interface_name_to_ifindex(const char* name);


#endif  /* __CI_APP_IFINDEX_H__ */
/*! \cidoxg_end */
