/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Onload version.
**   \date  2009/07/22
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#ifndef __ONLOAD_VERSION_H__
#define __ONLOAD_VERSION_H__


#ifndef ONLOAD_VERSION
# define ONLOAD_VERSION  "<dev-snapshot>"
#endif

#define ONLOAD_PRODUCT  "Onload"

#define ONLOAD_COPYRIGHT  "Copyright 2019-present Xilinx, 2006-2019 Solarflare Communications, 2002-2005 Level 5 Networks"

/* Max length of version string used for version skew checking. */
enum { OO_VER_STR_LEN = 40 };


/* We use an md5sum over certain headers to ensure that userland and kernel
 * drivers are built against a compatible interface.
 */
enum { CI_CHSUM_STR_LEN = 32 };


typedef struct oo_version_check_s {
  char                    in_version[OO_VER_STR_LEN + 1];
  char                    in_uk_intf_ver[CI_CHSUM_STR_LEN + 1];
  int32_t                 debug;
} oo_version_check_t;


#endif  /* __ONLOAD_VERSION_H__ */
