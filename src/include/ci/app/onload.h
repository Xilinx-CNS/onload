/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  Tools for testing onload.
**   \date  2009/05/13
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_ONLOAD_H__
#define __CI_APP_ONLOAD_H__


/* Return true if the onload transport library is linked to this
 * application, or present in LD_PRELOAD.
 *
 * This is slightly unreliable -- it can return false for old versions of
 * onload when it is linked via /etc/ld.so.preload.  Also it can return
 * true if onload is present in LD_PRELOAD but for some reason not linked.
 */
extern int ci_onload_is_active(void);

/* Dump info about onload-related execution environment to given stream.
 * Includes value of LD_PRELOAD, onload version (if available) and onload
 * configuration options in the environment.
 */
extern void ci_onload_info_dump(FILE* f, const char* prefix);


#endif  /* __CI_APP_ONLOAD_H__ */
