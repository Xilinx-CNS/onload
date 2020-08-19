/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Fixed width, cross-platform, timeval
**   \date  2008/08/14
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_TIMEVAL_H__
#define __CI_TOOLS_TIMEVAL_H__


/* Fixed width type equivalent of struct timeval */
typedef struct ci_timeval_s {
  ci_int32 tv_sec;
  ci_int32 tv_usec;
} ci_timeval_t;


#endif  /* __CI_TOOLS_TIMEVAL_H__ */
/*! \cidoxg_end */
