/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  slp
**  \brief  Code to ensure the CPU has all the features required by this build.
**   \date  2003/08/07
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_CPU_FEATURES_H__
#define __CI_TOOLS_CPU_FEATURES_H__

#define CI_CPU_OK 	(0)  /* CPU checked out ok */
#define CI_CPU_OLD 	(-1) /* CPU didn't respond to the cpuid instruction */
#define CI_CPU_ERROR	(-2) /* CPU cannot run this build */
#define CI_CPU_WARNING	(-3) /* CPU can run this build but performance could
				be impacted */

/*! Comment? */
extern int ci_cpu_features_check(int verbose);

extern int ci_cpu_has_feature(char* feature);

#endif  /* __CI_TOOLS_CPU_FEATURES_H__ */

/*! \cidoxg_end */
