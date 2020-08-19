/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Public types and defs for driver & h/w interface.
**   \date  2002/02/04
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_driver_efab  */
#ifndef __CI_DRIVER_EFAB_OPEN_H__
#define __CI_DRIVER_EFAB_OPEN_H__

#ifndef __CI_TOOLS_H__
# include <ci/tools.h>
#endif


#ifdef __KERNEL__
    struct efhw_nic_s;
    typedef struct efhw_nic_s* ci_fd_t;
# define CI_FD_BAD ((ci_fd_t)(NULL))
    typedef int ci_descriptor_t;
#else /* Userland */
    typedef int ci_fd_t;
# define CI_FD_BAD ((ci_fd_t)(-1))
    typedef int ci_descriptor_t;
#endif

#define  DESCRIPTOR_PRI_ARG(fd) fd


/*----------------------------------------------------------------------------
 *
 * Open hardware API - Internally this is compile time selectable 
 *
 *---------------------------------------------------------------------------*/


#endif  /* __CI_DRIVER_EFAB_OPEN_H__ */
/*! \cidoxg_end */
