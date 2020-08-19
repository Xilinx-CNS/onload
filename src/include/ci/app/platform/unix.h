/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app_platform */

#ifndef __CI_APP_PLATFORM_UNIX_H__
#define __CI_APP_PLATFORM_UNIX_H__

/****************************************************************************
 *
 * multi-platform support for sockets error handling
 * (also see app/net.h)
 *	
 ****************************************************************************/

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>


/* early glibc doesn't have MSG_DONTWAIT, MSG_WAITALL etc. */
#if defined(__GLIBC__)
# ifndef  MSG_DONTWAIT
#  define MSG_DONTWAIT   0x40
# endif
# ifndef  MSG_WAITALL
#  define MSG_WAITALL    0x100
# endif
# ifndef  SHUT_RD
#  define SHUT_RD    0
#  define SHUT_WR    1
#  define SHUT_RDWR  2
# endif
#endif


# ifndef INVALID_SOCKET 
# define INVALID_SOCKET (-1)
# endif

# define CI_SOCK_ERR(x)  	  ((x) < 0)
# define CI_SOCK_INV(x)  	  ((x) < 0)

# define CI_SOCK_ERR_INIT()
# define CI_SOCK_ERR_GET(err)	  (err = errno)
# define CI_SOCK_ERR_STR()   	  (strerror(errno))
# define CI_SOCK_ERR_PUT()
# define CI_SOCK_ERRNO()     	  errno


#endif

/*! \cidoxg_end */
