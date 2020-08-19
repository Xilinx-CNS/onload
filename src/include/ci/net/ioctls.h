/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  adp
**  \brief  Ioctls for ioctl() call compatibilty 
**   \date  2004/7/29
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_IOCTLS_H__
#define __CI_NET_IOCTLS_H__

#define SIOCINQ  FIONREAD
#define SIOCOUTQ TIOCOUTQ
#ifndef SIOCOUTQNSD
# define SIOCOUTQNSD 0x894b
#endif
#ifndef SIOCGSTAMPNS
# define SIOCGSTAMPNS 0x8907
#endif

#endif /* __CI_NET_IOCTLS_H__ */
