/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>

/* CI support for multi-platform error codes */

/* sockets */
ci_sock_err_t  CI_SOCK_OK 		= { 0 };
ci_sock_err_t  CI_SOCK_INVALID 		= { INVALID_SOCKET };
ci_sock_err_t  CI_SOCK_EWOULDBLOCK 	= { EWOULDBLOCK };
ci_sock_err_t  CI_SOCK_EMSGSIZE         = { EMSGSIZE };
ci_sock_err_t  CI_SOCK_ETIMEDOUT	= { ETIMEDOUT };
ci_sock_err_t  CI_SOCK_ECONNREFUSED	= { ECONNREFUSED };
ci_sock_err_t  CI_SOCK_ECONNABORTED	= { ECONNABORTED };
ci_sock_err_t  CI_SOCK_ENOBUFS		= { ENOBUFS };
ci_sock_err_t  CI_SOCK_EOPNOTSUPP	= { EOPNOTSUPP };

/*! \cidoxg_end */
