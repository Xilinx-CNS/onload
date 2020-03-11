/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  Hook to select a particular sockets implementation.
**   \date  2004/04/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_SOCKET_H__
#define __CI_APP_SOCKET_H__


#ifndef CIS_SOCK_MK_ID
# include <sys/socket.h>
# include <sys/poll.h>
# define CIS_SOCK_MK_ID(x)	x
# define CIS_SOCK_HAVE_SOCKOPT	1
# define CIS_SOCK_HAVE_SOCKNAME	1
# define CIS_SOCK_HAVE_SELECT	1
# define CIS_SOCK_HAVE_POLL	    1
# define CIS_SOCK_HAVE_EPOLL	0
# define setsockblocking	ci_setfdblocking

#endif


#define cis_socket		CIS_SOCK_MK_ID(socket)
#define cis_bind		CIS_SOCK_MK_ID(bind)
#define cis_connect		CIS_SOCK_MK_ID(connect)
#define cis_listen		CIS_SOCK_MK_ID(listen)
#define cis_accept		CIS_SOCK_MK_ID(accept)
#define cis_shutdown		CIS_SOCK_MK_ID(shutdown)
#define cis_close		CIS_SOCK_MK_ID(close)
#define cis_dup 		CIS_SOCK_MK_ID(dup)
#define cis_dup2 		CIS_SOCK_MK_ID(dup2)
#define cis_setsockblocking	CIS_SOCK_MK_ID(setsockblocking)
#define cis_sendfile		CIS_SOCK_MK_ID(sendfile)

#define cis_recv		CIS_SOCK_MK_ID(recv)
#define cis_send		CIS_SOCK_MK_ID(send)
#define cis_accept4		CIS_SOCK_MK_ID(accept4)
#define cis_recvfrom		CIS_SOCK_MK_ID(recvfrom)
#define cis_sendto		CIS_SOCK_MK_ID(sendto)
#define cis_recvmsg		CIS_SOCK_MK_ID(recvmsg)
#define cis_sendmsg		CIS_SOCK_MK_ID(sendmsg)
#define cis_read		CIS_SOCK_MK_ID(read)
#define cis_write		CIS_SOCK_MK_ID(write)
#define cis_writev		CIS_SOCK_MK_ID(writev)


#ifdef CIS_SOCK_HAVE_SOCKOPT
# define cis_getsockopt		CIS_SOCK_MK_ID(getsockopt)
# define cis_setsockopt		CIS_SOCK_MK_ID(setsockopt)
#endif
#ifdef CIS_SOCK_HAVE_SOCKNAME
# define cis_getsockname	CIS_SOCK_MK_ID(getsockname)
# define cis_getpeername	CIS_SOCK_MK_ID(getpeername)
#endif
#ifdef CIS_SOCK_HAVE_SELECT
# define cis_select		CIS_SOCK_MK_ID(select)
# define cis_pselect		CIS_SOCK_MK_ID(pselect)
#endif
#ifdef CIS_SOCK_HAVE_POLL
# define cis_poll		CIS_SOCK_MK_ID(poll)
# define cis_ppoll		CIS_SOCK_MK_ID(ppoll)
#endif
#ifdef CIS_SOCK_HAVE_EPOLL
# define cis_epoll_ctl		CIS_SOCK_MK_ID(epoll_ctl)
# define cis_epoll_wait		CIS_SOCK_MK_ID(epoll_wait)
#endif


#endif  /* __CI_APP_SOCKET_H__ */
/*! \cidoxg_end */
