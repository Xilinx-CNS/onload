/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER>
** \author  djr
**  \brief  Error checked convience functions for working with sockets.
**   \date  2004/04/06
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_app */
#ifndef __CI_APP_CHECKEDSOCKET_H__
#define __CI_APP_CHECKEDSOCKET_H__

#include <ci/app/socket.h>


/**********************************************************************
 ** Error-checked wrappers.
 */

#define CiClosesocket(s)           _CiClosesocket(s,__FILE__,__LINE__)
#define CiSocket(d,t,p)            _CiSocket(d,t,p,__FILE__,__LINE__)
#define CiBind(s,sa,sl)            _CiBind(s,sa,sl,__FILE__,__LINE__)
#define CiListen(s,b)              _CiListen(s,b,__FILE__,__LINE__)
#define CiAccept(s,sa,sl)          _CiAccept(s,sa,sl,__FILE__,__LINE__)
#define CiConnect(s,sa,sl)         _CiConnect(s,sa,sl,__FILE__,__LINE__)

#define CiGetsockname(s,sa,sl)     _CiGetsockname(s,sa,sl,__FILE__,__LINE__)
#define CiGetpeername(s,sa,sl)     _CiGetpeername(s,sa,sl,__FILE__,__LINE__)
#define CiSetsockopt(s,l,o,ov,ol)  _CiSetsockopt(s,l,o,ov,ol,__FILE__,__LINE__)
#define CiGetsockopt(s,l,o,ov,ol)  _CiGetsockopt(s,l,o,ov,ol,__FILE__,__LINE__)

#define CiFcntl(fd,cmd,arg)       _CiFcntl(fd,cmd,arg,__FILE__,__LINE__)

#define CiSetsockblocking(s,b)     _CiSetsockblocking(s,b,__FILE__,__LINE__)
#define CiGethostbyname(n)         _CiGethostbyname(n,__FILE__,__LINE__)
#define CiGethostbyaddr(sa,sl,t)   _CiGethostbyaddr(sa,sl,t,__FILE__,__LINE__)

  /*! [p] is in host order. */
#define CiBind2(s, p)              _CiBind2(s,p,__FILE__,__LINE__)
  /*! [p] is in host order. */
#define CiConnect2(s,h,p)          _CiConnect2(s,h,p,__FILE__,__LINE__)

#define CiSetsockopt_int(s,l,o,v)  _CiSetsockopt_int(s,l,o,v,__FILE__,__LINE__)
#define CiGetsockopt_int(s,l,o)    _CiGetsockopt_int(s,l,o,__FILE__,__LINE__)
#define CiGetsockport(s)           _CiGetsockport(s,__FILE__,__LINE__)
  /* Returns port number in host order. */


/**********************************************************************
 ** Implementation thereof.  We inline it so it works for any socket
 ** implementation (as chosen by ci/app/socket.h).
 */

#include <fcntl.h>
#define CI_SOCK_ERR(x)  ((x) < 0)
#define CI_SOCK_INV(x)  ((x) < 0)


#ifdef __wrap
# undef __wrap
#endif

#define __wrap(decl, name, params)		\
  ci_inline int decl {				\
    int rc = name params;			\
    if( CI_SOCK_ERR(rc) )			\
      __ci_sys_fail(#name, rc, file, line);	\
    return rc;					\
  }


ci_inline int _CiSocket(int d, int t, int p, const char* file, int line)
{
  int rc = cis_socket(d, t, p);
  if( CI_SOCK_INV(rc) )
    __ci_sys_fail("cis_socket", rc, file, line);
  return rc;
}

__wrap(_CiBind(int s, const struct sockaddr* sa, socklen_t sl,
	       const char*file,int line),
       cis_bind, (s,(struct sockaddr*)sa,sl))

__wrap(_CiListen(int s, int b,const char*file,int line),
       cis_listen, (s, b))

__wrap(_CiAccept(int s, struct sockaddr* sa, socklen_t* sl,
		 const char*file,int line),
       cis_accept, (s,sa,sl))

__wrap(_CiConnect(int s, const struct sockaddr* sa, socklen_t sl,
		  const char*file,int line),
       cis_connect, (s, (struct sockaddr*)sa, sl))

#ifdef cis_getsockname
__wrap(_CiGetsockname(int s, struct sockaddr* sa, socklen_t* sl,
		      const char*file,int line),
       cis_getsockname, (s, sa, sl))
#endif

#ifdef cis_getpeername
__wrap(_CiGetpeername(int s, struct sockaddr* sa, socklen_t* sl,
		      const char*file,int line),
       cis_getpeername, (s, sa, sl))
#endif

#ifdef cis_setsockopt
__wrap(_CiSetsockopt(int s, int l, int o, const void* ov, socklen_t ol,
		    const char*file,int line),
       cis_setsockopt, (s, l, o, ov, ol))
#endif

#ifdef cis_getsockopt
__wrap(_CiGetsockopt(int s, int l, int o, void* ov, socklen_t* ol,
		     const char*file,int line),
       cis_getsockopt, (s, l, o, ov, ol))
#endif

__wrap(_CiFcntl(int fd, int cmd, long arg,const char*file,int line),
       fcntl, (fd, cmd, arg))

__wrap(_CiSetsockblocking(int s, int b, const char*file,int line),
       cis_setsockblocking, (s, b))

#undef __wrap

/**********************************************************************/
/**********************************************************************/
/**********************************************************************/

/*! Comment? */
ci_inline void _CiClosesocket(int s, const char* file, int line)
{
  int rc = cis_close(s);
  if( rc == -1 )
    __ci_sys_fail("cis_close", rc, file, line);
}


/*! Comment? */
ci_inline struct hostent* _CiGethostbyname(const char* name,
					   const char* file, int line)
{
  struct hostent* he;
  if( (he = gethostbyname(name)) == 0 )
    __ci_sys_fail("gethostbyname", 0, file, line);
  return he;
}


/*! Comment? */
ci_inline struct hostent* _CiGethostbyaddr(const char *addr,
					   int len, int type,
					   const char* file, int line)
{
  struct hostent* he;

  if( (he = gethostbyaddr(addr, len, type)) == 0 )
    __ci_sys_fail("gethostbyaddr", 0, file, line);
  return he;
}


/*! Comment? */
ci_inline void _CiBind2(int sock, int port, const char* file, int line)
{
  struct sockaddr_in sa;
  sa.sin_family = AF_INET;
  sa.sin_port = htons((unsigned short) port);
  sa.sin_addr.s_addr = CI_BSWAPC_BE32(INADDR_ANY);
  _CiBind(sock, (struct sockaddr*) &sa, sizeof(sa), file, line);
}


/*! Comment? */
ci_inline void _CiConnect2(int sock, const char* host, int port,
			   const char* file, int line)
{
  struct sockaddr_in sa;
  struct hostent* he;
  sa.sin_family = AF_INET;
  sa.sin_port = htons((unsigned short) port);
  he = _CiGethostbyname(host, file, line);
  ci_assert(he->h_addrtype == AF_INET);
  memcpy(&sa.sin_addr, he->h_addr_list[0], sizeof(sa.sin_addr));
  _CiConnect(sock, (struct sockaddr*) &sa, sizeof(sa), file, line);
}


#ifdef cis_setsockopt
/*! Comment? */
ci_inline void _CiSetsockopt_int(int sock, int level, int optname, int value,
				 const char* file, int line)
{
  _CiSetsockopt(sock, level, optname, &value, sizeof(value), file, line);
}
#endif


#ifdef cis_getsockopt
/*! Comment? */
ci_inline int _CiGetsockopt_int(int sock, int level, int optname,
				const char* file, int line)
{
  int v;
  socklen_t vlen = sizeof(v);
  _CiGetsockopt(sock, level, optname, &v, &vlen, file, line);
  return v;
}
#endif


#ifdef cis_getsockname
/*! Comment? */
ci_inline int _CiGetsockport(int sock, const char* file, int line)
{
  struct sockaddr_storage sa;
  socklen_t l = sizeof(sa);
  _CiGetsockname(sock, (struct sockaddr*) &sa, &l, file, line);
  return sockaddr_get_port(&sa);
}
#endif


#endif  /* __CI_APP_CHECKEDSOCKET_H__ */
/*! \cidoxg_end */
