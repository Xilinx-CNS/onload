/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Socket affinity preload library.
**   \date  2008/09/02
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/* TODO
 *
 * - intercept bind() to install filters for udp
 *
 * - options for different usage models?  (e.g. For high connection rate
 *     servers we'd like to avoid per-socket ops.  For long lived
 *     connections we'd probably prefer per-socket ops to maximise
 *     accuracy).
 */

#define  _GNU_SOURCE
#include <ci/affinity/ul_drv_intf.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <dlfcn.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>


#define ME    "sfcaffinity"
#define LPF   ME": "
#define T(x)  x
#define E(x)  x


#define IP4_FMT                "%d.%d.%d.%d"
#define IP4_ARGS(ip_be32)      ((int) ((uint8_t*)&(ip_be32))[0]),       \
                               ((int) ((uint8_t*)&(ip_be32))[1]),       \
                               ((int) ((uint8_t*)&(ip_be32))[2]),       \
                               ((int) ((uint8_t*)&(ip_be32))[3])

#define IP4PORT_FMT            IP4_FMT":%d"
#define IP4PORT_ARGS(ip, port) IP4_ARGS(ip), ntohs(port)


struct wild_filter {
  struct wild_filter* next;
  unsigned addr, port;
};


/* Globals */
static int override_cpu = -1;
static int override_rxq = -1;
static int override_ifindex = -2;  /* -1 means "default" */

/**********************************************************************/

#define MAX_IPS  1024

static struct ifreq ip_list[MAX_IPS];
static int          ip_list_n;


#define ip_list_name(i)  (ip_list[i].ifr_name)
#define ip_list_sin(i)   ((const struct sockaddr_in*) &ip_list[i].ifr_addr)
#define ip_list_ip(i)    (ip_list_sin(i)->sin_addr.s_addr)


static void interface_get_basename(const char* intf_name, char* base_name)
{
  const char* sep;
  int n;
  if( (sep = strchr((char*) intf_name, '.')) ||
      (sep = strchr((char*) intf_name, ':')) ) {
    strncpy(base_name, intf_name, n = (sep - intf_name));
    base_name[n] = '\0';
  }
  else
    strcpy(base_name, intf_name);
}


static int interface_to_ifindex(const char* intf_name)
{
  struct ifreq ifr;
  int rc, sock;
  interface_get_basename(intf_name, ifr.ifr_name);
  if( (sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
    E(fprintf(stderr, LPF "%s: ERROR: socket() failed (%d, %s)\n",
              __FUNCTION__, errno, strerror(errno)));
    return sock;
  }
  rc = ioctl(sock, SIOCGIFINDEX, &ifr);
  close(sock);
  if( rc == 0 ) {
    return ifr.ifr_ifindex;
  }
  else {
    E(fprintf(stderr, LPF "%s: ERROR: ioctl(SIOCGIFINDEX) failed (%d, %s)\n",
              __FUNCTION__, errno, strerror(errno)));
    return rc;
  }
}


static void refresh_ip_list(void)
{
  struct ifconf ifc;
  int rc, sock;

  if( (sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
    E(fprintf(stderr, LPF "%s: ERROR: socket() failed (%d, %s)\n",
              __FUNCTION__, errno, strerror(errno)));
    ip_list_n = 0;
    return;
  }
  ifc.ifc_len = sizeof(ip_list);
  ifc.ifc_req = ip_list;
  rc = ioctl(sock, SIOCGIFCONF, &ifc);
  close(sock);
  if( rc < 0 ) {
    E(fprintf(stderr, LPF "%s: ERROR: ioctl(SIOCGIFCONF) failed (%d, %s)\n",
              __FUNCTION__, errno, strerror(errno)));
    ip_list_n = 0;
    return;
  }
  ip_list_n = ifc.ifc_len / sizeof(ip_list[0]);
}


static int ip_to_ifindex(unsigned ip)
{
  int i;
  refresh_ip_list();
  for( i = 0; i < ip_list_n; ++i )
    if( ip == ip_list_ip(i) )
      return interface_to_ifindex(ip_list_name(i));
  return -1;
}

/**********************************************************************/

static int load_sym_fail(const char* sym)
{
  fprintf(stderr, LPF "ERROR: dlsym(\"%s\") failed\n", sym);
  fprintf(stderr, LPF "ERROR: dlerror '%s'\n", dlerror());
  exit(-1);
}

/**********************************************************************/

static int do_sys_getpeername(int fd, struct sockaddr* sa, socklen_t* p_sa_len)
{
  static int (*sys_getpeername)(int, struct sockaddr*, socklen_t*);

  if( sys_getpeername == NULL ) {
    sys_getpeername = dlsym(RTLD_NEXT, "getpeername");
    if( sys_getpeername == NULL )
      return load_sym_fail("getpeername");
  }

  return sys_getpeername(fd, sa, p_sa_len);
}


static int is_inet_sock(int fd, int* type, struct sockaddr_in* sa)
{
  struct stat s;
  socklen_t sl;
  int rc;

  /* ?? Is this really necessary?  Surely getsockopt() will fail with
   * ENOTSOCK if not a socket.
   */
  rc = fstat(fd, &s);
  if( rc != 0 || ! S_ISSOCK(s.st_mode) )
    return 0;

  sl = sizeof(*type);
  rc = getsockopt(fd, SOL_SOCKET, SO_TYPE, type, &sl);
  if( rc != 0 )
    return 0;

  sl = sizeof(*sa);
  rc = getsockname(fd, (struct sockaddr*) sa, &sl);
  if( rc != 0 || sa->sin_family != AF_INET )
    return 0;

  return 1;
}


static int get_affinity_fd(void)
{
  static int the_affinity_fd;
  if( the_affinity_fd == 0 ) {
    int flags = O_RDWR | O_CLOEXEC;
    the_affinity_fd = open("/dev/sfc_affinity", flags);
    if( the_affinity_fd < 0 ) {
      E(fprintf(stderr, LPF "Could not open '/dev/sfc_affinity' (%d, %s)\n",
                errno, strerror(errno)));
      the_affinity_fd = -1;
    }
  }
  return the_affinity_fd;
}


static void set_affinity(int type, unsigned laddr, unsigned lport,
                         unsigned raddr, unsigned rport)
{
  struct sfc_aff_set sas;
  int affinity_fd, ifindex;
  int rc;

  if( override_ifindex == -2 ) {
    if( (ifindex = ip_to_ifindex(laddr)) < 0 ) {
      E(fprintf(stderr, LPF "Could not find ifindex for "IP4_FMT"\n",
                IP4_ARGS(laddr)));
      return;
    }
  }
  else {
    ifindex = override_ifindex;
  }

  affinity_fd = get_affinity_fd();
  if( affinity_fd < 0 )
    return;

  T(fprintf(stderr, LPF "%s(%s, "IP4PORT_FMT", "IP4PORT_FMT") => ifindex=%d\n",
            __FUNCTION__, type == SOCK_STREAM ? "tcp":"udp",
            IP4PORT_ARGS(laddr, lport), IP4PORT_ARGS(raddr, rport), ifindex));

  sas.cpu = override_cpu;
  sas.rxq = override_rxq;
  sas.ifindex = ifindex;
  sas.protocol = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
  sas.daddr = laddr;
  sas.dport = lport;
  sas.saddr = raddr;
  sas.sport = rport;
  sas.err_out = sfc_aff_no_error;
  rc = ioctl(affinity_fd, SFC_AFF_SET, &sas);
  if( rc != 0 )
    E(fprintf(stderr, LPF "Failed to set affinity (%d, %s) (%d, %s)\n",
              errno, strerror(errno), (int) sas.err_out,
              sfc_aff_err_msg(sas.err_out)));
}


static void set_affinity_wild_tcp(int type, unsigned laddr, unsigned lport)
{
  static struct wild_filter* tcp_wild_filters;
  struct wild_filter* wf;

  /* Check whether we've already attempted to set affinity for this local
   * address.  I'm not worrying too much about concurrency control when
   * accessing this list, as we're not ever removing items.
   */
  for( wf = tcp_wild_filters; wf != NULL; wf = wf->next )
    if( wf->addr == laddr && wf->port == lport )
      return;

  wf = malloc(sizeof(*wf));
  if( wf != NULL ) {
    wf->addr = laddr;
    wf->port = lport;
    wf->next = tcp_wild_filters;
    tcp_wild_filters = wf;
  }
  set_affinity(type, laddr, lport, 0, 0);
}


static void try_set_affinity_wild(const char* caller, int fd)
{
  struct sockaddr_in sa;
  int errno_save = errno;
  int type;

  T(fprintf(stderr, LPF "%s(%s(%d))\n", __FUNCTION__, caller, fd));

  if( is_inet_sock(fd, &type, &sa) ) {
    if( type == SOCK_STREAM )
      set_affinity_wild_tcp(type, sa.sin_addr.s_addr, sa.sin_port);
    else if( type == SOCK_DGRAM )
      set_affinity(type, sa.sin_addr.s_addr, sa.sin_port, 0, 0);
  }

  errno = errno_save;
}


static void try_set_affinity_full(const char* caller, int fd)
{
  struct sockaddr_in sa_local, sa_peer;
  socklen_t sa_len;
  int errno_save = errno;
  int rc, type;

  T(fprintf(stderr, LPF "%s(%s(%d))\n", __FUNCTION__, caller, fd));

  if( is_inet_sock(fd, &type, &sa_local) )
    if( type == SOCK_STREAM || type == SOCK_DGRAM ) {
      sa_len = sizeof(sa_peer);
      rc = do_sys_getpeername(fd, (struct sockaddr*) &sa_peer, &sa_len);
      if( rc == 0 )
        set_affinity(type, sa_local.sin_addr.s_addr, sa_local.sin_port,
                     sa_peer.sin_addr.s_addr, sa_peer.sin_port);
      else if( type == SOCK_DGRAM )
        /* ?? TODO: We'll sometimes want a full-match for UDP. */
        set_affinity(type, sa_local.sin_addr.s_addr,
                     sa_local.sin_port, 0, 0);
    }

  errno = errno_save;
}

/**********************************************************************
**********************************************************************/

int connect(int fd, const struct sockaddr* sa, socklen_t sa_len)
{
  static int (*sys_connect)(int, const struct sockaddr*, socklen_t);
  int rc;

  if( sys_connect == NULL ) {
    sys_connect = dlsym(RTLD_NEXT, "connect");
    if( sys_connect == NULL )
      return load_sym_fail("connect");
  }

  rc = sys_connect(fd, sa, sa_len);

  /* Okay -- not so easy.  Need to worry about non-blocking connect,
   * completion of which should be by checking getsockopt(SO_ERROR), but
   * not all apps do that.  e.g. Some use getpeername().
   */

  if( rc == 0 )
    try_set_affinity_full(__FUNCTION__, fd);

  return rc;
}


int getpeername(int fd, struct sockaddr* sa, socklen_t* p_sa_len)
{
  /* This is sometimes used by apps to determine whether a non-blocking
   * connect succeeded.
   */
  static int (*sys_getpeername)(int, struct sockaddr*, socklen_t*);
  int rc;

  if( sys_getpeername == NULL ) {
    sys_getpeername = dlsym(RTLD_NEXT, "getpeername");
    if( sys_getpeername == NULL )
      return load_sym_fail("getpeername");
  }

  rc = sys_getpeername(fd, sa, p_sa_len);

  if( rc == 0 )
    try_set_affinity_full(__FUNCTION__, fd);

  return rc;
}


int accept(int fd, struct sockaddr* sa, socklen_t* p_sa_len)
{
  static int (*sys_accept)(int, struct sockaddr*, socklen_t*);
  int rc;

  if( sys_accept == NULL ) {
    sys_accept = dlsym(RTLD_NEXT, "accept");
    if( sys_accept == NULL )
      return load_sym_fail("accept");
  }

  rc = sys_accept(fd, sa, p_sa_len);

  if( rc >= 0 )
    try_set_affinity_full(__FUNCTION__, rc);

  return rc;
}


void _init(void)
{
  const char* s;

  if( (s = getenv("SFC_AFFINITY_CPU")) )
    override_cpu = atoi(s);
  if( (s = getenv("SFC_AFFINITY_RXQ")) )
    override_rxq = atoi(s);
  if( (s = getenv("SFC_AFFINITY_IFINDEX")) )
    override_ifindex = atoi(s);

  T(fprintf(stderr, LPF "cpu=%d rxq=%d ifindex=%d\n",
            override_cpu, override_rxq, override_ifindex));

  /* Currently unused -- kill the warning. */
  (void) try_set_affinity_wild;
}
