/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Debug helpers for sys-call intercept code.
**   \date  2005/01/20
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_transport_unix */

#include <internal.h>
#include <onload/ul.h>
#include <ci/app.h>
#include <sys/sysmacros.h>


enum kfd_fmt_rc {
  kfd_fmt_closed,
  kfd_fmt_failed,
  kfd_fmt_onload,
  kfd_fmt_other
};


static int major_to_dev(int major, char* dev_name_out, int dev_name_size)
{
  char line[80];
  char dev[80];
  FILE* fp;
  int m, rc = -1;

  if( (fp = fopen("/proc/devices", "r")) == NULL )  return 0;
  while( fgets(line, sizeof(line), fp) )
    if( sscanf(line, "%u %s", &m, dev) == 2 && m == major ) {
      strncpy(dev_name_out, dev, dev_name_size);
      dev_name_out[dev_name_size - 1] = '\0';
      rc = 1;
      goto close_out;
    }
  rc = 0;
 close_out:
  fclose(fp);
  return rc;
}


#define bprintf(...)                                                    \
  do{                                                                   \
    if( buf_len - *buf_n > 0 )                                          \
      *buf_n += snprintf(buf + *buf_n, buf_len - *buf_n, __VA_ARGS__);  \
  }while(0)


static const char* type_to_string(int type)
{
  if( type == SOCK_STREAM )
    return "STREAM";
  else if( type == SOCK_DGRAM )
    return "DGRAM";
  else
    return "";
}


static const char* type_to_proto(int type)
{
  if( type == SOCK_STREAM )
    return "TCP";
  else if( type == SOCK_DGRAM )
    return "UDP";
  else
    return "";
}


static void sock_fmt(int fd, char* buf, int* buf_n, int buf_len)
{
  struct sockaddr_in sa;
  socklen_t sa_len;
  int type;
  bprintf("socket[");
  sa_len = sizeof(type);
  CI_TRY(ci_sys_getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &sa_len));
  sa_len = sizeof(sa);
  if( ci_sys_getsockname(fd, (struct sockaddr*) &sa, &sa_len) == 0 ) {
    switch( sa.sin_family ) {
    case AF_INET:
      bprintf("%s,"CI_IP_PRINTF_FORMAT":%u", type_to_proto(type),
              CI_IP_PRINTF_ARGS(&sa.sin_addr.s_addr),
              CI_BSWAP_BE16(sa.sin_port));
      break;
    case AF_UNIX:
      bprintf("UNIX,%s", type_to_string(type));
      break;
    default:
      bprintf("%d,%s", sa.sin_family, type_to_string(type));
      break;
    }
    sa_len = sizeof(sa);
    if( sa.sin_family == AF_INET &&
        ci_sys_getpeername(fd, (struct sockaddr*) &sa, &sa_len) == 0 )
      bprintf(","CI_IP_PRINTF_FORMAT":%u",
              CI_IP_PRINTF_ARGS(&sa.sin_addr.s_addr),
              CI_BSWAP_BE16(sa.sin_port));
  }
  bprintf("]");
}


static void onload_fmt(int fd, char* buf, int* buf_n, int buf_len)
{
  ci_ep_info_t info;
  CI_TRY(oo_ep_info(fd, &info));
  switch( info.fd_type ) {
  case CI_PRIV_TYPE_NONE:
    bprintf("onload[]");
    break;
  case CI_PRIV_TYPE_NETIF:
    bprintf("onload[stack,%u]", info.resource_id);
    break;
  case CI_PRIV_TYPE_TCP_EP:
    bprintf("onload[TCP,%u,%d]", info.resource_id, OO_SP_FMT(info.sock_id));
    break;
  case CI_PRIV_TYPE_UDP_EP:
    bprintf("onload[UDP,%u,%d]", info.resource_id, OO_SP_FMT(info.sock_id));
    break;
  default:
    bprintf("onload[type=%d,%u,%d,%lu]", info.fd_type, info.resource_id,
            OO_SP_FMT(info.sock_id), (unsigned long) info.mem_mmap_bytes);
    break;
  }
}


static enum kfd_fmt_rc char_fmt(int fd, int rdev, char* buf,
                                int* buf_n, int buf_len)
{
  char devname[20];

  if( ! major_to_dev(major(rdev), devname, sizeof(devname)) ) {
    bprintf("char[%u,%u]", (unsigned) major(rdev), (unsigned) minor(rdev));
  }
  else if( ! strcmp(devname, "onload") ) {
    onload_fmt(fd, buf, buf_n, buf_len);
    return kfd_fmt_onload;
  }
  else {
    bprintf("%s[%u]", devname, (unsigned) minor(rdev));
  }
  return kfd_fmt_other;
}


static enum kfd_fmt_rc kfd_fmt(int fd, char* buf, int* buf_n, int buf_len)
{
  struct stat s;
  int rc;

  rc = ci_sys_fstat(fd, &s);
  if( rc < 0 ) {
    if( errno == EBADF ) {
      bprintf("closed");
      return kfd_fmt_closed;
    }
    bprintf("fstat_failed[errno=%d]", errno);
    return kfd_fmt_failed;
  }

  if( S_ISREG(s.st_mode) )
    bprintf("file");
  else if( S_ISDIR(s.st_mode) )
    bprintf("dir");
  else if( S_ISLNK(s.st_mode) )
    bprintf("symlink");
  else if( S_ISFIFO(s.st_mode) )
    bprintf("pipe");
  else if( S_ISSOCK(s.st_mode) )
    sock_fmt(fd, buf, buf_n, buf_len);
  else if( S_ISCHR(s.st_mode) )
    return char_fmt(fd, s.st_rdev, buf, buf_n, buf_len);
  else if( S_ISBLK(s.st_mode) )
    bprintf("block[%u,%u]", (unsigned) major(s.st_rdev),
            (unsigned) minor(s.st_rdev));
  else
    bprintf("unknown[%x]", (unsigned) s.st_mode);
  return kfd_fmt_other;
}


void citp_fd_dump(int fd)
{
  char buf[256];
  int buf_len = sizeof(buf);
  int buf_n = 0;
  if( kfd_fmt(fd, buf, &buf_n, buf_len) != kfd_fmt_closed )
    ci_log("%d: %s", fd, buf);
}


int citp_fds_dump_max;


void citp_fds_dump(void)
{
  int fd, max = citp_fds_dump_max;
  if( max <= 0 )
    max = citp_fdtable.inited_count;
  for( fd = 0; fd < max; ++fd )
    citp_fd_dump(fd);
}

/**********************************************************************/

/* Set to 1 to make output from citp_fdtable_dump() verbose. */
int citp_fdtable_dump_verbose;


static void ufd_fmt(int fd, char* buf, int* buf_n, int buf_len)
{
  citp_fdinfo_p fdip;
  citp_fdinfo* fdi;
  char s[30];

  if( fd >= citp_fdtable.inited_count ) {
    bprintf("unknown");
    return;
  }
  fdip = citp_fdtable.table[fd].fdip;
  if( fdip_is_passthru(fdip) ) {
    bprintf("passthru");
    return;
  }
  else if( fdip_is_busy(fdip) ) {
    bprintf("busy");
    return;
  }
  else if( fdip_is_unknown(fdip) ) {
    bprintf("unknown");
    return;
  }

  fdi = fdip_to_fdi(fdip);

#if CI_CFG_FD_CACHING
  sprintf(s, "%s%s",
	  fdi->is_special ? "Special":"",
	  fdi->can_cache ? "Cancache":"");
#else
  sprintf(s, "%s",
	  fdi->is_special ? "Special":"");
#endif

  if( fdi == &citp_the_closed_fd ) {
    bprintf("closed_fd[%s]", s);
    return;
  }
  else if( fdi == &citp_the_reserved_fd ) {
    bprintf("reserved_fd[%s]", s);
    return;
  }

  if( fdi->protocol == &citp_tcp_protocol_impl ) {
    citp_sock_fdi* t = fdi_to_sock_fdi(fdi);
    if( citp_fdtable_dump_verbose )
      citp_waitable_dump(t->sock.netif, &t->sock.s->b, "");
    bprintf("tcp[%s]", s);
  }
  else if( fdi->protocol == &citp_udp_protocol_impl ) {
    citp_sock_fdi* u = fdi_to_sock_fdi(fdi);
    if( citp_fdtable_dump_verbose )
      citp_waitable_dump(u->sock.netif, &u->sock.s->b, "");
    bprintf("udp[%s]", s);
  }
  else if( fdi->protocol == &citp_epoll_protocol_impl ) {
    bprintf("epoll[%s]", s);
  }
  else {
    bprintf("bad[%s,%p] *****", s, fdi->protocol);
  }
}


void citp_fdtable_dump_fd(int fd)
{
  enum kfd_fmt_rc kfd_type;
  char buf[256];
  int buf_len = sizeof(buf);
  int the_buf_n = 0;
  int* buf_n = &the_buf_n;

  if( (kfd_type = kfd_fmt(fd, buf, buf_n, buf_len)) == kfd_fmt_closed )
    return;
  bprintf(" ");
  ufd_fmt(fd, buf, buf_n, buf_len);
  ci_log("%d: %s", fd, buf);
}


void citp_fdtable_dump(void)
{
  unsigned fd;

  for( fd = 0; fd < citp_fdtable.size; ++fd )
    citp_fdtable_dump_fd(fd);
}

/*! \cidoxg_end */
