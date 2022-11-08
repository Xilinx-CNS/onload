/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author ok_sasha 
**  \brief Functions to save/restore onload fd
**   \date  2008/08
**    \cop  (c) Solarflare communications
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_ip */
 
#include <onload/ul.h>
#include <onload/ul/tcp_helper.h>
#include <ci/internal/ip_log.h>
#include <ci/internal/efabcfg.h>
#include <ci/internal/syscall.h>
#include <onload/epoll.h>
#include <onload/version.h>
#include "uk_intf_ver.h"


/*! Names of the devices to open.
 */
const char* oo_device_name[] =
{
  "/dev/" OO_DEV_NAME,
  "/dev/" OO_EPOLL_DEV_NAME
};

static const int clone_ioctl[OO_MAX_DEV] =
{
  OO_IOC_CLONE_FD,
  OO_EPOLL_IOC_CLONE,
};

/*! Saved file descriptors for potential cloning with CI_CLONE_FD ioctl
 *  in the event that ci_open() fails.
 */
static int saved_fd[OO_MAX_DEV];
static int fd_is_saved[OO_MAX_DEV];

/*! Saved struct stat . st_rdev for our devices */
static unsigned long oo_st_rdev[OO_MAX_DEV];


int oo_version_check_ul(ci_fd_t fd)
{
  int rc;
  oo_version_check_t vc;
  strncpy(vc.in_version, onload_short_version, sizeof(vc.in_version));
  strncpy(vc.in_uk_intf_ver, OO_UK_INTF_VER, sizeof(vc.in_uk_intf_ver));
  vc.debug =
#ifdef NDEBUG
    0;
#else
    1;
#endif
  rc = ci_sys_ioctl(fd, OO_IOC_CHECK_VERSION, &vc);
  if( rc == -1 )
    return -errno;
  return rc;
}


/* Please do not add any logging here (else citp_log_fn() could recurse) */
ci_inline int oo_open(ci_fd_t* out, enum oo_device_type dev_type, int flags) {
  ci_fd_t fp  = ci_sys_open(oo_device_name[dev_type], O_RDWR | flags);
  int rc;
  if( fp < 0 )  return -errno;
  if( dev_type == OO_STACK_DEV ) {
    rc = oo_version_check_ul(fp);
    if( rc < 0 ) {
      ci_sys_close(fp);
      return rc;
    }
  }
  *out = fp;
  return 0;
}


int ef_onload_handle_move_and_do_cloexec(ef_driver_handle* pfd, int do_cloexec)
{
  int fd;

  if( do_cloexec )
    fd = ci_sys_fcntl(*pfd, F_DUPFD_CLOEXEC, CITP_OPTS.fd_base);
  else
    fd = ci_sys_fcntl(*pfd, F_DUPFD, CITP_OPTS.fd_base);

  /* If we've successfully done the dup then we've also set CLOEXEC if
   * needed on the new fd, so we're done.
   */
  if( fd >= 0 ) {
    my_syscall3(close, *pfd, 0, 0);
    *pfd = fd;
    return 0;
  }
  else {
    LOG_NV(ci_log("%s: Failed to move fd from %d, rc %d",
                  __func__, *pfd, fd));
  }

  return fd;
}

int ef_onload_driver_open(ef_driver_handle* pfd,
                          enum oo_device_type dev_type,
                          int do_cloexec)
{
  int rc;
  int flags = 0;
  int saved_errno = errno;

  if( do_cloexec )
    flags = O_CLOEXEC;

  ci_assert(pfd);
  rc = oo_open(pfd, dev_type, flags);
  if( rc != 0 && errno != EMFILE && fd_is_saved[dev_type] >= 0 ) {
    ci_clone_fd_t op;
    op.do_cloexec = do_cloexec;
    LOG_NV(ci_log("%s: open failed, but cloning from saved fd", __func__));
    rc = ci_sys_ioctl((ci_fd_t) saved_fd[dev_type],
                      clone_ioctl[dev_type], &op);
    if( rc < 0 )
      return rc;
    errno = saved_errno;
    *pfd = op.fd;
  }

  if( rc != 0 )
    return rc;

  /* Our internal driver handles are not visible to the application.  It may
   * make assumptions about the fd space available to it, and try to dup2/3
   * onto one of our driver fds.  To try and minimise this we allow the user
   * to specify a minimum value for us to use, to try and keep out of their
   * way.
   *
   * We have to be able to cope with them coming along and trying to dup onto
   * one of these fds anyway, as they may not have set the option up.  As such
   * we treat failure to shift the fd as acceptable, and just retain the old
   * one.
   */
  if( *pfd < CITP_OPTS.fd_base )
    if( ef_onload_handle_move_and_do_cloexec(pfd, do_cloexec) == 0 )
      return 0;
      
  return 0;
}


void ef_driver_save_fd(void)
{
  int rc = 0;
  ef_driver_handle fd;
  enum oo_device_type dev_type;

  for( dev_type = 0; dev_type < OO_MAX_DEV; dev_type++ ) {
    if( ! fd_is_saved[dev_type] ) {
      rc = ef_onload_driver_open(&fd, dev_type, 1);
      if( rc == 0 ) {
        saved_fd[dev_type] = fd;
        fd_is_saved[dev_type] = 1;
        LOG_NV(ci_log("%s: Saved fd %d %s for cloning",
                      __func__, (int)fd, oo_device_name[dev_type]));
        if( oo_st_rdev[dev_type] <= 0 ) {
          struct stat st;
          fstat(fd, &st);
          oo_st_rdev[dev_type] = st.st_rdev;
        }
      } else {
        ci_log("%s: failed to open %s - rc=%d",
               __func__, oo_device_name[dev_type], rc);
      }
    }
  }
}

unsigned long oo_get_st_rdev(enum oo_device_type dev_type)
{
  if( oo_st_rdev[dev_type] == 0 ) {
    struct stat st;
    if( stat(oo_device_name[dev_type], &st) == 0 )
      oo_st_rdev[dev_type] = st.st_rdev;
    else {
      LOG_NV(ci_log("%s: ERROR: stats(%s) failed errno=%d",
                    __func__, oo_device_name[dev_type], errno));
      oo_st_rdev[dev_type] = -1;
    }
  }
  return oo_st_rdev[dev_type];
}


dev_t oo_onloadfs_dev_t(void)
{
  static ci_uint32 onloadfs_dev_t = 0;

  if( onloadfs_dev_t == 0 ) {
    int fd;
    if( ef_onload_driver_open(&fd, OO_STACK_DEV, 1) != 0 ) {
      fprintf(stderr, "%s: Failed to open /dev/onload\n", __FUNCTION__);
      return 0;
    }
    if( ci_sys_ioctl(fd, OO_IOC_GET_ONLOADFS_DEV, &onloadfs_dev_t) != 0 ) {
      LOG_E(ci_log("%s: Failed to find onloadfs dev_t", __FUNCTION__));
    }
    ci_sys_close(fd);
  }
  return onloadfs_dev_t;
}


/*! \cidoxg_end */
