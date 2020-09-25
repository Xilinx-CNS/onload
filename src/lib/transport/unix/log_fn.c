/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
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
  
/*! \cidoxg_lib_transport_unix */
 
#include <internal.h>

/*
** We can't just use the default log function, as it uses the standard I/O
** mechanisms, which we intercept, leading to recursive nastiness.
**
** Hence we jump straight into a syscall.
**
** An alternative would be to use ci_sys_writev() or something, but that
** wouldn't be available as early in the library initialisation.
*/

/**********************************************************************/

#include <ci/internal/syscall.h>


void citp_log_fn_ul(const char* msg)
{
  struct iovec v[2];
  int tmp_fd = 0;

  if( citp.log_fd < 0 ) {
    if( citp.init_level >= CITP_INIT_SYSCALLS ) {
      citp.log_fd = ci_sys_fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC,
                                 CITP_OPTS.fd_base);
      if( citp.log_fd >= 0 && citp_fdtable.table != NULL )
        citp_fdtable.table[citp.log_fd].fdip =
          fdi_to_fdip(&citp_the_reserved_fd);
    }
    if( citp.log_fd < 0 ) {
      citp.log_fd = STDERR_FILENO;
      tmp_fd = 1;
    }
  }

  v[0].iov_base = (void*) msg;
  v[0].iov_len = strlen(v[0].iov_base);
  v[1].iov_base = "\n";
  v[1].iov_len = strlen(v[1].iov_base);

  my_syscall3(writev, citp.log_fd, (long) v, 2); 

  if( tmp_fd )
    citp.log_fd = -1;
}


void citp_log_fn_drv(const char* msg)
{
  if( citp.log_fd < 0 ) {
    /* This fd is already marked as reserved in the fdtable, so there is no
     * need to reserve it again. */
    citp.log_fd = oo_service_fd();
  }

  my_syscall3(ioctl, citp.log_fd, OO_IOC_PRINTK, (long) msg);
}

/*! \cidoxg_end */

