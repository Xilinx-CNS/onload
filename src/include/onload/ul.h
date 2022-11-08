/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2007-2020 Xilinx, Inc. */
/*! \cidoxg_include_onload */

#ifndef __ONLOAD_UL_H__
#define __ONLOAD_UL_H__

#include <etherfabric/base.h>

#if !defined(__KERNEL__)
# include <onload/unix_intf.h>
#endif

#include <onload/driveraccess.h>

extern const char* oo_device_name[];

/* ef_onload_driver_open - function to be used in the preloaded library.
 *                         It correctly handles open() replacement and
 *                         chroot.
 */

/*! Obtain a driver handle, with CLOEXEC. */
extern int ef_onload_driver_open(ef_driver_handle* nic_out,
                                 enum oo_device_type dev_type,
                                 int do_cloexec) CI_HF;

/*! Move a driver handle to a valid location, setting O_CLOEXEC if needed */
int ef_onload_handle_move_and_do_cloexec(ef_driver_handle* pfd,
                                         int do_cloexec) CI_HF;

/*! Close a driver handle. */
ci_inline int
ef_onload_driver_close(ef_driver_handle fd)
{
  if( ci_sys_close(fd) < 0 )  return -errno;
  return 0;
}

/*! Open and save a driver handle for later cloning. */
extern void ef_driver_save_fd(void) CI_HF;

/*! Get the cached value of "struct stat . st_rdev"  */
extern unsigned long oo_get_st_rdev(enum oo_device_type dev_type);

/* Get onloadfs dev_t value. */
extern dev_t oo_onloadfs_dev_t(void);

#endif /* __ONLOAD_UL_H__ */
/*! \cidoxg_end */
