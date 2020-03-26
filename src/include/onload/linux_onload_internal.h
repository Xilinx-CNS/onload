/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Internal API of linux onload driver.
**   \date  2005/04/25
**    \cop  (c) Solaraflare Communications
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*
** Do not include this into any files except ones that form part of the
** linux onload driver.
*/

#ifndef __LINUX_ONLOAD_INTERNAL__
#define __LINUX_ONLOAD_INTERNAL__

#include <ci/tools/sysdep.h>
#include <ci/internal/transport_config_opt.h>
#include <onload/primitive_types.h>
#include <onload/debug.h>


extern int phys_mode_gid;

extern struct rw_semaphore handover_rwlock;

extern int inject_kernel_gid;

extern bool oo_accelerate_veth;

/*--------------------------------------------------------------------
 *
 * Linux file operations.
 *
 *--------------------------------------------------------------------*/

extern struct file_operations oo_fops;

extern int  oo_fop_ioctl(struct inode*, struct file*, uint, ulong);
extern long oo_fop_unlocked_ioctl(struct file*, uint, ulong); 
#define oo_fop_compat_ioctl oo_fop_unlocked_ioctl
extern int  oo_fop_mmap(struct file* file, struct vm_area_struct*);
extern int  oo_fop_open(struct inode *inode, struct file*);
extern int  oo_fop_release(struct inode *inode, struct file*);

/* File-ops are external because they can be useful for discovering whether a
 * file structure is one of our's
 */
extern struct file_operations linux_tcp_helper_fops_udp;
extern struct file_operations linux_tcp_helper_fops_tcp;
extern struct file_operations linux_tcp_helper_fops_pipe_reader;
extern struct file_operations linux_tcp_helper_fops_pipe_writer;
extern struct file_operations oo_epoll_fops;
extern struct file_operations linux_tcp_helper_fops_passthrough;
extern struct file_operations linux_tcp_helper_fops_alien;

/*--------------------------------------------------------------------
 *
 * Misc.
 *
 *--------------------------------------------------------------------*/

#if ! CI_CFG_UL_INTERRUPT_HELPER
extern ssize_t
linux_tcp_helper_fop_sendpage(struct file*, struct page*, int offset,
                              size_t size, loff_t* ppos, int more);
extern ssize_t
linux_tcp_helper_fop_sendpage_udp(struct file*, struct page*, int offset,
                                  size_t size, loff_t* ppos, int more);
#endif

/* Decide whether a file descriptor is ours or not */
/* Check if file is our endpoint */
#define FILE_IS_ENDPOINT_SOCK(f) \
    ( (f)->f_op == &linux_tcp_helper_fops_tcp || \
      (f)->f_op == &linux_tcp_helper_fops_udp )
#define FILE_IS_ENDPOINT_SPECIAL(f) \
    ( (f)->f_op == &linux_tcp_helper_fops_passthrough || \
      (f)->f_op == &linux_tcp_helper_fops_alien )
#define FILE_IS_ENDPOINT_PIPE(f) \
    ( (f)->f_op == &linux_tcp_helper_fops_pipe_reader || \
      (f)->f_op == &linux_tcp_helper_fops_pipe_writer )
#define FILE_IS_ENDPOINT_EPOLL(f) \
    ( (f)->f_op == &oo_epoll_fops )

#define FILE_IS_ENDPOINT(f) \
    ( FILE_IS_ENDPOINT_SOCK(f) || FILE_IS_ENDPOINT_PIPE(f) || \
      FILE_IS_ENDPOINT_EPOLL(f) || FILE_IS_ENDPOINT_SPECIAL(f) )


#define CI_LOG_LIMITED(x) do { \
    static uint64_t last_jiffy;                                 \
    static int suppressed;                                      \
    if (jiffies - last_jiffy > HZ) {                            \
      if( suppressed )                                          \
        ci_log("Rate limiting suppressed %d msgs", suppressed); \
      x;                                                        \
      suppressed = 0;                                           \
      last_jiffy = jiffies;                                     \
    }                                                           \
    else {                                                      \
      ++suppressed;                                             \
    }                                                           \
  } while(0)


#endif  /* __LINUX_ONLOAD_INTERNAL__ */
