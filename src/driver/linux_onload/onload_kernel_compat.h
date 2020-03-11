/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_KERNEL_COMPAT_H__
#define __ONLOAD_KERNEL_COMPAT_H__

#include <driver/linux_net/kernel_compat.h>
#include <driver/linux_net/autocompat.h>
#include <driver/linux_affinity/autocompat.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/uaccess.h>


#ifndef __NFDBITS
# define __NFDBITS BITS_PER_LONG
#endif


#ifndef EFRM_HAVE_REINIT_COMPLETION
#define reinit_completion(c) INIT_COMPLETION(*c)
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0))
#define ci_call_usermodehelper call_usermodehelper
#else
extern int
ci_call_usermodehelper(char *path, char **argv, char **envp, int wait);
#endif


#ifndef get_file_rcu
/* Linux <= 4.0 */
#define get_file_rcu(x) atomic_long_inc_not_zero(&(x)->f_count)
#endif

/* init_timer() was removed in Linux 4.15, with timer_setup()
 * replacing it */
#ifndef EFRM_HAVE_TIMER_SETUP
#define timer_setup(timer, callback, flags)     \
  init_timer(timer);                            \
  (timer)->data = 0;                            \
  (timer)->function = &callback;
#endif


/* In linux-5.0 access_ok() lost its first parameter.
 * See bug 85932 comment 7 why we can't redefine access_ok().
 */
#ifndef EFRM_ACCESS_OK_HAS_2_ARGS
#define efab_access_ok(addr, size) access_ok(VERIFY_WRITE, addr, size)
#else
#define efab_access_ok access_ok
#endif


#endif /* __ONLOAD_KERNEL_COMPAT_H__ */
