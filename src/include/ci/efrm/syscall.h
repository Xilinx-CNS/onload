/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __CI_EFRM_SYSCALL_H__
#define __CI_EFRM_SYSCALL_H__

#include <linux/version.h>

/* On 4.17+ on x86_64 and ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#if (defined(__x86_64__) || defined(__aarch64__)) &&    \
    (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define EFRM_SYSCALL_PTREGS 1
#endif

extern void** efrm_syscall_table;

#ifdef CONFIG_COMPAT
extern void** efrm_compat_syscall_table;
#endif

#ifdef __x86_64__
/* The address of entry_SYSCALL_64() */
extern void *efrm_entry_SYSCALL_64_addr;
#endif

extern int efrm_syscall_ctor(void);

#endif /* __CI_EFRM_SYSCALL_H__ */
