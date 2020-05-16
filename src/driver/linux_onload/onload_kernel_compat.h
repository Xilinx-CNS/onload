/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_KERNEL_COMPAT_H__
#define __ONLOAD_KERNEL_COMPAT_H__

#include <driver/linux_affinity/autocompat.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>


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

/* is_compat_task() was removed for x86 in linux-4.6 */
#ifdef EFRM_NEED_IS_COMPAT_TASK
static inline int is_compat_task(void)
{
#if !defined(CONFIG_COMPAT)
  return 0;
#elif defined(CONFIG_X86_64)
  return test_thread_flag(TIF_IA32);
#elif defined(CONFIG_PPC64)
  return test_thread_flag(TIF_32BIT);
#else
  #error "cannot define is_compat_task() for this architecture"
#endif
}
#endif

/* skb_frag_off() was added in linux-5.4 */
#ifdef EFRM_NEED_SKB_FRAG_OFF
/**
 * skb_frag_off() - Returns the offset of a skb fragment
 * @frag: the paged fragment
 */
static inline unsigned int skb_frag_off(const skb_frag_t *frag)
{
	/* This later got renamed bv_offset (because skb_frag_t is now really
	 * a struct bio_vec), but the page_offset name should work in any
	 * kernel that doesn't already have skb_frag_off defined.
	 */
	return frag->page_offset;
}
#endif


#ifdef EFRM_HAVE_NETDEV_REGISTER_RH
/* The _rh versions of these appear in RHEL7.3.
 * Wrap them to make the calling code simpler.
 */
static inline int efrm_register_netdevice_notifier(struct notifier_block *b)
{
	return register_netdevice_notifier_rh(b);
}

static inline int efrm_unregister_netdevice_notifier(struct notifier_block *b)
{
	return unregister_netdevice_notifier_rh(b);
}

#define register_netdevice_notifier efrm_register_netdevice_notifier
#define unregister_netdevice_notifier efrm_unregister_netdevice_notifier
#endif

#endif /* __ONLOAD_KERNEL_COMPAT_H__ */
