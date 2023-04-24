#!/bin/bash -eu
# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2013-2020 Xilinx, Inc.
######################################################################

me=$(basename "$0")

######################################################################
# Symbol definition map

function generate_kompat_symbols() {
    echo "
EFRM_HAVE_NETFILTER_INDIRECT_SKB		memtype	struct_nf_hook_ops	hook	include/linux/netfilter.h	unsigned int(*)(unsigned int, struct sk_buff **, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *))
EFRM_HAVE_NETFILTER_HOOK_OPS		memtype	struct_nf_hook_ops	hook	include/linux/netfilter.h	unsigned int(*)(const struct nf_hook_ops *, struct sk_buff *, const struct net_device *, const struct net_device *, int (*)(struct sk_buff *))
EFRM_HAVE_NETFILTER_HOOK_STATE		memtype	struct_nf_hook_state	hook	include/linux/netfilter.h int
EFRM_HAVE_NETFILTER_OPS_HAVE_OWNER	memtype	struct_nf_hook_ops	owner	include/linux/netfilter.h struct module

EFRM_HAVE_REINIT_COMPLETION	symbol	reinit_completion	include/linux/completion.h

EFRM_HAVE_NEW_KALLSYMS	export	kallsyms_on_each_symbol	include/linux/kallsyms.h	kernel/kallsyms.c

EFRM_HAVE_TASK_NSPROXY	symbol	task_nsproxy	include/linux/nsproxy.h

EFRM_HAVE_MSG_ITER	memtype	struct_msghdr	msg_iter	include/linux/socket.h	struct iov_iter

EFRM_SOCK_SENDMSG_NEEDS_LEN	symtype	sock_sendmsg	include/linux/net.h int(struct socket *, struct msghdr *, size_t)
EFRM_SOCK_RECVMSG_NEEDS_BYTES	symtype sock_recvmsg	include/linux/net.h int(struct socket *, struct msghdr *, size_t, int)

EFRM_HAVE_FOP_READ_ITER	memtype	struct_file_operations	read_iter	include/linux/fs.h ssize_t (*) (struct kiocb *, struct iov_iter *)

EFRM_SOCK_CREATE_KERN_HAS_NET	symtype	sock_create_kern	include/linux/net.h int(struct net *, int, int, int, struct socket **)

EFRM_HAVE_SK_SLEEP_FUNC	symtype	sk_sleep	include/net/sock.h wait_queue_head_t *(struct sock *)

# Before 4.8, set_restore_sigmask() is defined by some architectures only, and
# there's a corresponding HAVE_SET_RESTORE_SIGMASK symbol.  On 4.8, the
# implementation is generic and HAVE_SET_RESTORE_SIGMASK has gone.  This compat
# will not find the pre-4.8 arch-specific and fallback implementations of
# set_restore_sigmask() as they were in different places, so it's necessary
# when using this to check for HAVE_SET_RESTORE_SIGMASK as well as for
# EFRM_HAVE_SET_RESTORE_SIGMASK.
EFRM_HAVE_SET_RESTORE_SIGMASK	symbol	set_restore_sigmask	include/linux/sched.h
EFRM_HAVE_SET_RESTORE_SIGMASK1	symbol	set_restore_sigmask	include/linux/sched/signal.h

EFRM_ALLOC_FILE_TAKES_STRUCT_PATH	symtype	alloc_file	include/linux/file.h struct file *(struct path *, fmode_t, const struct file_operations *)
EFRM_ALLOC_FILE_TAKES_CONST_STRUCT_PATH	symtype	alloc_file	include/linux/file.h struct file *(const struct path *, fmode_t, const struct file_operations *)
EFRM_FSTYPE_HAS_INIT_PSEUDO		symbol	init_pseudo	include/linux/pseudo_fs.h
EFRM_HAVE_ALLOC_FILE_PSEUDO		symbol	alloc_file_pseudo	include/linux/file.h

EFRM_NET_HAS_PROC_INUM			member	struct_net proc_inum	include/net/net_namespace.h
EFRM_NET_HAS_USER_NS			member	struct_net user_ns	include/net/net_namespace.h

EFRM_HAVE_OLD_FAULT			memtype struct_vm_operations_struct	fault	include/linux/mm.h	int (*)(struct vm_area_struct *vma, struct vm_fault *vmf)
EFRM_HAVE_NEW_FAULT			memtype struct_vm_operations_struct	fault	include/linux/mm.h	vm_fault_t (*)(struct vm_fault *vmf)

EFRM_HAVE_SCHED_TASK_H			file	include/linux/sched/task.h
EFRM_HAVE_CRED_H			file	include/linux/cred.h

EFRM_OLD_NEIGH_UPDATE	symtype	neigh_update	include/net/neighbour.h int(struct neighbour *neigh, const u8 *lladdr, u8 new, u32 flags)

EFRM_HAVE_WAIT_QUEUE_ENTRY	memtype	struct_wait_queue_entry	flags	include/linux/wait.h	unsigned int
EFRM_HAVE_NF_NET_HOOK	symbol	nf_register_net_hook	include/linux/netfilter.h

EFRM_GUP_RCINT_TASK_SEPARATEFLAGS symtype get_user_pages include/linux/mm.h int(struct task_struct *, struct mm_struct *, unsigned long, int, int, int, struct page **, struct vm_area_struct **)
EFRM_GUP_RCLONG_TASK_SEPARATEFLAGS symtype get_user_pages include/linux/mm.h long(struct task_struct *, struct mm_struct *, unsigned long, unsigned long, int, int, struct page **, struct vm_area_struct **)
EFRM_GUP_RCLONG_TASK_COMBINEDFLAGS symtype get_user_pages include/linux/mm.h long(struct task_struct *, struct mm_struct *, unsigned long, unsigned long, unsigned int, struct page **, struct vm_area_struct **)
EFRM_GUP_RCLONG_NOTASK_COMBINEDFLAGS symtype get_user_pages include/linux/mm.h long(unsigned long, unsigned long, unsigned int, struct page **, struct vm_area_struct **)
EFRM_GUP_HAS_PIN	symbol	pin_user_pages	include/linux/mm.h
EFRM_GUP_HAS_DMA_PINNED	symbol	page_maybe_dma_pinned	include/linux/mm.h

EFRM_HAVE_USERMODEHELPER_SETUP		symbol	call_usermodehelper_setup	include/linux/kmod.h
EFRM_HAVE_USERMODEHELPER_SETUP_INFO	symtype	call_usermodehelper_setup	include/linux/kmod.h	struct subprocess_info*(char *path, char **argv, char **envp, gfp_t gfp_mask, int (*init)(struct subprocess_info *info, struct cred *new), void (*cleanup)(struct subprocess_info *), void *data)

EFRM_RTMSG_IFINFO_EXPORTED		export	rtmsg_ifinfo	include/linux/rtnetlink.h	net/core/rtnetlink.c
EFRM_RTMSG_IFINFO_NEEDS_GFP_FLAGS	symtype	rtmsg_ifinfo	include/linux/rtnetlink.h	void(int type, struct net_device *dev, unsigned int change, gfp_t flags)

EFRM_DEV_GET_BY_NAME_TAKES_NS	symtype	dev_get_by_name	include/linux/netdevice.h	struct net_device*(struct net*, const char* name)

EFRM_HAVE_NS_SYSCTL_TCP_MEM		nsymbol sysctl_tcp_wmem include/net/tcp.h

EFRM_HAVE_TIMER_SETUP                   symbol timer_setup include/linux/timer.h
EFRM_HAVE_READ_SEQCOUNT_LATCH           symbol raw_read_seqcount_latch include/linux/seqlock.h
EFRM_HAVE_WRITE_SEQCOUNT_LATCH          symbol raw_write_seqcount_latch include/linux/seqlock.h
EFRM_HAVE_RBTREE                        symbol rb_link_node_rcu include/linux/rbtree.h
EFRM_HAVE_SKB_METADATA                  symbol skb_metadata_len include/linux/skbuff.h
EFRM_HAVE_BIN2HEX                       symbol bin2hex include/linux/kernel.h
EFRM_HAVE_ALLSYMS_SHOW_VALUE            symbol kallsyms_show_value include/linux/kallsyms.h
EFRM_HAVE_ARRAY_SIZE                    symbol array_size include/linux/overflow.h
EFRM_HAVE_WRITE_ONCE                    symbol WRITE_ONCE include/linux/compiler.h
EFRM_HAVE_INIT_LIST_HEAD_RCU            symbol INIT_LIST_HEAD_RCU include/linux/rculist.h
EFRM_HAVE_S_MIN_MAX                     symbol S32_MIN include/linux/kernel.h include/linux/limits.h

EFRM_RTNL_LINK_OPS_HAS_GET_LINK_NET	member	struct_rtnl_link_ops	get_link_net	include/net/rtnetlink.h

EFRM_ACCESS_OK_HAS_2_ARGS    custom

EFRM_PUT_USER_ACCEPTS_VOLATILE custom

EFRM_IP6_ROUTE_INPUT_LOOKUP_EXPORTED	export	ip6_route_input_lookup	include/net/ip6_route.h	net/ipv6/route.c

EFRM_HAVE_DEV_GET_IF_LINK		symbol	dev_get_iflink	include/linux/netdevice.h

EFRM_IP6_ROUTE_INPUT_LOOKUP_TAKES_SKB	symtype ip6_route_input_lookup	include/net/ip6_route.h	struct dst_entry* (struct net*, struct net_device*, struct flowi6*, const struct sk_buff*, int)

EFRM_RTABLE_HAS_RT_GW4		memtype struct_rtable rt_gw4 include/net/route.h __be32
EFRM_HAVE_FILE_INODE			symbol file_inode include/linux/fs.h

EFRM_NEIGH_USES_REFCOUNTS	memtype struct_neighbour refcnt include/net/neighbour.h refcount_t
EFRM_NEIGH_HAS_PROTOCOL		memtype struct_neighbour protocol include/net/neighbour.h u8

EFRM_HAS_STRUCT_TIMEVAL		member	struct_timeval	tv_sec	include/linux/time.h
EFRM_HAS_STRUCT_TIMESPEC64	member	struct_timespec64	tv_sec	include/linux/time.h

EFRM_HAVE_STRUCT_PROC_OPS	member	struct_proc_ops	proc_open	include/linux/proc_fs.h

EFRM_HAVE_NFPROTO_CONSTANTS	symbol	NFPROTO_NUMPROTO	include/linux/netfilter.h

EFRM_HAVE_IOREMAP_NOCACHE	symbol	ioremap_nocache	include/asm-generic/io.h

EFRM_NEED_IS_COMPAT_TASK	custom

EFRM_NEED_SKB_FRAG_OFF	nsymbol	skb_frag_off	include/linux/skbuff.h

EFRM_HAVE_NETDEV_REGISTER_RH		symbol	register_netdevice_notifier_rh	include/linux/netdevice.h

EFRM_HAVE_MMAP_LOCK_WRAPPERS		file	include/linux/mmap_lock.h
EFRM_HAVE_SOCK_BINDTOINDEX		symbol	sock_bindtoindex	include/net/sock.h

EFRM_MSGHDR_HAS_MSG_CONTROL_USER	member	struct_msghdr	msg_control_user	include/linux/socket.h
EFRM_HAS_SOCKPTR		memtype	struct_proto_ops	setsockopt	include/linux/net.h	int(*)(struct socket *sock, int level, int optname, sockptr_t optval, unsigned int optlen)

EFRM_SYS_CLOSE_EXPORTED 	export	sys_close	include/linux/syscalls.h	fs/open.c
EFRM_CLOSE_FD_EXPORTED		export	close_fd	include/linux/fdtable.h	fs/file.c

EFRM_REMAP_VMALLOC_RANGE_PARTIAL_NEW	symtype	remap_vmalloc_range_partial	include/linux/vmalloc.h int(struct vm_area_struct *vma, unsigned long uaddr, void *kaddr, unsigned long pgoff, unsigned long size)
EFRM_HAS_REMAP_VMALLOC_RANGE_PARTIAL	export	remap_vmalloc_range_partial	include/linux/vmalloc.h

EFRM_HAS_KTIME_GET_REAL_SECONDS	export	ktime_get_real_seconds	include/linux/timekeeping.h	kernel/time/timekeeping.c
EFRM_FILE_HAS_F_EP	member	struct_file	f_ep	include/linux/fs.h
EFRM_HAS_LOOKUP_FD_RCU	symbol	lookup_fd_rcu	include/linux/fdtable.h

EFRM_HAS_FLUSH_DELAYED_FPUT	export	flush_delayed_fput	include/linux/file.h	fs/file_table.c

EFRM_IRQ_FREE_RETURNS_NAME	symtype	free_irq	include/linux/interrupt.h void *(unsigned int, void *)

EFRM_HAS_LINUX_STDARG_H			file	include/linux/stdarg.h
EFRM_TASK_HAS_CPUMASK		member	struct_task_struct	cpus_mask	include/linux/sched.h

EFRM_HAVE_LOWCASE_PDE_DATA symbol pde_data include/linux/proc_fs.h
EFRM_HAVE_NETIF_RX_NI symbol netif_rx_ni include/linux/netdevice.h

EFRM_HAVE_MODULE_MUTEX		symbol	module_mutex	include/linux/module.h
EFRM_HAVE_ITER_UBUF symbol ITER_UBUF include/linux/uio.h

EFRM_CLASS_DEVNODE_DEV_IS_CONST memtype struct_class devnode include/linux/device/class.h char*(*)(const struct device *, umode_t *)

EFRM_HAVE_VM_FLAGS_SET symbol vm_flags_set include/linux/mm.h

EFRM_HAVE_GET_RANDOM_U32	symbol get_random_u32	include/linux/random.h

EFRM_HUGETLB_FILE_SETUP		symtype	hugetlb_file_setup	include/linux/hugetlb.h	struct file *(const char *, size_t, vm_flags_t, int, int)
EFRM_HUGETLB_FILE_SETUP_UCOUNTS	symtype	hugetlb_file_setup	include/linux/hugetlb.h	struct file *(const char *, size_t, vm_flags_t, struct ucounts **, int, int)
EFRM_HUGETLB_FILE_SETUP_USER	symtype	hugetlb_file_setup	include/linux/hugetlb.h	struct file *(const char *, size_t, vm_flags_t, struct user_struct**, int, int)

# TODO move onload-related stuff from net kernel_compat
" | grep -E -v -e '^#' -e '^$' | sed 's/[ \t][ \t]*/:/g'
}

######################################################################
# Implementation for more tricky types


# Depending on the kernel version, the platform and compiler version, 
# access_ok accepts either `unsigned long`, a pointer or both.
# Since kernel_compat.sh treats compiler warnings as errors, 
# passing a mistyped value breaks detecting the number of access_ok
# parameters. Fortunately, NULL is a magic constant that is 
# both pointer and integer as per ISO C.

function do_EFRM_ACCESS_OK_HAS_2_ARGS
{
    test_compile "
#include <linux/uaccess.h>
MODULE_LICENSE(\"GPL\");

int func(unsigned long size)
{
    return access_ok(NULL, size);
}
"
}

function do_EFRM_PUT_USER_ACCEPTS_VOLATILE
{
    test_compile "
#include <linux/uaccess.h>
MODULE_LICENSE(\"GPL\");

int func(unsigned long v, volatile unsigned long *ptr)
{
    return __put_user(v, ptr);
}
"
}

function do_EFRM_NEED_IS_COMPAT_TASK
{
    defer_test_compile neg "
#include <linux/compat.h>
int test(void) { return is_compat_task(); }
"
}

source $(dirname "$0")/kernel_compat_funcs.sh
