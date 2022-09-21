/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file ip_driver.c OS interface to the IP module
** <L5_PRIVATE L5_SOURCE>
** \author  gnb
**  \brief  Package - driver/linux	Linux IP driver support
**   \date  2005/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_driver_linux */
#include <onload/linux_onload.h>
#include <onload/tcp_helper_endpoint.h>
#include <onload/linux_mmap.h>
#include <onload/nic.h>
#include <ci/internal/ip.h>
#include <onload/linux_onload_internal.h>
#include <ci/internal/ip_log.h>
#include <onload/ioctl.h>
#include <onload/tcp_helper_fns.h>
#include <ci/efrm/nic_table.h>
#include "onload_internal.h"
#include <onload/version.h>
#include <onload/oof_interface.h>
#include <onload/cplane_driver.h>
#include "onload_kernel_compat.h"
#include <ci/driver/chrdev.h>
#include <ci/tools.h>
#include "onload_version.h"


/*--------------------------------------------------------------------
 *
 * Licence
 *
 *--------------------------------------------------------------------*/

MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");
MODULE_VERSION(ONLOAD_VERSION);

int inject_kernel_gid = 0;
module_param(inject_kernel_gid, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(inject_kernel_gid,
                 "When Onload receives a packet, but does not have a socket "
                 "to match, Onload can inject the packet into kernel.  "
                 "Because of security consideration, you can disallow such "
                 "injection using this option.\n"
                 "\t-2 : always disallow injection;\n"
                 "\t-1 : always allow injection;\n"
                 "\tother values : group id to allow injection.\n"
                 "Default is 0.\n\n"
                 "Namespace warning: this feature makes it possible to inject "
                 "a packet to the SFC interface from a net namespace "
                 "which owns vlan or macvlan interface over the SFC one.  "
                 "UID namespaces are taken into account when comparing "
                 "the group ids.\n");

/*--------------------------------------------------------------------
 *
 * Module load time variables
 *
 *--------------------------------------------------------------------*/

/* This is legacy and used by macros in ci/driver/efab/debug.h, but
 * currently there is no code that sets it to a non-default value.
 */
int ci_driver_debug_bits;

CI_DEBUG(int no_shared_state_panic;)
CI_DEBUG(EXPORT_SYMBOL(no_shared_state_panic);) /* used in iSCSI (?) */

int oo_debug_bits = __OO_DEBUGERR__;	  /* run-time debug options */
module_param(oo_debug_bits, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_debug_bits, "Onload driver log level");

CI_DEBUG(int oo_debug_code_level;)
CI_DEBUG(module_param(oo_debug_code_level, int, S_IRUGO | S_IWUSR);)

CI_DEBUG(module_param(no_shared_state_panic, int, S_IRUGO | S_IWUSR);)

unsigned ci_tp_log = CI_TP_LOG_DEFAULT;
module_param(ci_tp_log, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ci_tp_log, "Onload transport log level");

module_param(ci_log_options, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(ci_log_options,
		 "Bitmask to turn on CPU, PID and other logging params");

module_param(oof_shared_keep_thresh, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_shared_keep_thresh,
                 "Number of sockets sharing a wildcard filter that will cause "
                 "the filter to persist after the wildcard socket has gone "
                 "away.");

module_param(oof_shared_steal_thresh, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_shared_steal_thresh,
                 "Number of sockets sharing a wildcard filter that will cause "
                 "the filter to persist even when a new wildcard socket needs "
                 "the filter.");

module_param(oof_all_ports_required, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_all_ports_required, 
                 "When set Onload will generate an error if it is unable to "
                 "install a filter on all the up interfaces it needs to. "
                 "In some configurations - e.g. multiple PFs on a single "
                 "physical port - this is not necessary, and setting to 0 will "
                 "allow Onload to tolerate these filter errors.");

module_param(oof_use_all_local_ip_addresses, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oof_use_all_local_ip_addresses,
                 "By default Onload only those local IP addresses which are "
                 "assigned to Onloadable network interfaces.  This option "
                 "allows Onload to handle all local IP addresses regardless "
                 "of the network interface type.\n"
                 "See also cplane_use_prefsrc_as_local module option.");

#ifdef EFRM_DO_USER_NS
/* The code in this function and below are based on the kernel's
 * STANDARD_PARAM_DEF macros, but modified to add in the extra translation
 * between user namespaces.
 */
static int param_gid_set(const char* val,
                         const struct kernel_param* kp)
{
  long gid_ns;
  kgid_t gid_k;
  int rc;

  rc = kstrtol(val, 0, &gid_ns);
  if( rc != 0 || (int)gid_ns != gid_ns )
    return rc < 0 ? rc : -EINVAL;

  /* gid_ns is either a gid to be interpreted based on the current namespace,
   * or one of the special negative values that we accept.
   *
   * kp->arg points to the gid parameter that is being set.
   */
  if( gid_ns >= 0 ) {
    /* Translate our gid value into the global kernel gid */
    gid_k = make_kgid(current_user_ns(), gid_ns);

    /* If we found a valid gid then store the int representation */
    if( gid_valid(gid_k) )
      *((int*)kp->arg) = __kgid_val(gid_k);
    else
      rc = -EINVAL;
  }
  else {
    /* It's a special value */
    *((int*)kp->arg) = gid_ns;
  }

  return rc;
}

static int param_gid_get(char* buffer,
                         const struct kernel_param* kp)
{
  int gid_ns;
  int stored_gid = *((int*)kp->arg);

  /* kp->arg points to the gid param that we're getting.  If it's less
   * than 0 that indicates one of the special values that we can return
   * directly.  Otherwise we need to translate the global kernel gid that
   * we've stored into the namespace of the getter.
  */
  if( stored_gid >= 0 ) {
    /* If there's not a valid mapping of the gid in this namespace then
     * the lookup will return the special overflow gid value, which is what
     * the uid/gid related syscalls use to indicate the lack of mapping.
     */
    gid_ns = from_kgid_munged(current_user_ns(), KGIDT_INIT(stored_gid));
  }
  else {
    gid_ns = stored_gid;
  }

  /* The buffer provided by the kernel is 4K, so we know that any int value
   * can safely be printed into it.
   */
  return scnprintf(buffer, PAGE_SIZE, "%d", gid_ns);
}
#endif

int phys_mode_gid = -2;
#ifdef EFRM_DO_USER_NS
static const struct kernel_param_ops phys_mode_gid_ops = {
  .set = param_gid_set,
  .get = param_gid_get,
};
module_param_cb(phys_mode_gid, &phys_mode_gid_ops, 
                &phys_mode_gid, S_IRUGO | S_IWUSR);
#else
module_param(phys_mode_gid, int, S_IRUGO | S_IWUSR);
#endif
MODULE_PARM_DESC(phys_mode_gid,
                 "Group id which may use physical buffer mode.  "
                 "-2 (default) means \"physical buffer mode forbidden\"; "
                 "-1 means \"any user may use physical buffer mode\".  "
                 "See EF_PACKET_BUFFER_MODE environment variable.");

int scalable_filter_gid = -2;
#ifdef EFRM_DO_USER_NS
static const struct kernel_param_ops scalable_filter_gid_ops = {
  .set = param_gid_set,
  .get = param_gid_get,
};
module_param_cb(scalable_filter_gid, &scalable_filter_gid_ops, 
                &scalable_filter_gid, S_IRUGO | S_IWUSR);
#else
module_param(scalable_filter_gid, int, S_IRUGO | S_IWUSR);
#endif
MODULE_PARM_DESC(scalable_filter_gid,
                 "Group id which may use scalable filters.  "
                 "-2 (default) means \"CAP_NET_RAW required\"; "
                 "-1 means \"any user may use scalable filter mode\".  "
                 "See EF_SCALABLE_FILTERS environment variable.");


/* Module parameter controlling whether to accelerate traffic over veth
 * interfaces. */
bool oo_accelerate_veth = 0;
module_param(oo_accelerate_veth, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(oo_accelerate_veth,
                 "Controls whether Onload will accelerate traffic over veth "
                 "interfaces.  For traffic over a given veth interface to be "
                 "accelerated, its peer must be in the default network "
                 "namespace.");


/**************************************************************************** 
 * 
 * ioctl: customised driver interface
 * 
 ****************************************************************************/ 

#if CI_MEMLEAK_DEBUG_ALLOC_TABLE
#error "this code is broken, fix it if necessary"
ci_noinline int
ioctl_debug_alloc_table (ci_private_t *priv, ulong arg)
{
    if (!ci_is_sysadmin()) return -EPERM;

    {
      struct ci_alloc_info local;

      copy_from_user_ret(&local, (caddr_t) arg,
                         CI_ALLOC_INFO_SIZEOF_CTRL, -EFAULT);
      ci_log("Processing request for memory allocation table: bulk #%u",
             local.bulk);
      if (local.bulk < (ci_alloc_table_sz >> CI_ALLOC_TABLE_BULK_2)) {
          copy_to_user_ret((caddr_t)((unsigned int)arg + 
                                       CI_ALLOC_INFO_SIZEOF_CTRL),
                           ci_alloc_table[local.bulk],
                           sizeof(local.entries),
                           -EFAULT);
      } else {
          return -E2BIG;
      }
    }

    return 0;
}
#endif




/**********************************************************************
 *
 * File ops.
 *
 **********************************************************************/

/****************************************************************************
 *
 * open - create a new file descriptor and hang private state
 *
 ****************************************************************************/
int oo_fop_open(struct inode* inode, struct file* filp)
{
  ci_private_t* priv;

  OO_DEBUG_VERB(ci_log("ci_char_fop_open:"));

  if( (priv = CI_ALLOC_OBJ(ci_private_t)) == NULL )
    return -ENOMEM;

  CI_ZERO(priv);
  priv->_filp = filp;
  priv->fd_flags = 0;
  priv->priv_cp = NULL;
  ci_dllist_init(&priv->dshm_list);

  filp->private_data = (void*) priv;
  filp->f_op = &oo_fops;

  return 0;
}


/****************************************************************************
 *
 * close - cleanup filedescriptor and private state
 *
 ****************************************************************************/
int oo_fop_release(struct inode* inode, struct file* filp)
{
  ci_private_t *priv = (ci_private_t *) filp->private_data;

  OO_DEBUG_VERB(ci_log("ci_char_fop_close "OO_FDFLAG_FMT,
                       OO_FDFLAG_ARG(priv->fd_flags)));

  /* cleanup private state */
  filp->private_data = 0;
  if (priv->thr != NULL) {
    TCP_HELPER_RESOURCE_ASSERT_VALID(priv->thr, 0);
    oo_thr_ref_drop(priv->thr->ref,
                    (priv->fd_flags & OO_FDFLAG_SERVICE) ?
                    OO_THR_REF_FILE : OO_THR_REF_APP);
  }
  if (priv->priv_cp != NULL)
    cp_release(priv->priv_cp);

  onload_priv_free(priv);
  return 0;
}


#if OO_OPS_TABLE_HAS_NAME
# define OP_NAME(op)  ((op)->name)
#else
# define OP_NAME(op)  ""
#endif


/* It seems that gcc is a bit dumb, and if we inline all the case clauses in
 * this function, then it reserves cumulative stack for all of them.  So we
 * call separate functions for each case.
 */
long oo_fop_unlocked_ioctl(struct file* filp, unsigned cmd, unsigned long arg)
{
  ci_private_t *priv = filp->private_data;
  void __user* argp = (void __user*) arg;
  unsigned long local_arg[10];
  oo_operations_table_t* op;
  int ioc_nr = _IOC_NR(cmd);
  void* local_p;
  int rc;

  if( ioc_nr >= OO_OP_CONTIG_END || _IOC_TYPE(cmd) != OO_LINUX_IOC_BASE ) {
    /* If libc is used on our sockets, sometimes it may call TCGETS ioctl to
     * determine whether the file is a tty.
     * tc* functions (tcgetpgrp, tcflush, etc) use direct ioctl syscalls,
     * so TIOC* ioctl go around onload library even if it is used.
     * So, we do not print scary warning for 0x5401(TCGETS)
     * - 0x541A(TIOCSSOFTCAR).
     * Next is FIONREAD(0x541B), which we can support, but do not do this.
     * The only ioctl which was really seen in the real life is TIOCGPGRP.
     */
    if( cmd == OO_IOC_CHECK_VERSION ) {
        /* version check operation details are stored at the end fo the
         * of the oo_operations - tell code below to pull it in from there */
        ioc_nr = OO_OP_CHECK_VERSION_PLACEHOLDER;
    }
    else {
#if ! defined (__PPC__)
      BUILD_BUG_ON(_IOC_TYPE(TIOCSSOFTCAR) != _IOC_TYPE(TCGETS));
      if( _IOC_TYPE(cmd) != _IOC_TYPE(TCGETS) ||
          _IOC_NR(cmd) > _IOC_NR(TIOCSSOFTCAR) ) {
#else 
      /* On PPC TTY ioctls are organized in a complicated way, so for now
       * we just shut up warnings for a few known ioctl codes
       */
      if( cmd != TCGETS && cmd != TIOCGPGRP) {
#endif 
        if( _IOC_TYPE(cmd) != OO_LINUX_IOC_BASE ) {
          OO_DEBUG_ERR(ci_log("%s: Unsupported ioctl cmd=%x type=%d(%d) nr=%d",
                              __FUNCTION__, cmd, _IOC_TYPE(cmd),
                              OO_LINUX_IOC_BASE, ioc_nr));
        }
        else {
          OO_DEBUG_ERR(ci_log("%s: bad cmd=%x nr=%d(%d)",
                              __FUNCTION__, cmd, ioc_nr, OO_OP_END));
        }
      }
      return -EINVAL;
    }
  }
  op = &oo_operations[ioc_nr];
  if( op->ioc_cmd != cmd ) {
    /* If you see this, it is our bug.  Almost certainly means the
     * oo_operations table is out-of-sync with the ioctl numbers.
     */
    ci_log("%s: ioctl table bad cmd=%x nr=%u entry=%x", __FUNCTION__,
           cmd, ioc_nr, op->ioc_cmd);
    return -EINVAL;
  }

  /* Allocate in-kernel memory to keep ioctl arguments. */
  if( _IOC_SIZE(cmd) <= sizeof(local_arg) ) {
    local_p = &local_arg;
    /* In DEBUG case, we'd prefer to get oops instead of spoiled memory.
     * However, let's speed things up in NDEBUG case. */
    CI_DEBUG(if (_IOC_SIZE(cmd) == 0) local_p = NULL;)
  }
  else {
    if( (local_p = kmalloc(_IOC_SIZE(cmd), GFP_KERNEL)) == NULL )
      return -ENOMEM;
    memset(local_p, 0, _IOC_SIZE(cmd));
  }

  OO_DEBUG_OS(ci_log("%s: %s(arg=%lx,%s%s,%d)", __FUNCTION__, OP_NAME(op), arg,
                     _IOC_DIR(cmd) & _IOC_WRITE ? "W" : "",
                     _IOC_DIR(cmd) & _IOC_READ  ? "R" : "", _IOC_SIZE(cmd)));

  /* Copy data from user */
  if( (_IOC_DIR(cmd) & _IOC_WRITE) )
    if( copy_from_user(local_p, argp, _IOC_SIZE(cmd)) ) {
      rc = -EFAULT;
      goto cleanup_out;
    }

  /* Do the operation itself */
  rc = op->handler(priv, local_p);

  /* Copy arguments back to user in case of success and in case of
   * -ERESTARTSYS.  The last case is used in efab_tcp_helper_sock_sleep().
   */
  if( (rc == 0 || rc == -ERESTARTSYS) && (_IOC_DIR(cmd) & _IOC_READ) )
    if( copy_to_user(argp, local_p, _IOC_SIZE(cmd)) ) {
      rc = -EFAULT;
      goto cleanup_out;
    }

 cleanup_out:
  if( local_p != &local_arg ) 
    kfree(local_p);
  OO_DEBUG_OS(ci_log("%s: %s(arg=%lx) => %d", __FUNCTION__,
                     OP_NAME(op), arg, rc));
  return rc;
}

int oo_fop_stack_flush_unlock(struct file *f, fl_owner_t id)
{
  ci_private_t* priv = f->private_data;
  tcp_helper_resource_t* trs;

  if( priv->fd_flags != OO_FDFLAG_STACK )
    return 0;
  if( current == NULL )
    return 0;

  trs = efab_priv_to_thr(priv);
  if( trs->netif.state->exiting_pid != task_tgid_vnr(current) )
    return 0;

  /* This is an exiting task, and it closes the stack file descriptor.
   * Unlock it.
   * See oo_exit_hook().
   */
  trs->netif.state->exiting_pid = 0;
  ci_netif_unlock(&trs->netif);
  return 0;
}

struct file_operations oo_fops = {
  .owner   = THIS_MODULE,
  .open    = oo_fop_open,
  .release = oo_fop_release,
  .unlocked_ioctl = oo_fop_unlocked_ioctl,
  .compat_ioctl = oo_fop_compat_ioctl,
  .mmap    = oo_fop_mmap,

  /* read and poll are used by the cplane server only */
  .read = cp_fop_read,
  .poll = cp_fop_poll,

  /* flush is really needed for a stack fd only */
  .flush = oo_fop_stack_flush_unlock,
};


/****************************************************************************
 *
 * char device ctor and dtor
 *
 ****************************************************************************/

static int onload_sanity_checks(void)
{
  /* This 256 is chosen to match the 256 in ef10_vi_init where we set
   * rx_buffer_len.  If this assertion fails it means the ci_ip_pkt_fmt_s
   * structure doesn't fit into the space reserved for it in the packet
   * buffer.
   */
  CI_BUILD_ASSERT(CI_MEMBER_OFFSET(ci_ip_pkt_fmt, dma_start) <= 256);

  CI_BUILD_ASSERT(CI_CFG_MAX_HWPORTS >= CI_CFG_MAX_INTERFACES);
  return 0;
}


/**********************************************************************
 *
 * Module initialisation.
 *
 **********************************************************************/

static struct ci_chrdev_registration* oo_chrdev;


static int __init onload_module_init(void)
{
  int rc;

  ci_set_log_prefix("[onload] ");
  ci_log("%s %s", ONLOAD_PRODUCT, ONLOAD_VERSION);
  ci_log("%s", ONLOAD_COPYRIGHT);

  /* In library, .owner is not initialised correctly.
   * So, repeat it here. */
  linux_tcp_helper_fops_tcp.owner = THIS_MODULE;
  linux_tcp_helper_fops_udp.owner = THIS_MODULE;
  linux_tcp_helper_fops_pipe_writer.owner = THIS_MODULE;
  linux_tcp_helper_fops_pipe_reader.owner = THIS_MODULE;

  rc = onload_sanity_checks();
  if( rc < 0 )
    goto fail_sanity;

  rc = efab_tcp_driver_ctor();
  if( rc != 0 )
    goto fail_ip_ctor;

  rc = ci_install_proc_entries();
  if( rc < 0 ) {
    ci_log("%s: ERROR: ci_install_proc_entries failed (%d)", __FUNCTION__, rc);
    goto fail_proc;
  }

  /* Onloadfs should be created before the char dev */
  rc = onloadfs_init();
  if(rc < 0 )
    goto failed_onloadfs;

  /* Now register as a character device. */
  rc = create_one_chrdev_and_mknod(0, OO_DEV_NAME, &oo_fops, &oo_chrdev);
  if( rc < 0 )
    goto failed_chrdev;

  rc = oo_epoll_chrdev_ctor();
  if( rc < 0 )
    goto failed_epolldev_ctor;

  rc = oo_cp_driver_ctor();
  if( rc < 0 ) {
    ci_log("%s: oo_cp_driver_ctor failed (%d)", __func__, rc);
    goto failed_cp_ctor;
  }

  /* Now cplane is ready to handle hwport announcements.
   * Let's register hooks. */
  rc = oo_hooks_register();
  if( rc < 0 )
    goto failed_hooks;

  OO_DEBUG_LOAD(ci_log("Onload module initialised successfully."));
  return 0;

  oo_hooks_unregister();
 failed_hooks:
  oo_cp_driver_dtor();
 failed_cp_ctor:
  oo_epoll_chrdev_dtor();
 failed_epolldev_ctor:
  destroy_chrdev_and_mknod(oo_chrdev);
 failed_chrdev:
  onloadfs_fini();
 failed_onloadfs:

  /* User API was available for some time: make sure there are no Onload
   * stacks. */
  efab_tcp_driver_stop();
  ci_uninstall_proc_entries();
 fail_proc:
  /* Remove all NICs.
   * It is possible that efx_dl_register_driver() call was successful, so
   * we have to shut down all NICs even if oo_hooks_register() failed. */
  oo_nic_shutdown();
  efab_tcp_driver_dtor();
 fail_ip_ctor:
 fail_sanity:
  return rc;
}

module_init(onload_module_init);


static void onload_module_exit(void)
{
  OO_DEBUG_LOAD(ci_log("Onload module unloading"));

  /* Destroy User API: char devices. */
  oo_epoll_chrdev_dtor();
  destroy_chrdev_and_mknod(oo_chrdev);
  onloadfs_fini();

  /* Destroy all the stacks.
   * It should be done early, as soon as User API is not available. */
  efab_tcp_driver_stop();

  /* Remove hooks before cplane. */
  oo_hooks_unregister();

  /* By reverse order of creation, we should have destroyed the cplane driver
   * earlier than this, but because stacks have references to cplanes, we need
   * to have flushed the global workqueue in efab_tcp_driver_stop() before
   * calling oo_cp_driver_ctor(). */
  oo_cp_driver_dtor();

  /* Remove the rest of external interfaces to efab_tcp_driver. */
  ci_uninstall_proc_entries();

  /* Remove all NICs when hooks are gone. */
  oo_nic_shutdown();

  efab_tcp_driver_dtor();

  OO_DEBUG_LOAD(ci_log("Onload module unloaded"));
}

module_exit(onload_module_exit);


