/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */
/* In-kernel support for UL Control Plane */
#include <ci/compat.h>
#include <ci/tools.h>
#include <onload/debug.h>
#include <linux/mm.h>
#include <linux/netdevice.h>
#include <linux/spinlock.h>
#include <linux/moduleparam.h>
#include <linux/log2.h>
#include <linux/highuid.h>
#include <net/neighbour.h>
#include <net/arp.h>
#include <net/route.h>
#include <ci/driver/kernel_compat.h>
#include <onload/oof_interface.h> /* for oof_use_all_local_ip_addresses */
#include "../linux_onload/onload_kernel_compat.h"

/* Include transport_config_opt.h with CI_CFG_IPV6 definition first,
 * ci/net/ipvx.h next,
 * cplane headers last.
 *
 * Some code here assumes that in IPv6 build cplane types are aliased to
 * non-cplane, see ci_addr_sh_t.
 */
#include <ci/internal/transport_config_opt.h>
#include <ci/net/ipvx.h>
#include <onload/mmap.h>
#include <cplane/mib.h>
#include <onload/fd_private.h>
#include <onload/tcp_driver.h>
#include <onload/cplane_driver.h>
#include <onload/linux_onload_internal.h>
#include <cplane/server.h>

#include "onload_internal.h"


/*
 * Onload module parameters for cplane.
 */

static int cplane_init_timeout = 10;
module_param(cplane_init_timeout, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_init_timeout,
                 "Time in seconds to wait for the control plane to initialize "
                 "when creating a stack.  This initialization requires that "
                 "the user-level control plane process be spawned if one is "
                 "not already running for the current network namespace.  "
                 "If this parameter is zero, stack-creation will fail "
                 "immediately if the control plane is not ready.  If it is "
                 "negative, stack-creation will block indefinitely in wait "
                 "for the control plane.");


static bool cplane_spawn_server = 1;
module_param(cplane_spawn_server, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_spawn_server,
                 "If true, control plane server processes are spawned "
                 "on-demand.  Typically this occurs when a stack is created "
                 "in a network namespace in which there are no other stacks.");


char* cplane_server_path = NULL;
static int cplane_server_path_set(const char* val,
                                  const struct kernel_param*);
static int cplane_server_path_get(char* buffer,
                                  const struct kernel_param*);
static const struct kernel_param_ops cplane_server_path_ops = {
  .set = cplane_server_path_set,
  .get = cplane_server_path_get,
};
module_param_cb(cplane_server_path, &cplane_server_path_ops, 
                NULL, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_server_path,
                 "Sets the path to the onload_cp_server binary.  Defaults to "
                 DEFAULT_CPLANE_SERVER_PATH" if empty.");


/* cplane_server_params is a purely virtual module option */
static int cplane_server_params_set(const char* val,
                                    const struct kernel_param*);
static int cplane_server_params_get(char* buffer,
                                    const struct kernel_param*);
static const struct kernel_param_ops cplane_server_params_ops = {
  .set = cplane_server_params_set,
  .get = cplane_server_params_get,
};
module_param_cb(cplane_server_params, &cplane_server_params_ops, 
                NULL, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_server_params,
                 "Set additional parameters for the onload_cp_server "
                 "server when it is spawned on-demand.");


static int cplane_server_grace_timeout = 30;
static int 
cplane_server_grace_timeout_set(const char* val,
                                const struct kernel_param* kp);
static const struct kernel_param_ops cplane_server_grace_timeout_ops = {
  .set = cplane_server_grace_timeout_set,
  .get = param_get_int,
};
module_param_cb(cplane_server_grace_timeout, &cplane_server_grace_timeout_ops, 
                &cplane_server_grace_timeout, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_server_grace_timeout,
                 "Time in seconds to wait before killing the control plane "
                 "server after the last user has gone (i.e. the last Onload "
                 "stack in this namespace have been destroyed).  It is used "
                 "with cplane_spawn_server = Y only.");


static int cplane_route_request_limit = 1000;
module_param(cplane_route_request_limit, int, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_route_request_limit,
                 "Queue depth limit for route resolution requests.");


#define CP_ROUTE_REQ_TIMEOUT_DEFAULT_MS 200
static int cplane_route_request_timeout_ms = CP_ROUTE_REQ_TIMEOUT_DEFAULT_MS;
static unsigned long cplane_route_request_timeout_jiffies;
static int 
cplane_route_request_timeout_set(const char* val,
                                 const struct kernel_param* kp);
static const struct kernel_param_ops cplane_route_request_timeout_ms_ops = {
  .set = cplane_route_request_timeout_set,
  .get = param_get_int,
};
module_param_cb(cplane_route_request_timeout_ms, 
                &cplane_route_request_timeout_ms_ops, 
                &cplane_route_request_timeout_ms, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_route_request_timeout_ms,
                 "Time out value for route resolution requests.");


/* Helper for int/bool module parameters which require cp_server restart. */
static int
cplane_server_param_int_set(const char* val, const struct kernel_param* kp);
static int
cplane_server_param_bool_set(const char* val, const struct kernel_param* kp);
static const struct kernel_param_ops cplane_server_param_int_ops = {
  .set = cplane_server_param_int_set,
  .get = param_get_int,
};
static const struct kernel_param_ops cplane_server_param_bool_ops = {
  .set = cplane_server_param_bool_set,
  .get = param_get_bool,
};

/* Module parameters to set uid/gid. This default is overridden by
 * /etc/sysconfig/openonload, except in developer builds */
static int cplane_server_uid = DEFAULT_OVERFLOWUID;
static int cplane_server_gid = DEFAULT_OVERFLOWGID;
module_param_cb(cplane_server_uid, &cplane_server_param_int_ops,
                &cplane_server_uid, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_server_uid,
                 "UID to drop privileges to for the cplane server.");
module_param_cb(cplane_server_gid, &cplane_server_param_int_ops,
                &cplane_server_gid, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_server_gid,
                 "GID to drop privileges to for the cplane server.");


#ifndef NDEBUG
/* RLIMIT_CORE is unsigned, so -1 is "unlimited". */
static int cplane_server_core_size = -1;
module_param_cb(cplane_server_core_size, &cplane_server_param_int_ops,
                &cplane_server_core_size, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_server_core_size,
                 "RLIMIT_CORE value for the cplane server.  You probably want "
                 "to set fs.suid_dumpable sysctl to 2 if you are using this.");
#endif

bool cplane_use_prefsrc_as_local = 0;
module_param_cb(cplane_use_prefsrc_as_local, &cplane_server_param_bool_ops,
                &cplane_use_prefsrc_as_local, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_use_prefsrc_as_local,
                 "If true, use a preferred source of any accelerated route "
                 "in the same way as an address assigned to accelerated "
                 "interface.  This setting allows the acceleration of "
                 "unbound connections via accelerated routes when the "
                 "preferred source is assigned to another network "
                 "interface.\n"
                 "See also oof_use_all_local_ip_addresses module parameter.");


#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
bool cplane_track_xdp = false;
module_param_cb(cplane_track_xdp, &cplane_server_param_bool_ops,
                &cplane_track_xdp, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(cplane_track_xdp,
                 "If true, the Control Plane Server tracks XDP programs "
                 "linked to network interfaces.  It is needed for "
                 "EF_XDP_MODE=compatible mode to function properly.");
#endif


/*
 * Parsed cplane parameters, from cplane_server_params module option.
 */
int cplane_server_params_array_num = 0;
size_t cplane_server_params_array_len = 0;
char** cplane_server_params_array = NULL;

const char* cplane_server_const_params[] = {
#if !CI_CFG_IPV6
    "--"CPLANE_SERVER_NO_IPV6,
#else
#ifndef CONFIG_IPV6_SUBTREES
    "--"CPLANE_SERVER_IPV6_NO_SOURCE,
#endif
#endif /* CI_CFG_IPV6 */
    "--"CPLANE_SERVER_DAEMONISE_CMDLINE_OPT,
    "--"CPLANE_SERVER_HWPORT_NUM_OPT, OO_STRINGIFY(CI_CFG_MAX_HWPORTS),
    "--"CPLANE_SERVER_IPADDR_NUM_OPT, OO_STRINGIFY(CI_CFG_MAX_LOCAL_IPADDRS),
};
#define CP_SERVER_CONST_PARAM_NUM \
  (sizeof(cplane_server_const_params) / sizeof(char*))



/* Protects the state that is not associated with a single cplane instance
 * -- for example, the hash table containing all the instances.  The "link"
 * member of each oo_cplane_handle is protected by that lock, though.  Also,
 * the pool cp_instance_ids of free control plane IDs it protected by its own
 * lock.
 */
static spinlock_t cp_lock;

static ci_id_pool_t cp_instance_ids;
static ci_irqlock_t cp_instance_ids_lock;


/* When onload module is loaded with a parameter, a handler from
 * module_param_call() may be called before module_init() hook.
 * I.e. module-parsing function must ensure that cp_lock is initialized. */
static inline void cp_lock_init(void)
{
  /* The module loading is a single-threaded process which starts at
   * load_module() function.  At the end it calls the module_init() hook,
   * which calls oo_cp_driver_ctor(), and the cp_lock is definitely
   * initialized.  I.e. we do not need to protect cp_lock_inited variable
   * by another spinlock. */
  static bool cp_lock_inited = false;
  if( cp_lock_inited )
    return;
  spin_lock_init(&cp_lock);
  ci_irqlock_ctor(&cp_instance_ids_lock);
  cp_lock_inited = true;
}


struct cp_vm_private_data {
  struct oo_cplane_handle* cp;
  /* This mapping defines the association of a UL server with the kernel
   * control plane instance.  There are in gerenal other mappings held by the
   * server that do not have this flag set. */
#define CP_VM_PRIV_FLAG_SERVERLINK   0x0001ull
  uint64_t cp_vm_flags;

  /* Reference count for the memory mapping. */
  atomic_t cp_vm_refcount;

  union {
    struct {
      /* Forward table associated with this mapping. */
      cp_fwd_table_id table_id;
    } fwd;
    struct {
      off_t map_limit;
    } mib;
  } u;
};


/* All instances of the control plane are stored in a hash table that is
 * indexed by network namespace pointers.  Access to the table is protected by
 * cp_lock.
 *     The implementation of the hash table is modelled on that used for the
 * mm hash table by the trampoline.  Each entry in the table is a doubly-linked
 * list of oo_cplane_handle structures. */
#define CP_INSTANCE_HASH_SIZE  256
static ci_dllist cp_hash_table[CP_INSTANCE_HASH_SIZE];

/* Has the control plane subsystem been fully initialized? */
int cp_initialized = 0;

/* hash_mm() can make stronger assumptions about the alignment of the pointers
 * that it hashes than we can in hash_netns().  About the best we can do is to
 * expect that the kernel is likely to round the addresses up to a power of two
 * no smaller than the object, but not farther, and then to throw away the
 * corresponding number of bits. */
#define HASH_NETNS_SHIFT (ilog2(sizeof(struct oo_cplane_handle) - 1) + 1)
CI_BUILD_ASSERT(__builtin_constant_p(HASH_NETNS_SHIFT));

/* Function to hash a network namespace pointer. */
static inline unsigned hash_netns(const struct net* netns)
{
  ci_uintptr_t t = (ci_uintptr_t) netns;
  return (t >> HASH_NETNS_SHIFT) & (CP_INSTANCE_HASH_SIZE - 1);
}


/* Utility function to find control plane instance for a specified network
 * namespace.  Returns pointer to the control plane instance, or NULL if
 * not found.
 */
static struct oo_cplane_handle* cp_table_lookup(const struct net* netns)
{
  unsigned hash = hash_netns(netns);
  ci_dllink* link;

  ci_assert(spin_is_locked(&cp_lock));

  CI_DLLIST_FOR_EACH(link, &cp_hash_table[hash]) {
    struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                               link, link);
    if( cp->cp_netns == netns )
      return cp;
  }

  return NULL;
}


/* Add a new item to the control plane hash table. */
static void cp_table_insert(struct net* netns, struct oo_cplane_handle* cp)
{
  OO_DEBUG_CPLANE(ci_log("%s: netns=%p cp=%u@%p", __FUNCTION__, netns,
                         cp->cplane_id, cp));

  ci_assert(spin_is_locked(&cp_lock));
  ci_assert(! cp_table_lookup(netns));

  ci_dllist_push(&cp_hash_table[hash_netns(netns)], &cp->link);
}

static void cp_table_remove(struct oo_cplane_handle* cp)
{
  ci_assert(spin_is_locked(&cp_lock));
  ci_assert(spin_is_locked(&cp->cp_handle_lock));
  ci_dllist_remove_safe(&cp->link);
}


/* If this function returns true, then user may call all functions from
 * include/cplane/cplane.h without crash or other unexpected consequence. */
static int cp_is_usable(struct oo_cplane_handle* cp)
{
  return cp->usable;
}

/* Onload requires oof to be populated.  As oof instances
 * might come and go, cplane is asked each time new oof appears to
 * populate it with its state.  The oof_version tracks oof-populate
 * requests and wakes client (onload) once the request is fullfilled
 * or timeout happens (see oo_cp_wait_for_server and oo_cp_oof_ready).
 */
static int
cp_is_usable_for_oof(struct oo_cplane_handle* cp, cp_version_t version)
{
  return cp_is_usable(cp) && version != OO_ACCESS_ONCE(*cp->mib->oof_version);
}


static void cp_destroy(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib = &cp->mib[0];
  cp_fwd_table_id fwd_table_id;

  OO_DEBUG_CPLANE(ci_log("%s:", __FUNCTION__));

  ci_assert(! in_atomic());

  /* The memory mapping held by the server holds a reference to [cp], and when
   * that mapping is destroyed, [cp->server_pid] is released before the
   * reference to [cp] is dropped. */
  ci_assert_equal(cp->server_pid, NULL);

  if( cp->cplane_id != CI_ID_POOL_ID_NONE )
    ci_id_pool_free(&cp_instance_ids, cp->cplane_id, &cp_instance_ids_lock);

  for( fwd_table_id = 0; fwd_table_id < CP_MAX_INSTANCES; ++fwd_table_id ) {
    struct cp_fwd_table* fwd_table = &cp->fwd_tables[fwd_table_id];
    /* fwd rows pointer is equivalent to fwd_blob */
    vfree(fwd_table->rows);
    fwd_table->rows = NULL;
    fwd_table->prefix = NULL;
    vfree(fwd_table->rw_rows);
    fwd_table->rw_rows = NULL;
  }
  vfree(cp->mem);
  cp->mem = NULL;
  kfree(mib->dim);
  mib->dim = NULL;

  cicpplos_dtor(&cp->cppl);

#ifdef EFRM_HAVE_NF_NET_HOOK
  oo_unregister_nfhook(cp->cp_netns);
#endif

  put_net(cp->cp_netns);
  kfree(cp);
}


/* Frees all remaining control plane instances.  There shouldn't be any, and we
 * assert this in debug builds. */
static void cp_table_purge(void)
{
  int bucket;
  for( bucket = 0; bucket < CP_INSTANCE_HASH_SIZE; ++bucket ) {
    ci_dllink* link;
    ci_dllink* temp_link;
    CI_DLLIST_FOR_EACH4(link, &cp_hash_table[bucket], temp_link) {
      struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle, link,
                                                 link);
      ci_log("%s: purging cp for %p refcount=%d", __FUNCTION__, cp->cp_netns,
             atomic_read(&cp->refcount));
      ci_assert(0);
      cp_destroy(cp);
    }
  }
}


static void cp_kill(struct oo_cplane_handle* cp)
{

  cp_table_remove(cp);

  /* Holding cp_handle_lock ensures that cp->server_pid is not going to be
   * released under our feet.  Calling kill_pid() is safe in atomic context. */
  if( cp->server_pid != NULL )
    kill_pid(cp->server_pid, SIGQUIT, 1);

}

static void cp_kill_work(struct work_struct *work)
{
  struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                             destroy_work.work, work);
  spin_lock(&cp_lock);
  spin_lock_bh(&cp->cp_handle_lock);
  cp_kill(cp);
  spin_unlock_bh(&cp->cp_handle_lock);
  spin_unlock(&cp_lock);

  cp_release(cp);
}

/* Should be called under cp_lock only */
static int/*bool*/ cp_cancel_kill(struct oo_cplane_handle* cp)
{
  ci_assert(cp->killed);
  if( cancel_delayed_work(&cp->destroy_work) ) {
    OO_DEBUG_CPLANE(ci_log("%s: Cancel killing work item: cp=%p netns=%p",
                           __FUNCTION__, cp, cp->cp_netns));
    cp->killed = 0;
    return 1;
  }

  OO_DEBUG_CPLANE(ci_log("%s: Failed to cancel killing work item: "
                         "cp=%p netns=%p", __FUNCTION__,
                         cp, cp->cp_netns));
  return 0;
}

static void cp_destroy_work(struct work_struct *work)
{
  struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                             destroy_work.work, work);
  cp_destroy(cp);
}

void cp_release(struct oo_cplane_handle* cp)
{
  int /*bool*/ last_ref_gone;

  spin_lock(&cp_lock);
  spin_lock_bh(&cp->cp_handle_lock);

  OO_DEBUG_CPLANE(ci_log("%s: cp=%p netns=%p refcount=%d", __FUNCTION__, cp,
                         cp->cp_netns, atomic_read(&cp->refcount)));

  last_ref_gone = atomic_dec_and_test(&cp->refcount);
  if( last_ref_gone ) {
    OO_DEBUG_CPLANE(ci_log("%s: last ref gone: cp=%p netns=%p", __FUNCTION__,
                           cp, cp->cp_netns));
    cp_table_remove(cp);
  }
  /* If we have a server and the reference count has dropped to one, there
   * are no clients left, and we should kill the server, but only if Onload is
   * configured to spawn servers automatically. */
  else if( cplane_spawn_server && atomic_read(&cp->refcount) == 1 ) {
    if( cp->killed ) {
      /* If the cp_kill_work is scheduled, then the only refcount belongs to it.
       * We should cancel the delayed work and destroy the cp object. */
      if( cp_cancel_kill(cp) ) {
        OO_DEBUG_CPLANE(ci_log("%s: last ref gone when kill was pending: "
                               "cp=%p netns=%p", __FUNCTION__,
                                cp, cp->cp_netns));
        last_ref_gone = 1;
        cp_table_remove(cp);
      }
      /* else the refcount owner will release it in time */
    }
    else if( cp->server_pid != NULL ) {
      cp->killed = 1;
      atomic_inc(&cp->refcount);
      queue_delayed_work(CI_GLOBAL_WORKQUEUE, &cp->destroy_work,
                         HZ * cplane_server_grace_timeout);
      OO_DEBUG_CPLANE(ci_log("%s: Schedule killing orphaned server: cp=%p "
                             "netns=%p server_pid=%p", __FUNCTION__,
                             cp, cp->cp_netns, cp->server_pid));
    }
    else {
      OO_DEBUG_CPLANE(ci_log("%s:  One reference with no server. --bootstrap? "
                             "cp=%p netns=%p", __FUNCTION__,
                             cp, cp->cp_netns));
    }
  }
  spin_unlock_bh(&cp->cp_handle_lock);
  spin_unlock(&cp_lock);

  if( last_ref_gone ) {
    /* cp_destroy() may not be called in atomic context, but
     * cp_acquire_from_netns_if_exists/cp_release may be called by users from
     * any context.  So, we always use workqueue to call cp_destroy(). */
    INIT_DELAYED_WORK(&cp->destroy_work, cp_destroy_work);
    queue_delayed_work(CI_GLOBAL_WORKQUEUE, &cp->destroy_work, 0);
  }
}


/* /dev/onload file operations: read and poll: */

struct cp_message {
  struct list_head link;
  char buf[0];
};

struct cp_message_buffer {
  struct cp_message meta;
  struct cp_helper_msg data;
} __attribute__((packed));

/* See DEFINE_FOP_READ in lib/efthrm/tcp_helper_linux.c for the "proper way"
 * of doing this for all possible kernels.  We do not need iov&async
 * support here, so we do the easy way. */
ssize_t cp_fop_read(struct file* file, char __user* buf,
                    size_t len, loff_t* off)
{
  ci_private_t* priv = (ci_private_t*) file->private_data;
  struct oo_cplane_handle* cp;
  struct cp_message* msg;
  int rc = cp_acquire_from_priv_if_server(priv, &cp);

  if( rc != 0 )
    return rc;

  spin_lock_bh(&cp->msg_lock);
  if( list_empty(&cp->msg) ) {
    spin_unlock_bh(&cp->msg_lock);
    cp_release(cp);
    return 0;
  }
  msg = list_entry(cp->msg.prev, struct cp_message, link);
  list_del(&msg->link);
  spin_unlock_bh(&cp->msg_lock);

  /* Cplane server MUST proved valid and large buffer */
  ci_assert_ge(len, sizeof(struct cp_helper_msg));
  len = CI_MIN(len, sizeof(struct cp_helper_msg));
  if( copy_to_user(buf, msg->buf, len) )
    len = -EFAULT;

  kfree(msg);
  cp_release(cp);
  return len;
}

unsigned cp_fop_poll(struct file* file, poll_table* wait)
{
  ci_private_t* priv = (ci_private_t*) file->private_data;
  struct oo_cplane_handle* cp;
  int rc = cp_acquire_from_priv_if_server(priv, &cp);
  unsigned ret = 0;

  if( rc != 0 )
    return POLLERR;

  poll_wait(file, &cp->msg_wq, wait);

  /* list_empty does not need msg_lock, only a read barrier */
  ci_rmb();
  if( ! list_empty(&cp->msg) )
    ret = POLLIN | POLLRDNORM;

  cp_release(cp);
  return ret;
}


static cp_fwd_table_id priv_fwd_table_id(ci_private_t* priv)
{
  /* The fwd-table ID that we want is always the cplane ID of the _local_
   * cplane.  If we have a stack, we can look this up directly.  Stackless
   * handles did the lookup when they were associated with a cplane and
   * remembered the result. */
  if( priv->thr != NULL )
    return priv->thr->netif.cplane->cplane_id;
  else
    return priv->fwd_table_id;
}


static struct cp_vm_private_data*
cp_get_vm_data(const struct vm_area_struct* vma)
{
  return (struct cp_vm_private_data*) vma->vm_private_data;
}

static void vm_op_open(struct vm_area_struct* vma)
{
  struct cp_vm_private_data* cp_vm_data = cp_get_vm_data(vma);
  OO_DEBUG_CPLANE(ci_log("%s: cp=%p", __FUNCTION__, cp_vm_data->cp));
  atomic_inc(&cp_vm_data->cp_vm_refcount);

  /* The mappings do not need to hold their own reference to [cp] as they hold
   * a reference to the [struct file] for /dev/onload, which holds a reference
   * to [cp]. */
}

static void vm_op_close(struct vm_area_struct* vma)
{
  struct cp_vm_private_data* cp_vm_data = cp_get_vm_data(vma);

  ci_assert(cp_vm_data);
  ci_assert(cp_vm_data->cp);

  if( atomic_dec_and_test(&cp_vm_data->cp_vm_refcount) ) {
    /* If this mapping is the one that held the association between UL server
     * and kernel, tear that association down. */
    if( cp_vm_data->cp_vm_flags & CP_VM_PRIV_FLAG_SERVERLINK ) {
      struct oo_cplane_handle* cp = cp_vm_data->cp;
      struct pid* server_pid = cp->server_pid;
      struct file* server_file = cp->server_file;
      struct cp_message* msg;
      struct cp_message* t;

      ci_assert(server_pid);

      /* Interlock with cp_kill_work(). */
      spin_lock(&cp_lock);
      spin_lock_bh(&cp->cp_handle_lock);
      cp->server_pid = NULL;
      cp->server_file = NULL;
      cp_table_remove(cp);
      spin_unlock_bh(&cp->cp_handle_lock);
      spin_unlock(&cp_lock);

      put_pid(server_pid);
      fput(server_file);

      /* Free undelivered messages */
      spin_lock_bh(&cp->msg_lock);
      list_for_each_entry_safe(msg, t, &cp->msg, link) {
        list_del(&msg->link);
        kfree(msg);
      }
      spin_unlock_bh(&cp->msg_lock);
    }

    kfree(cp_vm_data);
  }
}

static int cp_fault_mib(struct vm_area_struct *vma, struct vm_fault *vmf)
{
  unsigned long offset = VM_FAULT_ADDRESS(vmf) - vma->vm_start;
  struct cp_vm_private_data* vm_data = cp_get_vm_data(vma);
  struct oo_cplane_handle* cp = vm_data->cp;

  ci_assert(cp->bytes);
  ci_assert(cp->mem);
  ci_assert_lt(offset, cp->bytes);

  if( offset < vm_data->u.mib.map_limit ) {
    vmf->page = vmalloc_to_page(cp->mem + offset);
    get_page(vmf->page);
    return 0;
  }
  else {
    return VM_FAULT_SIGBUS;
  }
}

static int cp_fault_fwd(struct vm_area_struct *vma, struct vm_fault *vmf)
{
  unsigned long offset = VM_FAULT_ADDRESS(vmf) - vma->vm_start;
  struct cp_vm_private_data* vm_data = cp_get_vm_data(vma);
  struct oo_cplane_handle* cp = vm_data->cp;
  struct cp_fwd_row* fwd_rows = cp->fwd_tables[vm_data->u.fwd.table_id].rows;

  vmf->page = vmalloc_to_page((void*) ((uintptr_t) fwd_rows + offset));
  get_page(vmf->page);

  return 0;
}

static int cp_fault_fwd_rw(struct vm_area_struct *vma, struct vm_fault *vmf)
{
  unsigned long offset = VM_FAULT_ADDRESS(vmf) - vma->vm_start;
  struct cp_vm_private_data* vm_data = cp_get_vm_data(vma);
  struct oo_cplane_handle* cp = vm_data->cp;
  cp_fwd_table_id fwd_table_id = vm_data->u.fwd.table_id;
  struct cp_fwd_rw_row* fwd_rw_rows = cp->fwd_tables[fwd_table_id].rw_rows;

  vmf->page = vmalloc_to_page((void*) ((uintptr_t) fwd_rw_rows + offset));
  get_page(vmf->page);

  return 0;
}

static vm_fault_t vm_op_fault(
#ifdef EFRM_HAVE_OLD_FAULT
                       struct vm_area_struct *vma,
#endif
                       struct vm_fault *vmf) {
#ifndef EFRM_HAVE_OLD_FAULT
  struct vm_area_struct *vma = vmf->vma;
#endif
  struct oo_cplane_handle* cp = cp_get_vm_data(vma)->cp;
  oo_mmap_id_t oo_mmap_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  cp_mmap_type_t cp_mmap_type = CP_MMAP_TYPE(oo_mmap_id);

  /* Is the server running?  It is silly to use cplane when server has
   * already gone. */
  if( cp->server_pid == NULL )
    return VM_FAULT_SIGBUS;

  switch( cp_mmap_type ) {
    case OO_MMAP_CPLANE_ID_MIB:
      return cp_fault_mib(vma, vmf);
    case OO_MMAP_CPLANE_ID_FWD:
      return cp_fault_fwd(vma, vmf);
    case OO_MMAP_CPLANE_ID_FWD_RW:
      return cp_fault_fwd_rw(vma, vmf);
    default:
      return VM_FAULT_SIGBUS;
  }
}

static struct vm_operations_struct vm_ops = {
  .open  = vm_op_open,
  .close = vm_op_close,
  .fault = vm_op_fault,
  /* linux/Documentation/filesystems/Locking: ->access is needed only for
   * VM_IO | VM_PFNMAP VMAs. */
};

static int
cp_mmap_mib(struct file* file, struct oo_cplane_handle* cp,
            struct vm_area_struct* vma)
{
  unsigned long bytes = vma->vm_end - vma->vm_start;
  struct cp_vm_private_data* vm_data = cp_get_vm_data(vma);

  if( vma->vm_flags & VM_WRITE ) {
    int rc;

    /* If server is started manually, the user must have CAP_NET_ADMIN
     * to avoid collisions. */
#ifdef EFRM_NET_HAS_USER_NS
    if( ! ns_capable(current->nsproxy->net_ns->user_ns, CAP_NET_ADMIN) )
#else
    if( ! capable(CAP_NET_ADMIN) )
#endif
      return -EPERM;

#ifdef CONFIG_COMPAT
    /* Do not allow cplane server under compat: __copy_siginfo_to_user32()
     * is completely wrong for us and does not copy cp_fwd_key to UL. */
    if( is_compat_task() ) {
      ci_log("The Onload Control Plane server is 32-bit, "
             "while the kernel is 64-bit.  This is not supported.  "
             "Please ensure that "
             "/sys/module/onload/parameters/cplane_server_path points to "
             "the 64-bit onload_cp_server binary.");
      return -EFAULT;
    }
#endif

    /* Cplane process starts.  Let's allocate new cplane instance. */
    rc = 0;
    spin_lock_bh(&cp->cp_handle_lock);
    /* Check that there isn't already a server running for this control plane.
     */
    if( cp->server_pid != NULL ) {
      OO_DEBUG_CPLANE(ci_log("%s: Already have a server: cp=%p "
                             "pid(server)=%d pid(current)=%d", __FUNCTION__,
                             cp, pid_nr(cp->server_pid),
                             task_tgid_nr(current)));
      rc = -EBUSY;
    }
    /* When a previous server exited, then we remove it from the
     * cp_table, and can't get here.  There is no known way get here.
     * See bugs 70351 & 89262 for some history. */
    else if( cp->mem != NULL ) {
      ci_log("%s: cp->mem not NULL: cp=%p", __FUNCTION__, cp);
      ci_assert(0);
      rc = -ENOTEMPTY;
    }
    /* Don't allow a server to run if there are no other references to the
     * control plane instance for this namespace.  We ourselves hold two
     * references: one for the fd and one for the mmap() call.  This is
     * required to prevent control plane servers becoming orphaned in the case
     * where Onload ceases to care about a namespace while a server is starting
     * up, and so the test is only necessary when Onload is configured to spawn
     * the servers itself.
     *     There is a race in the case where two servers are spawned in
     * parallel, but since only one will survive, it will be reaped in short
     * order. */
    else if( cplane_spawn_server && atomic_read(&cp->refcount) <= 2 ) {
      OO_DEBUG_CPLANE(ci_log("%s: No other references: cp=%p", __FUNCTION__,
                             cp));
      rc = -ENONET;
    }
    if( rc < 0 ) {
      spin_unlock_bh(&cp->cp_handle_lock);
      return rc;
    }
    /* get_pid() needn't be done inside the spinlock, so we drop the lock
     * first. */
    cp->server_pid = task_pid(current);
    cp->server_file = file;
    spin_unlock_bh(&cp->cp_handle_lock);
    get_pid(cp->server_pid);
    get_file(file);

    /* Since the association of the kernel state with the UL server has
     * happened here in the mmap() handler, we wish to break that association
     * when the mapping is destroyed.  This means that we need to recognise
     * this mapping as being the one defining the association.  So, set a flag.
     */
    vm_data->cp_vm_flags |= CP_VM_PRIV_FLAG_SERVERLINK;

    /* We need a chunk of memory, continuious in both kernel and UL address
     * spaces.
     * We probably need kvmalloc() https://lwn.net/Articles/711653/ */
    ci_assert_equal(cp->mem, NULL);
    cp->mem = vmalloc(bytes);
    cp->bytes = bytes;
    vm_data->u.mib.map_limit = bytes;
    memset(cp->mem, 0, bytes);
  }
  else {
    ci_private_t* priv = (ci_private_t*) file->private_data;

    /* Client wants to use MIBs. */
    if( cp->mem == NULL )
      return -ENOENT;
    if( ! cp_is_usable(cp) )
      return -ENOENT;
    if( bytes != cp->bytes )
      return -EPERM;

    /* Local clients and suitably privileged users may map the whole mib.
     * Other clients may only map the first portion of the mib.  Remember the
     * boundary now, so that we can enforce it when faulting. */
    if( cp->cplane_id != priv_fwd_table_id(priv) && ! capable(CAP_SYS_ADMIN) )
      vm_data->u.mib.map_limit = cp_find_public_mib_end(cp->mib[0].dim);
    else
      vm_data->u.mib.map_limit = bytes;
    ci_assert(vm_data->u.mib.map_limit);
    ci_assert_le(vm_data->u.mib.map_limit, bytes);
  }
  return 0;
}


static int
__cp_mmap_fwd(struct oo_cplane_handle* cp, struct vm_area_struct* vma,
              cp_fwd_table_id fwd_table_id, void** target_fwd, size_t length)
{
  unsigned long bytes = vma->vm_end - vma->vm_start;

  /* If the specified fwd doesn't exist yet, allocate it. */
  if( *target_fwd == NULL ) {
    /* kmalloc may be asked for too much memory, depending on fwd_mask */
    *target_fwd = vmalloc(CI_ROUND_UP(length, PAGE_SIZE));
    if( *target_fwd == NULL )
      return -ENOMEM;

    memset(*target_fwd, 0, bytes);
  }

  if( bytes != CI_ROUND_UP(length, PAGE_SIZE) ) {
    ci_log("Unexpected size %ld instead of %ld for mapping fwd/fwd_rw "
           "control plane memory", bytes,
           CI_ROUND_UP(length, PAGE_SIZE));
    return -EFAULT;
  }

  cp_get_vm_data(vma)->u.fwd.table_id = fwd_table_id;

  return 0;
}


/* Once the server has filled in the mib->dim structure, we can initialise the
 * kernel's mibs.  We also take a copy of mid->dim in UL-inaccessible memory,
 * so that the cplane server can't crash the kernel. */
int oo_cp_init_kernel_mibs(struct oo_cplane_handle* cp,
                           cp_fwd_table_id* fwd_table_id_out)
{
  struct cp_mibs* mib = &cp->mib[0];
  size_t mib_size;

  ci_assert_equal(task_pid(current), cp->server_pid);

  mib->dim = kmalloc(sizeof(struct cp_tables_dim), GFP_KERNEL);
  if( mib->dim == NULL )
    return -ENOMEM;
  memcpy(mib->dim, cp->mem, sizeof(struct cp_tables_dim));
  cp->mib[1].dim = mib->dim;
  mib_size = cp_init_mibs(cp->mem, mib);
  if( mib_size > cp->bytes ) {
    ci_log("%s: Cplane MIB dimensions 0x%zx do not match with mmaped area size"
           " 0x%lx", __FUNCTION__, mib_size, cp->bytes);
    kfree(mib->dim);
    mib->dim = NULL;
    return -EFAULT;
  }

  *fwd_table_id_out = cp->cplane_id;

  return 0;
}


static int check_fwd_table_id_validity(struct oo_cplane_handle* cp,
                                       cp_fwd_table_id fwd_table_id,
                                       cp_fwd_table_id local_fwd_table_id)
{
  /* Clients are only allowed to map their local table, but servers can map
   * them all. */
  if( cp->server_pid != task_pid(current) &&
      fwd_table_id != CP_FWD_TABLE_ID_INVALID ) {
    ci_assert_equal(fwd_table_id, CP_FWD_TABLE_ID_INVALID);
    return -EINVAL;
  }

  if( fwd_table_id != CP_FWD_TABLE_ID_INVALID &&
      fwd_table_id >= CP_MAX_INSTANCES ) {
    ci_assert_lt(fwd_table_id, CP_MAX_INSTANCES);
    return -EINVAL;
  }

  /* This one doesn't come from UL, so an assertion alone is sufficient. */
  ci_assert_lt(local_fwd_table_id, CP_MAX_INSTANCES);

  return 0;
}


static int
cp_mmap_fwd(struct oo_cplane_handle* cp, struct vm_area_struct* vma,
            cp_fwd_table_id fwd_table_id, cp_fwd_table_id local_fwd_table_id)
{
  struct cp_fwd_table* fwd_table;
  int rc = check_fwd_table_id_validity(cp, fwd_table_id, local_fwd_table_id);
  if( rc != 0 )
    return rc;

  if( fwd_table_id == CP_FWD_TABLE_ID_INVALID )
    fwd_table_id = local_fwd_table_id;

  fwd_table = &cp->fwd_tables[fwd_table_id];

  rc = __cp_mmap_fwd(cp, vma, fwd_table_id,
                     (void**) &fwd_table->rows,
                     cp_calc_fwd_blob_size(cp->mib[0].dim));
  if( rc != 0 )
    return rc;

  if( fwd_table->prefix == NULL ) {
    fwd_table->mask = cp->mib->dim->fwd_mask;
    fwd_table->prefix = cp_fwd_prefix_within_blob(fwd_table->rows,
                                                  cp->mib->dim);
  }

  return 0;
}


static int
cp_mmap_fwd_rw(struct oo_cplane_handle* cp, struct vm_area_struct* vma,
               cp_fwd_table_id fwd_table_id,
               cp_fwd_table_id local_fwd_table_id)
{
  int rc = check_fwd_table_id_validity(cp, fwd_table_id, local_fwd_table_id);
  if( rc != 0 )
    return rc;

  if( ! (vma->vm_flags & VM_WRITE) )
    return -EACCES;

  if( fwd_table_id == CP_FWD_TABLE_ID_INVALID )
    fwd_table_id = local_fwd_table_id;

  rc = __cp_mmap_fwd(cp, vma, fwd_table_id,
                     (void**)&cp->fwd_tables[fwd_table_id].rw_rows,
                     cp_calc_fwd_rw_size(cp->mib[0].dim));
  if( rc == 0 && fwd_table_id == cp->cplane_id ) {
    /* mmapping fwd_rw is the last thing the cplane server does.  Mark server
     * ready to accept notifications from the main netns cp_server. */
    ci_wmb();
    cp->server_initialized = 1;
  }
  return rc;
}


static struct net* netns_from_cp(struct oo_cplane_handle* cp)
{
  return cp->cp_netns;
}


static struct oo_cplane_handle*
__cp_acquire_from_netns_if_exists(const struct net* netns, int revive_killed)
{
  struct oo_cplane_handle* existing_cplane_inst;

  OO_DEBUG_CPLANE(ci_log("%s: netns=%p", __FUNCTION__, netns));

  spin_lock(&cp_lock);
  existing_cplane_inst = cp_table_lookup(netns);
  if( existing_cplane_inst != NULL && cplane_spawn_server &&
      existing_cplane_inst->killed ) {
    if( ! revive_killed || ! cp_cancel_kill(existing_cplane_inst) ) {
      /* There is a cplane server running, but we are going to kill it,
       * and we were not asked to revive. */
      existing_cplane_inst = NULL;
    }
    /* else we have cancelled the kill delayed work and
     * we are inheriting its refcount */
  }
  else if( existing_cplane_inst != NULL )
    atomic_inc(&existing_cplane_inst->refcount);
  spin_unlock(&cp_lock);
  return existing_cplane_inst;
}

static struct oo_cplane_handle* __cp_acquire_from_netns(struct net* netns)
{
  struct oo_cplane_handle* new_cplane_inst;
  struct oo_cplane_handle* existing_cplane_inst;
  int rc;
  const struct cred *orig_creds;
  struct cred *my_creds;
  ci_irqlock_state_t lock_flags;

  existing_cplane_inst = __cp_acquire_from_netns_if_exists(netns, CI_TRUE);
  if( existing_cplane_inst != NULL )
    return existing_cplane_inst;

  /* We need to create a new cplane instance, which may block, so better
   * not be in_atomic() here.
   */
  ci_assert(!in_atomic());

  OO_DEBUG_CPLANE(ci_log("%s: allocating new cplane for netns %p",
                         __FUNCTION__, netns));

  new_cplane_inst = kzalloc(sizeof(struct oo_cplane_handle), GFP_KERNEL);
  if( new_cplane_inst == NULL )
    return NULL;

  /* Invalidate the ID so that we can call cp_destroy() safely on the error
   * paths. */
  new_cplane_inst->cplane_id = CI_ID_POOL_ID_NONE;

#ifdef EFRM_HAVE_NF_NET_HOOK
  if( oo_register_nfhook(netns) != 0 ) {
    ci_log("Failed to register netfilter hook for namespace");
    return NULL;
  }
#endif

  /* Initialise the new instance and take a reference to it. */
  spin_lock_init(&new_cplane_inst->cp_handle_lock);
  init_waitqueue_head(&new_cplane_inst->cp_waitq);
  new_cplane_inst->cp_netns = get_net(netns);
  INIT_DELAYED_WORK(&new_cplane_inst->destroy_work, cp_kill_work);
  atomic_inc(&new_cplane_inst->refcount);
  INIT_LIST_HEAD(&new_cplane_inst->fwd_req);

  spin_lock_init(&new_cplane_inst->msg_lock);
  init_waitqueue_head(&new_cplane_inst->msg_wq);
  INIT_LIST_HEAD(&new_cplane_inst->msg);

  /* cicpplos_ctor() must be called with CAP_NET_RAW. */
  new_cplane_inst->cppl.cp = new_cplane_inst;
  orig_creds = oo_cplane_empower_cap_net_raw(netns, &my_creds);
  rc = cicpplos_ctor(&new_cplane_inst->cppl);
  oo_cplane_drop_cap_net_raw(orig_creds, my_creds);
  if( rc != 0 )
    goto fail;

  ci_irqlock_lock(&cp_instance_ids_lock, &lock_flags);
  new_cplane_inst->cplane_id = ci_id_pool_alloc(&cp_instance_ids);
  ci_irqlock_unlock(&cp_instance_ids_lock, &lock_flags);
  if( new_cplane_inst->cplane_id == CI_ID_POOL_ID_NONE ) {
    ci_log("%s: failed to allocate ID", __FUNCTION__);
    rc = -EBUSY;
    goto fail;
  }

  spin_lock(&cp_lock);

  existing_cplane_inst = cp_table_lookup(netns);
  if( existing_cplane_inst == NULL ) {
    /* Insert the new instance into the global state.  We already hold a
     * reference to it, so nobody can come along and destroy it under our feet,
     * even once we drop the lock. */
    cp_table_insert(netns, new_cplane_inst);
  }
  else {
    /* We raced against someone else creating a new instance.  Free our new
     * instance, and take a reference to theirs instead.  Since we hold the
     * lock, it will not go away before we get a chance to take a reference. */
    OO_DEBUG_CPLANE(ci_log("%s: raced", __FUNCTION__));
    atomic_inc(&existing_cplane_inst->refcount);
    spin_unlock(&cp_lock);
    cp_destroy(new_cplane_inst);
    return existing_cplane_inst;
  }
  spin_unlock(&cp_lock);

  return new_cplane_inst;

 fail:
  cp_destroy(new_cplane_inst);
  ci_log("ERROR: failed to create control plane protocol instance: rc=%d", rc);
  return NULL;
}

struct oo_cplane_handle* cp_acquire_and_sync(struct net* netns,
                                             enum cp_sync_mode mode)
{
  int rc;
  struct oo_cplane_handle* cp = __cp_acquire_from_netns(netns);
  if( cp == NULL )
    return NULL;

  rc = oo_cp_wait_for_server(cp, mode);
  if( rc ) {
    ci_log("%s: cplane didn't sync: rc=%d", __FUNCTION__, rc);
    return NULL;
  }
  return cp;
}

struct oo_cplane_handle* cp_acquire_from_netns_if_exists(const struct net* netns)
{
  struct oo_cplane_handle* cp =
                      __cp_acquire_from_netns_if_exists(netns, CI_FALSE);
  if( cp == NULL )
    return NULL;

  if( ! cp_is_usable(cp) ) {
    cp_release(cp);
    return NULL;
  }
  return cp;
}


/* Associates a priv with the control plane for the specified namespace. */
static int cp_find_or_create(ci_private_t* priv, struct net* netns)
{
  struct oo_cplane_handle* priv_cp;

  /* We mustn't already have a control plane for this priv. */
  if( priv->priv_cp != NULL || priv->thr != NULL )
    return -EALREADY;

  priv_cp = __cp_acquire_from_netns(netns);
  if( priv_cp == NULL )
    return -ENOENT;

  /* Interlock against other people trying to get a cplane handle for this fd.
   */
  spin_lock(&cp_lock);
  if( priv->priv_cp == NULL ) {
    /* Remember the handle.  The reference taken by __cp_acquire_from_netns()
     * now belongs to the priv. */
    priv->priv_cp = priv_cp;
    spin_unlock(&cp_lock);
  }
  else {
    /* Somebody else came along first and stashed a cplane handle inside this
     * fd, so use that instead of the one that we just obtained. */
    OO_DEBUG_CPLANE(ci_log("%s: Raced. priv=%p", __FUNCTION__, priv));
    spin_unlock(&cp_lock);
    cp_release(priv_cp);
    /* We deliberately fail with the same error code as in the initial check
     * in this function.  If there is a race such that we can hit this path,
     * then but for timing we could have failed the earlier check, too. */
    return -EALREADY;
  }

  return 0;
}


/* Takes out a reference to the control plane handle corresponding to a file
 * descriptor.  The caller should call cp_release() when it's finished with it.
 */
static struct oo_cplane_handle* cp_acquire_from_priv(ci_private_t* priv)
{
  OO_DEBUG_CPLANE(ci_log("%s: priv=%p", __FUNCTION__, priv));

  /* If we have a stack, just take a reference to its control plane. */
  if( priv->thr ) {
    ci_assert(priv->thr->netif.cplane);
    atomic_inc(&priv->thr->netif.cplane->refcount);
    return priv->thr->netif.cplane;
  }
  /* If we've used this fd before, it will have a handle already. */
  else if( priv->priv_cp != NULL ) {
    atomic_inc(&priv->priv_cp->refcount);
    return priv->priv_cp;
  }
  else {
    /* If we don't have a stack and we don't already have a handle, we find (or
     * create) a control plane for the current namespace. */

    int rc;

    OO_DEBUG_CPLANE(ci_log("%s: No handle. priv=%p", __FUNCTION__, priv));

    rc = cp_find_or_create(priv, current->nsproxy->net_ns);
    if( rc != 0 && rc != -EALREADY )
      return NULL;
    /* cp_find_or_create() took out a reference that is now owned by the priv.
     * We need to take out another reference on behalf of our caller. */
    atomic_inc(&priv->priv_cp->refcount);
    /* This is the local cplane, so the fwd-table ID is the cplane's own ID. */
    priv->fwd_table_id = priv->priv_cp->cplane_id;
    return priv->priv_cp;
  }

  /* Unreachable. */
  ci_assert(0);
}


/* Verifies that the calling process is a cplane server. If so,
 * returns a reference to the CP handle via 'out'. If not, returns a
 * suitable error code.
 */
extern int
cp_acquire_from_priv_if_server(ci_private_t* priv,
                               struct oo_cplane_handle** out)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);

  if( cp == NULL )
    return -ENOENT;

  if( cp->server_pid != task_pid(current) ) {
    cp_release(cp);
    return -EACCES;
  }

  if( out ) {
    *out = cp;
  }
  else {
    cp_release(cp);
  }

  return 0;
}


int
oo_cplane_mmap(struct file* file, struct vm_area_struct* vma)
{
  ci_private_t* priv = (ci_private_t*) file->private_data;
  struct oo_cplane_handle* cp;
  struct cp_vm_private_data* cp_vm_data;
  int rc;
  oo_mmap_id_t oo_mmap_id = OO_MMAP_OFFSET_TO_MAP_ID(VMA_OFFSET(vma));
  cp_mmap_type_t cp_mmap_type = CP_MMAP_TYPE(oo_mmap_id);
  cp_mmap_param_t cp_mmap_param = CP_MMAP_PARAM(oo_mmap_id);

  ci_assert_equal(OO_MMAP_TYPE(VMA_OFFSET(vma)), OO_MMAP_TYPE_CPLANE);
  cp = cp_acquire_from_priv(priv);
  if( cp == NULL )
    return -ENOMEM;

  cp_vm_data = kzalloc(sizeof(*cp_vm_data), GFP_KERNEL);
  if( cp_vm_data == NULL ) {
    rc = -ENOMEM;
    goto fail;
  }
  cp_vm_data->cp = cp;

  vma->vm_ops = &vm_ops;
  vma->vm_private_data = (void*) cp_vm_data;

  switch( cp_mmap_type ) {
    case OO_MMAP_CPLANE_ID_MIB:
      rc = cp_mmap_mib(file, cp, vma);
      break;
    case OO_MMAP_CPLANE_ID_FWD:
      /* cp_fwd_table_id and cp_mmap_param_t in fact resolve to the same type,
       * but we cast for the sake of clarity. */
      rc = cp_mmap_fwd(cp, vma, (cp_fwd_table_id) cp_mmap_param,
                       priv_fwd_table_id(priv));
      break;
    case OO_MMAP_CPLANE_ID_FWD_RW:
      rc = cp_mmap_fwd_rw(cp, vma, (cp_fwd_table_id) cp_mmap_param,
                          priv_fwd_table_id(priv));
      break;
    default:
      rc = -EINVAL;
  }

  if( rc != 0 )
    goto fail;

  /* Increment refcount: */
  vm_op_open(vma);

 out:
  cp_release(cp);
  return rc;

 fail:
  kfree(cp_vm_data);
  goto out;
}

int oo_cp_get_mib_size(ci_private_t *priv, void *arg)
{
  ci_uint32* arg_p = arg;
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  /* Fixme: get correct cplane instance. */

  *arg_p = cp->bytes;
  rc = cp->bytes == 0 ? -ENOENT : 0;
  cp_release(cp);
  return rc;
}

struct cp_fwd_req {
  struct list_head link;
  struct completion compl;
  int completed;
  int id; /* The id used to identify completion of the request */
};

/* True if the forward request id "large" is larger than "small", and the
 * distance is within limit "cplane_route_request_limit". */
static int/*bool*/ cp_fwd_req_id_ge(int large, int small)
{
  return ((large - small) & CP_FWD_FLAG_REQ_MASK) <
                                            cplane_route_request_limit;
}

/* This is similar to kill_pid_info() in the kernel, but the key difference is
 * that we call send_sig_info() directly, meaning that we bypass the
 * permissions check. */
static int cp_send_sig_info(int sig, struct siginfo* info, struct pid* pid)
{
  int rc = -ESRCH;
  struct task_struct* task;

  rcu_read_lock();
 retry:
  task = pid_task(pid, PIDTYPE_PID);
  if( task != NULL ) {
    /* From linux-4.20, kernel_siginfo should be used instead of siginfo.
     * They are basically the same, so we just cast it. */
    rc = send_sig_info(sig, (void*)info, task);
    if( rc == -ESRCH )
      goto retry;
  }
  rcu_read_unlock();

  return rc;
}


static void
cp_message_enqueue(struct oo_cplane_handle* cp, struct cp_message_buffer* msg)
{
  spin_lock_bh(&cp->msg_lock);
  list_add(&msg->meta.link, &cp->msg);
  spin_unlock_bh(&cp->msg_lock);
  /* spin_unlock implies write barrier, see cp_fop_poll() */

  wake_up_poll(&cp->msg_wq, POLLIN | POLLRDNORM);
}

int
__cp_announce_hwport(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                     ci_hwport_id_t hwport, ci_uint64 nic_flags)
{
  struct cp_message_buffer* msg;

  msg = kmalloc(sizeof(*msg), GFP_ATOMIC);
  if( msg == NULL )
    return -ENOMEM;

  msg->data.hmsg_type = CP_HMSG_SET_HWPORT;
  msg->data.u.set_hwport.ifindex = ifindex;
  msg->data.u.set_hwport.hwport = hwport;
  msg->data.u.set_hwport.nic_flags = nic_flags;
  cp_message_enqueue(cp, msg);

  return 0;
}

int
cp_announce_hwport(const struct efhw_nic* nic, ci_hwport_id_t hwport)
{
  struct oo_cplane_handle* cp;
  int rc;

  cp = __cp_acquire_from_netns_if_exists(dev_net(nic->net_dev), CI_TRUE);
  if( cp == NULL )
    return -ENOENT;

  rc = __cp_announce_hwport(cp, nic->net_dev->ifindex, hwport, nic->flags);
  cp_release(cp);
  return rc;
}


static int
cp_veth_set_fwd_table_id(struct oo_cplane_handle* cp, ci_ifid_t veth_ifindex,
                         cp_fwd_table_id fwd_table_id)
{
  struct cp_message_buffer* msg = kmalloc(sizeof(*msg), GFP_ATOMIC);
  if( msg == NULL )
    return -ENOMEM;
  msg->data.hmsg_type = CP_HMSG_VETH_SET_FWD_TABLE_ID;
  msg->data.u.veth_set_fwd_table_id.veth_ifindex = veth_ifindex;
  msg->data.u.veth_set_fwd_table_id.fwd_table_id = fwd_table_id;

  cp_message_enqueue(cp, msg);

  return 0;
}

static int cp_fwd_resolve(struct oo_cplane_handle* cp, ci_uint32 req_id,
                          cp_fwd_table_id fwd_table_id, struct cp_fwd_key* key)
{
  struct cp_message_buffer* msg = kmalloc(sizeof(*msg), GFP_ATOMIC);
  if( msg == NULL )
    return -ENOMEM;
  msg->data.hmsg_type = CP_HMSG_FWD_REQUEST;
  msg->data.u.fwd_request.id = req_id;
  msg->data.u.fwd_request.fwd_table_id = fwd_table_id;
  memcpy(&msg->data.u.fwd_request.key, key, sizeof(*key));

  cp_message_enqueue(cp, msg);

  return 0;
}

int oo_op_route_resolve(struct oo_cplane_handle* cp, struct cp_fwd_key* key,
                        cp_fwd_table_id fwd_table_id)
{
  int rc;
  struct cp_fwd_req* req;

  if( cp == NULL )
    return -ENOMEM;

  if( ! (key->flag & CP_FWD_KEY_REQ_WAIT) ) {
    atomic_inc(&cp->stats.fwd_req_nonblock);
    rc = cp_fwd_resolve(cp, 0, fwd_table_id, key);
    return rc;
  }

  if( ! cp_fwd_req_id_ge(cp->fwd_req_id, cp->stats.fwd_req_complete) )
    return -ENOSPC;
  req = kzalloc(sizeof(*req), GFP_ATOMIC);
  if( req == NULL )
    return -ENOMEM;
  init_completion(&req->compl);
  spin_lock_bh(&cp->cp_handle_lock);
  req->id = cp->fwd_req_id++ & CP_FWD_FLAG_REQ_MASK;
  list_add_tail(&req->link, &cp->fwd_req);
  spin_unlock_bh(&cp->cp_handle_lock);

  rc = cp_fwd_resolve(cp, req->id, fwd_table_id, key);
  if( rc < 0 )
    return rc;

  wait_for_completion_interruptible_timeout(
                                &req->compl,
                                cplane_route_request_timeout_jiffies);

  spin_lock_bh(&cp->cp_handle_lock);
  if( ! req->completed ) {
    list_del(&req->link);
    cp->stats.fwd_req_complete++;
    if( current && signal_pending(current) ) {
      rc = -EINTR; /* interrupted */
    }
    else {
      rc = -EAGAIN; /* timeout */
      ci_log("WARNING: no response to route request 0x%x "CP_FWD_KEY_FMT".",
             req->id, CP_FWD_KEY_ARGS(key));
      if( cp->server_pid != NULL )
        ci_log("The Onload Control Plane server pid is %d.  "
               "Consider increasing cplane_route_request_timeout_ms "
               "module parameter.",
               pid_vnr(cp->server_pid));
      else
        ci_log("The Onload Control Plane server does not appear "
               "to be running.");
    }
  }
  kfree(req);
  spin_unlock_bh(&cp->cp_handle_lock);

  return rc;
}


typedef int(* cp_wait_check_fn)(struct oo_cplane_handle* cp, cp_version_t arg);

static int
cp_wait_interruptible(struct oo_cplane_handle* cp, cp_wait_check_fn check,
                      cp_version_t arg)
{
  /* Wait for a server.  The wait_event...() functions return immediately if we
   * already have one. */
  if( cplane_init_timeout == 0 ) {
    return check(cp, arg) ? 0 : (cp_is_usable(cp) ? -EAGAIN: -ESRCH);
  }
  else if( cplane_init_timeout < 0 ) {
    return wait_event_interruptible(cp->cp_waitq, check(cp, arg));
    /* wait_event_interruptible() returns zero on success and negative on
     * error. */
  }
  else {
    int rc = wait_event_interruptible_timeout(cp->cp_waitq, check(cp, arg),
                                              cplane_init_timeout * HZ);
    /* wait_event_interruptible_timeout() returns zero on timeout, positive on
     * wake, and negative on error. */
    if( rc == 0 )
      return -ETIMEDOUT;
    else if( rc > 0 )
      return 0;
    return rc;
  }
  /* unreachable */
  ci_assert(0);
  return 0;
}


int oo_cp_oof_sync(struct oo_cplane_handle* cp)
{
  struct cp_mibs* mib = &cp->mib[0];
  int rc;
  cp_version_t ver;

  if( cp == NULL )
    return -ENOMEM;

  atomic_inc(&cp->stats.oof_req_nonblock);
  ver = *cp->mib->oof_version;

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    rc = kill_pid(cp->server_pid, mib->dim->oof_req_sig, 1);
  else
    rc = -ESRCH;
  spin_unlock_bh(&cp->cp_handle_lock);

  return cp_wait_interruptible(cp, cp_is_usable_for_oof, ver);
}

int oo_cp_fwd_resolve_rsop(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  struct cp_fwd_key* key = arg;
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = oo_op_route_resolve(cp, key, priv_fwd_table_id(priv));

  cp_release(cp);
  return rc;
}

int oo_cp_fwd_resolve_complete(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp;
  struct cp_fwd_req* req;
  ci_uint32 req_id = *(ci_uint32*)arg;
  int rc = 0;

  rc = cp_acquire_from_priv_if_server(priv, &cp);
  if( rc < 0 )
    return rc;

  ci_assert_nflags(req_id, ~CP_FWD_FLAG_REQ_MASK);
  if( req_id & ~CP_FWD_FLAG_REQ_MASK ) {
    rc = -EFAULT;
    goto out;
  }

  spin_lock_bh(&cp->cp_handle_lock);
  list_for_each_entry(req, &cp->fwd_req, link) {
    if( req->id == req_id ) {
      list_del(&req->link);
      cp->stats.fwd_req_complete++;
      break;
    }
  }
  if( &req->link == &cp->fwd_req ) {
    rc = -ENOENT;
    CI_DEBUG(ci_log("WARNING: %s: no route requests when asked "
                    "to complete 0x%x; next is 0x%x", __func__,
                    req_id, cp->fwd_req_id));
    goto out_unlock;
  }
  ci_assert_equal(req->id, req_id);

  complete(&req->compl);
  req->completed = 1;

 out_unlock:
  spin_unlock_bh(&cp->cp_handle_lock);

 out:
  cp_release(cp);
  return rc;
}

static int verinfo2arp_req(struct oo_cplane_handle* cp,
                           cicp_verinfo_t* verinfo,
                           struct neigh_table** neigh_table_out,
                           struct net_device** dev_out,
                           void* nexthop_out, cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_table* fwd_table = oo_cp_get_fwd_table(cp, fwd_table_id);
  struct cp_fwd_row* fwd;
  struct cp_fwd_data* data;
  ci_ifid_t ifindex;

  if( ! CICP_ROWID_IS_VALID(verinfo->id) ||
      verinfo->id > fwd_table->mask ) {
    return -ENOENT;
  }

  fwd = cp_get_fwd(fwd_table, verinfo);
  if( ~fwd->flags & CICP_FWD_FLAG_DATA_VALID )
    return -EBUSY;

  data = cp_get_fwd_data(fwd_table, verinfo);

  ifindex = data->base.ifindex;
  ci_assert_impl(cp_fwd_version_matches(fwd_table, verinfo),
                 ifindex != CI_IFID_BAD && ifindex != CI_IFID_LOOP);
  if( ifindex == CI_IFID_BAD || ifindex == CI_IFID_LOOP )
    return -ENOENT;

#if CI_CFG_IPV6
  if( CI_IS_ADDR_IP6(data->base.next_hop) ) {
    *neigh_table_out = &nd_tbl;
    memcpy(nexthop_out, &data->base.next_hop, sizeof(data->base.next_hop));
  }
  else
  /* Cplane is always IPv6-capable, but we do not expect it to work with
   * IPv6 unless Onload is compiled with it. */
#endif
  {
    *neigh_table_out = &arp_tbl;
    memcpy(nexthop_out, &data->base.next_hop.ip4,
           sizeof(data->base.next_hop.ip4));
  }
  ci_rmb();
  if( ! cp_fwd_version_matches(fwd_table, verinfo) )
    return -ENOENT;

  /* Someone is definitely using this route: */
  cp_get_fwd_rw(fwd_table, verinfo)->frc_used = ci_frc64_get();

  *dev_out = dev_get_by_index(netns_from_cp(cp), ifindex);
  if( *dev_out == NULL )
    return -ENOENT;
  return 0;
}

/* X-SPDX-Source-URL: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git */
/* X-SPDX-Source-Tag: v5.5 */
/* X-SPDX-Source-File: net/core/neighbour.c */
/* X-SPDX-License-Identifier: GPL-2.0-or-later */
/* X-SPDX-Comment: Onload sometimes calls neigh_event_send() which results
 *                 in neighbour table change but does not result in netlink
 *                 notification.  To fix this we'd like to call
 *                 neigh_update_notify() which is a static function in
 *                 linux/net/core/neighbour.c */
#include <net/netevent.h>
static int neigh_fill_info(struct sk_buff *skb, struct neighbour *neigh,
			   u32 pid, u32 seq, int type, unsigned int flags)
{
	unsigned long now = jiffies;
	struct nda_cacheinfo ci;
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;

	nlh = nlmsg_put(skb, pid, seq, type, sizeof(*ndm), flags);
	if (nlh == NULL)
		return -EMSGSIZE;

	ndm = nlmsg_data(nlh);
	ndm->ndm_family	 = neigh->ops->family;
	ndm->ndm_pad1    = 0;
	ndm->ndm_pad2    = 0;
	ndm->ndm_flags	 = neigh->flags;
	ndm->ndm_type	 = neigh->type;
	ndm->ndm_ifindex = neigh->dev->ifindex;

	if (nla_put(skb, NDA_DST, neigh->tbl->key_len, neigh->primary_key))
		goto nla_put_failure;

	read_lock_bh(&neigh->lock);
	ndm->ndm_state	 = neigh->nud_state;
	if (neigh->nud_state & NUD_VALID) {
		char haddr[MAX_ADDR_LEN];

		neigh_ha_snapshot(haddr, neigh, neigh->dev);
		if (nla_put(skb, NDA_LLADDR, neigh->dev->addr_len, haddr) < 0) {
			read_unlock_bh(&neigh->lock);
			goto nla_put_failure;
		}
	}

	ci.ndm_used	 = jiffies_to_clock_t(now - neigh->used);
	ci.ndm_confirmed = jiffies_to_clock_t(now - neigh->confirmed);
	ci.ndm_updated	 = jiffies_to_clock_t(now - neigh->updated);
#ifdef ERFM_NEIGH_USES_REFCOUNTS
	/* It is linux>=4.13 */
	ci.ndm_refcnt	 = refcount_read(&neigh->refcnt) - 1;
#else
	ci.ndm_refcnt	 = atomic_read(&neigh->refcnt) - 1;
#endif
	read_unlock_bh(&neigh->lock);

	if (nla_put_u32(skb, NDA_PROBES, atomic_read(&neigh->probes)) ||
	    nla_put(skb, NDA_CACHEINFO, sizeof(ci), &ci))
		goto nla_put_failure;

#ifdef ERFM_NEIGH_HAS_PROTOCOL
	/* It is linux>=5.0 */
	if (neigh->protocol && nla_put_u8(skb, NDA_PROTOCOL, neigh->protocol))
		goto nla_put_failure;
#endif

	nlmsg_end(skb, nlh);
	return 0;

nla_put_failure:
	nlmsg_cancel(skb, nlh);
	return -EMSGSIZE;
}

static inline size_t neigh_nlmsg_size(void)
{
	return NLMSG_ALIGN(sizeof(struct ndmsg))
	       + nla_total_size(MAX_ADDR_LEN) /* NDA_DST */
	       + nla_total_size(MAX_ADDR_LEN) /* NDA_LLADDR */
	       + nla_total_size(sizeof(struct nda_cacheinfo))
#ifdef ERFM_NEIGH_HAS_PROTOCOL
	       + nla_total_size(1)  /* NDA_PROTOCOL */
#endif
	       + nla_total_size(4); /* NDA_PROBES */
}


static void __neigh_notify(struct neighbour *n, int type, int flags,
			   u32 pid)
{
	struct net *net = dev_net(n->dev);
	struct sk_buff *skb;
	int err = -ENOBUFS;

	skb = nlmsg_new(neigh_nlmsg_size(), GFP_ATOMIC);
	if (skb == NULL)
		goto errout;

	err = neigh_fill_info(skb, n, pid, 0, type, flags);
	if (err < 0) {
		/* -EMSGSIZE implies BUG in neigh_nlmsg_size() */
		WARN_ON(err == -EMSGSIZE);
		kfree_skb(skb);
		goto errout;
	}
	rtnl_notify(skb, net, 0, RTNLGRP_NEIGH, NULL, GFP_ATOMIC);
	return;
errout:
	if (err < 0)
		rtnl_set_sk_err(net, RTNLGRP_NEIGH, err);
}

static void neigh_update_notify(struct neighbour *neigh, u32 nlmsg_pid)
{
	call_netevent_notifiers(NETEVENT_NEIGH_UPDATE, neigh);
	__neigh_notify(neigh, RTM_NEWNEIGH, 0, nlmsg_pid);
}
/* X-SPDX-Restore: */


int __oo_cp_arp_resolve(struct oo_cplane_handle* cp,
                        cicp_verinfo_t* op, cp_fwd_table_id fwd_table_id)
{
  struct net_device *dev;
  struct neighbour *neigh;
  int rc;
  char next_hop[sizeof(ci_addr_t)];
  struct neigh_table *neigh_table;

  rc = verinfo2arp_req(cp, op, &neigh_table, &dev, next_hop, fwd_table_id);
  if( rc != 0 )
    return rc;

  neigh = neigh_lookup(neigh_table, next_hop, dev);
  if( neigh == NULL ) {
    neigh = neigh_create(neigh_table, next_hop, dev);
    if(CI_UNLIKELY( IS_ERR(neigh) )) {
      rc = PTR_ERR(neigh);
      goto fail;
    }
  }

  /* We should not ask to re-resolve ARP if it is REACHABLE or in the
   * process of resolving.  Just-created entry has 0 state. */
  if( neigh->nud_state == 0 || neigh->nud_state & (~NUD_VALID | NUD_STALE) ) {
    neigh_event_send(neigh, NULL);
    /* Linux sometimes does not call neigh_update_notify() even when
     * neigh_event_send() changes the neighbour table, so let's do it
     * here: */
    neigh_update_notify(neigh, 0);
  }

  neigh_release(neigh);
 fail:
  dev_put(dev);
  return rc;
}

int oo_cp_arp_resolve_rsop(ci_private_t *priv, void *arg)
{
  struct oo_op_cplane_arp_resolve* op = arg;
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;
  cp_fwd_table_id fwd_table_id;

  if( cp == NULL )
    return -ENOMEM;

  /* We behave slightly differently depending on whether the ioctl was issued
   * from the server: the server specifies the fwd-table ID, but from clients
   * the ID is inferred. */
  if( cp->server_pid == task_pid(current) ) {
    fwd_table_id = op->fwd_table_id;
  }
  else {
    ci_assert_equal(op->fwd_table_id, CP_FWD_TABLE_ID_INVALID);
    fwd_table_id = priv_fwd_table_id(priv);
  }
  rc = __oo_cp_arp_resolve(cp, arg, fwd_table_id);

  cp_release(cp);
  return rc;
}

static int oo_cp_neigh_update(struct neighbour *neigh, int state)
{
  return neigh_update(neigh, NULL, state, NEIGH_UPDATE_F_ADMIN
#ifndef EFRM_OLD_NEIGH_UPDATE
                      /* linux>=4.12 needs nlmsg_pid parameter */
                      , 0
#endif
                      );

}

int __oo_cp_arp_confirm(struct oo_cplane_handle* cp,
                        cicp_verinfo_t* op, cp_fwd_table_id fwd_table_id)
{
  struct cp_fwd_table* fwd_table = oo_cp_get_fwd_table(cp, fwd_table_id);
  struct net_device *dev;
  struct neighbour *neigh;
  int rc;
  char next_hop[sizeof(ci_addr_t)];
  struct neigh_table *neigh_table;

  atomic_inc(&cp->stats.arp_confirm_try);

  rc = verinfo2arp_req(cp, op, &neigh_table, &dev, next_hop, fwd_table_id);
  if( rc != 0 )
    return rc;
  rc = -ENOENT;

  neigh = neigh_lookup(neigh_table, next_hop, dev);
  if( neigh == NULL )
    goto fail1;

  /* We've found a neigh entry based on fwd data.  Have it changed? */
  if( ! cp_fwd_version_matches(fwd_table, op) )
    goto fail2;

  switch( neigh->nud_state ) {
    case NUD_REACHABLE:
      /* We need the neigh timer to be restarted, so we must *change*
       * the state value.  So we change to NUD_DELAY and then back to
       * NUD_REACHABLE. */
      oo_cp_neigh_update(neigh, NUD_DELAY);
      /* fall through */
    case NUD_STALE:
      /* In theory, we should update in NUD_REACHABLE state only, but we
       * may be a bit slow in confirming ARP.  It is not sufficient to set
       * neigh->confirmed, because we need a netlink update to get the new
       * "confirmed" value in the Cplane server. */
      neigh->used = jiffies; /* We're confirming it => we're using it! */
      oo_cp_neigh_update(neigh, NUD_REACHABLE);
      atomic_inc(&cp->stats.arp_confirm_do);
  }
  rc = 0;

 fail2:
  neigh_release(neigh);
 fail1:
  dev_put(dev);
  return rc;
}

int oo_cp_arp_confirm_rsop(ci_private_t *priv, void *arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = __oo_cp_arp_confirm(cp, arg, priv_fwd_table_id(priv));

  cp_release(cp);
  return rc;
}


int
oo_cp_get_active_hwport_mask(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                             cicp_hwport_mask_t *hwport_mask)
{
  struct cp_mibs* mib;
  cp_version_t version;
  cicp_rowid_t id;
  int rc;

  if( cp == NULL )
    return -ENODEV;

  CP_VERLOCK_START(version, mib, cp)

  rc = 0;
  id = cp_llap_find_row(mib, ifindex);

  if( id == CICP_ROWID_BAD ) {
    rc = -ENODEV;
    goto out;
  }
  else {
    *hwport_mask = mib->llap[id].tx_hwports;
  }

 out:
  CP_VERLOCK_STOP(version, mib)

  return rc;
}


static void cplane_route_request_timeout_proceed(void)
{
  cplane_route_request_timeout_jiffies =
                msecs_to_jiffies(cplane_route_request_timeout_ms);
}

/* Returns the path to the onload_cp_server binary as configured by the module
 * parameter. */
static char* cp_get_server_path(void)
{
  return cplane_server_path != NULL && *cplane_server_path != '\0' ?
           cplane_server_path :
           DEFAULT_CPLANE_SERVER_PATH;
}


/* Control whether to switch into namespace of current process. */
#define CP_SPAWN_SERVER_SWITCH_NS 0x00000001u
/* Used at start-of-day to spawn a server that will run without a client. */
#define CP_SPAWN_SERVER_BOOTSTRAP 0x00000002u

/* Spawns a control plane server for the network namespace of the current
 * process. */
static int cp_spawn_server(ci_uint32 flags)
{
  /* The maximum number of parameters that we'll stick on the end of the
   * command line, after building up the invariable and user-specified
   * arguments.  This includes parameter names, parameter values and
   * the terminating NULL.
   *
   * The value can be decremented by 1, because CP_SPAWN_SERVER_SWITCH_NS
   * and CP_SPAWN_SERVER_BOOTSTRAP can't be used together, but let's be
   * safe.
   *
   * We also can use smaller value if !NDEBUG, etc etc.
   */
  const int DIRECT_PARAM_MAX = 13;

  char* ns_file_path = NULL;
  char* path = cp_get_server_path();
#define LOCAL_ARGV_N 20
  char* local_argv[LOCAL_ARGV_N];
#define LOCAL_STRLEN 200
  char local_str[LOCAL_STRLEN];
#define UID_STRLEN 7
  char uid_str[UID_STRLEN];
  char gid_str[UID_STRLEN];
#ifndef NDEBUG
#define UINT32_STRLEN 12
  char core_str[UINT32_STRLEN];
#endif
  char* str = NULL;
  char** argv;
  char* envp[] = { NULL };
  int rc = 0;
  int num; /* a copy of cplane_server_params_array_num */
  int direct_param;
  int direct_param_base;

  OO_DEBUG_CPLANE(ci_log("%s: pid=%d path=%s", __FUNCTION__,
                         task_tgid_nr(current), path));

  ci_assert(current);

  ci_assert(flags & (CP_SPAWN_SERVER_SWITCH_NS | CP_SPAWN_SERVER_BOOTSTRAP));
  ci_assert((flags & (CP_SPAWN_SERVER_SWITCH_NS | CP_SPAWN_SERVER_BOOTSTRAP))
            != (CP_SPAWN_SERVER_SWITCH_NS | CP_SPAWN_SERVER_BOOTSTRAP));
  if( cplane_spawn_server && ! (flags & CP_SPAWN_SERVER_BOOTSTRAP) &&
      current->nsproxy->net_ns == &init_net &&
      cplane_server_grace_timeout != 0 ) {
    flags = CP_SPAWN_SERVER_BOOTSTRAP;
  }

  if( flags & CP_SPAWN_SERVER_SWITCH_NS &&
      current->nsproxy->net_ns != &init_net ) {
    ns_file_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if( ns_file_path == NULL )
      return -ENOMEM;
    snprintf(ns_file_path, PATH_MAX, "/proc/%d/ns/net", task_tgid_nr(current));
  }

  spin_lock(&cp_lock);
  num = cplane_server_params_array_num;
  /* The extra 1 is to account for argv[0]. */
  if( 1 + num + CP_SERVER_CONST_PARAM_NUM + DIRECT_PARAM_MAX <= LOCAL_ARGV_N ) {
    argv = local_argv;
  }
  else {
    argv = kmalloc(sizeof(cplane_server_const_params) +
                   (1 + num + DIRECT_PARAM_MAX) * sizeof(char*),
                   GFP_ATOMIC);
    if( argv == NULL )
      rc = -ENOMEM;
  }
  if( argv != NULL && num > 0 ) {
    ci_assert(cplane_server_params_array);
    if( cplane_server_params_array_len < LOCAL_STRLEN )
      str = local_str;
    else
      str = kmalloc(cplane_server_params_array_len + 1, GFP_ATOMIC);
    if( str != NULL ) {
      int n;

      memcpy(str, cplane_server_params_array[0],
             cplane_server_params_array_len + 1);
      for( n = 0; n < num; n++ ) {
        argv[n + 1] = str +
          (cplane_server_params_array[n] - cplane_server_params_array[0]);
      }
    }
    else {
      rc = -ENOMEM;
    }
  }
  spin_unlock(&cp_lock);
#undef LOCAL_ARGV_N
#undef LOCAL_STRLEN

  if( rc < 0 )
    goto out;
  argv[0] = path;
  memcpy(argv + 1 + num, cplane_server_const_params,
         sizeof(cplane_server_const_params));
  direct_param_base = 1 + num + CP_SERVER_CONST_PARAM_NUM;
  direct_param = 0;

  if( ns_file_path != NULL ) {
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_NS_CMDLINE_OPT;
    argv[direct_param_base + direct_param++] = ns_file_path;
  }
  if( flags & CP_SPAWN_SERVER_BOOTSTRAP )
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_BOOTSTRAP;
  if( cplane_server_uid ) {
    snprintf(uid_str, UID_STRLEN, "%u", cplane_server_uid);
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_UID;
    argv[direct_param_base + direct_param++] = uid_str;
  }
  if( cplane_server_gid ) {
    snprintf(gid_str, UID_STRLEN, "%u", cplane_server_gid);
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_GID;
    argv[direct_param_base + direct_param++] = gid_str;
  }
#undef UID_STRLEN


  if( cplane_use_prefsrc_as_local )
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_PREFSRC_AS_LOCAL;
  if( oof_use_all_local_ip_addresses )
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_ALL_LADDR_AS_LOCAL;

#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
  if( cplane_track_xdp )
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_TRACK_XDP;
#endif

#ifndef NDEBUG
  if( cplane_server_core_size ) {
    snprintf(core_str, sizeof(core_str), "%u", cplane_server_core_size);
    argv[direct_param_base + direct_param++] = "--"CPLANE_SERVER_CORE_SIZE;
    argv[direct_param_base + direct_param++] = core_str;
  }
#endif

  argv[direct_param_base + direct_param++] = NULL;
  ci_assert_le(direct_param, DIRECT_PARAM_MAX);

  rc = ci_call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC
#ifdef UMH_KILLABLE
                                                | UMH_KILLABLE
#endif
                              );

 out:
  kfree(ns_file_path);
  if( argv != local_argv )
    kfree(argv);
  if( str != local_str )
    kfree(str);
  return rc;
}


/* Initialises driver state for the control plane. */
int
oo_cp_driver_ctor(void)
{
  int i;

  for( i = 0; i < CP_INSTANCE_HASH_SIZE; ++i )
    ci_dllist_init(&cp_hash_table[i]);

  cp_lock_init();
  cplane_route_request_timeout_proceed();
  if( cplane_spawn_server && cplane_server_grace_timeout != 0 )
    cp_spawn_server(CP_SPAWN_SERVER_BOOTSTRAP);
  cp_initialized = 1;

  ci_id_pool_ctor(&cp_instance_ids, CP_MAX_INSTANCES, /* initial size */ 8);

  return 0;
}


/* Tears down driver state for the control plane. */
int
oo_cp_driver_dtor(void)
{
  cp_table_purge();
  ci_id_pool_dtor(&cp_instance_ids);
  ci_irqlock_dtor(&cp_instance_ids_lock);
  if( cplane_server_params_array != NULL ) {
    kfree(*cplane_server_params_array);
    kfree(cplane_server_params_array);
  }
  if( cplane_server_path != NULL )
    kfree(cplane_server_path);
  return 0;
}

static int cp_is_usable_hook(struct oo_cplane_handle* cp, cp_version_t ver)
{
  return cp_is_usable(cp);
}

static int
cp_sync_tables_start(struct oo_cplane_handle* cp, enum cp_sync_mode mode,
                     cp_version_t* ver_out)
{
  cp_version_t old_ver = 0;
  int rc = 0;
  struct siginfo info = {};

  info.si_signo = cp->mib->dim->os_sync_sig;
  info.si_code = mode;

  switch( mode ) {
    case CP_SYNC_NONE:
      ci_assert(0);
      break;
    case CP_SYNC_LIGHT:
      old_ver = *cp->mib->idle_version;
      break;
    case CP_SYNC_DUMP:
      old_ver = *cp->mib->dump_version;
      /* Odd version means "dump in progress" - so we should wait for next-next
       * even version. */
      if( old_ver & 1 )
        old_ver++;
      break;

  }

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    cp_send_sig_info(cp->mib->dim->os_sync_sig, &info, cp->server_pid);
  else
    rc = -ESRCH;
  spin_unlock_bh(&cp->cp_handle_lock);

  *ver_out = old_ver;
  return rc;
}
static int cp_dump_synced(struct oo_cplane_handle* cp, cp_version_t old_ver)
{
  return cp_is_usable(cp) &&
         (old_ver ^ OO_ACCESS_ONCE(*cp->mib->dump_version)) & ~1;
}
static int cp_light_synced(struct oo_cplane_handle* cp, cp_version_t old_ver)
{
  return cp_is_usable(cp) &&
         (old_ver ^ OO_ACCESS_ONCE(*cp->mib->idle_version)) & ~1;
}


/* Spawns a control plane server if one is not running, and waits for it to
 * initialise up to a module-parameter-configurable timeout. */
int
oo_cp_wait_for_server(struct oo_cplane_handle* cp, enum cp_sync_mode mode)
{
  int rc;
  cp_version_t ver = 0;
  cp_wait_check_fn fn;

  switch( mode ) {
    case CP_SYNC_NONE:
      fn = cp_is_usable_hook;
      break;
    case CP_SYNC_LIGHT:
      fn = cp_light_synced;
      break;
    case CP_SYNC_DUMP:
      fn = cp_dump_synced;
      break;
    default:
      ci_assert(0);
      return -EINVAL;
  }


  if( cp->server_pid != NULL ) {
    /* Cplane server has been started, but it may be unusable yet.
     * First of all, wait for full setup: */
    if( ! cp_is_usable(cp) ) {
      rc = cp_wait_interruptible(cp, cp_is_usable_hook, 0);
      if( rc < 0 )
        return rc;
      if( mode == CP_SYNC_NONE )
        return 0;
    }

    /* We probably need to re-sync it with OS depending on the mode.
     *
     * The server may disappear under our feet.  We'll misbehave but do not
     * crash in this case. */
    switch( mode ) {
      case CP_SYNC_NONE:
        return cp_wait_interruptible(cp, fn, ver);
      case CP_SYNC_LIGHT:
      case CP_SYNC_DUMP:
        rc = cp_sync_tables_start(cp, mode, &ver);
        if( rc != 0 )
          return rc;
    }
  }
  else if( cplane_spawn_server ) {
    /* We have no server.  Try to spawn one. */
    rc = cp_spawn_server(CP_SPAWN_SERVER_SWITCH_NS);
    if( rc < 0 ) {
      ci_log("%s: Failed to spawn server: rc=%d", __FUNCTION__, rc);
      return rc;
    }

    /* Ploughing on is almost certain to block, so schedule to give ourselves a
     * chance of being lucky. */
    schedule();

    /* We've just spawned server.  It is fresh.  No need to sync with OS. */
    fn = cp_is_usable_hook;
  }
  else {
    return -ENOENT;
  }

  return cp_wait_interruptible(cp, fn, ver);
}


/* Entered via an ioctl in order to wait for the presence of a UL server for
 * the control plane for the current namespace.  If a server already exists, we
 * will return without blocking. */
int oo_cp_wait_for_server_rsop(ci_private_t *priv, void* arg)
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);
  int rc;

  if( cp == NULL )
    return -ENOMEM;

  rc = oo_cp_wait_for_server(cp, *(ci_uint32*)arg);

  cp_release(cp);
  return rc;
}

/* Associate this fd with a control plane handle if it is not yet associated
 * with one.  This association will last until the fd is closed.  Calling this
 * function is not normally necessary as the association is set up just-in-time
 * at other entry points, but doing so explicitly allows a control plane server
 * to start even if there are no clients. */
int oo_cp_link_rsop(ci_private_t *priv, void* arg __attribute__((unused)))
{
  struct oo_cplane_handle* cp = cp_acquire_from_priv(priv);

  if( cp == NULL )
    return -ENOMEM;

  /* This releases the function's reference, but not the priv's reference. */
  cp_release(cp);
  return 0;
}

int oo_cp_ready(ci_private_t *priv, void* arg)
{
  struct oo_cplane_handle* cp;
  int rc = cp_acquire_from_priv_if_server(priv, &cp);

  if( rc < 0 )
    return rc;

  if( ! cp->usable )
    cp->usable = 1;

  /* We've now initialised enough state to allow clients to start trying to
   * talk to us.  Wake up any clients who are waiting for a server. */
  wake_up_interruptible(&cp->cp_waitq);
  cp_release(cp);
  return 0;
}


/* Restart the control plane server in the init_net namepace after the
 * desired configuration has changed. */
static void cp_respawn_init_server(void)
{
  struct oo_cplane_handle* cp;
  if( ! cp_initialized || ! cplane_spawn_server )
    return;

  cp = __cp_acquire_from_netns_if_exists(&init_net, 0);
  if( cp != NULL ) {
    int killed = 0;

    spin_lock(&cp_lock);
    spin_lock_bh(&cp->cp_handle_lock);
    /* For unused cplane server, we expect 3 refcounts:
     * - from the server itself;
     * - from cp_acquire above;
     * - from the server itself because of --bootstrap option.
     */
    if( atomic_read(&cp->refcount) <= 3 ) {
      ci_log("Respawn the control plane server for the main (default) "
             "network namespace to apply new settings...");
      cp_kill(cp);
      killed = 1;
    }
    spin_unlock_bh(&cp->cp_handle_lock);
    spin_unlock(&cp_lock);
    cp_release(cp);

    if( ! killed ) {
      ci_log("New control plane server parameters will be applied after "
             "onload_cp_server restart");
      return;
    }
  }
  if( cplane_server_grace_timeout != 0 )
    cp_spawn_server(CP_SPAWN_SERVER_BOOTSTRAP);
}

static int cplane_server_path_set(const char* val,
                                  const struct kernel_param* kp)
{
  char* old_path;
  char* new_path = kstrdup(skip_spaces(val), GFP_KERNEL);

  if( new_path == NULL )
    return -ENOMEM;

  strim(new_path);

  cp_lock_init();
  spin_lock(&cp_lock);
  old_path = cplane_server_path;
  cplane_server_path = new_path;
  spin_unlock(&cp_lock);

  if( old_path == NULL || strcmp(old_path, new_path) != 0 )
    cp_respawn_init_server();

  kfree(old_path);

  return 0;
}


static int cplane_server_path_get(char* buffer,
                                  const struct kernel_param* kp)
{
  char* path;
  int len;

  spin_lock(&cp_lock);
  path = cp_get_server_path();
  /* The magic 4096 is documented in linux/moduleparam.h. */
  strncpy(buffer, path, 4096);
  len = strnlen(buffer, 4096);
  spin_unlock(&cp_lock);

  return len;
}

static int cp_proc_stats_show(struct seq_file *m,
                              void *private __attribute__((unused)))
{
  struct oo_cplane_handle* cp =
            cp_acquire_from_netns_if_exists(current->nsproxy->net_ns);
  if( cp == NULL ) {
    seq_printf(m, "No control plane instance in this net namespace.\n");
    return 0;
  }

  seq_printf(m, "Route requests (non-waiting):\t%d\n",
             atomic_read(&cp->stats.fwd_req_nonblock));
  seq_printf(m, "Route requests (waiting):\t%d\n", cp->fwd_req_id);
  seq_printf(m, "Route requests queue depth:\t%d\n",
             cp->fwd_req_id - cp->stats.fwd_req_complete);
  seq_printf(m, "Filter engine requests (non-waiting):\t%d\n",
             atomic_read(&cp->stats.oof_req_nonblock));
  seq_printf(m, "ARP confirmations (tried):\t%d\n",
             atomic_read(&cp->stats.arp_confirm_try));
  seq_printf(m, "ARP confirmations (successful):\t%d\n",
             atomic_read(&cp->stats.arp_confirm_do));

  cp_release(cp);
  return 0;
}

int cp_proc_stats_open(struct inode *inode, struct file *file)
{
  return single_open(file, cp_proc_stats_show, NULL);
}


struct cp_pid_seq_state {
  ci_dllink* cp;
  loff_t offset;
  unsigned bucket;
};


static void* cp_server_pids_next(struct seq_file* s, void* state_,
                                 loff_t* pos)
{
  struct cp_pid_seq_state* state = state_;

  state->offset++;

  state->cp = state->cp->next;

  while( ci_dllist_is_anchor(&cp_hash_table[state->bucket], state->cp) &&
         (state->bucket < CP_INSTANCE_HASH_SIZE) ) {
    state->bucket++;
    state->cp = ci_dllist_head(&cp_hash_table[state->bucket]);
  }

  *pos = state->offset;

  if( state->bucket == CP_INSTANCE_HASH_SIZE ) {
    /* End of file. */
    kfree(state);
    return NULL;
  }

  return state;
}


static void* cp_server_pids_start(struct seq_file* s, loff_t* pos)
{
  struct cp_pid_seq_state* state;
  loff_t i;

  spin_lock(&cp_lock);

  state = kmalloc(sizeof(struct cp_pid_seq_state), GFP_ATOMIC);
  if ( !state ) {
    return NULL;
  }

  state->offset = 0;

  for( state->bucket = 0;
       state->bucket < CP_INSTANCE_HASH_SIZE;
       state->bucket++ ) {
    if( ci_dllist_not_empty(&cp_hash_table[state->bucket]) )
      break;
  }

  if( state->bucket == CP_INSTANCE_HASH_SIZE ) {
    /* File is empty. */
    kfree(state);
    return NULL;
  }

  state->cp = ci_dllist_head(&cp_hash_table[state->bucket]);

  for( i = 0; i < *pos; )
    if( cp_server_pids_next(s, state, &i) == NULL )
      return NULL;

  return state;
}


static void cp_server_pids_stop(struct seq_file* s, void* state_)
{
  struct cp_pid_seq_state* state = state_;

  if( state != NULL ) {
    kfree(state);
  }

  spin_unlock(&cp_lock);
}


static int cp_server_pids_show(struct seq_file* s, void* state_)
{
  struct cp_pid_seq_state* state = state_;
  struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                             link, state->cp);
  pid_t pid = 0;

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    pid = pid_vnr(cp->server_pid);
  spin_unlock_bh(&cp->cp_handle_lock);

  if( pid != 0 )
    seq_printf(s, "%d\n", pid);

  return 0;
}


static struct seq_operations cp_server_pids_ops = {
  .start = cp_server_pids_start,
  .next = cp_server_pids_next,
  .stop = cp_server_pids_stop,
  .show = cp_server_pids_show
};

extern int cp_server_pids_open(struct inode *inode, struct file *file) {
  return seq_open(file, &cp_server_pids_ops);
}


static char* get_next_word(char* str)
{
  for( ; *str != '\0'; str++ ) {
    if( isspace(*str) ) {
      *str = '\0';
      return skip_spaces(str + 1);
    }
  }
  return NULL;
}

static int
cplane_server_params_set(const char* val,
                         const struct kernel_param* kp)
{
  char** old;
  char** new = NULL;
  int n = 0;
  size_t old_len;
  size_t len = 0;
  char* new_string = kstrdup(skip_spaces(val), GFP_KERNEL);

  if( new_string == NULL )
    return -ENOMEM;

  strim(new_string);
  if( new_string[0] == '\0' ) {
    kfree(new_string);
  }
  else {
    /* We need to allocate an array of the size of the word number in the
     * new_string.  strlen(new_string) is an over-estimation for the
     * number of words. */
    len = strlen(new_string);
    new = kmalloc(len * sizeof(void*), GFP_KERNEL);
    if( new == NULL ) {
      kfree(new_string);
      return -ENOMEM;
    }
    for( n = 0; new_string != NULL; n++) {
      new[n] = new_string;
      new_string = get_next_word(new_string);
    }
  }

  cp_lock_init();
  spin_lock(&cp_lock);
  old = cplane_server_params_array;
  old_len = cplane_server_params_array_len;
  cplane_server_params_array = new;
  cplane_server_params_array_num = n;
  cplane_server_params_array_len = len;
  spin_unlock(&cp_lock);

  if( (old == NULL) != (new == NULL) || old_len != len ||
      (old != NULL && new != NULL && memcmp(*old, *new, len) != 0) )
    cp_respawn_init_server();

  if( old != NULL ) {
    kfree(*old);
    kfree(old);
  }

  return 0;
}

static int
cplane_server_params_get(char* buffer,
                         const struct kernel_param* kp)
{
  char* s;
  size_t add, len;
  int n;
  /* The magic 4096 is documented in linux/moduleparam.h. */
  const int BUFFER_LEN = 4096;

  spin_lock(&cp_lock);
  s = buffer;
  len = 0;
  for( n = 0; n < cplane_server_params_array_num; n++ ) {
    add = strlen(cplane_server_params_array[n]);
    if( add + len > BUFFER_LEN )
      break;
    memcpy(s, cplane_server_params_array[n], add);
    s += add;
    len += add;
    if( add == BUFFER_LEN )
      break;
    *s = ' ';
    s++;
    len++;
  }
  spin_unlock(&cp_lock);

  /* The return value is the length of the string, excluding the terminating
   * \0.  If we've written any parameters, that \0 will overwrite the last
   * character, so fix up the accounting. */
  if( len > 0 ) {
    --s;
    --len;
  }

  *s = '\0';

  return len;
}


int oo_cp_get_server_pid(struct oo_cplane_handle* cp)
{
  int pid = 0;

  spin_lock_bh(&cp->cp_handle_lock);
  if( cp->server_pid != NULL )
    pid = pid_nr(cp->server_pid);
  spin_unlock_bh(&cp->cp_handle_lock);

  return pid;
}

static int
cplane_server_grace_timeout_set(const char* val,
                                const struct kernel_param* kp)
{
  int old_val = cplane_server_grace_timeout;
  int rc = param_set_int(val, kp);
  if( rc != 0 )
    return rc;
  if( (cplane_server_grace_timeout == 0) != (old_val == 0) )
    cp_respawn_init_server();
  return 0;
}

static int
cplane_route_request_timeout_set(const char* val,
                                 const struct kernel_param* kp)
{
  int rc = param_set_int(val, kp);
  if( rc != 0 )
    return rc;
  cplane_route_request_timeout_proceed();
  return 0;
}

static int
cplane_server_param_int_set(const char* val, const struct kernel_param* kp)
{
  int old_val = *(int *)kp->arg;
  int rc = param_set_int(val, kp);
  if( rc != 0 )
    return rc;
  if( old_val != *(int *)kp->arg )
    cp_respawn_init_server();
  return 0;
}
static int
cplane_server_param_bool_set(const char* val, const struct kernel_param* kp)
{
  bool old_val = *(bool *)kp->arg;
  int rc = param_set_bool(val, kp);
  if( rc != 0 )
    return rc;
  if( old_val != *(bool *)kp->arg )
    cp_respawn_init_server();
  return 0;

}

int oo_cp_llap_change_notify_all(struct oo_cplane_handle* main_cp)
{
  int rc = 0;
  int hash;
  spin_lock(&cp_lock);
  for( hash = 0; hash < CP_INSTANCE_HASH_SIZE; ++hash ) {
    ci_dllink* link;
    CI_DLLIST_FOR_EACH(link, &cp_hash_table[hash]) {
      struct oo_cplane_handle* cp = CI_CONTAINER(struct oo_cplane_handle,
                                                 link, link);
      if( cp == main_cp || ! cp->server_initialized )
          continue;
      spin_lock_bh(&cp->cp_handle_lock);
      if( cp->server_pid != NULL ) {
        int rc1 = kill_pid(cp->server_pid, cp->mib[0].dim->llap_update_sig, 1);
        if( rc == 0 )
          rc = rc1;
      }
      spin_unlock_bh(&cp->cp_handle_lock);
    }
  }
  spin_unlock(&cp_lock);
  return rc;
}

/* Determines whether Onload should attempt to accelerate traffic over a
 * specified veth interface.  Returns zero if so, or -errno otherwise. */
int
oo_cp_check_veth_acceleration(struct oo_cplane_handle* cp, ci_ifid_t ifindex)
{
  int rc = 0;
  struct net_device* dev;
  ci_ifid_t peer_ifindex = CI_IFID_BAD;

  if( ! oo_accelerate_veth )
    return -ENOENT;

  dev = dev_get_by_index(netns_from_cp(cp), ifindex);
  if( dev == NULL )
    return -ENODEV;

  rtnl_lock();

  /* Linux 3.19 gained the get_link_net() op, and Linux 4.0 introduced
   * dev_get_if_link().  RHEL7 has both. */
#if defined(EFRM_RTNL_LINK_OPS_HAS_GET_LINK_NET) && \
    defined(EFRM_HAVE_DEV_GET_IF_LINK)
  /* If this end of the veth is in init_net, there's no cross-namespace routing
   * to be done. */
  if( dev_net(dev) == &init_net ) {
    rc = -ELOOP;
  }
  /* There's no particularly clean way in the kernel to check that this is a
   * veth interface.  UL can do this easily and naturally using netlink, so
   * we will be content here to ensure that the interface at least quacks like
   * a veth. */
  else if( dev->rtnl_link_ops == NULL ||
           dev->rtnl_link_ops->get_link_net == NULL ) {
    rc = -EMEDIUMTYPE;
  }
  /* At present we require that the peer interface be in init_net. */
  else if( dev->rtnl_link_ops->get_link_net(dev) != &init_net ) {
    rc = -EXDEV;
  }
  else {
    peer_ifindex = dev_get_iflink(dev);
    if( peer_ifindex == CI_IFID_BAD )
      rc = -EPIPE;
  }
#else
  /* RHEL6 doesn't have the get_link_net() op.  The intended use-cases for
   * veth-acceleration are very likely to be run on more recent distros, so we
   * just give up now. */
  rc = -EOPNOTSUPP;
#endif

  rtnl_unlock();
  dev_put(dev);

  /* If this veth interface is acceleratable, we need to probe the associated
   * fwd-table ID to init_net's control plane. */
  if( rc == 0 ) {
    struct oo_cplane_handle* cplane_init_net;
    cplane_init_net = __cp_acquire_from_netns_if_exists(&init_net, CI_FALSE);
    if( cplane_init_net == NULL )
      return -ECOMM;
    rc = cp_veth_set_fwd_table_id(cplane_init_net, peer_ifindex,
                                  cp->cplane_id);
    cp_release(cplane_init_net);
  }

  return rc;
}


int
oo_cp_select_instance(ci_private_t* priv, enum oo_op_cp_select_instance inst)
{
  struct net* netns;
  int rc;

  switch( inst ) {
  case CP_SELECT_INSTANCE_LOCAL:
    netns = current->nsproxy->net_ns;
    break;
  case CP_SELECT_INSTANCE_INIT_NET:
    netns = &init_net;
    break;
  default:
    ci_assert(0);
    return -EINVAL;
  }

  rc = cp_find_or_create(priv, netns);
  if( rc != 0 )
    return rc;

  ci_assert(priv->priv_cp);

  /* The fwd-table ID depends on whether this is a local or a foreign control
   * plane: in both cases, we need to use the ID of the _local_ control plane,
   * which we need to find if it's not the one that we're associating with the
   * handle. */
  if( inst != CP_SELECT_INSTANCE_LOCAL ) {
    struct oo_cplane_handle* cplane_local =
      __cp_acquire_from_netns(current->nsproxy->net_ns);
    if( cplane_local == NULL ) {
      cp_release(priv->priv_cp);
      priv->priv_cp = NULL;
      return -ENOENT;
    }
    priv->fwd_table_id = cplane_local->cplane_id;
    cp_release(cplane_local);
  }
  else {
    priv->fwd_table_id = priv->priv_cp->cplane_id;
  }

  return 0;
}


/* Asks the kernel to resolve an output route: that is, a route for a packet
 * that morally originated on the local machine. */
static struct rtable*
cicp_ip4_route_output(struct net* netns, struct cp_fwd_key* key, uid_t uid,
                      ci_addr_sh_t* src_out)
{
  struct rtable *rt;

  struct flowi4 fl4;

  memset(&fl4, 0, sizeof(fl4));
  fl4.daddr = key->dst.ip4;
  fl4.saddr = key->src.ip4;
  fl4.flowi4_tos = key->tos;
  fl4.flowi4_oif = key->ifindex;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  fl4.flowi4_uid = make_kuid(current_user_ns(), uid);
#endif

  ci_assert_equal(key->iif_ifindex, CI_IFID_BAD);
  ci_assert_nflags(key->flag, CP_FWD_KEY_TRANSPARENT);

  rt = ip_route_output_key(netns, &fl4);
  *src_out = CI_ADDR_SH_FROM_IP4(fl4.saddr);

  return rt;
}


/* Asks the kernel to resolve an input route: that is, a route for a packet
 * that was received by the local machine on an interface, and is being
 * forwarded.  Such route requests are distinguished from output route requests
 * by specifying an input ifindex. */
static struct rtable*
cicp_ip4_route_input(struct net* netns, struct cp_fwd_key* key)
{
  ci_ifid_t iif = key->iif_ifindex;
  struct net_device *dev;
  struct sk_buff* skb;
  struct rtable* rt;
  int rc;
  struct dst_entry* dst;

  skb = alloc_skb(NLMSG_GOODSIZE, in_atomic() ? GFP_ATOMIC : GFP_KERNEL);
  if( skb == NULL )
    return ERR_PTR(-ENOBUFS);

  /* When bug87317 is fixed, this special case should be removed. */
  if( key->flag & CP_FWD_KEY_TRANSPARENT )
    iif = CI_IFID_LOOP;

  ci_assert_nequal(iif, CI_IFID_BAD);

  dev = dev_get_by_index(netns, iif);
  if( dev == NULL ) {
    rt = ERR_PTR(-ENODEV);
    goto fail1;
  }

  skb->protocol	= CI_ETHERTYPE_IP;
  skb->dev = dev;
  local_bh_disable();
  rc = ip_route_input(skb, key->dst.ip4, key->src.ip4, key->tos, dev);
  local_bh_enable();

  if( rc != 0 ) {
    rt = ERR_PTR(rc);
    goto fail2;
  }

  rt = skb_rtable(skb);
  dst = &rt->dst;
  if( dst->error != 0 ) {
    rt = ERR_PTR(-dst->error);
    goto fail2;
  }

  /* Take an extra reference to rt to counteract kfree_skb(). */
  dst_hold(dst);

 fail2:
  dev_put(dev);
 fail1:
  /* kfree_skb() will drop a reference to rt if ip_route_input() succeeded. */
  kfree_skb(skb);
  return rt;
}


#ifdef EFRM_RTABLE_HAS_RT_GW4
/* linux<5.2: rt_gateway field
 * linux>=5.2: union of rt_gw4 and rt_gw6 */
#define rt_gateway rt_gw4
#endif

static void
cicp_ip4_kernel_resolve(ci_netif* ni, struct oo_cplane_handle* cp,
                        struct cp_fwd_key* key, struct cp_fwd_data* data)
{
  int rc;
  struct rtable *rt;
  cicp_hwport_mask_t rx_hwports = 0;

  if( key->iif_ifindex != CI_IFID_BAD || key->flag & CP_FWD_KEY_TRANSPARENT ) {
    data->base.src = key->src;
    rt = cicp_ip4_route_input(cp->cp_netns, key);
  }
  else {
    rt = cicp_ip4_route_output(cp->cp_netns, key, ni->state->uuid,
                               &data->base.src);
  }

  if( IS_ERR(rt) ) {
    data->base.ifindex = CI_IFID_BAD;
    return;
  }

  data->base.ifindex = rt->dst.dev->ifindex;
  data->base.next_hop = CI_ADDR_SH_FROM_IP4(rt->rt_gateway);
  if( CI_IPX_ADDR_IS_ANY(data->base.next_hop) )
    data->base.next_hop = key->dst;

  data->base.mtu = rt->rt_pmtu;
  data->base.hop_limit = ip4_dst_hoplimit(&rt->dst);

  data->flags = 0;
  if( data->base.ifindex != 1 ) {
    /* In theory the rt->dst structure has a reference to the neigh,
     * but in practice it is not easy to dig the neigh out. */
    struct neighbour *neigh = neigh_lookup(&arp_tbl, &data->base.next_hop.ip4,
                                           rt->dst.dev);
    if( neigh != NULL && (neigh->nud_state & NUD_VALID) ) {
      data->flags |= CICP_FWD_DATA_FLAG_ARP_VALID;
      memcpy(data->dst_mac, neigh->ha, ETH_ALEN);
    }
    if( neigh != NULL )
      neigh_release(neigh);
  }

  ip_rt_put(rt);

  if( data->base.ifindex == CI_IFID_LOOP )
    return;

  /* We've got the route.  Let's look into llap table to find out the
   * network interface details. */
  rc = oo_cp_find_llap(cp, data->base.ifindex,
                       data->base.mtu == 0 ? &data->base.mtu : NULL,
                       &data->hwports, &rx_hwports, &data->src_mac, &data->encap);

  if( rc < 0 || rx_hwports == 0 )
    data->base.ifindex = CI_IFID_BAD;
}

#if CI_CFG_IPV6
#include <net/ip6_route.h>


/* Asks the kernel to resolve an IPv6 route.  This function handles both input
 * and output routes, and so provides the equivalent functionality of both
 * cicp_ip4_route_output() and cicp_ip4_route_input(). */
static struct rt6_info*
cicp_ip6_route(struct net* netns, struct cp_fwd_key* key, uid_t uid,
               ci_addr_sh_t* src_out)
{
  struct dst_entry *dst = NULL;

  /* When bug87317 is fixed, the special case for IP_TRANSPARENT should be
   * removed. */
  ci_ifid_t iif = key->flag & CP_FWD_KEY_TRANSPARENT ?
                  CI_IFID_LOOP : key->iif_ifindex;

  struct flowi6 fl6;

  memset(&fl6, 0, sizeof(fl6));
  memcpy(&fl6.daddr, key->dst.ip6, sizeof(fl6.daddr));
  memcpy(&fl6.saddr, key->src.ip6, sizeof(fl6.saddr));
  fl6.flowlabel = 0;
  fl6.flowi6_oif = key->ifindex;
  fl6.flowi6_iif = iif;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,10,0)
  fl6.flowi6_uid = make_kuid(current_user_ns(), uid);
#endif

  /* Now that we've built up the key, ask the kernel to resolve the route.  On
   * recent kernels, we need to distinguish between input and output routes.
   * Compare inet6_rtm_getroute(). */
  if( iif != CI_IFID_BAD ) {
#ifdef EFRM_IP6_ROUTE_INPUT_LOOKUP_EXPORTED  /* Linux >= 4.9 */
    struct net_device* dev = dev_get_by_index(netns, iif);
    if( dev == NULL )
      return ERR_PTR(-ENODEV);
    dst = ip6_route_input_lookup(netns, dev, &fl6,
#ifdef EFRM_IP6_ROUTE_INPUT_LOOKUP_TAKES_SKB /* Linux >= 4.17 */
                                 NULL,
#endif
                                 RT6_LOOKUP_F_HAS_SADDR);
    dev_put(dev);
#else
    dst = ip6_route_lookup(netns, &fl6, RT6_LOOKUP_F_HAS_SADDR);
#endif
    ci_assert(! CI_IPX_ADDR_IS_ANY(key->src));
  }
  else
  {
    dst = ip6_route_output(netns, NULL, &fl6);
    if( IS_ERR(dst) )
      return ERR_CAST(dst);
  }
  *src_out = CI_ADDR_SH_FROM_IP6((void*) &fl6.saddr);
  return container_of(dst, struct rt6_info, dst);
}


static void
cicp_ip6_kernel_resolve(ci_netif* ni, struct oo_cplane_handle* cp,
                        struct cp_fwd_key* key, struct cp_fwd_data* data)
{
  int rc;
  struct rt6_info *rt;
  cicp_hwport_mask_t rx_hwports = 0;

  rt = cicp_ip6_route(cp->cp_netns, key, ni->state->uuid, &data->base.src);
  if( IS_ERR(rt) ) {
    data->base.ifindex = CI_IFID_BAD;
    return;
  }

  data->base.ifindex = rt->dst.dev->ifindex;
  data->base.next_hop = CI_ADDR_SH_FROM_IP6((void*)&rt->rt6i_gateway);
  if( CI_IPX_ADDR_IS_ANY(data->base.next_hop) )
    data->base.next_hop = key->dst;
  data->base.mtu = dst_mtu(&rt->dst);

  data->base.hop_limit = ip6_dst_hoplimit(&rt->dst);

  data->flags = 0;
  if( data->base.ifindex != 1 ) {
    /* In theory the rt->dst structure has a reference to the neigh,
     * but in practice it is not easy to dig the neigh out. */
    struct neighbour *neigh = neigh_lookup(&nd_tbl, &data->base.next_hop,
                                           rt->dst.dev);
    if( neigh != NULL && (neigh->nud_state & NUD_VALID) ) {
      data->flags = CICP_FWD_DATA_FLAG_ARP_VALID;
      memcpy(data->dst_mac, neigh->ha, ETH_ALEN);
    }
    if( neigh != NULL )
      neigh_release(neigh);
  }

  ip6_rt_put(rt);

  if( data->base.ifindex == CI_IFID_LOOP )
    return;

  /* We've got the route.  Let's look into llap table to find out the
   * network interface details. */
  rc = oo_cp_find_llap(cp, data->base.ifindex,
                       data->base.mtu == 0 ? &data->base.mtu : NULL,
                       &data->hwports, &rx_hwports, &data->src_mac, &data->encap);

  if( rc < 0 || rx_hwports == 0 )
    data->base.ifindex = CI_IFID_BAD;
}
#endif /* CI_CFG_IPV6 */

void
cicp_kernel_resolve(ci_netif* ni, struct oo_cplane_handle* cp,
                    struct cp_fwd_key* key,
                    struct cp_fwd_data* data)
{
#if CI_CFG_IPV6
  if( IS_AF_INET6(fwd_key2af(key)) )
    cicp_ip6_kernel_resolve(ni, cp, key, data);
  else
#endif
    cicp_ip4_kernel_resolve(ni, cp, key, data);
}
