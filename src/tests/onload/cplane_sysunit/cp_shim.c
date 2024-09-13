/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <stdlib.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <signal.h>
#include <sys/syscall.h>

#include <net/if.h>

#include <private.h>
#include <onload/mmap_base.h>
#include <ci/efhw/common.h>
#include <cplane/mmap.h>
#include <cplane/cplane.h>
#include <cplane/create.h>
#include <cplane/server.h>


oo_cp_version_check_t oo_cplane_api_version;

int ef_driver_open(ef_driver_handle* dh_out)
{
  ci_assert(! "CPSHIM: calling ef_driver_open not expected");
  return 0;
}


void ef_pd_alloc(void)
{
  ci_assert(! "CPSHIM: calling ef_pd_alloc not expected");
}


void ef_pd_free(void)
{
  ci_assert(! "CPSHIM: calling ef_pd_free not expected");
}


int oo_fd_open(int * fd_out) {
  char* fname = getenv("CP_SHIM_FILE");
  *fd_out = open(fname, O_RDWR, 0);
  return 0;
}


/* creates r/w clone of mib for given handle - for test side code only */
ci_inline void clone_cp(int fd, struct oo_cplane_handle* cp)
{
  void* mem;
  void* fwd_mem;

  cp->bytes = CP_SHIM_MIB_BYTES;
  cp->fd = fd;
  mem = mmap(NULL, cp->bytes, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
             OO_MMAP_MAKE_OFFSET(OO_MMAP_TYPE_CPLANE, OO_MMAP_CPLANE_ID_MIB));
  ci_assert_nequal(mem, MAP_FAILED);
  cp->mib[1].dim = cp->mib[0].dim = mem;
  cp_init_mibs(mem, cp->mib);

  fwd_mem = mmap(NULL, CP_SHIM_FWD_BYTES, PROT_READ | PROT_WRITE, MAP_SHARED,
                 fd, CP_SHIM_MIB_BYTES);
  ci_assert_nequal(fwd_mem, MAP_FAILED);
  cp_init_mibs_fwd_blob(fwd_mem, cp->mib);
}


int rt_sigqueueinfo(pid_t tgid, int sig, siginfo_t *uinfo)
{
  return syscall( SYS_rt_sigqueueinfo, tgid, sig, uinfo);
}


int shim_oo_op_notify_all(struct cp_mibs* mib);
int shim_oo_op_route_resolve(struct cp_mibs* mib,
                             struct cp_fwd_key* key);
static int shim_cp_hmsg_send(struct cp_mibs* mib, struct cp_helper_msg* msg);

static int shim_cp_set_hwport(int fd, ci_ifid_t ifindex, ci_hwport_id_t hwport)
{
  struct oo_cplane_handle cp = {};
  struct cp_helper_msg msg;
  clone_cp(fd, &cp);

  msg.hmsg_type = CP_HMSG_SET_HWPORT;
  msg.u.set_hwport.ifindex = ifindex;
  msg.u.set_hwport.hwport = hwport;
  msg.u.set_hwport.nic_flags = ~(ci_uint64) NIC_FLAG_ONLOAD_UNSUPPORTED;
  int rc = shim_cp_hmsg_send(&cp.mib[0], &msg);
  oo_cp_destroy(&cp);
  return rc;
}


static int this_is_server_process = 0;

struct hwport_info {
  unsigned num_hwports;
  ci_hwport_id_t hwports[2]; /* At most 2 hwports per intf*/
};
#define IFINDEX_HWPORT_TABLE_ENTRIES 64
#define IFINDEX_HWPORT_TABLE_SIZE \
                       IFINDEX_HWPORT_TABLE_ENTRIES * sizeof(struct hwport_info)
#define IFINDEX_HWPORT_TABLE_OFFSET \
                    CP_SHIM_MIB_BYTES + CP_SHIM_FWD_BYTES + CP_SHIM_FWD_RW_BYTES

struct hwport_info* map_shim_table(int fd)
{
  void *table;
  table = mmap(NULL, IFINDEX_HWPORT_TABLE_SIZE, PROT_READ | PROT_WRITE,
               MAP_SHARED, fd, IFINDEX_HWPORT_TABLE_OFFSET);
  ci_assert_nequal(table, MAP_FAILED);
  return table;
}

void unmap_shim_table(struct hwport_info *table)
{
  munmap(table, IFINDEX_HWPORT_TABLE_SIZE);
}

int cp_unit_cplane_ioctl(int fd, long unsigned int op, ...)
{
  void* v;
  va_list va;
  va_start(va, op);
  v = (void*)va_arg(va, long);
  va_end(va);
  unsigned i;

  switch(op) {
  case OO_IOC_CP_DUMP_HWPORTS:
  {
    ci_ifid_t ifindex = *(ci_ifid_t*)v;
    if( ifindex != CI_IFID_BAD ) {
      struct hwport_info *table, *info;
      ci_assert(ifindex < IFINDEX_HWPORT_TABLE_ENTRIES);
      table = map_shim_table(fd);
      info = &table[ifindex];
      assert(info->num_hwports <= 2);
      for( i = 0; i < info->num_hwports; i++ )
        shim_cp_set_hwport(fd, ifindex, info->hwports[i]);
      unmap_shim_table(table);
    }
    int rc = shim_cp_set_hwport(fd, CI_IFID_BAD, CI_HWPORT_ID_BAD);
    if( rc < 0 )
      return rc;
    break;
  }
  case OO_IOC_CP_LINK:
  {
    /* flag this process as server.
     * When main_cp_client is later created, we will let the main_cp know
     * this client is in fact a subordinate namespace */
    this_is_server_process = 1;
    break;
  }
  case OO_IOC_CP_READY:
  {
    struct oo_cplane_handle cp = {};
    clone_cp(fd, &cp);
    ci_assert_impl(cp.mib[0].dim->server_pid != 0,
                   cp.mib[0].dim->server_pid == getpid());
    /* set server pid field - our client(s) will consider us ready and will know
     * where to send signals to */
    cp.mib[0].dim->server_pid = getpid();
    oo_cp_destroy(&cp);
    break;
  }

  case OO_IOC_CP_CHECK_VERSION:
  case OO_IOC_OOF_CP_LLAP_MOD:
  case OO_IOC_OOF_CP_LLAP_UPDATE_FILTERS:
  case OO_IOC_OOF_CP_IP_MOD:
  case OO_IOC_CP_INIT_KERNEL_MIBS:
  case OO_IOC_CP_ARP_RESOLVE:
  case OO_IOC_CP_FWD_RESOLVE_COMPLETE:
    break;

  case OO_IOC_GET_CPU_KHZ:
    /* assume 2.5Ghz clock - close enough for most machines */
    *((int64_t*)v) = 2500000;
    break;
  case OO_IOC_CP_WAIT_FOR_SERVER:
    {
      struct oo_cplane_handle cp = {};
      int i;
      const char* env_startup_delay = getenv("CP_SHIM_STARTUP_DELAY_US");
      int max_delay = 2000000; /* 2 seconds */
      if( env_startup_delay ) {
        max_delay = atoi(env_startup_delay);
        if( max_delay < 0 )
          max_delay = INT_MAX;
      }

      clone_cp(fd, &cp);
      for( i = max_delay; cp.mib[0].dim->server_pid == 0 && i > 0; i -= 10000)
        usleep(10000);
      if( i <= 0 ) {
        oo_cp_destroy(&cp);
        return -ETIMEDOUT;
      }
      if( this_is_server_process ) {
        ci_log("Setting sub_server_pid to %d, main_cp server_pid is %d",
               getpid(), cp.mib[0].dim->server_pid);
        /* The handle given is the main cp handle, so
         * write into main cp server memory the pid (our pid) so it knows where
         * to send llap update notifications to.
         * Note: this means that only single subordinate namespace will receive them
         * FIXME: support multiple subordinate namespaces
         */
        cp.mib[0].dim->sub_server_pid = getpid();
      }
      oo_cp_destroy(&cp);
    }
    break;

  case OO_IOC_CP_MIB_SIZE:
    *((int32_t*)v) = CP_SHIM_MIB_BYTES;
    break;
  case OO_IOC_CP_NOTIFY_LLAP_MONITORS:
  {
    struct oo_cplane_handle cp = {};
    clone_cp(fd, &cp);
    shim_oo_op_notify_all(cp.mib);
    oo_cp_destroy(&cp);
    break;
  }
  case OO_IOC_CP_FWD_RESOLVE:
  {
    struct oo_cplane_handle cp = {};
    clone_cp(fd, &cp);
    shim_oo_op_route_resolve(cp.mib, v);
    oo_cp_destroy(&cp);
    break;
  }

  /* This ioctl implements kernel-to-server CP_HMSG_SET_HWPORT message for
   * the sysunit tests */
  case OO_IOC_CP_SYSUNIT_MAKE_NIC:
  {
    cp_set_hwport_t* arg = v;
    struct hwport_info *table, *info;
    int rc = shim_cp_set_hwport(fd, arg->ifindex, arg->hwport);
    if( rc < 0 )
      return rc;
    ci_assert(arg->ifindex < IFINDEX_HWPORT_TABLE_ENTRIES);
    table = map_shim_table(fd);
    info = &table[arg->ifindex];
    ci_assert(info->num_hwports < 2);
    info->hwports[info->num_hwports] = arg->hwport;
    info->num_hwports++;
    unmap_shim_table(table);
    break;
  }

  default:
    ci_log("%s: op = %lx", __func__, op);
    ci_assert(! "not expect to see unrelated ioctls");

  }
  return 0;
}

extern int cplane_ioctl(int, long unsigned int, ...)
    __attribute__ ((alias ("cp_unit_cplane_ioctl")));


static int shim_cp_hmsg_send(struct cp_mibs* mib, struct cp_helper_msg* msg)
{
  /* Closing of the write-end of pipe is destructive, so we do not close it
   * as long as we work with the same server. */
  static int comm_pipe;
  static int last_server_pid = -1;

  ci_assert_nequal(mib->dim->server_pid, 0);
  if( last_server_pid != mib->dim->server_pid ) {
    char pipe_name[50];
    snprintf(pipe_name, sizeof(pipe_name), "/tmp/onload_cp_server.%d",
             mib->dim->server_pid);
    pipe_name[sizeof(pipe_name) - 1] = '\0';
    close(comm_pipe);
    comm_pipe = open(pipe_name, O_WRONLY);
    if( comm_pipe < 0 )
      return comm_pipe;
  }

  int rc = write(comm_pipe, msg, sizeof(*msg));
  return rc > 0 ? 0 : rc;
}

int shim_oo_op_route_resolve(struct cp_mibs* mib,
                             struct cp_fwd_key* key)
{
  struct cp_helper_msg msg;
  msg.hmsg_type = CP_HMSG_FWD_REQUEST;
  msg.u.fwd_request.id = 0;
  memcpy(&msg.u.fwd_request.key, key, sizeof(*key));
  int rc = shim_cp_hmsg_send(mib, &msg);

  /* FIXME implement wait */

  return rc;
}


int shim_oo_op_notify_all(struct cp_mibs* mib)
{
  if( mib->dim->sub_server_pid == 0 )
    return 0;

  siginfo_t info = {};

  info.si_signo = mib->dim->llap_update_sig;
  info.si_errno = 0;
  info.si_code = CP_FWD_FLAG_REQ;

  return rt_sigqueueinfo(mib->dim->sub_server_pid, info.si_signo, &info);
}
