/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr/ctk
**  \brief  Table mapping [fd]s to userlevel state.
**   \date  2003/01/08
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_transport_unix */

#include "internal.h"
#include <fcntl.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/vfs.h>
#include <onload/ul.h>
#include <onload/dup2_lock.h>
#include <onload/ul/tcp_helper.h>
#include <onload/version.h>
#include <dlfcn.h>

#include "ul_pipe.h"
#include "ul_poll.h"
#include "ul_epoll.h"

#include <ci/internal/syscall.h>
#include <ci/internal/banner.h>

/* FIXME Yes, it is ugly. But we do not have any appropriate header */
#define CI_ID_POOL_ID_NONE ((unsigned)(-1))

#define DEBUGPREINIT(x)


citp_fdtable_globals	citp_fdtable;

/* Initial seqno should differ from the seqno in special fdi, such as
 * citp_the_closed_fd */
ci_uint64 fdtable_seq_no = 1;


static void dup2_complete(citp_fdinfo* prev_newfdi,
			  citp_fdinfo_p prev_newfdip, int fdt_locked);


static void exit_with_status(int status)
{
  /* oo_exit_hook() takes too long, we should exit ungraciously */
  if( WIFEXITED(status) )
    ci_sys__exit(WEXITSTATUS(status));
  else if( WIFSIGNALED(status) )
    ci_sys_syscall(__NR_tgkill, getpid(), ci_sys_syscall(__NR_gettid),
                   WTERMSIG(status));

  return;
}

void oo_signal_terminate(int signum)
{
  struct sigaction act = { };

  Log_CALL(ci_log("%s(%d)", __func__, signum));

  /* Set SIGDFL for this signal, so that we do what the user expects next
   * time
   */
  oo_syscall_sigaction(signum, &act, NULL);

  oo_exit_hook(signum);

  exit_with_status(signum);
}

static void sighandler_sigonload(int sig, siginfo_t* info, void* context)
{
  /* The signal was sent solely in order to wake up the app, so nothing to do */
}

/* Hook to be called at gracious exit */
void oo_exit_hook(int status)
{
  citp_lib_context_t lib_context;
  /* exit status as in waitpid:
   *   (exit_status << 8) | exit_sig
   * combined with OO_EXIT_STATUS_SET when really exiting.
   * _fini() exits with status=0, so we have to mark it somehow.
   */
#define OO_EXIT_STATUS_SET 0x10000
  static ci_uint32 exit_status;
  ci_uint32 old_status;

  Log_CALL(ci_log("%s(0x%x)", __func__, status));

  do {
    old_status = exit_status;
  } while( ci_cas32u_fail(&exit_status, old_status,
                          status | OO_EXIT_STATUS_SET) );

  if( old_status != 0 ) {
    if( status != 0 ) {
      /* We have been already exiting, and now we see emergency exit via
       * _exit() or via signal.  Do the emergency thing.
       */
      exit_with_status(status);
      return;
    }
    else {
      /* This hook have already been called, from either _exit() or signal.
       * Now we are in _fini(): return.
       */
      return;
    }
  }

  if( ! have_active_netifs() )
    return;

  citp_enter_lib(&lib_context);
  CITP_FDTABLE_LOCK_RD();

#if CI_CFG_FD_CACHING
  uncache_active_netifs();
#endif

  exit_lock_all_stacks();

  CITP_FDTABLE_UNLOCK_RD();
  citp_exit_lib(&lib_context, 1);
}


/*! Block until fdtable entry is neither closing nor busy, and return the
** new (non-closing-or-busy) fdip. */
static citp_fdinfo_p citp_fdtable_closing_wait(unsigned fd, int fdt_locked);

#ifdef __x86_64__
#if __GNUC__ >= 6
__attribute__((force_align_arg_pointer))
static long oo_close_nocancel_entry(long fd)
#else
extern long oo_close_nocancel_entry(long fd);
__asm__(
  ".globl oo_close_nocancel_entry;"
  "oo_close_nocancel_entry:"
    "push %rbp;"
    "mov  %rsp,%rbp;"
    "and  $0xfffffffffffffff0,%rsp;"
    "call close_nocancel_entry_fixed;"
    "mov  %rbp,%rsp;"
    "pop  %rbp;"
    "ret;"
);

__attribute__((used))
static long close_nocancel_entry_fixed(long fd)
#endif
#else
static long oo_close_nocancel_entry(long fd)
#endif
{
  int rc;
  citp_lib_context_t lib_context;

  if( fd < 0 || fd >= citp_fdtable.inited_count ||
      fdip_is_unknown(citp_fdtable.table[fd].fdip) ) {
    /* Don't enter lib when we're not going to affect anything. This avoids
     * cases of infinite recursion, most notably when grabbing the TLS entry
     * requires doing TLS init (which might require initialising malloc too,
     * which might call close()) */
    return ci_tcp_helper_close_no_trampoline(fd);
  }

  Log_CALL(ci_log("%s: close_nocancel(%ld)", __func__, fd));
  citp_enter_lib(&lib_context);
  rc = citp_ep_close((int)fd);
  citp_exit_lib(&lib_context, false);
  Log_CALL_RESULT(rc);
  return rc;
}


#ifdef __aarch64__
static void aarch64_write_ptr_insns(void* dst, const void* value)
{
  unsigned* u = dst;
  uintptr_t v = (uintptr_t)value;
  u[0] |= ((v >> 0) & 0xffff) << 5;
  u[1] |= ((v >> 16) & 0xffff) << 5;
  u[2] |= ((v >> 32) & 0xffff) << 5;
  u[3] |= ((v >> 48) & 0xffff) << 5;
}
#endif


static int modify_glibc_code(void* dst, const void* src, size_t n)
{
  int rc;
  void* patch_page_start;
  size_t patch_page_size;

  /* This patching is thread-unsafe, but happens at process startup when
   * there's only one thread */
  patch_page_start = CI_PTR_ALIGN_BACK(dst, CI_PAGE_SIZE);
  patch_page_size = (char*)CI_PTR_ALIGN_FWD((char*)dst + n, CI_PAGE_SIZE) -
                    (char*)patch_page_start;
  rc = mprotect(patch_page_start, patch_page_size, PROT_READ | PROT_WRITE);
  if( rc != 0 ) {
    rc = -errno;
    LOG_S(ci_log("ERROR: mprotect(glibc write) = %d", errno));
    return rc;
  }
  memcpy(dst, src, n);
  rc = mprotect(patch_page_start, patch_page_size, PROT_READ | PROT_EXEC);
  if( rc != 0 ) {
    rc = -errno;
    ci_log("CRITICAL: mprotect(glibc exec) = %d. "
            "Process will likely crash now", errno);
    return rc;
  }
  return 0;
}

#ifdef __x86_64__
static const unsigned char x64_endbr[] = {0xf3, 0x0f, 0x1e, 0xfa};
static const unsigned char x64_nop[] = {0x90};

/* Returns the length of the given instruction, if it's one of the
 * instructions that we expect to find in the implementation of libc's
 * _IO_file_close. Currently this is just some movs */
static int is_io_file_close_insn(const unsigned char* insn)
{
  if( insn[0] == 0x8b ) {   /* mov r,r/m */
    bool has_sib = (insn[1] & 7) == 4 && insn[1] < 0xc0;
    bool has_disp8 = (insn[1] >> 6) == 1;
    bool has_disp32 = (insn[1] >> 6) == 2 || (insn[1] & 0xc7) == 0x04;
    return 2 + has_sib + has_disp8 + has_disp32 * 4;
  }
  return 0;
}
#endif

static void* find_close_nocancel(void)
{
  void* close_nocancel = dlsym(NULL, "__close_nocancel");
  if( close_nocancel )
    return close_nocancel;

#ifdef __x86_64__
  {
    /* Only newish versions of glibc (e.g. RHEL8) export __close_nocancel.
     * Prior versions (before glibc 329ea513b4) had it inline in close().
     * That's still hard to find, however, since other components of glibc
     * also export a close/__close, e.g. libpthread.so.
     * Instead we start at _IO_file_close, which is a moderately simple
     * wrapper of __close_nocancel, i.e. it ends with a jmp to it. */
    int n;
    unsigned char* io_file_close;

    io_file_close = dlsym(RTLD_NEXT, "_IO_file_close");
    if( ! io_file_close )
      return NULL;
    if( ! memcmp(io_file_close, x64_endbr, sizeof(x64_endbr)) )
      io_file_close += sizeof(x64_endbr);
    /* Needed for SLES15 sp4 with GNU libc 2.31 */
    while( ! memcmp(io_file_close, x64_nop, sizeof(x64_nop)) )
      io_file_close += sizeof(x64_nop);
    while( (n = is_io_file_close_insn(io_file_close)) != 0 )
      io_file_close += n;
    if( *io_file_close != 0xe9 )  /* jmp rel32 */
      return NULL;
    return io_file_close + 5 + *(uint32_t*)(io_file_close + 1);
  }
#else
  /* We do not do extra searching on aarch64, since we don't support old glibc
   * there */
  return NULL;
#endif
}


static int patch_libc_close_nocancel(void)
{
  unsigned char* close_nocancel = find_close_nocancel();
  if( ! close_nocancel ) {
    LOG_S(ci_log("libc __close_nocancel not found: not running glibc?"));
    return -ENOENT;
  }

#ifdef __x86_64__
  {
    static const unsigned char sysclose[] = {
      0xb8, 0x03, 0x00, 0x00, 0x00,   /* mov $3, %eax */
      0x0f, 0x05                      /* syscall */
    };
    static const unsigned char call_rax[] = {
      0xff, 0xd0                      /* call *%rax */
    };
    static const unsigned char trampo_code[] = {
      0xf3, 0x0f, 0x1e, 0xfa,         /* endbr64 */
      0x48, 0xb8, 0xef, 0xcd, 0xab, 0x89, 0x67,
      0x45, 0x23, 0x01,               /* movabs $0x123456789abcdef,%rax */
      0xff, 0xe0,                     /* jmpq *%rax */
    };
    unsigned char new_glibc_bytes[6];
    unsigned char* trampoline;
    long (*target)(long) = &oo_close_nocancel_entry;
    int rc;

    /* One x86-64 we somehow have to replace the 7 bytes "mov $3,eax;syscall"
     * with a call to an 8-byte absolute address. The fundamental insight here
     * is to use mmap(MAP_32BIT) to get ourselves a 32-bit address and put an
     * intermediate trampoline there. That allows us to replace those 7 bytes
     * with a call to a 4-byte absolute address. Doable. */
    if( ! memcmp(close_nocancel, x64_endbr, sizeof(x64_endbr)) )
      close_nocancel += sizeof(x64_endbr);
    /* Needed for SLES15 sp4 with GNU libc 2.31 */
    while( ! memcmp(close_nocancel, x64_nop, sizeof(x64_nop)) )
      close_nocancel += sizeof(x64_nop);
    if( memcmp(close_nocancel, sysclose, sizeof(sysclose)) ) {
      LOG_S(ci_log("Mismatching syscall implementation in __close_nocancel"));
      return -ESRCH;
    }
    trampoline = mmap(NULL, sizeof(trampo_code), PROT_READ | PROT_WRITE,
                      MAP_32BIT | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if( trampoline == MAP_FAILED ) {
      rc = -errno;
      LOG_S(ci_log("__close_nocancel mmap failed: %d", errno));
      return rc;
    }
    ci_assert_le((uintptr_t)trampoline, 0xffffffff);
    memcpy(trampoline, trampo_code, sizeof(trampo_code));
    memcpy(trampoline + 6, &target, sizeof(void*));
    rc = mprotect(trampoline, CI_PAGE_SIZE, PROT_READ | PROT_EXEC);
    if( rc != 0 ) {
      rc = -errno;
      LOG_S(ci_log("ERROR: mprotect(trampoline) = %d", errno));
      return rc;
    }

    memcpy(new_glibc_bytes, &trampoline, 4);
    memcpy(new_glibc_bytes + 4, call_rax, sizeof(call_rax));
    return modify_glibc_code(close_nocancel + 1, new_glibc_bytes,
                             sizeof(new_glibc_bytes));
  }
#elif defined __aarch64__
  {
    static const unsigned expected[] = {
      0x93407c00,   /* sxtw x0, w0 */
      0xd2800728,   /* mov  x8, #57 */
      0xd4000001,   /* svc  #0 */
    };
    unsigned replacement[] = {
      0xd2a00008,   /* mov	x8, #0xnnnn0000 */
      0xf2c00008,   /* movk	x8, #0xnnnn, lsl #32 */
      0xd61f0100,   /* br x8 */
    };
    static const unsigned trampo_code[] = {
      0xa9bf7bfd,   /* stp  x29, x30, [sp, #-16]! */
      0x910003fd,   /* mov  x29, sp */
      0xd2800008,   /* mov  x8, #0xnnnn */
      0xf2a00008,   /* movk x8, #0xnnnn, lsl #16 */
      0xf2c00008,   /* movk x8, #0xnnnn, lsl #32 */
      0xf2e00008,   /* movk x8, #0xnnnn, lsl #48 */
      0xd63f0100,   /* blr  x8 */
      0xa8c17bfd,   /* ldp  x29, x30, [sp], #16 */
      0xd2800008,   /* mov  x8, #0xnnnn */
      0xf2a00008,   /* movk x8, #0xnnnn, lsl #16 */
      0xf2c00008,   /* movk x8, #0xnnnn, lsl #32 */
      0xf2e00008,   /* movk x8, #0xnnnn, lsl #48 */
      0xd61f0100,   /* br x8 */
    };
    void* trampo_area;
    unsigned* trampoline;
    int rc;

    if( memcmp(close_nocancel, expected, sizeof(expected)) ) {
      LOG_S(ci_log("Mismatching syscall implementation in __close_nocancel"));
      return -ESRCH;
    }
    /* In order to fit the replacement into the requisite 3 instructions we
     * need a 64KB-aligned address to jump to. Allocate 64KB of address space
     * and map only the useful page. AArch64 has only a 48-bit virtual address
     * space, so we get a pointer we can fit in to two mov instructions. */
    trampo_area = mmap(NULL, 65536, PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if( trampo_area == MAP_FAILED ) {
      rc = -errno;
      LOG_S(ci_log("__close_nocancel reservation failed: %d", errno));
      return rc;
    }
    trampoline = (unsigned*)CI_PTR_ALIGN_FWD(trampo_area, 65536);
    if( mmap(trampoline, CI_PAGE_SIZE, PROT_READ | PROT_WRITE,
             MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != trampoline ) {
      rc = -errno;
      LOG_S(ci_log("__close_nocancel mmap failed: %d", errno));
      return rc;
    }
    memcpy(trampoline, trampo_code, sizeof(trampo_code));
    aarch64_write_ptr_insns(trampoline + 2, oo_close_nocancel_entry);
    aarch64_write_ptr_insns(trampoline + 8, (unsigned*)close_nocancel + 3);
    rc = mprotect(trampoline, CI_PAGE_SIZE, PROT_READ | PROT_EXEC);
    if( rc != 0 ) {
      rc = -errno;
      LOG_S(ci_log("ERROR: mprotect(trampoline) = %d", errno));
      return rc;
    }

    ci_assert_equal((uintptr_t)trampoline & 0xffff, 0);
    ci_assert_equal((uintptr_t)trampoline >> 48, 0);
    replacement[0] |= (((uintptr_t)trampoline >> 16) & 0xffff) << 5;
    replacement[1] |= (((uintptr_t)trampoline >> 32) & 0xffff) << 5;
    return modify_glibc_code(close_nocancel, replacement, sizeof(replacement));
  }
#else
  /* x86 plan:
   * The syscall instruction is 65 ff 15 10 00 00 00 call *%gs:0x10, so we
   * can just overwrite the whole thing with
   * "push %ebx;call close_nocancel_entry;pop %ebx"
   */
  LOG_S(ci_log("Unsupported architecture for patching libc close"));
  return -EOPNOTSUPP;
#endif
}


int citp_fdtable_ctor()
{
  struct rlimit rlim;
  int rc;

  Log_S(log("%s:", __FUNCTION__));

  /* How big should our fdtable be by default?  It's pretty arbitrary, but we have
   * seen a few apps that use setrlimit to set the fdtable to 4096 entries on
   * start-up (see bugs 3253 and 3373), so we choose that.  (Note: we can't grow
   * the table if the app later does setrlimit, and unused entries consume virtual
   * space only, so it's worth allocating a table of reasonable sized.)
   */
  citp_fdtable.size = 4096;

  if( getrlimit(RLIMIT_NOFILE, &rlim) == 0 ) {
    citp_fdtable.size = rlim.rlim_max;
    if( CITP_OPTS.fdtable_size != 0 &&
        CITP_OPTS.fdtable_size != rlim.rlim_max ) {
      Log_S(ci_log("Set the limits for the number of opened files "
                   "to EF_FDTABLE_SIZE=%u value.",
                   CITP_OPTS.fdtable_size));
      rlim.rlim_max = CITP_OPTS.fdtable_size;
      if( rlim.rlim_cur > rlim.rlim_max )
        rlim.rlim_cur = rlim.rlim_max;
      if( ci_sys_setrlimit(RLIMIT_NOFILE, &rlim) == 0 )
          citp_fdtable.size = rlim.rlim_max;
      else {
        /* Most probably, we've got EPERM */
        ci_assert_lt(citp_fdtable.size, CITP_OPTS.fdtable_size);
        ci_log("Can't set EF_FDTABLE_SIZE=%u; using %u",
               CITP_OPTS.fdtable_size, citp_fdtable.size);
        rlim.rlim_max = rlim.rlim_cur = citp_fdtable.size;
        CI_TRY(ci_sys_setrlimit(RLIMIT_NOFILE, &rlim));
      }
    }
  }
  else
    Log_S(ci_log("Assume EF_FDTABLE_SIZE=%u", citp_fdtable.size));

  citp_fdtable.inited_count = 0;

  citp_fdtable.table = malloc(sizeof (citp_fdtable_entry) *
                              citp_fdtable.size);
  if( ! citp_fdtable.table ) {
    Log_U(log("%s: failed to allocate fdtable (0x%x)", __FUNCTION__,
              citp_fdtable.size));
    return -1;
  }

  /* The whole table is not initialised at start-of-day, but is initialised
  ** on demand.  citp_fdtable.inited_count counts the number of initialised
  ** entries.
  */

  if( (rc = oo_rwlock_ctor(&citp_ul_lock)) != 0 ) {
    Log_E(log("%s: oo_rwlock_ctor(ul_lock) %d", __FUNCTION__, rc));
    return -1;
  }
  if( (rc = oo_rwlock_ctor(&citp_dup2_lock)) != 0 ) {
    Log_E(log("%s: oo_rwlock_ctor(dup2_lock) %d", __FUNCTION__, rc));
    return -1;
  }

  rc = patch_libc_close_nocancel();
  if( rc < 0 ) {
    Log_E(log("%s: Didn't intercept libc internal close %d", __FUNCTION__, rc));
    /* Which is bad, but not fatal */
  }

  /* Install SIGONLOAD handler */
  rc = oo_sigonload_init(sighandler_sigonload);
  if( rc < 0 )
    return rc;

  return 0;
}


#if !defined (NDEBUG) || CI_CFG_FDTABLE_CHECKS
/* This function does some simple tests to ensure that the fdtable makes sense.
 * There are many more tests we could do; feel free to add them at your
 * leisure!
 */
void
citp_fdtable_assert_valid(void)
{
  int i;

  if( ! citp_fdtable.table )  return;

  CITP_FDTABLE_LOCK_RD();

  for( i = 0; i < citp_fdtable.inited_count; i++ ) {
    citp_fdinfo_p fdip = citp_fdtable.table[i].fdip;

    if( fdip_is_normal(fdip) ) {
      citp_fdinfo * fdi = fdip_to_fdi(fdip);

      ci_assert(fdi);
      ci_assert(fdi->protocol);
      if( ( fdi->protocol->type == CITP_TCP_SOCKET ||
            fdi->protocol->type == CITP_UDP_SOCKET )
          && fdi_to_socket(fdi)->s )
	ci_assert(! (fdi_to_socket(fdi)->s->b.sb_aflags & CI_SB_AFLAG_ORPHAN));

      if (!fdi->is_special) {
        /* Ensure the "back pointer" makes sense */
        ci_assert (fdi->fd == i);
        /* Ensure that the reference count is in a vaguely sensible range */
        ci_assert ((oo_atomic_read (&fdi->ref_count) > 0) &&
                   (oo_atomic_read (&fdi->ref_count) < 10000));

        /* 10,000 threads is a bit mad, warn if more than 20 */
        if (oo_atomic_read (&fdi->ref_count) > 20) {
          Log_U (log ("Warning: fd %d's ref-count suspiciously large (%d)\n",
                      i, oo_atomic_read (&fdi->ref_count)));
        }
      }
    }
  }

  CITP_FDTABLE_UNLOCK_RD();
}
#endif


static void fdtable_swap(unsigned fd, citp_fdinfo_p from,
			 citp_fdinfo_p to, int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;

  p_fdip = &citp_fdtable.table[fd].fdip;

 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, fdt_locked);
  ci_assert_equal(fdip, from);
  if( fdip_cas_fail(p_fdip, from, to) )  goto again;
}

/* If this is called with OO_IOC_TCP_HANDOVER the stack lock must be held */
static int fdtable_fd_move(ci_fd_t sock_fd, int op)
{
  ci_uint32 io_fd = sock_fd;
  int rc;

  oo_rwlock_lock_read(&citp_dup2_lock);
  rc = oo_resource_op(sock_fd, op, &io_fd);

  if( rc != 0 || io_fd == sock_fd ) {
    oo_rwlock_unlock_read(&citp_dup2_lock);
    return rc;
  }

  /* Kernel failed to hand over, but there is no epoll here - let's dup */
  rc = ci_sys_dup2(io_fd, sock_fd);
  ci_tcp_helper_close_no_trampoline(io_fd);
  oo_rwlock_unlock_read(&citp_dup2_lock);
  if( rc == sock_fd )
    return 0;
  else if( rc >= 0 )
    return -EINVAL;
  return rc;
}

static int
citp_fdtable_probe_restore(int fd, ci_ep_info_t * info, int print_banner,
                           citp_fdinfo_p* fdip_out)
{
  citp_protocol_impl* proto = 0;
  citp_fdinfo* fdi = 0;
  ci_netif* ni;
  int rc = 0;
  int c_sock_fdi = 1;

  /* Must be holding the FD table writer lock */
  CITP_FDTABLE_ASSERT_LOCKED(1);
  ci_assert_nequal(info->resource_id, CI_ID_POOL_ID_NONE);

  /* Will need to review this function if the following assert fires */
  switch( info->fd_flags & OO_FDFLAG_EP_MASK ) {
  case OO_FDFLAG_EP_TCP:  proto = &citp_tcp_protocol_impl;  break;
  case OO_FDFLAG_EP_UDP:  proto = &citp_udp_protocol_impl;  break;
  case OO_FDFLAG_EP_PASSTHROUGH:
    proto = &citp_passthrough_protocol_impl;
    c_sock_fdi = 0;
    break;
  case OO_FDFLAG_EP_ALIEN:
    proto = NULL;
    c_sock_fdi = 0;
    break;
  case OO_FDFLAG_EP_PIPE_READ:
    proto = &citp_pipe_read_protocol_impl;
    c_sock_fdi = 0;
    break;
  case OO_FDFLAG_EP_PIPE_WRITE:
    proto = &citp_pipe_write_protocol_impl;
    c_sock_fdi = 0;
    break;
  default:                   ci_assert(0);
  }

  /* Attempt to find the user-level netif for this endpoint */
  ni = citp_find_ul_netif(info->resource_id, 1);
  if( ! ni ) {
    ef_driver_handle netif_fd;

    /* Not found, rebuild/restore the netif for this endpoint */
    rc = citp_netif_recreate_probed(fd, &netif_fd, &ni);
    if ( rc < 0 ) {
      Log_E(log("%s: citp_netif_recreate_probed failed! (%d)",
		__FUNCTION__, rc));
      goto fail;
    }

    if( print_banner ) {
      ci_netif_log_startup_banner(ni, "Importing");
    }
  }
  else
    citp_netif_add_ref(ni);

  /* There is a race condition where the fd can have been created, but it has
   * not yet been initialised, as we can't put a busy marker in the right place
   * in the fdtable until we know what the fd is.  In this case we don't want
   * to probe this new info, so return the closed fd.
   */
  if( SP_TO_WAITABLE(ni, info->sock_id)->sb_aflags & CI_SB_AFLAG_NOT_READY ) {
    citp_fdtable_busy_clear(fd, fdip_unknown, 1);
    fdi = &citp_the_closed_fd;
    citp_fdinfo_ref(fdi);
    *fdip_out = fdi_to_fdip(fdi);
    return rc;
  }

  if (c_sock_fdi) {
    citp_sock_fdi* sock_fdi;

    sock_fdi = CI_ALLOC_OBJ(citp_sock_fdi);
    if( ! sock_fdi ) {
      Log_E(log("%s: out of memory (sock_fdi)", __FUNCTION__));
      rc = -ENOMEM;
      goto fail;
    }
    fdi = &sock_fdi->fdinfo;

    sock_fdi->sock.s = SP_TO_SOCK_CMN(ni, info->sock_id);
    sock_fdi->sock.netif = ni;
  }
  else if( info->fd_flags & OO_FDFLAG_EP_PASSTHROUGH ) {
    citp_waitable* w = SP_TO_WAITABLE(ni, info->sock_id);
    citp_alien_fdi* alien_fdi;
    if( ~w->sb_aflags & CI_SB_AFLAG_MOVED_AWAY_IN_EPOLL &&
        fdtable_fd_move(fd, OO_IOC_FILE_MOVED) == 0 ) {
      citp_netif_release_ref(ni, 1);
      *fdip_out = fdip_passthru; 
      return rc;
    }

    alien_fdi = CI_ALLOC_OBJ(citp_alien_fdi);
    if( ! alien_fdi ) {
      Log_E(log("%s: out of memory (alien_fdi)", __FUNCTION__));
      rc = -ENOMEM;
      goto fail;
    }
    fdi = &alien_fdi->fdinfo;
    alien_fdi->netif = ni;
    alien_fdi->ep = SP_TO_WAITABLE(ni, info->sock_id);
    citp_passthrough_init(alien_fdi);
  }
#if CI_CFG_ENDPOINT_MOVE
  else if( info->fd_flags & OO_FDFLAG_EP_ALIEN ) {
    citp_waitable* w = SP_TO_WAITABLE(ni, info->sock_id);
    citp_sock_fdi* sock_fdi;
    ci_netif* alien_ni;

    sock_fdi = CI_ALLOC_OBJ(citp_sock_fdi);
    if( ! sock_fdi ) {
      Log_E(log("%s: out of memory (alien sock_fdi)", __FUNCTION__));
      rc = -ENOMEM;
      goto fail;
    }
    fdi = &sock_fdi->fdinfo;
    rc = citp_netif_by_id(w->moved_to_stack_id, &alien_ni, 1);
    if( rc != 0 ) {
      goto fail;
    }
    sock_fdi->sock.s = SP_TO_SOCK_CMN(alien_ni, w->moved_to_sock_id);
    sock_fdi->sock.netif = alien_ni;
    citp_netif_release_ref(ni, 1);

    /* Replace the file under this fd if possible */
    if( ~w->sb_aflags & CI_SB_AFLAG_MOVED_AWAY_IN_EPOLL )
      fdtable_fd_move(fd, OO_IOC_FILE_MOVED);

    if( sock_fdi->sock.s->b.state & CI_TCP_STATE_TCP )
      proto = &citp_tcp_protocol_impl;
    else if( sock_fdi->sock.s->b.state == CI_TCP_STATE_UDP )
      proto = &citp_udp_protocol_impl;
    else {
      CI_TEST(0);
    }
  }
#endif
  else {
    citp_pipe_fdi* pipe_fdi;

    pipe_fdi = CI_ALLOC_OBJ(citp_pipe_fdi);
    if( ! pipe_fdi ) {
      Log_E(log("%s: out of memory (pipe_fdi)", __FUNCTION__));
      rc = -ENOMEM;
      goto fail;
    }
    fdi = &pipe_fdi->fdinfo;

    pipe_fdi->pipe = SP_TO_PIPE(ni, info->sock_id);
    pipe_fdi->ni = ni;
  }

  citp_fdinfo_init(fdi, proto);

  /* We're returning a reference to the caller. */
  citp_fdinfo_ref(fdi);
  citp_fdtable_insert(fdi, fd, 1);
  *fdip_out = fdi_to_fdip(fdi); 
  return rc;
 
 fail:
  if( ni  )  citp_netif_release_ref(ni, 1);
  *fdip_out = fdip_unknown;
  return rc;
}


/* Find out what sort of thing [fd] is, and if it is a user-level socket
 * then map in the user-level state.
 */
static int
citp_fdtable_probe_locked(unsigned fd, int print_banner,
                          int fdip_is_already_busy, citp_fdinfo** fdi_out)
{
  citp_fdinfo* fdi = NULL;
  struct stat64 st;
  ci_ep_info_t info;
  int rc = 0;

  if( ! fdip_is_already_busy ) {
    volatile citp_fdinfo_p* p_fdip;
    citp_fdinfo_p fdip;
    /* ?? We're repeating some effort already expended in lookup() here, but
    ** this keeps it cleaner.  May optimise down the line when I understand
    ** what other code needs to call this.
    */
    
    p_fdip = &citp_fdtable.table[fd].fdip;
   again:
    fdip = *p_fdip;
    if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);
    if( ! fdip_is_unknown(fdip) && ! fdip_is_normal(fdip) )  goto exit;
    if( fdip_cas_fail(p_fdip, fdip, fdip_busy) )  goto again;
    
    if( fdip_is_normal(fdip) ) {
      fdi = fdip_to_fdi(fdip);
      citp_fdinfo_ref(fdi);
      citp_fdtable_busy_clear(fd, fdip, 1);
      goto exit;
    }
  }

  if( ci_sys_fstat64(fd, &st) != 0 ) {
    /* fstat() failed.  Must be a bad (closed) file descriptor, so
    ** leave this entry as unknown.  Return citp_the_closed_fd to avoid the
    ** caller passing through to an fd that is created asynchronously.
    */
    citp_fdtable_busy_clear(fd, fdip_unknown, 1);
    fdi = &citp_the_closed_fd;
    citp_fdinfo_ref(fdi);
    goto exit;
  }

  /* oo_get_st_rdev() and oo_onloadfs_dev_t() open-and-close fd, so
   * fdtable should be locked if strict mode requested. */
  if( fdtable_strict() )  { CITP_FDTABLE_ASSERT_LOCKED(1); }

  if(  st.st_dev == oo_onloadfs_dev_t() ) {
    /* Retrieve user-level endpoint info */
    if( oo_ep_info(fd, &info) < 0 ) {
      Log_V(log("%s: fd=%d unknown type "OO_FDFLAG_FMT,
                __FUNCTION__, fd, OO_FDFLAG_ARG(info.fd_flags)));
      citp_fdtable_busy_clear(fd, fdip_passthru, 1);
      goto exit;
    }

    switch( info.fd_flags & (OO_FDFLAG_EP_MASK | OO_FDFLAG_STACK) ) {
    case OO_FDFLAG_EP_TCP:
    case OO_FDFLAG_EP_UDP:
    case OO_FDFLAG_EP_PASSTHROUGH:
    case OO_FDFLAG_EP_ALIEN:
    case OO_FDFLAG_EP_PIPE_READ:
    case OO_FDFLAG_EP_PIPE_WRITE:
    {
      citp_fdinfo_p fdip;

      Log_V(log("%s: fd=%d restore type "OO_FDFLAG_FMT, __FUNCTION__, fd,
                OO_FDFLAG_ARG(info.fd_flags)));
      rc = citp_fdtable_probe_restore(fd, &info, print_banner, &fdip);
      if( fdip_is_normal(fdip) )
        fdi = fdip_to_fdi(fdip);
      else
        citp_fdtable_busy_clear(fd, fdip, 1);
      goto exit;
    }

    case OO_FDFLAG_STACK:
      /* This should never happen, because netif fds are close-on-exec.
      ** But let's leave this code here just in case my reasoning is bad.
      */
      Log_U(log("%s: fd=%d NETIF reserved", __FUNCTION__, fd));
      citp_fdtable_busy_clear(fd, fdip_reserved, 1);
      fdi = &citp_the_reserved_fd;
      citp_fdinfo_ref(fdi);
      goto exit;

    default:
      /* This happens if a thread gets at an onload driver fd that has just
       * been created, but not yet specialised.  On Linux I think this
       * means it will shortly be a new netif internal fd.  (fds associated
       * with sockets and pipes are never unspecialised).
       */
      Log_V(log("%s: fd=%d TYPE_NONE", __FUNCTION__, fd));
      citp_fdtable_busy_clear(fd, fdip_passthru, 1);
      goto exit;
    }
  }
#if CI_CFG_EPOLL2
  else if( ci_major(st.st_rdev) == ci_major(oo_get_st_rdev(OO_EPOLL_DEV)) ) {
    citp_epollb_fdi *epi = CI_ALLOC_OBJ(citp_epollb_fdi);
    if( ! epi ) {
      Log_E(log("%s: out of memory (epoll_fdi)", __FUNCTION__));
      citp_fdtable_busy_clear(fd, fdip_passthru, 1);
      goto exit;
    }
    oo_epollb_ctor(epi);
    fdi = &epi->fdinfo;
    citp_fdinfo_init(fdi, &citp_epollb_protocol_impl);
    citp_fdinfo_ref(fdi);
    citp_fdtable_insert(fdi, fd, 1);
    goto exit;
  }
#endif

#ifndef NDEBUG
  /* /dev/onload may be netif or log_fd or onload_fd;
   * they are closed on fork or exec */
  if( ci_major(st.st_rdev) == ci_major(oo_get_st_rdev(OO_STACK_DEV)) )
    Log_U(log("%s: %d is /dev/onload", __FUNCTION__, fd));
#endif

  /* Not one of ours, so pass-through. */
  Log_V(log("%s: fd=%u non-efab", __FUNCTION__, fd));
  citp_fdtable_busy_clear(fd, fdip_passthru, 1);

 exit:
  *fdi_out = fdi;
  return rc;
}

static citp_fdinfo *
citp_fdtable_probe(unsigned fd)
{
  citp_fdinfo* fdi;
  int saved_errno;

  ci_assert(fd < citp_fdtable.size);

  if( ! CITP_OPTS.probe || oo_per_thread_get()->in_vfork_child )
    return NULL;

  saved_errno = errno;
  CITP_FDTABLE_LOCK();
  __citp_fdtable_extend(fd);
  citp_fdtable_probe_locked(fd, CI_FALSE, CI_FALSE, &fdi);
  CITP_FDTABLE_UNLOCK();
  errno = saved_errno;
  return fdi;
}

static int
citp_fdinfo_is_consistent(citp_fdinfo* fdi)
{
  switch( fdi->protocol->type ) {
  case CITP_TCP_SOCKET:
  case CITP_UDP_SOCKET:
    return ~fdi_to_sock_fdi(fdi)->sock.s->b.sb_aflags & CI_SB_AFLAG_MOVED_AWAY;
  }
  return CI_TRUE;
}

citp_fdinfo *
citp_fdtable_lookup(unsigned fd)
{
  /* Note that if we haven't yet initialised this module, then
  ** [inited_count] will be zero, and the following test will fail.  So the
  ** test for initialisation is done further down...
  **
  ** This is highly performance critial.  DO NOT add any code between here
  ** and the first [return] statement.
  */
  citp_fdinfo* fdi;

  /* In some cases, we'll lock fdtable.  Assert that it is possible: */
  ci_assert(oo_per_thread_get()->sig.c.inside_lib);

  if( fd < citp_fdtable.inited_count ) {

    volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
    citp_fdinfo_p fdip;

  again:
    /* Swap in the busy marker. */
    fdip = *p_fdip;

    if( fdip_is_normal(fdip) ) {
      if( citp_fdtable_not_mt_safe() ) {
	if( fdip_cas_succeed(p_fdip, fdip, fdip_busy) ) {
	  fdi = fdip_to_fdi(fdip);
	  ci_assert(fdi);
	  ci_assert_gt(oo_atomic_read(&fdi->ref_count), 0);
	  ci_assert(fdip_is_closing(fdip) || fdip_is_reserved(fdip) ||
		    fdi->fd == fd);
	  /* Bump the reference count. */
	  citp_fdinfo_ref(fdi);

          if( ! citp_fdinfo_is_consistent(fdi) ) {
            /* Something is wrong.  Re-probe. */
            fdi = citp_reprobe_moved(fdi, CI_FALSE, CI_TRUE);
          }
          else {
            /* Swap the busy marker out again. */
            citp_fdtable_busy_clear(fd, fdip, 0);
          }
	  return fdi;
	}
	goto again;
      }
      else {
	/* No need to use atomic ops when single-threaded.  The definition
         * of "fds_mt_safe" is that the app does not change the meaning of
         * a file descriptor in one thread when it is being used in another
         * thread.  In that case I'm hoping this should be safe, but at
         * time of writing I'm really not confident.  (FIXME).
         */
	fdi = fdip_to_fdi(fdip);
        if( ci_is_multithreaded() )
	  citp_fdinfo_ref(fdi);
        else
          ++fdi->ref_count.n;

        if( ! citp_fdinfo_is_consistent(fdi) )
          fdi = citp_reprobe_moved(fdi, CI_FALSE, CI_FALSE);

	return fdi;
      }
    }

    /* Not normal! */
    if( fdip_is_passthru(fdip) )  return NULL;

    if( fdip_is_busy(fdip) ) {
      citp_fdtable_busy_wait(fd, 0);
      goto again;
    }

    ci_assert(fdip_is_unknown(fdip));
    goto probe;
  }

  if (citp.init_level < CITP_INIT_FDTABLE) {
    if (_citp_do_init_inprogress == 0)
      CI_TRY(citp_do_init(CITP_INIT_MAX));
    else
      CI_TRY(citp_do_init(CITP_INIT_FDTABLE)); /* get what we need */
  }

  if( fd >= citp_fdtable.size )  return NULL;

 probe:
  fdi = citp_fdtable_probe(fd);

  return fdi;
}


citp_fdinfo*
citp_fdtable_lookup_fast(citp_lib_context_t* ctx, unsigned fd)
{
  /* Note that if we haven't yet initialised this module, then
  ** [inited_count] will be zero, and the following test will fail.  So the
  ** test for initialisation is done further down...
  **
  ** This is highly performance critial.  DO NOT add any code between here
  ** and the first [return] statement.
  */
  citp_fdinfo* fdi;

  /* Try to avoid entering lib. */
  ctx->thread = NULL;

  if(CI_LIKELY( fd < citp_fdtable.inited_count )) {
    volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
    citp_fdinfo_p fdip;

  again:
    fdip = *p_fdip;
    if(CI_LIKELY( fdip_is_normal(fdip) )) {

      citp_enter_lib_if(ctx);
      if( citp_fdtable_is_mt_safe() ) {
	/* No need to use atomic ops or add a ref to the fdi when MT-safe.
         * The definition of "fds_mt_safe" is that the app does not change
         * the meaning of a file descriptor in one thread when it is being
         * used in another thread.
         */
        fdi = fdip_to_fdi(fdip);
        if(CI_UNLIKELY( ! citp_fdinfo_is_consistent(fdi) ))
          fdi = citp_reprobe_moved(fdi, CI_TRUE, CI_FALSE);

	return fdi;
      }
      else {
        /* Swap in the busy marker. */
	if( fdip_cas_succeed(p_fdip, fdip, fdip_busy) ) {
	  fdi = fdip_to_fdi(fdip);

	  ci_assert(fdi);
	  ci_assert_gt(oo_atomic_read(&fdi->ref_count), 0);
	  ci_assert(fdip_is_closing(fdip) || fdip_is_reserved(fdip) ||
		    fdi->fd == fd);
	  /* Bump the reference count. */
	  citp_fdinfo_ref(fdi);

          if( ! citp_fdinfo_is_consistent(fdi) )
            fdi = citp_reprobe_moved(fdi, CI_FALSE, CI_TRUE);
          else {
            /* Swap the busy marker out again. */
            citp_fdtable_busy_clear(fd, fdip, 0);
          }
	  return fdi;
	}
	goto again;
      }
    }

    /* Not normal! */
    if( fdip_is_passthru(fdip) )
      return NULL;

    citp_enter_lib_if(ctx);
    if( fdip_is_busy(fdip) ) {
      citp_fdtable_busy_wait(fd, 0);
      goto again;
    }

    ci_assert(fdip_is_unknown(fdip));
    goto probe;
  }

  if( citp.init_level < CITP_INIT_FDTABLE ) {
    if( _citp_do_init_inprogress == 0 )
      CI_TRY(citp_do_init(CITP_INIT_MAX));
    else
      CI_TRY(citp_do_init(CITP_INIT_FDTABLE)); /* get what we need */
  }

  if( fd >= citp_fdtable.size )
    return NULL;

 probe:
  citp_enter_lib_if(ctx);
  fdi = citp_fdtable_probe(fd);
  if( fdi && citp_fdtable_is_mt_safe() )
    citp_fdinfo_release_ref(fdi, 0);
  return fdi;
}


/* Looks up the user-level 'FD info' for a given file descriptor.
** Returns pointer to the user-level 'FD info' for a given file
** descriptor, or NULL if the FD is not user-level.
** NOTE: The reference count of the 'FD info' is incremented, the
**       caller should ensure the reference is dropped when no
**       longer needed by calling citp_fdinfo_release_ref().
*/
citp_fdinfo* citp_fdtable_lookup_noprobe(unsigned fd, int fdt_locked)
{
  /* Need to be initialised before we can try and grab the lock at the
  ** moment.  TODO: make this more efficient by using a trylock to grab the
  ** fdtable lock, and on fail see if we need to initialise it.
  */
  if( CI_UNLIKELY(citp.init_level < CITP_INIT_FDTABLE) ) {
    if (_citp_do_init_inprogress == 0)
      CI_TRY(citp_do_init(CITP_INIT_MAX));
    else
      CI_TRY(citp_do_init(CITP_INIT_FDTABLE)); /* get what we need */

    return NULL;
  }

  if( fd < citp_fdtable.inited_count ) {

    volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
    citp_fdinfo_p fdip;

  again:
    /* Swap in the busy marker. */
    fdip = *p_fdip;
    if( fdip_is_normal(fdip) ) {
      if( fdip_cas_succeed(p_fdip, fdip, fdip_busy) ) {
	/* Bump the reference count. */
	citp_fdinfo* fdi = fdip_to_fdi(fdip);
	citp_fdinfo_ref(fdi);
	/* Swap the busy marker out again. */
	citp_fdtable_busy_clear(fd, fdip, fdt_locked);
        return fdi;
      }
      goto again;
    }
    /* Not normal! */
    else if( fdip_is_busy(fdip) ) {
      citp_fdtable_busy_wait(fd, fdt_locked);
      goto again;
    }

  }

  return NULL;
}

static ci_netif* fd_to_netif(int fd, int fdt_locked)
{
  ci_netif* ni = NULL;
  ci_ep_info_t info;

  if( oo_ep_info(fd, &info) < 0 ) {
    Log_V(log("%s: fd=%d unknown", __FUNCTION__, fd));
  }
  else {
    ni = citp_find_ul_netif(info.resource_id, fdt_locked);
  }

  return ni;
}

static void citp_fdinfo_do_handover(citp_fdinfo* fdi, int fdt_locked)
{
  int rc;
  citp_fdinfo* epoll_fdi = NULL;
  int os_fd = fdi->fd;
  ci_netif* ni;
  ci_sock_cmn* sock;
#ifndef NDEBUG
  /* Yuk: does for UDP too. */
  volatile citp_fdinfo_p* p_fdip;
  p_fdip = &citp_fdtable.table[fdi->fd].fdip;
  ci_assert(fdip_is_busy(*p_fdip));
#endif


  Log_V(ci_log("%s: fd=%d nonb_switch=%d", __FUNCTION__, fdi->fd,
	       fdi->on_rcz.handover_nonb_switch));

  epoll_fdi = citp_epoll_fdi_from_member(fdi, fdt_locked);
#if CI_CFG_EPOLL2
  if( fdi->epoll_fd >= 0 && epoll_fdi != NULL &&
      epoll_fdi->protocol->type == CITP_EPOLLB_FD ) {
      citp_epollb_on_handover(epoll_fdi, fdi);
  }
#endif

  /* Handover requires stack state modification, but we also need the dup2
   * lock to avoid the fd we're furtling changing under our feet, and lock
   * ordering requires the stack lock be taken first.
   */
  ni = fd_to_netif(fdi->fd, fdt_locked);
  sock = fdi_to_sock_fdi(fdi)->sock.s;
  /* We should always be able to obtain the netif from our fdi, because if
   * we're handing something over that implies it's currently in a stack.
   */
  ci_assert(ni);
  ci_netif_lock(ni);
  /* Remove SO_LINGER flag from the old ep: we want to close it silently */
  sock->s_flags &=~ CI_SOCK_FLAG_LINGER;
  citp_waitable_cleanup(ni, SOCK_TO_WAITABLE_OBJ(sock), 0);
  rc = fdtable_fd_move(fdi->fd, OO_IOC_TCP_HANDOVER);
  ci_netif_unlock(ni);

  if( rc == -EBUSY && fdi->epoll_fd >= 0 ) {
    ci_assert(sock->b.sb_aflags & CI_SB_AFLAG_MOVED_AWAY);
    /* If this is our epoll, we can do full handover: we manually add os
     * fd into the epoll set.
     * Fixme: ensure we are not in _other_ epoll sets */
    ci_bit_clear(&sock->b.sb_aflags, CI_SB_AFLAG_MOVED_AWAY_IN_EPOLL_BIT);
    rc = fdtable_fd_move(fdi->fd, OO_IOC_FILE_MOVED);
  }
  if( rc != 0 ) {
    citp_fdinfo* new_fdi;
    if( ! fdt_locked ) CITP_FDTABLE_LOCK();
    citp_fdtable_probe_locked(fdi->fd, CI_TRUE, CI_TRUE, &new_fdi);
    citp_fdinfo_release_ref(new_fdi, 1);
    if( ! fdt_locked ) CITP_FDTABLE_UNLOCK();
    ci_assert_equal(citp_fdinfo_get_type(new_fdi), CITP_PASSTHROUGH_FD);
    os_fd = fdi_to_alien_fdi(new_fdi)->os_socket;
  }
  if( fdi->on_rcz.handover_nonb_switch >= 0 ) {
    int on_off = !! fdi->on_rcz.handover_nonb_switch;
    int rc = ci_sys_ioctl(os_fd, FIONBIO, &on_off);
    if( rc < 0 )
      Log_E(ci_log("%s: ioctl failed on_off=%d", __FUNCTION__, on_off));
  }
  if( rc != 0 )
    goto exit;
  citp_fdtable_busy_clear(fdi->fd, fdip_passthru, fdt_locked);
exit:
  citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked);
  if( epoll_fdi != NULL && epoll_fdi->protocol->type == CITP_EPOLL_FD ) {
    citp_epoll_on_handover(epoll_fdi, fdi, fdt_locked);
  }
  else {
    if( epoll_fdi != NULL )
      citp_fdinfo_release_ref(epoll_fdi, fdt_locked);
    citp_fdinfo_free(fdi);
  }
}

#if CI_CFG_FD_CACHING
/* Closes a cached fd. In the typical case, this boils down to sys_close. */
static int uncache_fd_ul(ci_netif* ni, ci_tcp_state* ts, int cur_tgid, int quiet)
{
  int fd  = ts->cached_on_fd;
  int pid = ts->cached_on_pid;
  Log_V(ci_log("Uncaching fd %d on pid %d running pid %d", fd,
               pid, cur_tgid));
  /* No tasklets or other bottom-halves - we always have "current" */
  if( ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE &&
      !(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) ) {
    if( pid != cur_tgid ) {
      if( quiet )
        return -1;
      Log_V(ci_log("%s: file cached on unexpected PID %d , expected %d",
                   __FUNCTION__, pid, cur_tgid));
      return -1;
    }
    S_TO_EPS(ni,ts)->fd = CI_FD_BAD;
    /* simply close kernel FD, it should not affect endpoint at all */
    ci_tcp_helper_close_no_trampoline(fd);
    CITP_STATS_NETIF_INC(ni, epoll_fd_uncache);
  }
  return 0;
}


static void
__citp_uncache_fds_ul(ci_netif* netif, struct oo_p_dllink_state list)
{
  int cur_tgid = getpid();
  ci_tcp_state** eps;
  int n = 0;
  /* Let's do minimal work under the lock that is grab the references to
   * relvant ep bufs*/
  ci_netif_lock(netif);
  {
    int n_ep_bufs = netif->state->n_ep_bufs;
    struct oo_p_dllink_state l;

    eps = malloc(sizeof(ci_tcp_state*) * n_ep_bufs);
    oo_p_dllink_for_each(netif, l, list) {
      if( n >= n_ep_bufs ) {
        ci_log("%s: ep %d with n_ep_bufs %d", __FUNCTION__, n, n_ep_bufs);
        break;
      }
      ci_tcp_state* ts = CI_CONTAINER(ci_tcp_state, epcache_link, l.l);
      ci_assert(ts);
      ci_assert(ci_tcp_is_cached(ts));
      if( ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE &&
          !(ts->s.b.sb_aflags & CI_SB_AFLAG_IN_CACHE_NO_FD) &&
          ts->cached_on_pid == cur_tgid )
        eps[n++] = ts;
    }
  }
  ci_netif_unlock(netif);
  {
    int i;
    for( i = 0; i < n; ++i )
      uncache_fd_ul(netif, eps[i], cur_tgid, 1/*quiet*/);
  }
  free(eps);
}


void
citp_uncache_fds_ul(ci_netif* netif)
{
  {
    int i;
    for( i = 0; i < netif->state->n_ep_bufs; ++i) {
      int fd = netif->eps[i].fd;
      if( fd != CI_FD_BAD )
        ci_tcp_helper_close_no_trampoline(fd);
    }
  }
  return;
  if( netif->cached_count == 0 )
    return;
  Log_V(ci_log("%s: %d: %s: cached_count %d", __func__,
               getpid(), netif->state->pretty_name, netif->cached_count));
  /* Remove all fds from the cache that belong to the current process */
  __citp_uncache_fds_ul(netif, oo_p_dllink_ptr(netif,
                                &netif->state->passive_scalable_cache.cache));
  __citp_uncache_fds_ul(netif, oo_p_dllink_ptr(netif,
                                &netif->state->passive_scalable_cache.pending));
  __citp_uncache_fds_ul(netif, oo_p_dllink_ptr(netif,
                                &netif->state->active_cache.cache));
  __citp_uncache_fds_ul(netif, oo_p_dllink_ptr(netif,
                                &netif->state->active_cache.pending));
}
#endif

#if CI_CFG_UL_INTERRUPT_HELPER
static inline ci_netif* fdi_to_stack(citp_fdinfo* fdi)
{
  switch( fdi->protocol->type ) {
    case CITP_TCP_SOCKET:
    case CITP_UDP_SOCKET:
      return fdi_to_socket(fdi)->netif;
    case CITP_PIPE_FD:
      return fdi_to_pipe_fdi(fdi)->ni;
    case CITP_PASSTHROUGH_FD:
      return fdi_to_alien_fdi(fdi)->netif;
  }
  return NULL;
}
#endif

void __citp_fdinfo_ref_count_zero(citp_fdinfo* fdi, int fdt_locked)
{
#if CI_CFG_FD_CACHING
  int cached;
#endif
  Log_V(log("%s: fd=%d on_rcz=%d", __FUNCTION__, fdi->fd,
	    fdi->on_ref_count_zero));

  citp_fdinfo_assert_valid(fdi);
  ci_assert(oo_atomic_read(&fdi->ref_count) == 0);
  ci_assert_ge(fdi->fd, 0);
  ci_assert_lt(fdi->fd, citp_fdtable.inited_count);
  ci_assert_nequal(fdi_to_fdip(fdi), citp_fdtable.table[fdi->fd].fdip);

  switch( fdi->on_ref_count_zero ) {
  case FDI_ON_RCZ_CLOSE:
#if CI_CFG_FD_CACHING
    cached = citp_fdinfo_get_ops(fdi)->cache(fdi);
    if( cached == 1 ) {
      if( ! fdt_locked && fdtable_strict() )  CITP_FDTABLE_LOCK();
      fdi_to_socket(fdi)->netif->cached_count++;
      fdtable_swap(fdi->fd, fdip_closing, fdip_unknown,
                    fdt_locked | fdtable_strict());
      citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked | fdtable_strict());
      if( ! fdt_locked && fdtable_strict() )  CITP_FDTABLE_UNLOCK();
      citp_fdinfo_free(fdi);
      break;
    }
#endif
    {
#if CI_CFG_UL_INTERRUPT_HELPER
      ci_netif* netif = fdi_to_stack(fdi);
#endif

      /* We mark the fd as busy before closing it to avoid races.  This means
       * that if this fd is looked up during this phase of the close the looker
       * upper will have to wait.
       *
       * There are problems if we try and keep this safe just by swapping
       * the unknown and closing fdi entries.  If we set to unknown before
       * close that could result in things being re-probed in the gap between
       * setting to uknown and actually closing the fd.  If we close before
       * setting to unknown then the fd could be re-used by the kernel
       * without onload seeing it, and lookups would still return the closing
       * fdi until the unknown entry had been swapped in.
       */
      if( ! fdt_locked && fdtable_strict() )  CITP_FDTABLE_LOCK();

      fdtable_swap(fdi->fd, fdip_closing, fdip_busy,
		   fdt_locked | fdtable_strict());
      if( fdi->protocol->type == CITP_TCP_SOCKET )
        SC_TO_EPS(fdi_to_socket(fdi)->netif,fdi_to_socket(fdi)->s)->fd = CI_FD_BAD;

      if( fdi->on_ref_count_zero == FDI_ON_RCZ_CLOSE )
        ci_tcp_helper_close_no_trampoline(fdi->fd);

#if CI_CFG_UL_INTERRUPT_HELPER
      /* If it was the last fd for this socket, then we should proceed with
       * the real closing right now.
       * Todo: In case of SO_LINGER it is really important to handle it all
       * here.
       */
      if( netif != NULL && ci_netif_trylock(netif) ) {
        ci_netif_handle_actions(netif);
        ci_netif_unlock(netif);
      }
#endif

      citp_fdtable_busy_clear(fdi->fd, fdip_unknown,
                              fdt_locked | fdtable_strict());
      citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked | fdtable_strict());
      if( ! fdt_locked && fdtable_strict() )  CITP_FDTABLE_UNLOCK();
      citp_fdinfo_free(fdi);
      break;
    }
  case FDI_ON_RCZ_DUP2:
    dup2_complete(fdi, fdi_to_fdip(fdi), fdt_locked);
    break;
  case FDI_ON_RCZ_HANDOVER:
    citp_fdinfo_do_handover(fdi, fdt_locked);
    break;
  case FDI_ON_RCZ_MOVED:
    citp_fdinfo_get_ops(fdi)->dtor(fdi, fdt_locked);
    citp_fdinfo_free(fdi);
    break;
  default:
    CI_DEBUG(ci_log("%s: fd=%d on_ref_count_zero=%d", __FUNCTION__,
		    fdi->fd, fdi->on_ref_count_zero));
    ci_assert(0);
  }
}


void citp_fdinfo_assert_valid(citp_fdinfo* fdinfo)
{
  ci_assert(fdinfo);
  ci_assert(fdinfo->fd >= 0);
}


void citp_fdinfo_handover(citp_fdinfo* fdi, int nonb_switch)
{
  /* Please see comments in internal.h. */

  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;
  unsigned fd = fdi->fd;

  /* We're about to free some user-level state, so we need to interlock
  ** against select and poll.
  */
  CITP_FDTABLE_LOCK();

  p_fdip = &citp_fdtable.table[fd].fdip;
 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);

  if( fdip == fdi_to_fdip(fdi) ) {
    if( fdip_cas_fail(p_fdip, fdip, fdip_busy) )
      goto again;
  }
  else {
    /* [fd] must have changed meaning under our feet.  It must be closing,
    ** so do nothing except drop the ref passed in.
    */
    ci_assert(fdip_is_closing(fdip));
    ci_assert_nequal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
  }

  if( fdip == fdi_to_fdip(fdi) ) {
    ci_assert_equal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
    fdi->on_ref_count_zero = FDI_ON_RCZ_HANDOVER;
    fdi->on_rcz.handover_nonb_switch = nonb_switch;

    /* Drop the fdtable ref.  When the ref count goes to zero, the handover
    ** will be done.  We return without waiting, because the caller
    ** shouldn't do anything more with this socket anyway.
    */
    citp_fdinfo_release_ref(fdi, 1);
  }

  /* Drop the ref passed in. */
  citp_fdinfo_release_ref(fdi, 1);

  CITP_FDTABLE_UNLOCK();
}


/* This function is called from citp_netif_child_fork_hook() only.
 * It handles any non-standard fdip - currently is "fixes" busy fdip.
 */
void citp_fdtable_fork_hook(void)
{
  unsigned fd;

  for (fd = 0; fd < citp_fdtable.inited_count; fd++) {
    citp_fdinfo_p fdip = citp_fdtable.table[fd].fdip;

    /* Parent has forked when one of its threads had made an fdtable
     * entry busy.  Here in the child no-one will clear the busy state.
     * We can't do any better than just clearing back to the unknown
     * state. */
    if (fdip_is_busy(fdip)) {
      citp_fdtable.table[fd].fdip = fdip_unknown;
      continue;
    }
  }
}


citp_fdinfo_p
citp_fdtable_new_fd_set(unsigned fd, citp_fdinfo_p new_fdip, int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p prev;

  if( fd >= citp_fdtable.inited_count ) {
    ci_assert_lt(fd, citp_fdtable.size);
    if( ! fdt_locked )  CITP_FDTABLE_LOCK();
    __citp_fdtable_extend(fd);
    if( ! fdt_locked )  CITP_FDTABLE_UNLOCK();
  }

  p_fdip = &citp_fdtable.table[fd].fdip;

  do {
    prev = *p_fdip;

    /* Busy?  Perhaps just closed, but not yet marked unknown.  Or perhaps it
    ** is being probed. */
    if( fdip_is_busy(prev) )
      prev = citp_fdtable_busy_wait(fd, fdt_locked);

    /* There is a close in progress, so we wait until it is resolved. */
    if( fdip_is_closing(prev) )
      prev = citp_fdtable_closing_wait(fd, fdt_locked);

    /* Reserved?  Perhaps it was a netif fd that has just been closed.  So it
    ** should be about to be unreserved. */
  } while (fdip_is_reserved(prev) || fdip_cas_fail(p_fdip, prev, new_fdip) );

  if( fdip_is_normal(prev) ) {
    /* We can get here is close-trampolining fails.  So for release
    ** builds we accept that the user-level state got out-of-sync, and
    ** leak [fdi] since it seems like a suitably cautious thing to do.
    */
    ci_log("%s: ERROR: Orphaned entry %d in user-level fd-table",
           __FUNCTION__, fd);
  }
  else
    /* We (at time of writing) only register a trampoline handler when we
    ** create a netif, so we can miss the closing of pass-through
    ** descriptors.
    */
    ci_assert(fdip_is_unknown(prev) || fdip_is_passthru(prev));

  return prev;
}


void citp_fdtable_insert(citp_fdinfo* fdi, unsigned fd, int fdt_locked)
{
  ci_assert(fdi);
  ci_assert(fdi->protocol);
  ci_assert(citp_fdtable.inited_count > fd);
  ci_assert_ge(oo_atomic_read(&fdi->ref_count), 1);

  fdi->fd = fd;
  CI_DEBUG(fdi->on_ref_count_zero = FDI_ON_RCZ_NONE);
  fdi->is_special = 0;
  citp_fdtable_busy_clear(fd, fdi_to_fdip(fdi), fdt_locked);
}


void __citp_fdtable_busy_clear_slow(unsigned fd, citp_fdinfo_p new_fdip,
				    int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
  citp_fdinfo_p fdip, next;
  citp_fdtable_waiter* waiter;

  ci_assert(fd < citp_fdtable.inited_count);

  Log_V(ci_log("%s: fd=%u", __FUNCTION__, fd));

  /* We need to write-lock citp_ul_lock to avoid races between
   * this oo_rwlock_cond_broadcast() and oo_rwlock_cond_wait() below. */
  if( !fdt_locked )
    CITP_FDTABLE_LOCK();

 again:
  fdip = *p_fdip;
  ci_assert(fdip_is_busy(fdip));
  waiter = fdip_to_waiter(fdip);
  ci_assert(waiter);
  ci_assert(fdip_is_busy(waiter->next));
  if( waiter->next == fdip_busy )  next = new_fdip;
  else                             next = waiter->next;
  if( fdip_cas_fail(p_fdip, fdip, next) )  goto again;

  oo_rwlock_cond_broadcast(&waiter->cond);

  if( next != new_fdip )  goto again;

  if( !fdt_locked )
    CITP_FDTABLE_UNLOCK();
}


citp_fdinfo_p citp_fdtable_busy_wait(unsigned fd, int fdt_locked)
{
  volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
  citp_fdtable_waiter waiter;
  int saved_errno = errno;

  Log_V(ci_log("%s: fd=%u", __FUNCTION__, fd));

  ci_assert(ci_is_multithreaded());

  oo_rwlock_cond_init(&waiter.cond);

  /* We should lock citp_ul_lock before checking the condition which can
   * lead to oo_rwlock_cond_wait() call. */
  if( !fdt_locked )
    CITP_FDTABLE_LOCK();

 again:
  waiter.next = *p_fdip;
  if( fdip_is_busy(waiter.next) ) {
    /* we can replace one "busy" fdip by another without fdtable lock */
    if( fdip_cas_succeed(p_fdip, waiter.next, waiter_to_fdip(&waiter)) )
      oo_rwlock_cond_wait(&waiter.cond, &citp_ul_lock);
    goto again;
  }

  if( !fdt_locked )
    CITP_FDTABLE_UNLOCK();

  oo_rwlock_cond_destroy(&waiter.cond);

  errno = saved_errno;
  return waiter.next;
}


static citp_fdinfo_p citp_fdtable_closing_wait(unsigned fd, int fdt_locked)
{
  /* We're currently spinning in this case.  Not ideal, but implementing
  ** blocking here is slightly tricky.  (Can be done, but I want proof that
  ** it's needed first!)
  */
  volatile citp_fdinfo_p* p_fdip = &citp_fdtable.table[fd].fdip;
  citp_fdinfo_p fdip;

  Log_V(ci_log("%s: fd=%u", __FUNCTION__, fd));

 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip)    )  fdip = citp_fdtable_busy_wait(fd, fdt_locked);
  if( fdip_is_closing(fdip) ) {
    if( fdt_locked ) {
      /* Need to drop the lock to avoid deadlock with the other thread
      ** trying to closing this fd! */
      CITP_FDTABLE_UNLOCK();
      CITP_FDTABLE_LOCK();
    }
    goto again;
  }
  return fdip;
}


void __citp_fdtable_reserve(int fd, int protect)
{
  /* Must be holding the lock. */
  CITP_FDTABLE_ASSERT_LOCKED(1);
  ci_assert_lt((unsigned) fd, citp_fdtable.size);

  if( protect )  citp_fdtable_new_fd_set(fd, fdip_reserved, 1);
  else           fdtable_swap(fd, fdip_reserved, fdip_unknown, 1);
}


/**********************************************************************
 * citp_ep_dup()
 */

int citp_ep_dup_dup(int oldfd, long arg_unused)
{
  return ci_sys_dup(oldfd);
}


int citp_ep_dup_fcntl_dup(int oldfd, long arg)
{
  return ci_sys_fcntl(oldfd, F_DUPFD, arg);
}

int citp_ep_dup_fcntl_dup_cloexec(int oldfd, long arg)
{
  return ci_sys_fcntl(oldfd, F_DUPFD_CLOEXEC, arg);
}

/*
** Why do these live here?  Because they need to hack into the low-level
** dirty nastiness of the fdtable.
*/
int citp_ep_dup(unsigned oldfd, int (*syscall)(int oldfd, long arg),
		long arg)
{
  /* This implements dup(oldfd) and fcntl(oldfd, F_DUPFD, arg). */

  volatile citp_fdinfo_p* p_oldfdip;
  citp_fdinfo_p oldfdip;
  citp_fdinfo* newfdi = 0;
  citp_fdinfo* oldfdi;
  int newfd;

  Log_V(log("%s(%d)", __FUNCTION__, oldfd));

  if(CI_UNLIKELY( citp.init_level < CITP_INIT_FDTABLE ||
                  oo_per_thread_get()->in_vfork_child ))
    /* Lib not initialised, so no U/L state, and therefore system dup()
    ** will do just fine. */
    return syscall(oldfd, arg);

  if( oldfd >= citp_fdtable.inited_count ) {
    /* NB. We can't just pass through in this case because we need to worry
    ** about other threads racing with us.  So we need to be able to lock
    ** this fd while we do the dup. */
    ci_assert(oldfd < citp_fdtable.size);
    CITP_FDTABLE_LOCK();
    __citp_fdtable_extend(oldfd);
    CITP_FDTABLE_UNLOCK();
  }

  p_oldfdip = &citp_fdtable.table[oldfd].fdip;
 again:
  oldfdip = *p_oldfdip;
  if( fdip_is_busy(oldfdip) )
    oldfdip = citp_fdtable_busy_wait(oldfd, 0);
  if( fdip_is_closing(oldfdip) | fdip_is_reserved(oldfdip) ) {
    errno = EBADF;
    return -1;
  }
#if CI_CFG_FD_CACHING
  /* Need to check in case this sucker's cached */
  if( fdip_is_unknown(oldfdip) ) {
    CITP_FDTABLE_LOCK();
    citp_fdtable_probe_locked(oldfd, CI_FALSE, CI_FALSE, &oldfdi);
    CITP_FDTABLE_UNLOCK();
    if( oldfdi == &citp_the_closed_fd ) {
      citp_fdinfo_release_ref(oldfdi, CI_TRUE);
      errno = EBADF;
      return -1;
    }
    if( oldfdi )
      citp_fdinfo_release_ref(oldfdi, CI_TRUE);
  }
#endif
  if( fdip_cas_fail(p_oldfdip, oldfdip, fdip_busy) )
    goto again;

#if CI_CFG_FD_CACHING
  /* May end up with multiple refs to this, don't allow it to be cached. */
  if( fdip_is_normal(oldfdip) )
    fdip_to_fdi(oldfdip)->can_cache = 0;
#endif

  if( fdip_is_normal(oldfdip) &&
      (((oldfdi = fdip_to_fdi(oldfdip))->protocol->type) == CITP_EPOLL_FD) ) {
    newfdi = citp_fdinfo_get_ops(oldfdi)->dup(oldfdi);
    if( ! newfdi ) {
      citp_fdtable_busy_clear(oldfd, oldfdip, 0);
      errno = ENOMEM;
      return -1;
    }

    if( fdtable_strict() )  CITP_FDTABLE_LOCK();
    newfd = syscall(oldfd, arg);
    if( newfd >= 0 )
      citp_fdtable_new_fd_set(newfd, fdip_busy, fdtable_strict());
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
    if( newfd >= 0 ) {
      citp_fdtable_insert(newfdi, newfd, 0);
      newfdi = 0;
    }
  }
  else {
    if( fdtable_strict() )  CITP_FDTABLE_LOCK();
    newfd = syscall(oldfd, arg);
    if( newfd >= 0 && newfd < citp_fdtable.inited_count ) {
      /* Mark newfd as unknown.  When used, it'll get probed.
       *
       * We are not just being lazy here: Setting to unknown rather than
       * installing a proper fdi (when oldfd is accelerated) is essential to
       * vfork()+dup()+exec() working properly.  Reason is that child and
       * parent share address space, so child is modifying the parent's
       * fdtable.  Setting an entry to unknown is safe.
       */
      citp_fdtable_new_fd_set(newfd, fdip_unknown, fdtable_strict());
    }
    if( fdtable_strict() )  CITP_FDTABLE_UNLOCK();
  }

  citp_fdtable_busy_clear(oldfd, oldfdip, 0);
  if( newfdi )  citp_fdinfo_free(newfdi);
  return newfd;
}


static void dup2_complete(citp_fdinfo* prev_tofdi,
			  citp_fdinfo_p prev_tofdip, int fdt_locked)
{
  volatile citp_fdinfo_p *p_fromfdip;
  unsigned fromfd = prev_tofdi->on_rcz.dup3_args.fd;
  unsigned tofd = prev_tofdi->fd;
  citp_fdinfo_p fromfdip;
  int rc;
  int flags = prev_tofdi->on_rcz.dup3_args.flags;

#ifndef NDEBUG
  volatile citp_fdinfo_p* p_tofdip;
  p_tofdip = &citp_fdtable.table[tofd].fdip;
  ci_assert(fdip_is_busy(*p_tofdip));
#endif
  citp_fdinfo* fromfdi;

  p_fromfdip = &citp_fdtable.table[fromfd].fdip;
 lock_fromfdip_again:
  fromfdip = *p_fromfdip;
  if( fdip_is_busy(fromfdip) )
    fromfdip = citp_fdtable_busy_wait(fromfd, fdt_locked);
  if( fdip_is_closing(fromfdip) | fdip_is_reserved(fromfdip) ) {
    prev_tofdi->on_rcz.dup2_result = -EBADF;
    ci_wmb();
    prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
    return;
  }
#if CI_CFG_FD_CACHING
  /* Need to check in case this sucker's cached */
  if( fdip_is_unknown(fromfdip) ) {
    if( !fdt_locked ) CITP_FDTABLE_LOCK();
    citp_fdtable_probe_locked(fromfd, CI_FALSE, CI_FALSE, &fromfdi);
    if( !fdt_locked ) CITP_FDTABLE_UNLOCK();
    if( fromfdi == &citp_the_closed_fd ) {
      prev_tofdi->on_rcz.dup2_result = -EBADF;
      ci_wmb();
      prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
      citp_fdinfo_release_ref(fromfdi, CI_TRUE);
      return;
    }
    if( fromfdi )
      citp_fdinfo_release_ref(fromfdi, CI_TRUE);
  }
#endif
  if( fdip_cas_fail(p_fromfdip, fromfdip, fdip_busy) )
    goto lock_fromfdip_again;

  oo_rwlock_lock_write(&citp_dup2_lock);
  rc = ci_sys_dup3(fromfd, tofd, flags);
  oo_rwlock_unlock_write(&citp_dup2_lock);
  if( rc < 0 ) {
    citp_fdtable_busy_clear(fromfd, fromfdip, fdt_locked);
    prev_tofdi->on_rcz.dup2_result = -errno;
    ci_wmb();
    prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
    return;
  }

  ci_assert(fdip_is_normal(fromfdip) | fdip_is_passthru(fromfdip) |
	    fdip_is_unknown(fromfdip));

  if( fdip_is_normal(fromfdip) &&
     (((fromfdi = fdip_to_fdi(fromfdip))->protocol->type) == CITP_EPOLL_FD) ) {
    citp_fdinfo* newfdi = citp_fdinfo_get_ops(fromfdi)->dup(fromfdi);
    if( newfdi ) {
      citp_fdinfo_init(newfdi, fdip_to_fdi(fromfdip)->protocol);
      citp_fdtable_insert(newfdi, tofd, fdt_locked);
    }
    else {
      /* Out of memory.  Can't probe epoll1 fd later on, so fail. */
      citp_fdtable_busy_clear(fromfd, fromfdip, fdt_locked);
      prev_tofdi->on_rcz.dup2_result = -ENOMEM;
      ci_wmb();
      prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
      return;
    }
  }
  else {
    /* Mark newfd as unknown.  When used, it'll get probed.
     *
     * We are not just being lazy here: Setting to unknown rather than
     * installing a proper fdi (when oldfd is accelerated) is essential to
     * vfork()+dup2()+exec() working properly.  Reason is that child and
     * parent share address space, so child is modifying the parent's
     * fdtable.  Setting an entry to unknown is safe.
     */
    citp_fdtable_busy_clear(tofd, fdip_unknown, fdt_locked);

#if CI_CFG_FD_CACHING
    /* Multiple refs to this now, don't allow it to be cached. */
    if( fdip_is_normal(fromfdip) )
      fdip_to_fdi(fromfdip)->can_cache = 0;
#endif
  }

  citp_fdtable_busy_clear(fromfd, fromfdip, fdt_locked);
  prev_tofdi->on_rcz.dup2_result = tofd;
  ci_wmb();
  prev_tofdi->on_ref_count_zero = FDI_ON_RCZ_DONE;
}

pthread_mutex_t citp_dup_lock = PTHREAD_MUTEX_INITIALIZER;

int citp_ep_dup3(unsigned fromfd, unsigned tofd, int flags)
{
  volatile citp_fdinfo_p* p_tofdip;
  citp_fdinfo_p tofdip;
  citp_fdinfo_p fromfdip;
  unsigned max;

  Log_V(log("%s(%d, %d)", __FUNCTION__, fromfd, tofd));

  /* Must be checked by callers. */
  ci_assert(fromfd != tofd);

  ci_assert(citp.init_level >= CITP_INIT_FDTABLE);

  max = CI_MAX(fromfd, tofd);
  if( max >= citp_fdtable.inited_count ) {
    ci_assert(max < citp_fdtable.size);
    CITP_FDTABLE_LOCK();
    __citp_fdtable_extend(max);
    CITP_FDTABLE_UNLOCK();
  }

  /* If we don't know what fromfd is then we'll need it to be probed later
   * in the dup process.  By doing it now we ensure that any side affects
   * happen before we end up taking more locks and changing the state.  In
   * particular this can result in us attaching to a stack, and trying to
   * insert the new stack fd into the fdtable.  This causes problems if the
   * fd we're dup'ing onto is the same as the fd selected for the stack as
   * we'll end up waiting for the target fd to stop being busy, and it won't.
   */
  fromfdip = citp_fdtable.table[fromfd].fdip;
  if( fdip_is_unknown(fromfdip) ) {
    citp_fdinfo* fromfdi;
    CITP_FDTABLE_LOCK();
    citp_fdtable_probe_locked(fromfd, CI_FALSE, CI_FALSE, &fromfdi);
    if( fromfdi )
      citp_fdinfo_release_ref(fromfdi, CI_TRUE);
    CITP_FDTABLE_UNLOCK();
  }

  /* Bug1151: Concurrent threads doing dup2(x,y) and dup2(y,x) can deadlock
  ** against one another.  So we take out a fat lock to prevent concurrent
  ** dup2()s.
  */
  /* Lock tofd.  We need to interlock against select and poll etc, so we
  ** also grab the exclusive lock.  Also grab the bug1151 lock.
  */
  pthread_mutex_lock(&citp_dup_lock);
  CITP_FDTABLE_LOCK();
  p_tofdip = &citp_fdtable.table[tofd].fdip;
 lock_tofdip_again:
  tofdip = *p_tofdip;
  if( fdip_is_busy(tofdip) )
    tofdip = citp_fdtable_busy_wait(tofd, 1);
  if( fdip_is_closing(tofdip) )
    tofdip = citp_fdtable_closing_wait(tofd, 1);
  if( fdip_is_reserved(tofdip) ) {
    /* ?? FIXME: we can't cope with this at the moment */
    CITP_FDTABLE_UNLOCK();
    Log_U(log("%s(%d, %d): target is reserved, see EF_ONLOAD_FD_BASE",
              __FUNCTION__, fromfd, tofd));
    errno = EBUSY;
    tofd = -1;
    goto out;
  }
  if( fdip_cas_fail(p_tofdip, tofdip, fdip_busy) )
    goto lock_tofdip_again;
  CITP_FDTABLE_UNLOCK();
  ci_assert(fdip_is_normal(tofdip) | fdip_is_passthru(tofdip) |
 	    fdip_is_unknown(tofdip));

  if( fdip_is_normal(tofdip) ) {
    /* We're duping onto a user-level socket. */
    citp_fdinfo* tofdi = fdip_to_fdi(tofdip);

#if CI_CFG_EPOLL3
    if( tofdi->epoll_fd >= 0 ) {
      citp_fdinfo* epoll_fdi = citp_epoll_fdi_from_member(tofdi, 0);
      if( epoll_fdi ) {
        if( epoll_fdi->protocol->type == CITP_EPOLL_FD )
          citp_epoll_on_close(epoll_fdi, tofdi, 0);
        citp_fdinfo_release_ref(epoll_fdi, 0);
      }
    }
#endif

#if CI_CFG_FD_CACHING
    if( citp_fdinfo_get_ops(tofdi)->close != NULL )
      citp_fdinfo_get_ops(tofdi)->close(tofdi);
#endif

    ci_assert_equal(tofdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
    tofdi->on_ref_count_zero = FDI_ON_RCZ_DUP2;
    tofdi->on_rcz.dup3_args.fd = fromfd;
    tofdi->on_rcz.dup3_args.flags = flags;
    citp_fdinfo_release_ref(tofdi, 0);
    {
      int i = 0;
      /* We need to free this fdi.  If someone is using it right now,
       * we are in trouble.  So, we spin for a while and interrupt the
       * user.  See bug 28123. */
      while( tofdi->on_ref_count_zero != FDI_ON_RCZ_DONE ) {
        if( ci_is_multithreaded() && i % 10000 == 9999 ) {
          pthread_t pth = tofdi->thread_id;
          if( pth !=  pthread_self() && pth != PTHREAD_NULL ) {
            pthread_kill(pth, SIGONLOAD);
            sleep(1);
          }
        }
        ci_spinloop_pause();
        i++;
      }
      ci_rmb();
    }
    if( tofdi->on_rcz.dup2_result < 0 ) {
      errno = -tofdi->on_rcz.dup2_result;
      /* Need to re-insert [tofdi] into the table. */
      ci_assert_equal(oo_atomic_read(&tofdi->ref_count), 0);
      oo_atomic_set(&tofdi->ref_count, 1);
      CI_DEBUG(tofdi->on_ref_count_zero = FDI_ON_RCZ_NONE);
      citp_fdtable_busy_clear(tofd, tofdip, 0);
      tofd = -1;
    }
    else {
      ci_assert(tofdi->on_rcz.dup2_result == tofd);
      citp_fdinfo_get_ops(tofdi)->dtor(tofdi, 0);
      citp_fdinfo_free(tofdi);
    }
    goto out;
  }

  ci_assert(fdip_is_passthru(tofdip) | fdip_is_unknown(tofdip));

  { /* We're dupping onto an O/S descriptor, or it may be closed.  Create a
    ** dummy [citp_fdinfo], just so we can share code with the case above.
    */
    citp_fdinfo fdi;
    fdi.fd = tofd;
    fdi.on_rcz.dup3_args.fd = fromfd;
    fdi.on_rcz.dup3_args.flags = flags;
    dup2_complete(&fdi, tofdip, 0);
    if( fdi.on_rcz.dup2_result < 0 ) {
      errno = -fdi.on_rcz.dup2_result;
      citp_fdtable_busy_clear(tofd, tofdip, 0);
      tofd = -1;
    }
    else
      ci_assert(fdi.on_rcz.dup2_result == tofd);
  }

 out:
  pthread_mutex_unlock(&citp_dup_lock);
  return tofd;
}


/**********************************************************************
 * citp_ep_close()
 */

int citp_ep_close(unsigned fd)
{
  volatile citp_fdinfo_p* p_fdip;
  citp_fdinfo_p fdip;
  int rc, got_lock;
  citp_fdinfo* fdi;

  if( fd < 0 )
    RET_WITH_ERRNO(EINVAL);

  /* Do not touch fdtable when in vfork. */
  if( oo_per_thread_get()->in_vfork_child )
    ci_tcp_helper_close_no_trampoline(fd);

  /* Initialise fdtable and log fd if needed */
  if( fd >= citp_fdtable.inited_count ) {
    if( citp_fdtable.inited_count == 0 || citp_fd_is_special(fd) ) {
      CITP_FDTABLE_LOCK();
      __citp_fdtable_extend(citp.log_fd);
      CITP_FDTABLE_UNLOCK();
    }
    if( fd >= citp_fdtable.inited_count )
      return ci_tcp_helper_close_no_trampoline(fd);
  }

  /* Interlock against other closes, against the fdtable being extended,
  ** and against select and poll.
  */
  CITP_FDTABLE_LOCK();
  got_lock = 1;

  p_fdip = &citp_fdtable.table[fd].fdip;
 again:
  fdip = *p_fdip;
  if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);

  if( fdip_is_closing(fdip) | fdip_is_reserved(fdip) ) {
    /* Concurrent close or attempt to close reserved. */
    Log_V(ci_log("%s: fd=%d closing=%d reserved=%d", __FUNCTION__, fd,
		 fdip_is_closing(fdip), fdip_is_reserved(fdip)));
    errno = EBADF;
    rc = -1;
    goto done;
  }

#if CI_CFG_FD_CACHING
  /* Need to check in case this sucker's cached */
  if( fdip_is_unknown(fdip) ) {
    citp_fdtable_probe_locked(fd, CI_FALSE, CI_FALSE, &fdi);
    if( fdi == &citp_the_closed_fd ) {
      citp_fdinfo_release_ref(fdi, CI_TRUE);
      errno = EBADF;
      rc = -1;
      goto done;
    }
    if( fdi )
      citp_fdinfo_release_ref(fdi, CI_TRUE);
  }
#endif

  ci_assert(fdip_is_normal(fdip) | fdip_is_passthru(fdip) |
	    fdip_is_unknown(fdip));

  /* Swap in the "closed" pseudo-fdinfo.  This lets any other thread know
  ** that we're in the middle of closing this fd.
  */
  if( fdip_cas_fail(p_fdip, fdip, fdip_closing) )
    goto again;

  if( fdip_is_normal(fdip) ) {
    fdi = fdip_to_fdi(fdip);

    CITP_FDTABLE_UNLOCK();
    got_lock = 0;

    if( fdi->is_special ) {
      Log_V(ci_log("%s: fd=%d is_special, returning EBADF", __FUNCTION__, fd));
      errno = EBADF;
      rc = -1;
      fdtable_swap(fd, fdip_closing, fdip, 0);
      goto done;
    }

    Log_V(ci_log("%s: fd=%d u/l socket", __FUNCTION__, fd));
    ci_assert_equal(fdi->fd, fd);
    ci_assert_equal(fdi->on_ref_count_zero, FDI_ON_RCZ_NONE);
    fdi->on_ref_count_zero = FDI_ON_RCZ_CLOSE;

#if CI_CFG_EPOLL3
    if( fdi->epoll_fd >= 0 ) {
      citp_fdinfo* epoll_fdi = citp_epoll_fdi_from_member(fdi, 0);
      if( epoll_fdi ) {
        if( epoll_fdi->protocol->type == CITP_EPOLL_FD )
          citp_epoll_on_close(epoll_fdi, fdi, 0);
        citp_fdinfo_release_ref(epoll_fdi, 0);
      }
    }
#endif

#if CI_CFG_FD_CACHING
    if( citp_fdinfo_get_ops(fdi)->close != NULL )
      citp_fdinfo_get_ops(fdi)->close(fdi);
#endif

    citp_fdinfo_release_ref(fdi, 0);
    rc = 0;
  }
  else {
    ci_assert(fdip_is_passthru(fdip) ||
	      fdip_is_unknown(fdip));
    if( ! fdtable_strict() ) {
      CITP_FDTABLE_UNLOCK();
      got_lock = 0;
    }
    Log_V(ci_log("%s: fd=%d passthru=%d unknown=%d", __FUNCTION__, fd,
		 fdip_is_passthru(fdip), fdip_is_unknown(fdip)));
    fdtable_swap(fd, fdip_closing, fdip_unknown, fdtable_strict());
    rc = ci_tcp_helper_close_no_trampoline(fd);
  }

 done:
  if( got_lock )  CITP_FDTABLE_UNLOCK();
  FDTABLE_ASSERT_VALID();
  return rc;
}

/* Re-probe fdinfo after endpoint was moved to another stack.
 * The function assumes that fdinfo was obtained via citp_fdtable_lookup()
 * or from citp_fdtable_lookup_fast().  The _fast() variant is used by
 * read/write/recvmsg/sendto/... socket call interceptors. */
int citp_reprobe_moved_common(citp_fdinfo* fdinfo, int from_fast_lookup,
                              int fdip_is_already_busy,
                              citp_fdinfo** fdinfo_out)
{
  int fd = fdinfo->fd;
  citp_fdinfo* new_fdinfo = NULL;
  int rc = 0;

  CITP_FDTABLE_LOCK();

  if( ! fdip_is_already_busy ) {
    volatile citp_fdinfo_p* p_fdip;
    citp_fdinfo_p fdip;
    
    p_fdip = &citp_fdtable.table[fd].fdip;
   again:
    fdip = *p_fdip;
    if( fdip_is_busy(fdip) )  fdip = citp_fdtable_busy_wait(fd, 1);
    ci_assert( fdip_is_normal(fdip) || fdip_is_passthru(fdip) );
    if( fdip_cas_fail(p_fdip, fdip, fdip_busy) )  goto again;
    
    /* Possibly, a parrallel thread have already called
     * citp_reprobe_moved() for us. */
    if( fdip_is_passthru(fdip) ) {
      citp_fdtable_busy_clear(fd, fdip, 1);
      if( new_fdinfo != NULL )
        citp_fdinfo_ref(new_fdinfo);
      goto done;
    }
    ci_assert( fdip_is_normal(fdip) );
    new_fdinfo = fdip_to_fdi(fdip);
    if( new_fdinfo != fdinfo) {
      citp_fdtable_busy_clear(fd, fdip, 1);
      if( new_fdinfo != NULL )
        citp_fdinfo_ref(new_fdinfo);
      goto done;
    }
  }
  else
    ci_assert(fdip_is_busy(citp_fdtable.table[fd].fdip));

  /* re-probe new fd */
  rc = citp_fdtable_probe_locked(fd, CI_TRUE, CI_TRUE, &new_fdinfo);

  if( fdinfo->epoll_fd >= 0 ) {
    citp_fdinfo* epoll_fdi = citp_epoll_fdi_from_member(fdinfo, 1);
#if CI_CFG_EPOLL2
    if( epoll_fdi->protocol->type == CITP_EPOLLB_FD ) {
      citp_epollb_on_handover(epoll_fdi, fdinfo);
      citp_fdinfo_release_ref(epoll_fdi, 1);
    }
    else
#endif
    {
      citp_epoll_on_move(epoll_fdi, fdinfo, new_fdinfo, 1);
    }
  }

  /* Drop refcount from fdtable */
  fdinfo->on_ref_count_zero = FDI_ON_RCZ_MOVED;
  citp_fdinfo_release_ref(fdinfo, 1);

 done:
  /* One refcount from the caller */
  if( from_fast_lookup )
    citp_fdinfo_release_ref_fast(fdinfo);
  else
    citp_fdinfo_release_ref(fdinfo, 1);

  CITP_FDTABLE_UNLOCK();
  if( new_fdinfo == NULL ) {
    *fdinfo_out = NULL;
    return rc;
  }

  if( from_fast_lookup ) {
    citp_fdinfo_ref_fast(new_fdinfo);
    citp_fdinfo_release_ref(new_fdinfo, 0);
  }

  *fdinfo_out = new_fdinfo;
  return rc;
}

void init_citp_log_fd(void)
{
  int fd;

  if( ef_onload_driver_open(&fd, OO_STACK_DEV, 1) )  return;
  if( ci_cas32_succeed(&citp.log_fd, -1, fd) ) {
    /* We do not know the current context, so we can't lock fdtable,
     * or leverage the already-taken lock.
     * Let's hope that logging happens at start of day, so our fd is
     * small enough.
     * __citp_fdtable_extend() will take care about our fd as well.
     */
    if( citp_fdtable.table ) {
      ci_assert_lt(fd, citp_fdtable.size);
      citp_fdtable.table[citp.log_fd].fdip =
                                      fdi_to_fdip(&citp_the_reserved_fd);
    }
  }
  else {
    /* Unspecialised /dev/onload does not trampoline,
     * so simple close is OK.  */
    ci_sys_close(fd);
  }
}


int ci_tcp_helper_close_no_trampoline(int fd)
{
  return my_syscall3(close, fd, 0, 0);
}

/*! \cidoxg_end */
