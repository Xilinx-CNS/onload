/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include "onload_kernel_compat.h"

#include <onload/linux_onload_internal.h>
#include <onload/linux_trampoline.h>
#include <onload/linux_mmap.h>
#include <onload/linux_onload.h>
#include <asm/unistd.h>
#include <linux/unistd.h>
#include <asm/errno.h>
#include <asm/sysreg.h>
#include <asm/esr.h>
#include <asm/insn.h>
#include <asm/ptrace.h>
#include <linux/stop_machine.h>

/* On 4.17+ on ARM64 the system calls are taking a single
   ptregs argument.
   (The user-space calling convention is the same as before, though).
*/
#ifdef ONLOAD_SYSCALL_PTREGS
#  define SYSCALL_PTR_DEF(_name)                        \
  asmlinkage long (*saved_##_name)(const struct pt_regs *regs)
#  define PASS_SYSCALL1(_name, _arg)                    \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg)}))
#  define PASS_SYSCALL2(_name, _arg1, _arg2)                  \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1), \
        .regs[1] = (u64)(_arg2)}))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3)                     \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1),           \
        .regs[1] = (unsigned long)(_arg2),                              \
        .regs[2] = (unsigned long)(_arg3)}))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)              \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1),           \
        .regs[1] = (u64)(_arg2),                                        \
        .regs[2] = (u64)(_arg3),                                        \
        .regs[3] = (u64)(_arg4)}))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6) \
  ((saved_##_name)(&(struct pt_regs){.regs[0] = (u64)(_arg1),           \
        .regs[1] = (u64)(_arg2),                                        \
        .regs[2] = (u64)(_arg3),                                        \
        .regs[3] = (u64)(_arg4),                                        \
        .regs[4] = (u64)(_arg5),                                        \
        .regs[5] = (u64)(_arg6)}))
#else
#  define SYSCALL_PTR_DEF(_name)                \
    asmlinkage typeof(_name) *saved_##_name
#  define PASS_SYSCALL1(_name, _arg) ((saved_##_name)(_arg))
#  define PASS_SYSCALL2(_name, _arg1, _arg2) ((saved_##_name)(_arg1, _arg2))
#  define PASS_SYSCALL3(_name, _arg1, _arg2, _arg3) \
  ((saved_##_name)(_arg1, _arg2, _arg3))
#  define PASS_SYSCALL4(_name, _arg1, _arg2, _arg3, _arg4)    \
  ((saved_##_name)(_arg1, _arg2, _arg3, _arg4))
#  define PASS_SYSCALL6(_name, _arg1, _arg2, _arg3, _arg4, _arg5, _arg6)    \
  ((saved_##_name)(_arg1, _arg2, _arg3, _arg4, _arg5, _arg6))
#endif

static typeof(aarch64_insn_decode_immediate) *aarch64_insn_decode_immediate_sym;
static typeof(aarch64_insn_read) *aarch64_insn_read_sym;
static typeof(aarch64_insn_extract_system_reg) *aarch64_insn_extract_system_reg_sym;
static typeof(aarch64_get_branch_offset) *aarch64_get_branch_offset_sym;
static typeof(aarch64_insn_adrp_get_offset) *aarch64_insn_adrp_get_offset_sym;

/* Depending on the kernel version, locating the syscall table may be more
 * or less straigthforward.
 * In the most lucky event, sys_call_table symbol is declared extern, and so
 * it can be fetched directly with efrm_find_ksym().
 * Otherwise we need to proceed through syscall calling sequence. There are
 * some intermediate symbols that may happen to be available so we try to
 * use them first, and if they are not found, resort to assembler code
 * scanning.
 *
 * So the syscall routine looks like this:
 * - the address of exception handler table is in vbar_el1 system register;
 *   this is the value used by `svc` instruction in the user space and so
 *   it is always available irrespective to any kernel symbols being exposed
 * - the exception table is a table of 128-byte blocks. The handler for
 *   user-space generated exceptions is 9th. The content of the block is
 *   some code which includes a jump to real handler. Depending on the
 *   kernel version and configuration, that may be either a first instruction
 *   in the block or at some fixed position forward.
 * - the handler is labelled `el0_sync` and it may be an extern symbol.
 *   Locating it is the task of find_el_sync() function.
 *   The handler itself does some dispatching based on the exception
 *   syndrome register.
 *   So it consist of the kernel entry code which we must skip and then a
 *   read from esr_el1 register which uniquely identifies the start of the
 *   code we're looking for.
 *   Then there will be a cascade of comparisons, and we expect that the
 *   branch we are interested in is the first one. However, we make sure
 *   that this is the case by ensuring that there is indeed the cmp
 *   instruction with a proper immediate argument.
 *   The next instruction is a jump to the actual handler for syscalls.
 * - it is labelled `el0_svc` and it may also be an extern symbol, and
 *   finding it is the task of find_el_svc() function.
 *   Now the first instruction of `el0_svc` should be the load of the
 *   address of the sys_call_table, where we can obtain it in the function
 *   find_syscall_table_via_vbar().
 *
 * The employed scheme should be robust enough to survive small changes in
 * the syscall calling sequence across the kernel, but of course we cannot
 * be sure it will never break, so there are as many safety checks here as possible.
 */

static ci_uint8 *
find_el_sync(void)
{
  ci_uint8 *vectors;
  ci_uint32 insn;
  ci_uint8 *el_sync = efrm_find_ksym("el0_sync");

  if (el_sync != NULL)
    return el_sync;

  vectors = (ci_uint8 *)read_sysreg(vbar_el1);
  vectors += 8 * 128;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
  vectors += sizeof(ci_uint32);
#if defined(CONFIG_VMAP_STACK)
  vectors += 5 * sizeof(ci_uint32);
#endif
#endif
  if (aarch64_insn_read_sym(vectors, &insn)) {
    ci_log("cannot read vbar_el1");
    return NULL;
  }
  if (!aarch64_insn_is_b(insn)) {
    ci_log("el0_sync entry is not a branch");
    return NULL;
  }
  el_sync = vectors + aarch64_get_branch_offset_sym(insn);

  return el_sync;
}

static ci_uint8 *
find_el_svc_entry(void)
{
  ci_uint8 *el_svc = efrm_find_ksym("el0_svc");
  ci_uint8 *el_sync;
  ci_uint32 insn;

  if (el_svc != NULL)
    return el_svc;
  el_sync = find_el_sync();
  if (el_sync == NULL)
    return NULL;

  while (1) {
    if (aarch64_insn_read_sym(el_sync, &insn)) {
      ci_log("cannot read el0_sync code @ %d", __LINE__);
      return NULL;
    }
    if (aarch64_insn_is_mrs(insn) &&
        aarch64_insn_extract_system_reg_sym(insn) == SYS_ESR_EL1) {
      el_sync += 2 * sizeof(ci_uint32);
      if (aarch64_insn_read_sym(el_sync, &insn)) {
        ci_log("cannot read el0_sync code @ %d", __LINE__);
        return NULL;
      }
      if (!aarch64_insn_is_subs_imm(insn) ||
          aarch64_insn_decode_immediate_sym(AARCH64_INSN_IMM_12, insn) !=
          ESR_ELx_EC_SVC64) {
        ci_log("expected check for ESR_ELx_EC_SVC64");
        return NULL;
      }
      el_sync += sizeof(ci_uint32);
      if (aarch64_insn_read_sym(el_sync, &insn)) {
        ci_log("cannot read el0_sync code @ %d", __LINE__);
        return NULL;
      }
      if (!aarch64_insn_is_bcond(insn) ||
          (insn & 0x0f) != AARCH64_INSN_COND_EQ) {
        ci_log("branching to el0_svc not found");
        return NULL;
      }
      el_svc = el_sync + aarch64_get_branch_offset_sym(insn);
      break;
    }
    el_sync += sizeof(ci_uint32);
  }
  return el_svc;
}

static ci_uint8 *
find_syscall_table_via_vbar(void)
{
  ci_uint8 *el_svc = find_el_svc_entry();
  ci_uint32 insn;

  if (el_svc == NULL)
    return NULL;

  if (aarch64_insn_read_sym(el_svc, &insn)) {
    ci_log("cannot read el0_svc start @ %016lx", (unsigned long)el_svc);
    return NULL;
  }
  if (!aarch64_insn_is_adrp(insn)) {
    ci_log("expected adrp instruction at el0_svc, found %08x", insn);
    return NULL;
  }
  return CI_PTR_ALIGN_BACK(el_svc, SZ_4K) + aarch64_insn_adrp_get_offset_sym(insn);
}

static void *find_syscall_table(void)
{
  void *syscalls = efrm_find_ksym("sys_call_table");

  if (syscalls != NULL)
    return syscalls;

/* The kernel contains some neat routines for doing AArch64 code inspection.
 * Some of them are available as inline routines, but some are
 * unfortunately not exported to modules. We could reimplement them, of
 * course, but since we do efrm_find_ksym in other places, that seems like
 * the least effort path
 */

  aarch64_insn_decode_immediate_sym = efrm_find_ksym("aarch64_insn_decode_immediate");
  aarch64_insn_read_sym = efrm_find_ksym("aarch64_insn_read");
  aarch64_insn_extract_system_reg_sym = efrm_find_ksym("aarch64_insn_extract_system_reg");
  aarch64_get_branch_offset_sym = efrm_find_ksym("aarch64_get_branch_offset");
  aarch64_insn_adrp_get_offset_sym = efrm_find_ksym("aarch64_insn_adrp_get_offset");
  if (aarch64_insn_decode_immediate_sym == NULL ||
      aarch64_insn_read_sym == NULL ||
      aarch64_insn_extract_system_reg_sym == NULL ||
      aarch64_get_branch_offset_sym == NULL ||
      aarch64_insn_adrp_get_offset_sym == NULL) {
    ci_log("some symbols required for AArch64 assembler analysis are not found");
    return NULL;
  }

  return find_syscall_table_via_vbar();
}

/* ARM64 TODO these are stub implementations only */
atomic_t efab_syscall_used;

#ifndef NDEBUG

void efab_linux_trampoline_ul_fail(void)
{
  return;
}

#endif

/*
 * This is somewhat dubious. On the one hand, the syscall
 * number is available to the syscall routine in x8 register,
 * so if it would ever like to consult it, it should be very much
 * upset by finding some random garbage there.
 * On another hand, in most contexts x8 is just a scratch register,
 * so the compiler theoretically could use it for its own purposes,
 * which the following code would mess up with. (Note that x8 is
 * _intentionally_ not marked as clobbered in the asm statement, so
 * that it would be forwarded to the original syscall).
 * However, in such short functions as our thunks, it seems unlikely and
 * empirically confirmed not to be.
 */
#define SET_SYSCALL_NO(_sc) \
  asm volatile("mov x8, %0" :: "i" (__NR_##_sc))

static SYSCALL_PTR_DEF(sys_close);

asmlinkage int efab_linux_sys_close(int fd)
{
  int rc;
  SET_SYSCALL_NO(close);
  rc = (int)PASS_SYSCALL1(sys_close, fd);
  return rc;
}

static SYSCALL_PTR_DEF(sys_exit_group);

asmlinkage int efab_linux_sys_exit_group(int status)
{
  int rc;
  SET_SYSCALL_NO(exit_group);
  rc = (int)PASS_SYSCALL1(sys_exit_group, status);
  return rc;
}

static SYSCALL_PTR_DEF(sys_epoll_create1);

int efab_linux_sys_epoll_create1(int flags)
{
  int rc;
  SET_SYSCALL_NO(epoll_create1);
  rc = (int)PASS_SYSCALL1(sys_epoll_create1, flags);
  return rc;
}

static SYSCALL_PTR_DEF(sys_epoll_ctl);

int efab_linux_sys_epoll_ctl(int epfd, int op, int fd,
                             struct epoll_event *event)
{
  int rc;
  SET_SYSCALL_NO(epoll_ctl);
  rc = (int)PASS_SYSCALL4(sys_epoll_ctl, epfd, op, fd, event);
  return rc;
}

static SYSCALL_PTR_DEF(sys_epoll_pwait);

int efab_linux_sys_epoll_wait(int epfd, struct epoll_event *events,
                              int maxevents, int timeout)
{
  int rc;
  SET_SYSCALL_NO(epoll_pwait);
  rc = (int)PASS_SYSCALL6(sys_epoll_pwait,
                          epfd, events, maxevents, timeout,
                          NULL, sizeof(sigset_t));
  return rc;
}

static SYSCALL_PTR_DEF(sys_rt_sigaction);

int efab_linux_sys_sigaction(int signum,
                             const struct sigaction *act,
                             struct sigaction *oact)
{
  int rc;
  SET_SYSCALL_NO(rt_sigaction);
  rc = (int)PASS_SYSCALL4(sys_rt_sigaction, signum, act, oact, sizeof(sigset_t));
  return rc;
}

static SYSCALL_PTR_DEF(sys_sendmsg);

int efab_linux_sys_sendmsg(int fd, struct msghdr __user* msg,
                           unsigned long __user* socketcall_args,
                           unsigned flags)
{
  int rc;
  SET_SYSCALL_NO(sendmsg);
  rc = (int)PASS_SYSCALL3(sys_sendmsg, fd, (struct user_msghdr __user *)msg, flags);
  return rc;
}

#ifdef CONFIG_COMPAT
int
efab_linux_sys_sendmsg32(int fd, struct compat_msghdr __user* msg,
                         unsigned long __user* socketcall_args,
                         unsigned flags)
{
  return 0;
}

int efab_linux_sys_sigaction32(int signum,
                               const struct sigaction32 *act,
                               struct sigaction32 *oact)
{
  return 0;
}
#endif


static inline int /* bool */
tramp_close_begin(int fd, ci_uintptr_t *tramp_entry_out,
                  ci_uintptr_t *tramp_exclude_out)
{
  struct file *f;
  efab_syscall_enter();

  f = fget(fd);
  if( f != NULL ) {
    if( FILE_IS_ENDPOINT(f) ) {
      struct mm_hash *p;

      read_lock (&oo_mm_tbl_lock);
      p = oo_mm_tbl_lookup(current->mm);
      if (p) {
        *tramp_entry_out =
            (ci_uintptr_t)CI_USER_PTR_GET(p->trampoline_entry);
        *tramp_exclude_out =
            (ci_uintptr_t)CI_USER_PTR_GET(p->trampoline_exclude);
      }
      read_unlock (&oo_mm_tbl_lock);

      if( *tramp_entry_out != 0 &&
          efab_access_ok((const void *)*tramp_entry_out, 1)) {
        fput(f);
        return true;
      }
    }
    fput(f);
  }

  /* Not one of our FDs -- usual close */
  return false;
}

static inline int
tramp_close_passthrough(int fd)
{
  int rc = PASS_SYSCALL1(sys_close, fd);
  efab_syscall_exit();
  return rc;
}

#ifndef ONLOAD_SYSCALL_PTREGS
asmlinkage long efab_linux_aarch64_trampoline_close(int fd, struct pt_regs *regs)
#else
asmlinkage int efab_linux_trampoline_close(struct pt_regs *regs)
#endif
{
#ifdef ONLOAD_SYSCALL_PTREGS
  int fd = regs->regs[0];
#endif
  ci_uintptr_t trampoline_entry = 0;
  ci_uintptr_t trampoline_exclude = 0;

  if (!tramp_close_begin(fd, &trampoline_entry, &trampoline_exclude))
      return tramp_close_passthrough(fd);

  if (regs->pc == trampoline_exclude) {
    return tramp_close_passthrough(fd);
  }

  regs->regs[1] = fd;
  regs->regs[2] = regs->pc;

  /* Hack the return address on the stack to do the trampoline */
  regs->pc = trampoline_entry;

  efab_syscall_exit();
  /* this is the return value in x0 that will become the first argument
     of trampoline_entry */
  return CI_TRAMP_OPCODE_CLOSE;
}

struct patch_item {
    unsigned syscall;
    void *addr;
};

static int patch_syscall_table(void **table,
                               const struct patch_item *patches)
{

  for (; patches->addr != NULL; patches++) {
    int rc = probe_kernel_write(table + patches->syscall, &patches->addr,
                                sizeof(patches->addr));
    if (rc != 0) {
      unsigned offset = ((uintptr_t)(table + patches->syscall) &
                         ~PAGE_MASK) / sizeof(*table);
      struct page *page = phys_to_page(__pa_symbol(table +
                                                   patches->syscall));
      void **waddr;
      BUG_ON(!page);

      waddr = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
      if (waddr == NULL)
      {
        ci_log("cannot map sys_call_table r/w");
        return -EFAULT;
      }

      if (waddr[offset] != table[patches->syscall])
      {
        ci_log("mapped table mismatch: %p != %p",
               waddr[offset], table[patches->syscall]);
        vunmap(waddr);
        return -EFAULT;
      }

      waddr[offset] = patches->addr;

      vunmap(waddr);
    }
  }
  return 0;
}

static void **syscall_table = NULL;

int efab_linux_trampoline_ctor(int no_sct)
{
  void *check_sys_close;

  syscall_table = find_syscall_table();
  if (syscall_table == NULL) {
    ci_log("Cannot detect syscall table!!!");
    return -ENOTSUPP;
  }

  atomic_set(&efab_syscall_used, 0);
  efab_linux_termination_ctor();

  saved_sys_close = syscall_table[__NR_close];
#if defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
  check_sys_close = efrm_find_ksym("__arm64_sys_close");
#else
  check_sys_close = efrm_find_ksym("sys_close");
#endif
  if (check_sys_close != NULL) {
    if (check_sys_close != saved_sys_close) {
      ci_log("ERROR: sys_close address does not match (%p != %p)",
             check_sys_close, saved_sys_close);
      return -EFAULT;
    }
  }
  saved_sys_exit_group = syscall_table[__NR_exit_group];
  saved_sys_sendmsg = syscall_table[__NR_sendmsg];
  saved_sys_rt_sigaction = syscall_table[__NR_rt_sigaction];
  saved_sys_epoll_create1 = syscall_table[__NR_epoll_create1];
  saved_sys_epoll_ctl = syscall_table[__NR_epoll_ctl];
  saved_sys_epoll_pwait = syscall_table[__NR_epoll_pwait];

  if (!no_sct) {
    struct patch_item patches[] = {
      {__NR_close, efab_linux_trampoline_close},
      {__NR_exit_group, efab_linux_trampoline_exit_group},
      {__NR_rt_sigaction, efab_linux_trampoline_sigaction},
      {0, NULL}
    };
    int rc = patch_syscall_table(syscall_table, patches);

    if (rc != 0)
      return rc;
  }

  return 0;
}

/* See wait_for_other_syscall_callers() in x86_linux_trampoline.c */
static int stop_machine_do_nothing(void *arg)
{
  return 0;
}


int efab_linux_trampoline_dtor (int no_sct)
{
  if (!no_sct) {
    int waiting = 0;
    struct patch_item patches[] = {
      {__NR_close, *saved_sys_close},
      {__NR_exit_group, *saved_sys_exit_group},
      {__NR_rt_sigaction, *saved_sys_rt_sigaction},
      {0, NULL}
    };
    int rc = patch_syscall_table(syscall_table, patches);

    if (rc != 0)
      return rc;

    /* If anybody have already entered our syscall handlers, he should get
     * to efab_syscall_used++ now: let's wait a bit.
     *
     * See wait_for_other_syscall_callers() in x86_linux_trampoline.c
     * for further details
     */
    stop_machine(stop_machine_do_nothing, NULL, NULL);
#ifdef CONFIG_PREEMPT
    /* No guarantee, but let's try to wait */
    schedule_timeout(msecs_to_jiffies(50));
#endif
    while( atomic_read(&efab_syscall_used) ) {
      if( !waiting ) {
        ci_log("%s: Waiting for intercepted syscalls to finish...",
               __FUNCTION__);
        waiting = 1;
      }
      schedule_timeout(msecs_to_jiffies(50));
    }
    if( waiting )
      ci_log("%s: All syscalls have finished", __FUNCTION__);
    /* And now wait for exiting from syscall after efab_syscall_used-- */
    stop_machine(stop_machine_do_nothing, NULL, NULL);
#ifdef CONFIG_PREEMPT
    /* No guarantee, but let's try to wait */
    schedule_timeout(msecs_to_jiffies(50));
#endif
  }

  return 0;
}
