/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <internal.h>

/* Trampoline support on PPC is in progress. See bug31834 for details */
#ifndef NO_TRAMPOLINE


# include <onload/common.h>
# include <ci/internal/trampoline.h>
# include <asm/unistd.h>
#include <onload/ul/tcp_helper.h>
#include <onload/signals.h>


/* This is the code that receives the trampoline.  In certain cirumstances 
 * (such as when it sees a close on one of our FDs) the kernel (ie. our module)
 * assumes that for some reason the interposing library didn't catch it.  The
 * module munges the return address to "trampoline_entry", and returns from
 * syscall, thus jumping back into here.  (The module knows about our
 * trampoline entry point because we pass it down in tcp_helper_alloc).
 *
 *  There are currently two cases when we receive a trampoline:
 *  1) When the module detects a close system-call that wasn't intercepted as
 *     we'd normally hope to.
 *  2) An internal module error (i.e. assert fail).  Rather than kernel panic,
 *     unwinds to here, to give more meaningful and useful diagnostics.
 *
 * Note: this entry point itself is in some assembler at the bottom of this
 * function -- the handler needs to be a bit of assembler because the calling
 * covention/stack is all screwy at this point.
 *
 * Note 2: the handler needs to take care not to set errno, and to return errs
 * as -ve return values.  This is because the handler is emulating the system
 * call, not the library call.
 *
 * Note 3: Modern x86 ABI requires that stack pointer be 16-byte aligned
 * on function entry. Not doing so may result in SSE-related memory traps
 * (see bug 84269/ON-10044 and ON-11561).
 * For old 64-bit gcc there is some asm code at ci_trampoline_handler_entry
 */
#if (__GNUC__ >= 6 && defined(__x86_64__)) || defined(i386)
long
ci_trampoline_handler(unsigned opcode, unsigned data)
  __attribute__ ((force_align_arg_pointer));
#endif
long
ci_trampoline_handler(unsigned opcode, unsigned data) {
  int rc = 0;
  int saved_errno = errno;

  switch (opcode) {
    case CI_TRAMP_OPCODE_CLOSE:
        /* Reflect the trampoline bounce to the user-mode close */
        if (onload_close(data))
            rc = -errno;
      break;

    default:
      ci_log ("Unknown trampoline (%d)", opcode);
      ci_assert (0);
  }

  /* Restore errno and return -ve error code */
  errno = saved_errno;
  return rc;
}

static void
ci_trampoline_ul_fail(void)
{
  __ci_fail ("*** Deliberate user-level fail on syscall exit");
}

extern void ci_trampoline_handler_entry (void);
#if defined(__PPC64__)
extern uint32_t onload_trampoline_user_fixup_64;
#elif defined(__PPC__)
extern uint32_t onload_trampoline_user_fixup_32;
#endif

#if defined(__PPC__)
/* syscall_rv is whatever the syscall handler (our, replacement, syscall handler)
 * returned after it set up the trampoline - this is always 0 for us, but you 
 * could theoretically use it to pass data back from kernel space.
 *
 * It is important that we return an int, as our return code will be passed
 *  up to whoever called the syscall.
 */
int ci_trampoline_handler_ppc(int syscall_rv)
{
    int code, data;
    int rc;

#if defined(__PPC64__)
    (code) = ((uint64_t *)__builtin_frame_address(1))[0x60>>3]; 
    (data) = ((uint64_t *)__builtin_frame_address(1))[0x68>>3]; 
#else
    (code) = ((uint32_t *)__builtin_frame_address(1))[0x30>>2]; 
    (data) = ((uint32_t *)__builtin_frame_address(1))[0x34>>2]; 
#endif
    rc = ci_trampoline_handler(code, data);
    return rc;
}
#endif



int
citp_init_trampoline(ci_fd_t fd)
{
  /* Trampoline is not supported on PPC right now */
  int rc;
  int i;
  ci_tramp_reg_args_t args;
#if defined(__PPC64__) && (!defined(_CALL_ELF) || _CALL_ELF < 2)
  /* intermediate buffer is needed as not to break strict aliasing rules
   * see bug31834.  Note that ELFv2 (mostly used on LE systems) uses
   * "normal" fn ptrs.
   */
  int (*handler_ptr)(int) = ci_trampoline_handler_ppc;
  uint32_t *ptrbuf[sizeof(handler_ptr)];
#endif

  CI_USER_PTR_SET (args.trampoline_exclude, ci_tcp_helper_close_no_trampoline_retaddr);
  CI_USER_PTR_SET (args.trampoline_ul_fail, ci_trampoline_ul_fail);
#if defined(__PPC64__) && (!defined(_CALL_ELF) || _CALL_ELF < 2)
  /* PPC64 ELFv1 - function pointers are in fact transition vectors */
  memcpy(ptrbuf, handler_ptr, sizeof(ptrbuf));
  CI_USER_PTR_SET (args.trampoline_entry, ptrbuf[0]);
  CI_USER_PTR_SET (args.trampoline_toc,   ptrbuf[1]);
  CI_USER_PTR_SET (args.trampoline_user_fixup, &onload_trampoline_user_fixup_64 );
#elif defined(__PPC__)
  /* PPC32 and PPC64 ELFv2: function pointers are just pointers, r2 points
   * to ELF GOT.
   */
  {
      uint32_t r2;
      asm("mr %0,2" : "=r"(r2));
      CI_USER_PTR_SET (args.trampoline_entry, &ci_trampoline_handler_ppc);
      CI_USER_PTR_SET (args.trampoline_toc,   r2);
#ifdef __PPC64__
      CI_USER_PTR_SET (args.trampoline_user_fixup,
                       &onload_trampoline_user_fixup_64 );
#else
      CI_USER_PTR_SET (args.trampoline_user_fixup,
                       &onload_trampoline_user_fixup_32 );
#endif
  }
#else
  /* x86, x86_64, aarch64 - no toc or user fixup, function pointers mean what they say */
  CI_USER_PTR_SET (args.trampoline_entry, ci_trampoline_handler_entry);  
  CI_USER_PTR_SET (args.trampoline_toc,   NULL);
  CI_USER_PTR_SET (args.trampoline_user_fixup, NULL );
#endif


  args.max_signum = NSIG;
  CI_USER_PTR_SET(args.signal_handler_postpone, citp_signal_intercept);
  for( i = 0; i <= OO_SIGHANGLER_DFL_MAX; i++ )
    CI_USER_PTR_SET(args.signal_handlers[i], citp_signal_handlers[i]);
  CI_USER_PTR_SET(args.signal_data, citp_signal_data);
  CI_USER_PTR_SET(args.signal_sarestorer, citp_signal_sarestorer_get());
  args.sa_onstack_intercept = CITP_OPTS.sa_onstack_intercept;

  rc = ci_sys_ioctl (fd, OO_IOC_IOCTL_TRAMP_REG, &args);

  if(rc == -1)
    ci_log ("Error %d registering trampoline handler", errno);

  return rc;
}


#else

/* Dummy stubs to make non-Linux UNIXes (e.g. Solaris) compile */
int
citp_init_trampoline (ci_fd_t fd)
{
  return 0;
}

int
ci_trampoline_handler(unsigned opcode, unsigned data)
{
  (void)opcode;
  (void)data;
  return 0;
}


#endif /* __linux */
