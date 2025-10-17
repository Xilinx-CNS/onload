/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <ci/efrm/sysdep_linux.h>
#include <ci/efrm/debug_linux.h>
#include <ci/efrm/syscall.h>

#if 1
#define TRAMP_DEBUG(x...) (void)0
#else
#define TRAMP_DEBUG(x...) EFRM_NOTICE(x)
#endif

void** efrm_syscall_table = NULL;
EXPORT_SYMBOL(efrm_syscall_table);
void *efrm_entry_SYSCALL_64_addr = NULL;
syscall_fn_t efrm_x64_sys_call = NULL;
EXPORT_SYMBOL(efrm_x64_sys_call);

static void* find_entry_SYSCALL_64(void)
{
  unsigned long result = 0;

  /* linux<4.2:
   *   MSR_LSTAR points to system_call(); we are returning this address.
   * 4.3<=linux<5.0:
   *   MSR_LSTAR points to per-cpu SYSCALL64_entry_trampoline variable,
   *   which is a wrapper for entry_SYSCALL_64_trampoline(),
   *   which is a wrapper for entry_SYSCALL_64_stage2(),
   *   which is a wrapper for entry_SYSCALL_64().
   *   We need the entry_SYSCALL_64() address to parse the content of this
   *   function.
   * 5.1<=linux:
   *   MSR_LSTAR points to entry_SYSCALL_64().
   */
#ifdef EFRM_HAVE_NEW_KALLSYMS
  void *ret = efrm_find_ksym("entry_SYSCALL_64");
  if( ret != NULL )
    return ret;
#endif

  /* This won't work for future CPUs that support FRED. Currently none are known
   * to exist, and upstream kernel patch have only been run on simulators.
   */
  rdmsrl(MSR_LSTAR, result);
  return (void*)result;
}


#if defined(CONFIG_RETPOLINE) || defined(CONFIG_MITIGATION_RETPOLINE)
/*
 * Test whether p points to something like
 *                            mov    0x0(,%rNN,8),%rax
 * On Debian linux-5.7 it was seen as
 *  48 8b 04 fd XX XX XX XX   mov    0x0(,%rdi,8),%rax
 * On Fedora linux-5.7 it was seen as
 *  48 8b 04 dd XX XX XX XX   mov 0x0(,%rbx,8),%rax
 *
 * We assume:
 *    48         8b         04          c5
 * 0100 1000  1000 1011  0000 0100  1100 0101
 * xxxx x!!x  xxxx xxxx  xx!! !xxx  xx!! !xxx
 * (x means must-match and ! means don't-care)
 *
 * See also a comment at the call to this function.
 */
static bool is_movq_indirect_8(const unsigned char *p)
{
  return (p[0] & 0xf9) == 0x48 && p[1] == 0x8b && (p[2] & 0xc7) == 0x04 &&
         (p[3] & 0xc7) == 0xc5;
}

/* Test whether p points to something like
 *  e8 XX XX XX XX callq __x86_indirect_thunk_rax   (vulnerable CPU)
 * or for new, fixed CPU:
 *  ff d0     callq *%rax     (linux-5.15)
 *  0f 1f 00  nop3
 * or
 *  0f ae e8  lfence
 *  ff d0     callq *%rax     (linux-5.16 amd, see patch_retpoline())
 * or
 *  41 ff d3  callq *%r11     (linux-5.15 clang)
 *  66 90     nop2
 */
static bool is_callq_indirect_reg(const unsigned char *p)
{
  if( p[0] == 0xe8 )
    return true;
  if( p[0] == 0xff && (p[1] & 0xf8) == 0xd0 && p[2] == 0x0f && p[3] == 0x1f &&
      p[4] == 0x00 )
    return true;
  if( p[0] == 0x0f && p[1] == 0xae && p[2] == 0xe8 && p[3] == 0xff &&
      (p[1] & 0xf8) == 0xd0 )
    return true;
  if( p[0] == 0x41 && p[1] == 0xff && (p[2] & 0xf8) == 0xd0 && p[3] == 0x66 &&
      p[4] == 0x90 )
    return true;
  return false;
}

#else

/* Test whether p points to something like
 *                            callq  *0x0(,%rNN,8)
 * ff 14 c5 XX XX XX XX       callq  *0x0(,%rax,8)
 *
 * We assume:
 *    ff         14         c5
 * 1111 1111 0001 0100 1100 0101
 * xxxx xxxx xxxx xxxx xx!! !xxx
 *   callq             8 %r base=none
 * (x means must-match and ! means don't-care)
 */
static bool is_callq_indirect_8(const unsigned char *p)
{
  return p[0] == 0xff && p[1] == 0x14 && (p[2] & 0xc7) == 0xc5;
}
#endif /* CONFIG_RETPOLINE || CONFIG_MITIGATION_RETPOLINE */

/*
 * Test whether p points to something like
 *                  mov    %rNN,%rdi
 * On Debian linux-5.7 it was seen as
 *    48 89 ef      mov    %rbp,%rdi
 * On Fedora linux-5.7 it was seen as
 *    4c 89 e7      mov    %r12,%rdi
 *
 * We assume:
 *    48         89          c7
 * 0100 1000  1000 1001  1110 1111
 * xxxx x!!x  xxxx xxxx  xx!! !xxx
 * (x means must-match and ! means don't-care)
 *
 * See also a comment at the call to this function.
 */
static bool is_movq_to_rdi(const unsigned char *p)
{
  return (p[0] & 0xf9) == 0x48 && p[1] == 0x89 && (p[2] & 0xc7) == 0xc7;
}

/*
 * Test whether p points to something like
 *                  mov    %rNN,%esi
 * On Debian12 linux-6.1.0-20 and Ubuntu22.04 linux-5.15.156 it was seen as
 *    89 c6         mov    %eax,%esi
 * On Ubuntu23.10 6.9.0-rc5 it was seen as
 *    44 89 ee      mov    %r13d,%esi
 * We can ignore REX.r prefix since it only affects the source operand.
 * This gives us:
 *    89 ee      mov    %r13d,%esi
 *
 * We assume:
 *    89         c6
 * 1000 1001  1100 0110
 * xxxx xxxx  xx!! !xxx
 * (x means must-match and ! means don't-care)
 */
static bool is_movl_to_esi(const unsigned char *p)
{
  return p[0] == 0x89 && (p[1] & 0xc7) == 0xc6;
}

/*
 * Test whether p points to something like
 *                  and    %rNN,%esi
 * On Debian12 linux-6.1.0-20 and Ubuntu22.04 linux-5.15.156 it was seen as
 *    21 d6         and    %edx,%esi
 * On Ubuntu23.10 6.9.0-rc5 it was seen as
 *    21 de         and    %ebx,%esi
 *
 * We assume:
 *    21         c6
 * 0010 0001  1100 0110
 * xxxx xxxx  xx!! !xxx
 * (x means must-match and ! means don't-care)
 */
static bool is_andl_to_esi(const unsigned char *p)
{
  return p[0] == 0x21 && (p[1] & 0xc7) == 0xc6;
}

/*
 * Test whether p points to the endbr64 instruction. Onload doesn't support
 * 32-bit mode, so we needn't check for endbr32.
 */
static bool is_endbr64(const unsigned char *p)
{
  return p[0] == 0xf3 && p[1] == 0x0f && p[2] == 0x1e && p[3] == 0xfa;
}

static bool ibt_enabled(void)
{
#if defined(EFRM_HAVE_IBT) && defined(CONFIG_X86_KERNEL_IBT)
  return cpu_feature_enabled(X86_FEATURE_IBT);
#else
  return false;
#endif
}

static bool check_syscall_ibt_valid(const void *p)
{
  if( ibt_enabled() && ! is_endbr64(p) ) {
    EFRM_ERR("%s: FATAL: Found syscall function, but missing endbr64 instruction. To use onload, please disable IBT with ibt=off in your kernel command line.",
             __FUNCTION__);
    return false;
  }

  return true;
}

static bool set_syscall_table(void **syscall_table)
{
#define CHECK_SYSCALL_IBT_VALID_OP(syscall) \
  if( ! check_syscall_ibt_valid(syscall_table[__NR_##syscall]) ) \
    return false;

  FOR_EACH_DISPATCHABLE_SYSCALL(CHECK_SYSCALL_IBT_VALID_OP);

  efrm_syscall_table = syscall_table;
  return true;
}

static bool set_syscall_func(void *p)
{
  if( ! check_syscall_ibt_valid(p) )
    return false;

  efrm_x64_sys_call = p;
  return true;
}

static void *is_syscall_table(const unsigned char *p)
{
  /* For linux>=4.6 do_syscall_64() resides in
   * linux/arch/x86/entry/common.c:
   * regs->ax = sys_call_table[nr](regs);
   * Debian linux-5.7 has following:
   *    48 8b 04 fd XX XX XX XX	mov    0x0(,%rdi,8),%rax
   *    48 89 ef            	mov    %rbp,%rdi
   *    e8 YY YY YY YY      	callq
   *
   * See the comments at is_movq_indirect_8() and is_movq_to_rdi().
   * And 2 mov instructions can be swapped.
   * Kernels built for retpoline but running on a modern, mitigated chip will
   * patch the call instruction with "callq *%rax; nop3"
   *
   * Without RETPOLINE (see ON-13350) it can be following:
   *    48 89 ef             	mov    %rbp,%rdi
   *    ff 14 c5 XX XX XX XX 	callq  *0x0(,%rax,8)
   */
  unsigned long result = 0;
#if defined(CONFIG_RETPOLINE) || defined(CONFIG_MITIGATION_RETPOLINE)
  if( is_movq_indirect_8(p) ) {
    if( (is_movq_to_rdi(p + 8) && is_callq_indirect_reg(p + 11)) ||
        (is_movq_to_rdi(p-3) && is_callq_indirect_reg(p + 8)) ) {
      s32 addr = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
      result = (long)addr;
      TRAMP_DEBUG("sys_call_table=%lx", result);
      return (void*)result;
    }
  }
#else
  if( is_callq_indirect_8(p) ) {
    if( is_movq_to_rdi(p-3) ) {
      s32 addr = p[3] | (p[4] << 8) | (p[5] << 16) | (p[6] << 24);
      result = (long)addr;
      TRAMP_DEBUG("sys_call_table=%lx", result);
      return (void*)result;
    }
  }
#endif
  return NULL;
}

static void *is_syscall_func(unsigned char *p)
{
  /* For linux>=4.6 do_syscall_64() resides in
   * linux/arch/x86/entry/common.c:
   * regs->ax = x64_sys_call(regs, unr);
   * Debian linux-6.1.0-20 (based on mainline kernel 6.1.85) has the following:
   *    89 c6                   mov    %eax,%esi
   *    48 89 df                mov    %rbx,%rdi
   *    21 d6                   and    %edx,%esi
   *    e8 YY YY YY YY          call   x64_sys_call
   *
   * Ubuntu 22.04 5.15.156 has the following:
   *    89 c6                   mov    %eax,%esi
   *    4c 89 e7                mov    %r12,%rdi
   *    21 d6                   and    %edx,%esi
   *    e8 YY YY YY YY          call   x64_sys_call
   *
   * Ubuntu 23.10 6.9.0-rc5 has the following:
   *    44 89 ee                mov    %r13d,%esi
   *    4c 89 e7                mov    %r12,%rdi
   *    21 de                   and    %ebx,%esi
   *    e8 YY YY YY YY          call   x64_sys_call
   *
   * Note: We can essentially treat the first mov instruction as a two byte
   * instruction (ignoring the REX prefix)
   *
   * RHEL9 6.8.7-1.el9.elrepo.x86_64 has the following:
   *    44 21 e6                and    %r12d,%esi
   *    48 89 df                mov    %rbx,%rdi
   *    e8 YY YY YY YY          callq  x64_sys_call
   */

  s32 offset;
  if( *p == 0xe8 ) {
    if(
        (is_movl_to_esi(p-7) &&              /* mov %rXX,%esi */
         is_movq_to_rdi(p-5) &&              /* mov %rXX,%rdi */
         is_andl_to_esi(p-2))                /* and %rXX,%esi */
        ||
        (is_andl_to_esi(p-5) &&              /* and %rXX,%esi */
         is_movq_to_rdi(p-3))                /* mov %rXX,%rdi */
      ) {
      offset = p[1] | (p[2] << 8) | (p[3] << 16) | (p[4] << 24);
      TRAMP_DEBUG("sys_call_func=%lx", (long unsigned int)(p + 5) + offset);
      return (p + 5) + offset;
    }
  }
  return NULL;
}


static bool find_syscall_from_do_syscall_64(unsigned char *my_do_syscall_64)
{
  unsigned char *p = my_do_syscall_64;
  unsigned char *pend;

  TRAMP_DEBUG("try do_syscall_64=%px", p);
  p += 0x20; /* skip the first part of do_syscall_64() */
  pend = p + 1024 - 12;
#if 0
  printk("%px: %02x %02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n"
              "%02x %02x %02x %02x %02x %02x %02x %02x\n",
              p, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
              p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16],
              p[17], p[18], p[19], p[20], p[21], p[22], p[23], p[24],
              p[25], p[26], p[27], p[28], p[29], p[30], p[31], p[32],
              p[33], p[34], p[35], p[36], p[37], p[38], p[39], p[40],
              p[41], p[42], p[43], p[44], p[45], p[46], p[47], p[48],
              p[49], p[50], p[51], p[52], p[53], p[54], p[55], p[56],
              p[57], p[58], p[59], p[60], p[61], p[62], p[63], p[64]
              );
#endif

  while (p < pend) {
    void *syscall_table, *syscall_func;
    if( (syscall_table = is_syscall_table(p)) != NULL ) {
      return set_syscall_table((void**)syscall_table);
    } else if( (syscall_func = is_syscall_func(p)) != NULL) {
      return set_syscall_func(p);
    }
    p++;
  }

  /* This pointer does not look like do_syscall_64 */
  return false;
}

/* Finds either the syscall table or, for new linux versions, a function calling
 * the right syscall implementation.
 * Returns true if either the table or function were found and updates the
 * corresponding global variable, false if neither were found. */
static bool find_syscall(void)
{
  unsigned char *p = NULL;
  unsigned long result;
  unsigned char *pend;

  /* First see if it is in kallsyms */
#ifdef EFRM_HAVE_NEW_KALLSYMS
  p = efrm_find_ksym("x64_sys_call");
  if( p != NULL ) {
    TRAMP_DEBUG("syscall function ksym at %px", (unsigned long*)p);
    return set_syscall_func(p);
  }
  /* It works with CONFIG_KALLSYMS_ALL=y only. */
  p = efrm_find_ksym("sys_call_table");
  if( p != NULL ) {
    TRAMP_DEBUG("syscall table ksym at %px", (unsigned long*)p);
    return set_syscall_table((void**)p);
  }
#endif

  /* If kallsyms lookup failed, fall back to looking at some assembly
   * code that we know references the syscall table.
   */
  if( (p = find_entry_SYSCALL_64()) == NULL )
    return false;

  TRAMP_DEBUG("entry_SYSCALL_64=%px", p);
  /* linux>=4.17 has following layout:
   * linux/arch/x86/entry/entry_64.S: entry_SYSCALL_64():
   * movq	%rax, %rdi
   *    48 89 c7
   * movq	%rsp, %rsi
   *    48 89 e6
   * call	do_syscall_64
   *    e8 XX XX XX XX
   *
   * NB It is possible to extend this to support linux>=4.6,
   * which is slightly different.  We do not have any DUTs to test such
   * a linux system without KALLSYMS, though.
   *
   * linux>=5.14 is slightly different, see
   * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=3e5e7f7736b05d5fdf2cc4e0ba4f2d8bc42c630d
   * https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=0595494891723a1dcca5eaa8eeca8ab54ad953b9
   * movq	%rsp, %rdi
   *    48 89 e7
   * movslq	%eax, %rsi
   *    48 63 f0
   * linux>=5.18.14: "clobbers %rax" with IBRS in the middle
   * linux>=6.9(+backports): CLEAR_BRANCH_HISTORY
   * call	do_syscall_64
   *    e8 XX XX XX XX
   *
   * linux>=5.18.14 and various backports (Debian's 5.10.0-17-amd64,
   * Ubuntu's 5.15.0-46) add some code before the call instruction above.
   * The code is: IBRS_ENTER + UNTRAIN_RET with a comment
   * "clobbers %rax, make sure it is after saving the syscall nr"
   *
   * For now we just look for the first "e8" byte, but it is very
   * error-prone.  Such a "e8" byte may be data, offset or something like
   * this.  However it is hard to find a better solution, because these
   * 2 macros depends on the kernel config option, and then the asm code is
   * hot-patched at load time depending on CPU properties.
   *
   * CLEAR_BRANCH_HISTORY: On CPUs that don't have hardware support for clearing
   * the branch history this will call into a function (clear_bhp_loop). When
   * testing on Debian12 6.1.0-20 this didn't affect the ability to find the
   * syscall function, it was just an extra point to test before continuing.
   */
  p += 0x40; /* skip the first part of entry_SYSCALL_64() */
  result = 0;
  pend = p + 1024 - 11;
  while (p < pend) {
#if 0
    if( p[0] == 0x48 )
      EFRM_ERR("%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
               "%02x %02x %02x %02x %02x %02x",
               p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9],
               p[10], p[11], p[12], p[13], p[14], p[15], p[16], p[17]);
#endif
    if( p[0] == 0x48 && p[1] == 0x89 && p[3] == 0x48 &&
        ((p[2] == 0xc7 && p[4] == 0x89 && p[5] == 0xe6) ||
         (p[2] == 0xe7 && p[4] == 0x63 && p[5] == 0xf0)) ) {
      /* Skip IBRS: search for the nearest "call", 0xe8. */
      unsigned char *p1 = p + 6;
      bool ret;
      do {
        while( *p1 != 0xe8 )
          p1++;
        result = (unsigned long)p1 + 5;
        result += p1[1] | (p1[2] << 8) | (p1[3] << 16) | (p1[4] << 24);

        /* Check that the result address is sane. Do not allow next steps to
         * read from the address if it does not point to a valid page within
         * kernel memory area. Otherwise kernel can crash. */
        if( !virt_addr_valid(result) ) {
          ++p1;
          continue;
        }

        ret = find_syscall_from_do_syscall_64((void*)result);
        if( ret )
          return true;
        p1 += 5; /* skip this e8 XX XX XX XX instruction */
      } while( p1 < pend );
    }
    p++;
  }

  TRAMP_DEBUG("didn't find syscall table address%c",'!');
  return false;
}

/* Used as a backup when we don't have x64_sys_call() */
long efrm_syscall_table_call(const struct pt_regs *regs, unsigned int nr)
{
  long (*syscall_fn)(const struct pt_regs *regs) = efrm_syscall_table[nr];
  return syscall_fn(regs);
};
EXPORT_SYMBOL(efrm_syscall_table_call);

/* The syscall table isn't as important as it once was due to the new trampoline
 * implementation, but it is still needed in a few locations (specifically epoll
 * and bpf) */
int efrm_syscall_ctor(void)
{
  return find_syscall() ? 0 : -ENOENT;
}
