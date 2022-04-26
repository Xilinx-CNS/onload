/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#include <ci/efrm/sysdep_linux.h>
#include <ci/efrm/debug_linux.h>
#include <ci/efrm/syscall.h>

#if 1
#define TRAMP_DEBUG(x...) (void)0
#else
#define TRAMP_DEBUG(x...) EFRM_NOTICE(x...)
#endif

void** efrm_syscall_table = NULL;
EXPORT_SYMBOL(efrm_syscall_table);
void *efrm_entry_SYSCALL_64_addr = NULL;
EXPORT_SYMBOL(efrm_entry_SYSCALL_64_addr);


#ifdef CONFIG_RETPOLINE
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
 */
static bool is_callq_indirect_reg(const unsigned char *p)
{
  if( p[0] == 0xe8 )
    return true;
  if( p[0] == 0xff && p[1] == 0xd0 && p[2] == 0x0f && p[3] == 0x1f &&
      p[4] == 0x00 )
    return true;
  if( p[0] == 0x0f && p[1] == 0xae && p[2] == 0xe8 && p[3] == 0xff &&
      p[4] == 0xd0 )
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
#endif /* CONFIG_RETPOLINE */

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


void** find_syscall_table(void)
{
  unsigned char *p = NULL;
  unsigned long result;
  unsigned char *pend;

  /* First see if it is in kallsyms */
#ifdef EFRM_HAVE_NEW_KALLSYMS
  /* It works with CONFIG_KALLSYMS_ALL=y only. */
  p = efrm_find_ksym("sys_call_table");
#endif
  if( p != NULL ) {
    TRAMP_DEBUG("syscall table ksym at %px", (unsigned long*)p);
    return (void**)p;
  }

  /* If kallsyms lookup failed, fall back to looking at some assembly
   * code that we know references the syscall table.
   */
  if( efrm_entry_SYSCALL_64_addr == NULL )
    return NULL;
  p = efrm_entry_SYSCALL_64_addr;

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
   * call	do_syscall_64
   *    e8 XX XX XX XX
   *
   */
  p += 0x40; /* skip the first part of entry_SYSCALL_64() */
  result = 0;
  pend = p + 1024 - 11;
  while (p < pend) {
    if( p[0] == 0x48 && p[1] == 0x89 && p[3] == 0x48 && p[6] == 0xe8 &&
        ((p[2] == 0xc7 && p[4] == 0x89 && p[5] == 0xe6) ||
         (p[2] == 0xe7 && p[4] == 0x63 && p[5] == 0xf0)) ) {
      result = (unsigned long)p + 11;
      result += p[7] | (p[8] << 8) | (p[9] << 16) | (p[10] << 24);
      break;
    }
    p++;
  }

  if( result == 0 ) {
    EFRM_WARN("%s: didn't find do_syscall_64()", __func__);
    return 0;
  }

  p = (void*)result;
  TRAMP_DEBUG("do_syscall_64=%px", p);
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
  p += 0x20; /* skip the first part of do_syscall_64() */
  result = 0;
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
#ifdef CONFIG_RETPOLINE
    if( is_movq_indirect_8(p) ) {
      if( (is_movq_to_rdi(p + 8) && is_callq_indirect_reg(p + 11)) ||
          (is_movq_to_rdi(p-3) && is_callq_indirect_reg(p + 8)) ) {
        s32 addr = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
        result = (long)addr;
        TRAMP_DEBUG("sys_call_table=%lx", result);
        return (void**)result;
      }
    }
#else
    if( is_callq_indirect_8(p) ) {
      if( is_movq_to_rdi(p-3) ) {
        s32 addr = p[3] | (p[4] << 8) | (p[5] << 16) | (p[6] << 24);
        result = (long)addr;
        return (void**)result;
      }
    }
#endif
    p++;
  }

  TRAMP_DEBUG("didn't find syscall table address");
  return NULL;
}


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

  rdmsrl(MSR_LSTAR, result);
  return (void*)result;
}


int efrm_syscall_ctor(void)
{
  efrm_entry_SYSCALL_64_addr = find_entry_SYSCALL_64();
  if( efrm_entry_SYSCALL_64_addr == NULL )
    return -ENOENT;
  efrm_syscall_table = find_syscall_table();
  if( efrm_syscall_table == NULL )
    return -ENOENT;
  return 0;
}
