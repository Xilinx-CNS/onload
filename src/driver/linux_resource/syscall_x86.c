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

#ifdef CONFIG_COMPAT
void** efrm_compat_syscall_table = NULL;
EXPORT_SYMBOL(efrm_compat_syscall_table);
#endif


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
#ifdef ERFM_HAVE_NEW_KALLSYMS
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
   */
  p += 0x40; /* skip the first part of entry_SYSCALL_64() */
  result = 0;
  pend = p + 1024 - 11;
  while (p < pend) {
    if( p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xc7 &&
        p[3] == 0x48 && p[4] == 0x89 && p[5] == 0xe6 &&
        p[6] == 0xe8 ) {
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
   */
  p += 0x20; /* skip the first part of do_syscall_64() */
  result = 0;
  pend = p + 1024 - 12;
  while (p < pend) {
    if( is_movq_indirect_8(p) ) {
      TRAMP_DEBUG("%px: %02x %02x %02x %02x %02x %02x %02x %02x %02x "
                  "%02x %02x %02x %02x %02x %02x %02x %02x",
                  p, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
                  p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16]);
      if( (is_movq_to_rdi(p + 8) && p[11] == 0xe8) ||
          (is_movq_to_rdi(p-3) && p[8] == 0xe8) ) {
        s32 addr = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
        result = (long)addr;
        TRAMP_DEBUG("sys_call_table=%lx", result);
        return (void**)result;
      }
    }
    p++;
  }

  TRAMP_DEBUG("didn't find syscall table address");
  return NULL;
}

#ifdef CONFIG_COMPAT
/* We also need to find the ia32_syscall_table used by 32-bit apps in 64-bit
 * mode.  This can be found via int 0x80 in a similar way to x86 -- but the
 * IDTR and entries in it are larger here, and the instruction we're looking
 * for is "call *table(,%rax,8)" (as for the 64-bit syscall table).
 */
static void **find_syscall_table32(void)
{
  unsigned int *idtbase;
  unsigned char idt[10];
  unsigned char *p = NULL;
  unsigned long result;
  unsigned char *pend;

#ifdef ERFM_HAVE_NEW_KALLSYMS
  /* It works with CONFIG_KALLSYMS_ALL=y only. */
  /* Linux>=4.2: ia32_sys_call_table is not a local variable any more, so
   * we can use kallsyms to find it if CONFIG_KALLSYMS_ALL=y. */
  p = efrm_find_ksym("ia32_sys_call_table");
  if( p != NULL )
    return (void**)p;
#endif

  __asm__("sidt %0" : "=m"(idt));
  idtbase = *(unsigned int **)(&idt[2]);
  TRAMP_DEBUG("idt base=%p, entry 0x80=%08x,%08x,%08x", idtbase,
              idtbase[0x80*4], idtbase[0x80*4+1], idtbase[0x80*4+2]);
  result = (idtbase[0x80*4] & 0xffff) | (idtbase[0x80*4+1] & 0xffff0000)
           | ((unsigned long)idtbase[0x80*4+2] << 32);
  p = (unsigned char *)result;
  TRAMP_DEBUG("int 0x80 entry point at %px", p);

  /* linux>=4.6 has following layout:
   * linux/arch/x86/entry/entry_64_compat.S:
   * movq	%rsp, %rdi
   *    48 89 e7
   * call	do_int80_syscall_32
   *    e8 XX XX XX XX
   */
  p += 0x60; /* skip the first part of int80 handler */
  result = 0;
  pend = p + 1024 - 8;
  while (p < pend) {
    if( p[0] == 0x48 && p[1] == 0x89 && p[2] == 0xe7 &&
        p[3] == 0xe8 ) {
      result = (unsigned long)p + 8;
      result += p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
      break;
    }
    p++;
  }

  if( result == 0 ) {
    EFRM_WARN("%s: didn't find do_int80_syscall_32()", __func__);
    return 0;
  }

  p = (void*)result;
  TRAMP_DEBUG("do_int80_syscall_32=%px", p);
  /* For linux>=4.6 do_int80_syscall_32() resides in
   * linux/arch/x86/entry/common.c:
   * regs->ax = ia32_sys_call_table[nr](regs)
   * in objdump -Dl:
   * 48 8b 04 c5 XX XX XX XX	mov    0x0(,%rax,8),%rax
   * e8 YY YY YY YY       	callq
   */
  p += 0x20; /* skip the first part of do_syscall_64() */
  result = 0;
  pend = p + 1024 - 12;
  while (p < pend) {
    if( p[0] == 0x48 && p[1] == 0x8b && p[2] == 0x04 && p[3] == 0xc5 &&
        p[8] == 0xe8 ) {
      s32 addr = p[4] | (p[5] << 8) | (p[6] << 16) | (p[7] << 24);
      TRAMP_DEBUG("%px: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
                  "%02x %02x %02x %02x %02x %02x %02x",
                  p, p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8],
                  p[9], p[10], p[11], p[12], p[13], p[14], p[15], p[16]);
      result = (long)addr;
      TRAMP_DEBUG("ia32_sys_call_table=%lx", result);
      return (void**)result;
    }
    p++;
  }

  EFRM_WARN("%s: didn't find ia32_sys_call_table address", __func__);
  return NULL;
}
#endif

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
#ifdef ERFM_HAVE_NEW_KALLSYMS
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
#ifdef CONFIG_COMPAT
  efrm_compat_syscall_table = find_syscall_table32();
#if 0
  /* We are unable to find efrm_compat_syscall_table for linux-5.8.
   * Do not complain for now. */
  if( efrm_compat_syscall_table == NULL )
    return -ENOENT;
#endif
#endif
  return 0;
}
