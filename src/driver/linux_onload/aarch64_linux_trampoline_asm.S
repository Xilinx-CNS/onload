/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <linux/linkage.h>
#include <linux/version.h>
#include <asm/assembler.h>
#include <ci/internal/trampoline.h>

/* Unfortunately, onload/linux_trampoline.h
 * where ONLOAD_SYSCALL_PTREGS is defined,
 * cannot be included in an assembler source
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,17,0)
ENTRY(efab_linux_trampoline_close)
mov x1, sp
b efab_linux_aarch64_trampoline_close
ENDPROC(efab_linux_trampoline_close)
#endif
