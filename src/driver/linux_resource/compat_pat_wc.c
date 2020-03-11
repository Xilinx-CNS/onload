/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *
 * This file provides public API for protection domain resource.
 *
 * Copyright 2011-2011: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#include <linux_resource_internal.h>
#include <linux/io.h>

#ifdef HAS_COMPAT_PAT_WC

#include <asm/processor.h>
#include <asm/msr.h>


#define MSR_IA32_CR_PAT 0x00000277

#define PAT_NO 1

#define IOREMAP_WC_FLAGS (((PAT_NO&1)?_PAGE_PWT:0) | ((PAT_NO&2)?_PAGE_PCD:0))
#define IOREMAP_WC_FLAGS_MASK (_PAGE_PWT|_PAGE_PCD)

#define PAT_REG_EXPECTED_VALUE 4ll // write through
#define PAT_REG_MODIFIED_VALUE 1ll // write combining
#define PAT_REG_BIT_OFFSET 8
#define PAT_REG_BIT_WIDTH 3
#define PAT_REG_LBN (PAT_REG_BIT_OFFSET * PAT_NO)
#define PAT_REG_MASK ( ((1ll<<PAT_REG_BIT_WIDTH) - 1) << PAT_REG_LBN )


typedef union
{
  uint32_t u32[2];
  uint64_t u64;
} efx_qword_t;


static struct
{
  int inited;
  efx_qword_t original_pat;
  efx_qword_t modified_pat;
  int pat_modified;
} compat_pat_wc = { .inited = 0 };


static int write_pat(efx_qword_t* pat)
{
  int r = wrmsr_safe(MSR_IA32_CR_PAT, pat->u32[0], pat->u32[1]);
  if( r )
    return -EIO;
  return 0;
}


#ifdef CONFIG_SMP
static void write_pat_on_cpu(efx_qword_t* pat)
{
  write_pat(pat);
}
#endif


static int write_pat_on_cpus(efx_qword_t* pat)
{
  int rc = write_pat(pat);
  if( rc != 0 )
    return rc;
  smp_call_function((void(*)(void*))write_pat_on_cpu, pat, 1, 1);
  return 0;
}


static int read_pat(efx_qword_t* pat)
{
  int r = rdmsr_safe(MSR_IA32_CR_PAT, &(pat->u32[0]), &(pat->u32[1]));
  if( r )
    return -EIO;
  return 0;
}


#ifdef CONFIG_SMP
static void read_pat_on_cpu(int* fail)
{
  efx_qword_t pat;
  int r = read_pat(&pat);
  if( r != 0 ) {
    fail[0] = 1;
    return;
  }
  if( pat.u64 != compat_pat_wc.original_pat.u64 )
    fail[1] = 1;
}
#endif


static int read_pat_on_cpus(void)
{
  int fail[2] = {0, 0};

  int rc = read_pat(&compat_pat_wc.original_pat);
  if( rc != 0 )
    return rc;

  smp_call_function((void(*)(void*))read_pat_on_cpu, &fail, 1, 1);

  if( fail[0] )
    return -EIO;
  if( fail[1] )
    return -EFAULT;
  return 0;
}


static int read_and_verify_pat(void)
{
  int rc;
  if( (rc = read_pat_on_cpus()) != 0 )
    return rc;
  else {
    int pat_reg_value = ((compat_pat_wc.original_pat.u64 & PAT_REG_MASK) >> PAT_REG_LBN);
    if( pat_reg_value != PAT_REG_EXPECTED_VALUE ) {
      if( pat_reg_value != PAT_REG_MODIFIED_VALUE )
        return -ENOSPC;
      else
        return -EALREADY;
    }
  }
  return 0;
}


static int update_pat(void)
{
  int rc;
  compat_pat_wc.modified_pat.u64 = compat_pat_wc.original_pat.u64 & (~PAT_REG_MASK);
  compat_pat_wc.modified_pat.u64 |= PAT_REG_MODIFIED_VALUE << PAT_REG_LBN;

  rc = write_pat_on_cpus(&compat_pat_wc.modified_pat);
  if( rc != 0 )
    return rc;

  compat_pat_wc.pat_modified = 1;
  return 0;
}


static int setup_pat(void)
{
  int rc;
  preempt_disable();
  {
    rc = read_and_verify_pat();
    if( rc == 0 )
      rc = update_pat();
  }
  preempt_enable();
  return rc;
}


static void restore_pat(void)
{
  int fail = 0;
  efx_qword_t pat;
  preempt_disable();
  {
    EFRM_VERIFY_EQ(read_pat(&pat), 0);
    if( pat.u64 == compat_pat_wc.modified_pat.u64 )
      write_pat_on_cpus(&compat_pat_wc.original_pat);
    else
      fail = 1;
  }
  preempt_enable();
  if( fail )
    EFRM_WARN("%s: WARNING: PAT was modified while the driver was running, PAT: "
      "  original %llx, modified %llx, current %llx", __func__,
      compat_pat_wc.original_pat.u64, compat_pat_wc.modified_pat.u64, pat.u64);
  else
    EFRM_WARN("%s: PAT restored", __func__);
}


int compat_pat_wc_init(void)
{
  int rc;
  struct cpuinfo_x86* cpu_info = &boot_cpu_data;
  if( compat_pat_wc.inited ) {
    ++compat_pat_wc.inited;
    return 0;
  }

  if( !cpu_has(cpu_info, X86_FEATURE_MSR) || !cpu_has(cpu_info, X86_FEATURE_PAT) ) {
    EFRM_ERR("%s: ERROR: PAT not available on this processor", __func__);
    return -ENOSYS;
  }

  rc = setup_pat();
  switch (rc) {
    case -EIO:
      EFRM_ERR("%s: ERROR: failed accessing PAT register", __func__);
      return rc;
    case -EFAULT:
      EFRM_ERR("%s: ERROR: PAT registers inconsistent across CPUs", __func__);
      return rc;
    case -ENOSPC:
      EFRM_ERR("%s: ERROR: incompatible PAT modification detected %llx",
          __func__, compat_pat_wc.original_pat.u64);
      return rc;
    case -EALREADY:
      EFRM_WARN("%s: WARNING: compatible PAT modification detected %llx",
          __func__, compat_pat_wc.original_pat.u64);
    case 0:
      EFRM_WARN( "%s: PAT modified for WC", __func__);
      break;
    default:
      EFRM_ERR( "%s: unknown return code", __func__);
  }

  compat_pat_wc.inited = 1;
  return 0;
}


void compat_pat_wc_shutdown(void)
{
  EFRM_ASSERT(compat_pat_wc.inited);
  if( --compat_pat_wc.inited )
    return;
  if( compat_pat_wc.pat_modified )
    restore_pat();
}


int compat_pat_wc_is_initialized(void)
{
  return compat_pat_wc.inited;
}
EXPORT_SYMBOL(compat_pat_wc_is_initialized);


pgprot_t compat_pat_wc_pgprot_writecombine(pgprot_t _prot)
{
	return __pgprot((pgprot_val(_prot) & (~IOREMAP_WC_FLAGS_MASK)) | IOREMAP_WC_FLAGS);
}
EXPORT_SYMBOL(compat_pat_wc_pgprot_writecombine);


void __iomem *compat_pat_wc_ioremap_wc(unsigned long phys_addr, unsigned long size)
{
	return __ioremap(phys_addr, size, IOREMAP_WC_FLAGS);
}
EXPORT_SYMBOL(compat_pat_wc_ioremap_wc);

#endif
