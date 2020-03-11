/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  
**  \brief  
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
 
/*! \cidoxg_lib_citools */
 
#include "citools_internal.h"

unsigned ci_cpu_khz;


/* Throughout the code is the assumption that the value returned by ci_frc64()
 * has the same frequency as the cpu.  However, on aarch64 the only timer we
 * have available for this purpose actually runs at a fixed 20MHz.  That means
 * that although the value returned from this function on arm isn't really
 * the cpu frequency, it is really the value that is desired, which is the
 * ci_frc64() frequency.
 *
 * Revision history contains an implementation for aarch64 that actually does
 * calculate the cpu frequency.
 */
# if defined(__i386__) || defined(__x86_64__) || defined(__aarch64__)

# if defined(__aarch64__)

/*
 * No CPU frequency is reported in /proc/cpuinfo for ARM64,
 * but this function is never actually called, because
 * ci_measure_cpu_khz should always succeed, as it's calculating
 * a stable timer value.
 */
ci_inline int try_get_hz(const char* line, unsigned* cpu_khz_out)
{
  ci_assert(0);
  return 0;
}

#else

ci_inline int try_get_hz(const char* line, unsigned* cpu_khz_out)
{
  float f;

  if( sscanf(line, "cpu MHz : %f", &f) != 1 )  return 0;

  *cpu_khz_out = (unsigned) (f * 1000.0);
  return 1;
}

#endif

/* The following routine has been obtained sfnettest code */
static int ci_measure_cpu_khz(unsigned* cpu_khz)
{
  int interval_usec = 100000;
  struct timeval tv_s, tv_e;
  uint64_t tsc_s, tsc_e, tsc_e2;
  uint64_t tsc_gtod, min_tsc_gtod, usec = 0;
  int n, skew = 0;

  ci_frc64(&tsc_s);
  gettimeofday(&tv_s, NULL);
  ci_frc64(&tsc_e2);
  min_tsc_gtod = tsc_e2 - tsc_s;
  n = 0;
  do {
    ci_frc64(&tsc_s);
    gettimeofday(&tv_s, NULL);
    ci_frc64(&tsc_e2);
    tsc_gtod = tsc_e2 - tsc_s;
    if( tsc_gtod < min_tsc_gtod )
      min_tsc_gtod = tsc_gtod;
  } while( ++n < 20 || (tsc_gtod > min_tsc_gtod * 2 && n < 100) );

  do {
    ci_frc64(&tsc_e);
    gettimeofday(&tv_e, NULL);
    ci_frc64(&tsc_e2);
    if( tsc_e2 < tsc_e || timercmp(&tv_e, &tv_s, <) ) {
      skew = 1;
      break;
    }
    tsc_gtod = tsc_e2 - tsc_e;
    usec = (tv_e.tv_sec - tv_s.tv_sec) * (uint64_t) 1000000;
    usec += tv_e.tv_usec - tv_s.tv_usec;
  } while( usec < interval_usec || tsc_gtod > min_tsc_gtod * 2 );

  if( skew )
    return 0;
  *cpu_khz = (tsc_e - tsc_s) * 1000 / usec;
  return 1;
}


# elif defined(__PPC__)

/*
 * On PPC Suse 9 linux  /proc/cpuinfo gives cpu speed in the format ..
 *  .
 *  clock           : 1655.984000MHz
 *  .
 */

ci_inline int try_get_hz(const char* line, unsigned* cpu_khz_out)
{
  long l;

  if( sscanf(line, "timebase           : %lu", &l) != 1 )  
  	return 0;

  *cpu_khz_out = (unsigned) (l / 1000);
  return 1;
}


# else
#  error "ci: Dont know how to get cpu frequency."
# endif

int
ci_get_cpu_khz(unsigned* cpu_khz_out)
{
  FILE* f;
  char buf[80];

  if( ! ci_cpu_khz ) {
    /* On powerpc /proc/cpuinfo gives reliable information, hence no need to
     * measure.
     * On x86 cpuinfo readings might be ugely inaccurate when cpu_scaling
     * is enabled */
#ifndef __powerpc__
    if( ci_measure_cpu_khz(&ci_cpu_khz) )
      goto end;
    else
      ci_log("Warning measured cpu_khz not stable, querying /proc/cpuinfo");
#endif
    /* We only go get the khz if we need to.  Obviously it's sensible for
     * performance, but also we need to do this because we can't call fclose
     * once the system is fully initialized, since our overridden version of
     * fclose needs to get the fdtable-lock.  (Note: we would ideally just
     * ensure we always call the 'real' libc fclose from here, but since this
     * gets linked into the ciapp library, finding real libc is not so easy)
     * Therefore, it is important that this function get called early, to
     * ensure that we can't deadlock on ourselves by calling fclose when the
     * fdtable lock is held.
     */
    f = fopen("/proc/cpuinfo", "r");
    if( !f )  return -errno;

    while( 1 ) {
      if( !fgets(buf, sizeof(buf), f) )  {
        fclose (f);
        return -EIO;
      }
      if( try_get_hz(buf, &ci_cpu_khz) )  break;
    }

    fclose (f);
  }
#ifndef __powerpc__
end:
#endif
  if( cpu_khz_out )  *cpu_khz_out = ci_cpu_khz;
  return 0;
}


/*! \cidoxg_end */
