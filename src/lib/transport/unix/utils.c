/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2019 Xilinx, Inc. */
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

/*! \cidoxg_lib_transport_unix */

#include <internal.h>


static inline int citp_timestamp_compare(const ci_int64 a_sec,
                                         const ci_uint32 a_nsec,
                                         const ci_uint32 a_nsec_frac,
                                         const ci_int64 b_sec,
                                         const ci_uint32 b_nsec,
                                         const ci_uint32 b_nsec_frac)
{
  if( a_sec < b_sec ) {
    return -1;
  }
  else if( a_sec == b_sec ) {
    if( a_nsec < b_nsec )
      return -1;
    else if( a_nsec == b_nsec ) {
      if( a_nsec_frac < b_nsec_frac )
        return -1;
      else if( a_nsec_frac == b_nsec_frac )
        return 0;
      else
        return 1;
    }
    else {
      return 1;
    }
  }
  else {
    return 1;
  }
}


int citp_timespec_compare(const struct timespec* a, const struct timespec* b)
{
  return citp_timestamp_compare(a->tv_sec, a->tv_nsec, 0,
                                b->tv_sec, b->tv_nsec, 0);
}


int citp_oo_timespec_compare(const struct oo_timespec* a,
                             const struct timespec* b)
{
  /* Don't compare the midpoint of the low precision timespec with the high
   * precision one to avoid creating an inconsistent result when the high
   * precision timestamp is subsequently truncated; truncate both now. */
  return citp_timestamp_compare(a->tv_sec, a->tv_nsec, 0,
                                b->tv_sec, b->tv_nsec, 0);
}


void citp_oo_get_cpu_khz(ci_uint32* cpu_khz)
{
  ef_driver_handle fd;

  /* set up a constant value for the case everything goes wrong */
  *cpu_khz = 1000;

  if( ef_onload_driver_open(&fd, OO_STACK_DEV, 1) != 0 ) {
    fprintf(stderr, "%s: Failed to open /dev/onload\n", __FUNCTION__);
    ci_get_cpu_khz(cpu_khz);
    return;
  }
  if( ci_sys_ioctl(fd, OO_IOC_GET_CPU_KHZ, cpu_khz) != 0 ) {
    Log_E(log("%s: Failed to query cpu_khz", __FUNCTION__));
    ci_get_cpu_khz(cpu_khz);
  }
  ef_onload_driver_close(fd);
}

/*! \cidoxg_end */
