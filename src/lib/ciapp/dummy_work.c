/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Keep CPU busy with dummy work.
**   \date  2005/07/28
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_lib_ciapp */
#include <ci/app.h>


static int do_loops(unsigned n_loops)
{
  static int hoopey = 1;
  while( n_loops-- )  hoopey += hoopey;
  return hoopey;
}


void ci_dummy_work(unsigned work_for_usec)
{
  static unsigned cpu_mhz, loops_per_usec;
  if( cpu_mhz == 0 ) {
    ci_uint32 start, end;
    int i, usec, n = 100;
    CI_TRY(ci_get_cpu_khz(&cpu_mhz));
    cpu_mhz /= 1000;
    ci_frc32(&end);
    do {
      n *= 2;
      start = end;
      do_loops(n);
      ci_frc32(&end);
      usec = (end - start) / cpu_mhz;
    } while( usec < 500 );
    for( i = 0; i < 10; ++i ) {
      start = end;
      do_loops(n);
      ci_frc32(&end);
      usec = CI_MIN(usec, (int)((end - start) / cpu_mhz));
    }
    loops_per_usec = n / usec;
  }

  do_loops(loops_per_usec * work_for_usec);
}

/*! \cidoxg_end */
