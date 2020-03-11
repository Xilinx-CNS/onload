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

/*! \cidoxg_lib_ciapp */

#include <ci/app.h>


static void post_mortem_dword(const volatile void* p, unsigned len_dwords,
			      int start_off);


void ci_write_dword_pattern(volatile void* p, unsigned len_dwords)
{
  ci_uint32* pdw;

  ci_assert(p);
  ci_assert(((ci_ptr_arith_t) p & 0x3) == 0);

  for( pdw = (ci_uint32*) p; len_dwords--; )
    *pdw++ = len_dwords;
}


int  ci_check_dword_pattern(const volatile void* p, unsigned len_dwords,
			    int log_errors, int start_off)
{
  const ci_uint32* pdw;
  unsigned n;

  ci_assert(p);
  ci_assert(((ci_ptr_arith_t) p & 0x3) == 0);

  for( pdw = (const ci_uint32*) p, n = len_dwords; n--; )
    if( *pdw++ != n ) {
      if( log_errors )  post_mortem_dword(p, len_dwords, start_off);
      return 0;
    }
  return 1;
}


ci_uint32 ci_sum_dwords(const volatile void* p, unsigned len_dwords)
{
  const ci_uint32* pdw;
  ci_uint32 sum = 0;

  ci_assert(p);
  ci_assert(((ci_ptr_arith_t) p & 0x3) == 0);

  for( pdw = (const ci_uint32*) p; len_dwords--; )
    sum += *pdw++;

  return sum;
}


/**********************************************************************
 * Post mortem.
 */

#define PM_BAD       0
#define PM_CONSTANT  1
#define PM_OK        2
#define PM_OFFSET    3


static void describe(int start_off, unsigned from, unsigned to,
		     int state, ci_uint32 current, int offset)
{
  if( from - 1 == to )  return;

  from += start_off;
  to += start_off;

  switch( state ) {
  case PM_BAD:
    ci_log("[%x->%x] bad", from, to);
    break;
  case PM_CONSTANT:
    ci_log("[%x->%x] 0x%x", from, to, (unsigned) current);
    break;
  case PM_OK:
    ci_log("[%x->%x] okay", from, to);
    break;
  case PM_OFFSET:
    ci_log("[%x->%x] offset by %d", from, to, offset);
    break;
  }
}


#define diff(a,b)  ((a) > (b) ? (a) - (b) : (b) - (a))


static void post_mortem_dword(const volatile void* p, unsigned len_dwords,
			      int start_off)
{
  unsigned start_i, i;
  int state = PM_OK;
  ci_uint32 expected;
  int offset = 0;
  const ci_uint32* pdw;

  pdw = (const ci_uint32*) p;
  expected = len_dwords - 1;

  for( start_i = i = 0; i < len_dwords; ++i, expected-- ) {
    switch( state ) {
    case PM_CONSTANT:
      if( pdw[i] == pdw[i-1] )  continue;
      break;
    case PM_OK:
      if( pdw[i] == expected )  continue;
      break;
    case PM_OFFSET:
      if( pdw[i] == (unsigned) (expected + offset) )  continue;
      break;
    case PM_BAD:
      break;
    default:
      ci_assert(0);
    }

    if( pdw[i] == expected ) {
      describe(start_off, start_i, i - 1, state, pdw[i-1], offset);
      start_i = i;
      state = PM_OK;
    }
    else if( i + 1 < len_dwords && pdw[i+1] == expected - 1 ) {
      /* Next one is okay, so this is isolated bad.  We check explicitly to
      ** avoid thinking we've got ourselves a trend.
      */
      describe(start_off, start_i, i - 1, state, pdw[i-1], offset);
      start_i = i;
      state = PM_BAD;
    }
    else if( i + 1 < len_dwords && pdw[i] == pdw[i+1] ) {
      describe(start_off, start_i, i - 1, state, pdw[i-1], offset);
      start_i = i;
      state = PM_CONSTANT;
    }
    else if( diff((int) pdw[i] - (int) expected, offset) < 10 ) {
      describe(start_off, start_i, i - 1, state, pdw[i-1], offset);
      offset = (int) pdw[i] - (int) expected;
      start_i = i;
      state = PM_OFFSET;
    }
    else if( state != PM_BAD ) {
      describe(start_off, start_i, i - 1, state, pdw[i-1], offset);
      start_i = i;
      state = PM_BAD;
    }
  }

  describe(start_off, start_i, i - 1, state, pdw[i-1], offset);
}

/*! \cidoxg_end */
