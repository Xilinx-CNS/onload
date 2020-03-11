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


#define EXPECTED(left,seed)  ((ci_uint8) (((left) & 0x1) ? (seed) : (left)))


static void post_mortem(const volatile void* p, unsigned len_bytes,
			unsigned start_n, ci_uint8 seed,
			int start_off);


void ci_byte_pattern_write(volatile void* p, unsigned len_bytes,
			   unsigned start_n, ci_uint8 seed)
{
  ci_uint8* pdw;

  ci_assert(p);

  pdw = (ci_uint8*) p;

  for( ; len_bytes--; --start_n )
    *pdw++ = EXPECTED(start_n, seed);
}


int  ci_byte_pattern_check(const volatile void* p, unsigned len_bytes,
			   unsigned start_n, ci_uint8 seed, int log_errors,
			   int start_off)
{
  const ci_uint8* pdw;
  unsigned c, n;

  ci_assert(p);

  pdw = (const ci_uint8*) p;
  c = len_bytes;
  n = start_n;

  for( ; c--; --n )
    if( *pdw++ != EXPECTED(n, seed) ) {
      if( log_errors )  post_mortem(p, len_bytes, start_n, seed, start_off);
      return 0;
    }

  return 1;
}


int  ci_byte_pattern_valid(const volatile void* p, unsigned len_bytes,
			   unsigned* start_n_out, ci_uint8* seed_out)
{
  ci_uint8 seed;
  const ci_uint8* pdw;
  unsigned n;

  ci_assert(p);

  pdw = (const ci_uint8*) p;

  seed = pdw[0];
  n = pdw[1] + 1;
  if( pdw[2] != seed || pdw[3] != (ci_uint8) (n - 3) ) {
    seed = pdw[1];
    n = pdw[0];
    if( pdw[3] != seed || pdw[2] != (ci_uint8) (n - 2) )
      return 0;
  }

  if( start_n_out )  *start_n_out = n;
  if( seed_out    )  *seed_out = seed;

  return ci_byte_pattern_check(p, len_bytes, n, seed, 0, 0);
}


void ci_byte_pattern_repeat(volatile void* buf, int buf_bytes,
			    const void* patn, int patn_bytes)
{
  const ci_uint8* s;
  ci_uint8* d;
  int i;

  ci_assert(buf);
  ci_assert(buf_bytes >= 0);
  ci_assert(patn);
  ci_assert(patn_bytes > 0);

  s = (const ci_uint8*) patn;
  d = (ci_uint8*) buf;

  for( i = 0; i < buf_bytes; ++i )  d[i] = s[i % patn_bytes];
}


int ci_byte_pattern_find(const void* buf, int buf_bytes,
			 ci_uint32 pattern)
{
  const ci_uint8* b;
  const ci_uint8* p;
  int i;

  ci_assert(buf);
  ci_assert(buf_bytes >= 0);

  p = (ci_uint8*) &pattern;
  b = (ci_uint8*) buf;
  i = buf_bytes - 1;

  while( i >= 0 && b[i] == p[i & 3u] )  --i;

  return ++i;
}


ci_uint8 ci_sum_bytes(const volatile void* p, unsigned len_bytes)
{
  const ci_uint8* pdw;
  ci_uint8 sum = 0;

  ci_assert(p);

  for( pdw = (const ci_uint8*) p; len_bytes--; )
    sum += *pdw++;

  return sum;
}


/**********************************************************************
 * Post mortem.
 */

static unsigned find_extent(const ci_uint8* pdw, unsigned len,
			    int off, ci_uint32 what)
{
  ci_uint8 deadbeef[4];
  unsigned i;

  what = CI_BSWAP_BE32(what);
  memcpy(deadbeef, &what, 4);

  for( i = 0; i < len; ++i )
    if( pdw[i] != deadbeef[(i + off) & 3u] )
      break;

  return i;
}


static unsigned match_pattern(const ci_uint8* p, unsigned len,
			      const char** what)
{
  unsigned l, max = 0;
  unsigned i, off;
  static unsigned patterns[] = {
    0xDEADBEEF,
    0xCABBA9E5,
    0xDECEA5ED,
    0xDEADC0DE,
    0xACCE55ED,
    0xDEFFACED,
  };
  const char* names[] = {
    "deadbeef",
    "cabbages",
    "deceased",
    "deadcode",
    "accessed",
    "defaced ",
  };
  for( i = 0u; i < sizeof(patterns) / sizeof(patterns[0]); ++i ) {
    for( off = 0u; off < 4u; ++off ) {
      l = find_extent(p, len, off, patterns[i]);
      if( l > max ) {
	max = l;
	*what = names[i];
      }
    }
  }
  return max;
}


static void handle_bad(const ci_uint8* pdw, unsigned i, unsigned len_bytes,
		       int start_off)
{
  /* Look for certain 'deadbeef'-style patterns.  Otherwise its just plain
  ** and simple bad.
  */

  unsigned bad_i, len;
  const char* what;
  bad_i = i;

  while( i < len_bytes ) {
    len = 0;
    what = 0;

    len = match_pattern(pdw + i, len_bytes - i, &what);
    if( len < 2 )  { ++i; continue; }

    if( bad_i != i )
      ci_log("[0x%04x->%04x] bad  (bytes=%04u)", start_off+bad_i,
	     start_off+i - 1, i - bad_i);

    ci_log("[0x%04x->%04x] %s (bytes=%04u)", start_off+i,
	   start_off+i + len - 1, what, len);

    i += len;
    bad_i = i;
  }

  if( bad_i != i )
    ci_log("[0x%04x->%04x] bad  (bytes=%04u)", start_off+bad_i,
	   start_off+len_bytes - 1, len_bytes - bad_i);
}


static int find_valid_extent(const ci_uint8* pdw, unsigned seed,
			     unsigned val, unsigned len)
{
  int num = 0;

  while( len-- ) {
    if( *pdw++ != EXPECTED(val, seed) )  return num;
    ++num;
    --val;
  }

  return num;
}


static void post_mortem(const volatile void* p, unsigned len_bytes,
			unsigned start_n, ci_uint8 expected_seed,
			int start_off)
{
  unsigned seed, n;
  unsigned bad_i = 0, i = 0, len;
  const ci_uint8* pdw;
  ci_uint8 expected_n;

  pdw = (const ci_uint8*) p;

  while( len_bytes - i >= 4 ) {
    seed = pdw[i];
    n = pdw[i + 1] + 1;
    if( pdw[i + 2] != seed || pdw[i + 3] != (ci_uint8) (n - 3) ) {
      seed = pdw[i + 1];
      n = pdw[i];
      if( pdw[i + 3] != seed || pdw[i + 2] != (ci_uint8) (n - 2) ) {
	++i;
	continue;
      }
    }

    len = find_valid_extent(pdw + i, seed, n, len_bytes - i);
    ci_assert(len >= 4);
    expected_n = (ci_uint8) (start_n - i);

    if( bad_i != i )  handle_bad(pdw, bad_i, i, start_off);

    if( seed == expected_seed && (n & 0xff) == expected_n )
      ci_log("[0x%04x->%04x] okay (bytes=%04u seed=0x%02x n=0x%02x)",
	     start_off+i, start_off+i+len-1, len, seed, (unsigned) expected_n);
    else
      ci_log("[0x%04x->%04x] patn (bytes=%04u seed=0x%02x{%02x} "
	     "n=0x%02x{%02x})", start_off+i, start_off+i+len-1,
	     len, seed, expected_seed, n & 0xff, (unsigned) expected_n);

    i += len;
    bad_i = i;
  }

  if( i < len_bytes || bad_i != i )
    handle_bad(pdw, bad_i, len_bytes, start_off);
}

/*! \cidoxg_end */
