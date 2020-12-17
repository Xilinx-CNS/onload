/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2002-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Dump data as hex.
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
 
/*! \cidoxg_lib_citools */
 
#include "citools_internal.h"

#ifdef __KERNEL__
#define CI_HAS_CTYPE 	0	/*  ?? bit conservative */

#else
#define CI_HAS_CTYPE 	1	

#include <ctype.h>
#endif


#define POCTET(s)  ((const ci_octet*) (s))


char ci_printable_char(char c)
{
#if CI_HAS_CTYPE
  return isprint((unsigned char)c) ? c : '.';
#else
  return (c < 32 || c > 126) ? '.' : c;
#endif
}

void ci_hex_dump_format_single_octets(char* buf, int buf_len, const ci_octet* s,
                                      int i, int offset, int len)
{
  static const char*const fmt[] = { "%02x ", "%02x ", "%02x ", "%02x " };
  static const char*const xx[] =  { "xx "  , "xx "  , "xx "  , "xx "   };

  if( i >= offset && i < offset + len )
    snprintf(buf, buf_len, fmt[i & 3], (unsigned) POCTET(s)[i - offset]);
  else
    snprintf(buf, buf_len, "%s", xx[i & 3]);
}


void ci_hex_dump_format_octets(char* buf, int buf_len, const ci_octet* s, int i,
			       int offset, int len)
{
  static const char*const fmt[] = { "%02x", "%02x ", "%02x", "%02x  " };
  static const char*const xx[] =  { "xx"  , "xx "  , "xx"  , "xx  "   };

  if( i >= offset && i < offset + len )
    snprintf(buf, buf_len, fmt[i & 3], (unsigned) POCTET(s)[i - offset]);
  else
    snprintf(buf, buf_len, "%s", xx[i & 3]);
}


void ci_hex_dump_format_dwords(char* buf, int buf_len, const ci_octet* s, int i,
			       int offset, int len)
{
  static const char*const fmt[] = { "%02x   ", "%02x", "%02x ", "%02x" };
  static const char*const xx[] =  { "xx   "  , "xx"  , "xx "  , "xx"   };

  i = (i & 0xc) | (3 - (i & 3));

  if( i >= offset && i < offset + len )
    snprintf(buf, buf_len, fmt[i & 3], (unsigned) POCTET(s)[i - offset]);
  else
    snprintf(buf, buf_len, "%s", xx[i & 3]);
}


void (*ci_hex_dump_formatter)(char* buf, int buf_len, const ci_octet* s,
			      int i, int off, int len)
     = ci_hex_dump_format_octets;


/* Must add a zero byte at the end */
void ci_hex_dump_format_stringify(char* buf, int buf_len, const ci_octet* s,
                                  int offset, int len)
{
  int i,o=0;

  for( i = 0; i < offset && o < buf_len; i++ )
    o += snprintf(buf+o, buf_len-o, "_");
  for( i = 0; i < len && o < buf_len; i++, o++ )
    buf[o] = ci_printable_char(POCTET(s)[i]);
  buf[o < buf_len ? o : buf_len-1] = '\0';
}


void (*ci_hex_dump_stringifier)(char* buf, int buf_len, const ci_octet* s,
                                int off, int len)
     = ci_hex_dump_format_stringify;


void ci_hex_dump_row(char* buf, int buf_len, volatile const void* sv, int len,
		      ci_ptr_arith_t address)
{
  const ci_octet* s = (const ci_octet*) sv;
  int i, o, offset;
  offset = (int)(address & 15u);

  ci_assert(buf);  ci_assert(s || !len);  ci_assert(len >= 0);
  ci_assert(len + offset <= 16);

  o = snprintf(buf, buf_len, "%08lx   ", (unsigned long) CI_ALIGN_BACK(address, 16));

  for( i = 0; i < 16 && o < buf_len; ++i ) {
    ci_hex_dump_formatter(buf+o, buf_len-o, s, i, offset, len);
    o += strlen(buf+o);
  }

  if( o < buf_len )
    buf[o++] = ' ';
  ci_hex_dump_stringifier(buf+o, buf_len-o, s, offset, len);
}


void ci_hex_dump(void (*log_fn)(const char* msg), volatile const void* s,
		 int len, ci_ptr_arith_t address)
{
  char buf[80]; /* TODO beware of stack overflow! */
  int n;

  ci_assert(log_fn);  ci_assert(s || !len);  ci_assert(len >= 0);

  while( len > 0 ) {
    n = len;
    if( n > 16 )  n = 16;
    if( n + (int)(address & 15u) > 16 )  n = 16 - (int)(address & 15u);
    ci_hex_dump_row(buf, sizeof(buf), s, n, address);
    len -= n;
    address += n;
    s = (ci_octet*) s + n;
    log_fn(buf);
  }
}

/*! \cidoxg_end */
