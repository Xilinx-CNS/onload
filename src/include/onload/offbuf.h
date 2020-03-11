/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  A buffer described by offsets.
**   \date  2004/01/05
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __ONLOAD_OFFBUF_H__
#define __ONLOAD_OFFBUF_H__


typedef struct oo_offbuf {
  /* offsets are relative to the start of the [oo_offbuf] */
  ci_uint32  off;
  ci_uint32  end;
} oo_offbuf;


ci_inline void oo_offbuf_init(oo_offbuf* b, void* start, int len) {
  b->off = (ci_uint32)((char*) start - (char*) b);
  b->end = b->off + len;
}

ci_inline void oo_offbuf_init2(oo_offbuf* b, void* start, void* end) {
  b->off = (ci_uint32)((char*) start - (char*) b);
  b->end = (ci_uint32)((char*) end - (char*) b);
}


ci_inline void oo_offbuf_set_start(oo_offbuf* b, void* start)
{ b->off = (ci_uint32) ((char*) start - (char*) b); }

ci_inline void oo_offbuf_set_end(oo_offbuf* b, void* end)
{ b->end = (ci_uint32) ((char*) end - (char*) b); }

ci_inline void oo_offbuf_set_len(oo_offbuf* b, int len)
{ b->end = b->off + len; }


ci_inline char* oo_offbuf_ptr(const oo_offbuf* b)
{ return (char*) b + b->off; }

ci_inline char* oo_offbuf_end(const oo_offbuf* b)
{ return (char*) b + b->end; }

ci_inline int   oo_offbuf_offset(const oo_offbuf* b)
{ return b->off; }

ci_inline int   oo_offbuf_left(const oo_offbuf* b)
{ return b->end - b->off; }

ci_inline void  oo_offbuf_advance(oo_offbuf* b, int n)
{ b->off += n; }

ci_inline void  oo_offbuf_retard(oo_offbuf* b, int n)
{ b->off -= n; }

ci_inline void  oo_offbuf_squeeze_end(oo_offbuf* b, int n)
{ b->end -= n; }

/* NB. Maintains alignment of the current position. */
ci_inline void oo_offbuf_empty(oo_offbuf* b)
{ b->end = b->off; }

ci_inline int oo_offbuf_size(const oo_offbuf* b)
{ return b->end - b->off; }

ci_inline int oo_offbuf_is_empty(const oo_offbuf* b)
{ return b->end == b->off; }

ci_inline int oo_offbuf_not_empty(const oo_offbuf* b)
{ return b->end != b->off; }


#define OO_OFFBUF_ASSERT_VALID(b, minp, maxp)	do {	\
    ci_assert(b);					\
    ci_assert_ge(oo_offbuf_ptr(b), (char*)(minp));	\
    ci_assert_le(oo_offbuf_end(b), (char*)(maxp));	\
    ci_assert_le((b)->off, (b)->end);			\
  } while(0)


#endif  /* __ONLOAD_OFFBUF_H__ */
/*! \cidoxg_end */
