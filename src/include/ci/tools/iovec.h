/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2005-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Tools for handling iovecs.
**   \date  2003/06/18
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */
#ifndef __CI_TOOLS_IOVEC_H__
#define __CI_TOOLS_IOVEC_H__

typedef struct {
  const ci_iovec*     iov;
  int                 iovlen;
  ci_iovec            io;
} ci_iovec_ptr;


ci_inline void ci_iovec_ptr_init(ci_iovec_ptr* p, const ci_iovec* iov,
				 int iovlen) {
  p->iov = iov;
  p->iovlen = iovlen;
  CI_IOVEC_LEN(&p->io) = 0;
}

ci_inline void ci_iovec_ptr_init_nz(ci_iovec_ptr* p, const ci_iovec* iov,
				    int iovlen) {
  ci_assert(iovlen > 0);
  p->iov = iov + 1;
  p->iovlen = iovlen - 1;
  p->io = *iov;
}

  /*! Initialise [p] so that it points to the single segment [buf:len]. */
ci_inline void ci_iovec_ptr_init_buf(ci_iovec_ptr* p, void* buf, int len) {
  p->iovlen = 0;
  CI_IOVEC_BASE(&p->io) = (char *)buf;
  CI_IOVEC_LEN(&p->io) = len;
}


  /*! Returns number of bytes left in the ci_iovec_ptr structure. */
ci_inline int ci_iovec_ptr_bytes_count(const ci_iovec_ptr* p) {
  int i, n = CI_IOVEC_LEN(&p->io);
  for( i = 0; i < p->iovlen; ++i )  n += CI_IOVEC_LEN(&p->iov[i]);
  return n;
}


  /*! Returns true if [p] is known to be empty.  Note that it will return
  ** false if [p] only contains zero-length segments (even though it is
  ** technically 'empty').
  */
ci_inline int ci_iovec_ptr_is_empty(const ci_iovec_ptr* p)
{ return CI_IOVEC_LEN(&p->io) == 0 && p->iovlen == 0; }

  /*! This one does a thorough job of determining whether [p] is empty.
  ** That is, it skips over empty segments.
  */
ci_inline int ci_iovec_ptr_is_empty_proper(ci_iovec_ptr* p) {
  while( CI_IOVEC_LEN(&p->io) == 0 ) {
    if( p->iovlen == 0 )  return 1;
    p->io = *p->iov++;
    --p->iovlen;
  }
  return 0;
}

ci_inline void ci_iovec_ptr_advance(ci_iovec_ptr* p, int n) {
  CI_IOVEC_LEN(&p->io) -= n;
  CI_IOVEC_BASE(&p->io) = (char*)CI_IOVEC_BASE(&p->io) + n;
}


  /*! Copy from [src] to [dest].  Returns the number of bytes copied, and
  ** updates [*src].
  */
extern int ci_copy_iovec(void* dest, int dest_len, ci_iovec_ptr* src) CI_HF;


  /*! Copy from [src] to [dest].  Returns the number of bytes copied, and
  ** updates [*dest].
  */
extern int ci_copy_to_iovec(ci_iovec_ptr* dest, const void* src,
			    int src_len) CI_HF;


ci_inline int ci_iovec_bytes(const ci_iovec* iov, int iovlen) {
  int n = 0;
  while( iovlen-- )  n += CI_IOVEC_LEN(iov++);
  return n;
}


#endif  /* __CI_TOOLS_IOVEC_H__ */
/*! \cidoxg_end */
