/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Efficient fifo (based on circular buffer).
**   \date  2003/06/30
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_FIFO_H__
#define __CI_TOOLS_FIFO_H__

/*!
** [f] is a pointer to a data structure that should have at least the
** following members (or similar):
**
**   struct type_t_fifo {
**     unsigned  fifo_size;
**     unsigned  fifo_rd_i;
**     unsigned  fifo_wr_i;
**     type_t*   fifo;
**   };
**
** Alternatively you can put the data inline like this:
**
**   struct type_t_fifo {
**     unsigned  fifo_size;
**     unsigned  fifo_rd_i;
**     unsigned  fifo_wr_i;
**     type_t    fifo[FIFO_CAPACITY_PLUS_ONE];
**   };
*/

#define CI_FIFO_M(f, x)   ((x) % (f)->fifo_size)

#define ci_fifo_valid(f)  ((f)->fifo_size > 1 &&                        \
			   (f)->fifo_rd_i < (f)->fifo_size        &&	\
			   (f)->fifo_wr_i < (f)->fifo_size)

#define CI_FIFO_FMT		"[rd=%x wr=%x num=%d(%d) spc=%d(%d)]"
#define CI_FIFO_PRI_ARG(f)	(unsigned) (f).fifo_rd_i,		\
				(unsigned) (f).fifo_wr_i,		\
				(int) ci_fifo_num(&(f)),		\
				(int) ci_fifo_contig_num(&(f)),         \
				(int) ci_fifo_space(&(f)),		\
				(int) ci_fifo_contig_space(&(f))

#define ci_fifo_init(f, cap)						   \
  do{ (f)->fifo_rd_i=(f)->fifo_wr_i=0; (f)->fifo_size = (cap)+1; }while(0)

#define ci_fifo_ctor_wcast(f, cap, prc, cast)				\
  do{ (f)->fifo = cast ci_alloc(((cap)+1)*sizeof((f)->fifo[0]));	\
      ci_fifo_init((f), (cap));						\
      ci_assert(!(f)->fifo || ci_fifo_valid(f));			\
      *(prc) = (f)->fifo ? 0 : -ENOMEM;					\
  }while(0)

#define ci_fifo_ctor(f, cap, prc) ci_fifo_ctor_wcast(f,cap,prc,)

#define ci_fifo_dtor(f)							\
  do{ ci_assert(ci_fifo_valid(f));  ci_free((f)->fifo); }while(0)

#define ci_fifo_is_empty(f)  ((f)->fifo_rd_i == (f)->fifo_wr_i)
#define ci_fifo_not_empty(f) ((f)->fifo_rd_i != (f)->fifo_wr_i)
#define ci_fifo_is_full(f)   (CI_FIFO_M((f),(f)->fifo_wr_i+1u)==(f)->fifo_rd_i)
#define ci_fifo_not_full(f)  (CI_FIFO_M((f),(f)->fifo_wr_i+1u)!=(f)->fifo_rd_i)

#define ci_fifo_num(f)							\
  CI_FIFO_M((f), (f)->fifo_wr_i + (f)->fifo_size - (f)->fifo_rd_i)

#define ci_fifo_space(f)						\
  CI_FIFO_M((f), (f)->fifo_rd_i+(f)->fifo_size-(f)->fifo_wr_i-1u)

#define ci_fifo_buf_size(f) ((f)->fifo_size)
#define ci_fifo_capacity(f) ((f)->fifo_size - 1u)

#define ci_fifo_peek(f)     ((f)->fifo[(f)->fifo_rd_i])
#define ci_fifo_peekp(f)    ((f)->fifo + (f)->fifo_rd_i)
#define ci_fifo_poke(f)     ((f)->fifo[(f)->fifo_wr_i])
#define ci_fifo_pokep(f)    ((f)->fifo + (f)->fifo_wr_i)
#define ci_fifo_peek_i(f,i) ((f)->fifo[CI_FIFO_M((f), (f)->fifo_rd_i+(i))])
#define ci_fifo_poke_i(f,i) ((f)->fifo[CI_FIFO_M((f), (f)->fifo_wr_i+(i))])

#define ci_fifo_rd_next(f)						\
  do{ (f)->fifo_rd_i = CI_FIFO_M((f), (f)->fifo_rd_i + 1u); }while(0)
#define ci_fifo_wr_next(f)						\
  do{ (f)->fifo_wr_i = CI_FIFO_M((f), (f)->fifo_wr_i + 1u); }while(0)

#define ci_fifo_rd_adv(f, n)						\
  do{ (f)->fifo_rd_i = CI_FIFO_M((f), (f)->fifo_rd_i + (n)); }while(0)
#define ci_fifo_wr_adv(f, n)						\
  do{ (f)->fifo_wr_i = CI_FIFO_M((f), (f)->fifo_wr_i + (n)); }while(0)
#define ci_fifo_wr_retreat(f, n)				        \
  do{(f)->fifo_wr_i=CI_FIFO_M((f),(f)->fifo_wr_i+(f)->fifo_size-(n));}while(0)

#define ci_fifo_put(f, v)					\
  do{ ci_fifo_poke(f) = (v); ci_fifo_wr_next(f); }while(0)

#define ci_fifo_get(f, pv)					\
  do{ *(pv) = ci_fifo_peek(f); ci_fifo_rd_next(f); }while(0)

/* This macro defines a get function that returns the value. */
#define CI_FIFO_DEFINE_GET(name, fifo_t, elem_t)	\
  ci_inline elem_t name(fifo_t* f) {			\
    elem_t v = ci_fifo_peek(f);				\
    ci_fifo_rd_next(f);					\
    return v;						\
  }

#define ci_fifo_contig_num(f)						\
  (((f)->fifo_wr_i >= (f)->fifo_rd_i) ?					\
   (f)->fifo_wr_i - (f)->fifo_rd_i : (f)->fifo_size - (f)->fifo_rd_i)

#define ci_fifo_contig_space(f)				\
  (((f)->fifo_rd_i > (f)->fifo_wr_i) ?			\
   (f)->fifo_rd_i - (f)->fifo_wr_i - 1 :		\
   (f)->fifo_size - (f)->fifo_wr_i - !(f)->fifo_rd_i)


/**********************************************************************
 * Fifo where buffer size is power of 2.  (Even faster!)
 */

/*!
** Power-of-2 fifos should look like this:
**
**   struct type_t_fifo {
**     type_t*   fifo;
**     unsigned  fifo_mask;
**     unsigned  fifo_rd_i;
**     unsigned  fifo_wr_i;
**   };
**
** Note that capacity is [(1<<n)-1], and that [fifo_mask] is one less than
** the buffer size.
*/

#define CI_FIFO2_M(f, x)     ((x) & ((f)->fifo_mask))
#define ci_fifo2_rd_i(f)     CI_FIFO2_M((f), (f)->fifo_rd_i)
#define ci_fifo2_wr_i(f)     CI_FIFO2_M((f), (f)->fifo_wr_i)

#define ci_fifo2_valid(f)  ((f)->fifo                              &&   \
                            CI_IS_POW2((f)->fifo_mask+1u)          &&   \
                            (int) ci_fifo2_num(f) >= 0             &&   \
                            (int) ci_fifo2_num(f) <= ci_fifo2_capacity(f))

#define CI_FIFO2_FMT		"[rd=%x wr=%x num=%d(%d) spc=%d(%d)]"
#define CI_FIFO2_PRI_ARG(f)	(unsigned) ci_fifo2_rd_i(f),            \
                                (unsigned) ci_fifo2_wr_i(f),            \
                                (int) ci_fifo2_num(&(f)),               \
                                (int) ci_fifo2_contig_num(&(f)),	\
                                (int) ci_fifo2_space(&(f)),             \
                                (int) ci_fifo2_contig_space(&(f))

#define ci_fifo2_init(f, cap)                   \
  do{ ci_assert(CI_IS_POW2((cap)));             \
      (f)->fifo_rd_i = (f)->fifo_wr_i = 0u;     \
      (f)->fifo_mask = (cap) - 1;               \
  }while(0)

#define ci_fifo2_ctor(f, cap, prc)					\
  do{ *(void**) &(f)->fifo = ci_alloc((cap) * sizeof((f)->fifo[0]));	\
      ci_fifo2_init((f), (cap));					\
      ci_assert(!(f)->fifo || ci_fifo2_valid(f));			\
      *(prc) = (f)->fifo ? 0 : -ENOMEM;					\
  }while(0)

#define ci_fifo2_dtor(f)						\
  do{ ci_assert(ci_fifo2_valid(f));  ci_free((f)->fifo); }while(0)

#define ci_fifo2_is_empty(f)  ((f)->fifo_rd_i == (f)->fifo_wr_i)
#define ci_fifo2_not_empty(f) ((f)->fifo_rd_i != (f)->fifo_wr_i)
#define ci_fifo2_is_full(f)   (ci_fifo2_num(f) == ci_fifo2_capacity(f))
#define ci_fifo2_not_full(f)  (ci_fifo2_num(f) != ci_fifo2_capacity(f))

#define ci_fifo2_num(f)       ((f)->fifo_wr_i - (f)->fifo_rd_i)
#define ci_fifo2_space(f)     (ci_fifo2_capacity(f) - ci_fifo2_num(f))
#define ci_fifo2_buf_size(f)  ((f)->fifo_mask + 1u)
#define ci_fifo2_capacity(f)  ((f)->fifo_mask + 1u)

#define ci_fifo2_peek(f)      ((f)->fifo[ci_fifo2_rd_i(f)])
#define ci_fifo2_poke(f)      ((f)->fifo[ci_fifo2_wr_i(f)])
#define ci_fifo2_peekp(f)     ((f)->fifo + ci_fifo2_rd_i(f))
#define ci_fifo2_pokep(f)     ((f)->fifo + ci_fifo2_wr_i(f))
#define ci_fifo2_peek_i(f,i)  ((f)->fifo[CI_FIFO2_M((f), (f)->fifo_rd_i+(i))])
#define ci_fifo2_poke_i(f,i)  ((f)->fifo[CI_FIFO2_M((f), (f)->fifo_wr_i+(i))])

#define ci_fifo2_rd_next(f)   do{ ++(f)->fifo_rd_i; }while(0)
#define ci_fifo2_wr_next(f)   do{ ++(f)->fifo_wr_i; }while(0)
#define ci_fifo2_rd_adv(f, n) do{ (f)->fifo_rd_i += (n); }while(0)
#define ci_fifo2_wr_adv(f, n) do{ (f)->fifo_wr_i += (n); }while(0)

#define ci_fifo2_put(f, v)					\
  do{ ci_fifo2_poke(f) = (v); ci_fifo2_wr_next(f); }while(0)

#define ci_fifo2_get(f, pv)					\
  do{ *(pv) = ci_fifo2_peek(f); ci_fifo2_rd_next(f); }while(0)

/* This macro defines a get function that returns the value. */
#define CI_FIFO2_DEFINE_GET(name, fifo_t, elem_t)	\
  ci_inline elem_t name(fifo_t* f) {			\
    elem_t v = ci_fifo2_peek(f);			\
    ci_fifo2_rd_next(f);				\
    return v;						\
  }

ci_inline unsigned ci_fifo_min(unsigned a, unsigned b)
{ return a < b ? a : b; }

#define ci_fifo2_contig_num(f)                                          \
  ci_fifo_min(ci_fifo2_num(f), (f)->fifo_mask + 1u - ci_fifo2_rd_i(f))

#define ci_fifo2_contig_space(f)                                        \
  ci_fifo_min(ci_fifo2_space(f), (f)->fifo_mask + 1u - ci_fifo2_wr_i(f))

#define ci_fifo2_grow_lock_a(f, s, l, al, fr, prc)		        \
  do{ ci_fifo_grow_lock_helper(&(f)->fifo, sizeof((f)->fifo[0]),	\
			       &(f)->fifo_mask, 1, &(f)->fifo_rd_i,	\
			       &(f)->fifo_wr_i, (s), (l),		\
			       (al), (fr), (prc));			\
      ci_assert(ci_fifo2_valid(f));					\
  }while(0)


/**********************************************************************
 * Private / internals.
 */

extern void ci_fifo_grow_lock_helper(void* pfifo_a, unsigned elemsize,
		     unsigned* size, unsigned size_off, unsigned* rd_i,
		     unsigned* wr_i, unsigned current_size, ci_irqlock_t* lock,
		     void* (*alloc)(size_t), void (*free)(void*), int* prc);


#endif  /* __CI_TOOLS_FIFO_H__ */
/*! \cidoxg_end */
