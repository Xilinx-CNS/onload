/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2015-2019 Xilinx, Inc. */

#ifndef __CI_TOOLS_LOG2_H__
#define __CI_TOOLS_LOG2_H__

/**********************************************************************
 * powers of two
 **********************************************************************/ 

/* The smallest [o] such that (1u << o) >= n. */

ci_inline unsigned ci_log2_ge(unsigned long n, unsigned min_order) {
  unsigned order = min_order;
  while( (1ul << order) < n )  ++order;
  return order;
}


/* The smallest [o] such that (1u << o) > n. */

ci_inline unsigned ci_log2_g(unsigned long n, unsigned min_order) {
  unsigned order = min_order;
  while( (1ul << order) <= n )  ++order;
  return order;
}


/* The largest [o] such that (1u << o) <= n.  Requires n > 0. */

ci_inline unsigned ci_log2_le(unsigned long n) {
  unsigned order = 1;
  while( (1ul << order) <= n )  ++order;
  return (order - 1);
}

ci_inline unsigned long
ci_pow2(unsigned order) {
  return (1ul << order);
}

#define CI_IS_POW2(x)  ((x) && ! ((x) & ((x) - 1)))


#endif /* __CI_TOOLS_LOG2_H__ */
