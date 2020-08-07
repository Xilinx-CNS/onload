/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2019 Xilinx, Inc. */
#ifndef __ONLOAD_ATOMICS_H__
#define __ONLOAD_ATOMICS_H__


ci_inline ci_int32 oo_atomic_read(const oo_atomic_t* a) { return a->n; }
ci_inline void oo_atomic_set(oo_atomic_t* a, ci_int32 v) { a->n = v; }

ci_inline void oo_atomic_inc(oo_atomic_t* a)
{ ci_atomic32_inc(&a->n); }

ci_inline int oo_atomic_dec_and_test(oo_atomic_t* a)
{ return ci_atomic32_dec_and_test(&a->n); }

ci_inline void oo_atomic_add(oo_atomic_t* a, int n)
{ ci_atomic32_add(&a->n, n); }

ci_inline void oo_atomic_and(oo_atomic_t* a, int n)
{ ci_atomic32_and(&a->n, n); }

ci_inline void oo_atomic_or(oo_atomic_t* a, int n)
{ ci_atomic32_or(&a->n, n); }

#endif  /* __ONLOAD_ATOMICS_H__ */
