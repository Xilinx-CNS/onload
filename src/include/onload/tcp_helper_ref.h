/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_TCP_HELPER_REF_H__
#define __ONLOAD_TCP_HELPER_REF_H__

enum oo_thr_ref_type {
  /* Invalid.  In a sense, no refcount is taken on this level. */
  OO_THR_REF_NONE = -1,

  /* References taken for internal purposes */
  OO_THR_REF_BASE = 0,
  /* References taken for a UL process (i.e. struct file) */
  OO_THR_REF_FILE = 1,
  /* References taken for a user application (i.e. UL which is not
   * stackdump, tcpdump, helper, etc) */
  OO_THR_REF_APP = 2,

  /* No more level exists. */
  OO_THR_REF_INFTY = 3
};

/* A tcp helper reference count is a collection of 3 atomic 32-bit
 * reference counts.  A high-level reference count is less then or equal to
 * a low-level one.
 *
 * I.e. to get an app-level refcount, one must take an internal refcount
 * first, file refcount next, and app refcount last.  It is forbidden to
 * increment a refcount from 0.
 */
typedef ci_uint32 oo_thr_ref_t[OO_THR_REF_INFTY];

/* When logging, users are probably interested in deltas between refcounts
 * only.
 */
#define OO_THR_REF_FMT "app=%d file=%d base=%x"
#define OO_THR_REF_ARG(ref) \
  (ref)[OO_THR_REF_APP], (ref)[OO_THR_REF_FILE] - (ref)[OO_THR_REF_APP], \
  (ref)[OO_THR_REF_BASE] - (ref)[OO_THR_REF_FILE]

typedef void (*oo_thr_ref_release_fn)(oo_thr_ref_t ref);

/* oo_thr_ref_release[type] handles the release of the last refcount of
 * this particular type.
 */
extern oo_thr_ref_release_fn oo_thr_ref_release[OO_THR_REF_INFTY];


/* Try to get a refcount of a particular type.
 *
 * Base refcount is typically taken by efab_thr_table_lookup().
 *
 * File refcount must be
 * taken before creating a struct file referring to this tcp helper.
 *
 * If the process does not show itself as an "Onload service", then an
 * app-level refcount should be taken and appropriate mark in ci_private_t
 * created.
 */
static inline int
oo_thr_ref_get_one(oo_thr_ref_t ref,
                   enum oo_thr_ref_type type) OO_MUST_CHECK_RET;
static inline int
oo_thr_ref_get_one(oo_thr_ref_t ref, enum oo_thr_ref_type type)
{
  ci_uint32 val;

  /* It is tempting to write something like
   * ci_assert_le(ref[OO_THR_REF_APP], ref[OO_THR_REF_BASE]);
   * but there is no possible way to get synchronous values,
   * so this assertion is racy.
   */

  do {
    val = OO_ACCESS_ONCE(ref[type]);
    if( val == 0 )
      return -EBUSY;

    /* Integer overflow must be checked for the base recount only;
     * others get it automatically because any code path takes the
     * baserefcount first. */
    if( type == OO_THR_REF_BASE && ( (val + 1) & (1 << 31) ) ) {
      ci_assert(0);
      return -ETOOMANYREFS;
    }
    ci_assert_nflags(val + 1, 1 << 31);

  } while( ci_cas32u_fail(&ref[type], val, val + 1) );

  return 0;
}

/* Drop a refcount of this particular type. */
static inline void
oo_thr_ref_drop_one(oo_thr_ref_t ref, enum oo_thr_ref_type type)
{
  if( ci_atomic32_dec_and_test(&ref[type]) )
    oo_thr_ref_release[type](ref);
}

/* Get a full stack of refcounts up to type. */
static inline int
oo_thr_ref_get(oo_thr_ref_t ref, enum oo_thr_ref_type type) OO_MUST_CHECK_RET;
static inline int
oo_thr_ref_get(oo_thr_ref_t ref, enum oo_thr_ref_type type)
{
  enum oo_thr_ref_type t;
  int rc = 0;

  ci_assert_lt(OO_THR_REF_NONE, type);

  for( t = OO_THR_REF_NONE + 1; t <= type; t++ ) {
    if( (rc = oo_thr_ref_get_one(ref, t)) != 0 )
      break;
  }
  if( rc == 0)
    return 0;

  /* The <t> level failed; we should release all the previous ones. */
  for( t--; t > OO_THR_REF_NONE; t-- )
    oo_thr_ref_drop_one(ref, t);

  return rc;
}

/* Drop all the refcounts, starting from type. */
static inline void
oo_thr_ref_drop(oo_thr_ref_t ref, enum oo_thr_ref_type type)
{
  enum oo_thr_ref_type t;

  ci_assert_gt(type, OO_THR_REF_NONE);

  for( t = type; t > OO_THR_REF_NONE; t-- )
    oo_thr_ref_drop_one(ref, t);
}

/* Checks whether a particular refcount is zero.
 *
 * It is sometimes useful to think that OO_THR_REF_NONE is always
 * non-zero, and OO_THR_REF_INFTY is always zero.  This idea matches to
 * the monotonic nature of this stack of refcounts.
 */
static inline bool
oo_thr_ref_is_zero(oo_thr_ref_t ref, enum oo_thr_ref_type type)
{
  ci_assert_ge(type, OO_THR_REF_NONE);
  ci_assert_le(type, OO_THR_REF_INFTY);

  if( type == OO_THR_REF_NONE )
    return false;
  else if( type == OO_THR_REF_INFTY )
    return true;
  else
    return ref[type] == 0;
}
#endif
