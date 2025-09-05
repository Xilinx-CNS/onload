/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2019 Xilinx, Inc. */
/****************************************************************************
 * Copyright 2002-2005: Level 5 Networks Inc.
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Maintained by Solarflare Communications
 *  <linux-xen-drivers@solarflare.com>
 *  <onload-dev@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

/*! \cidoxg_include_ci_tools */

#ifndef __CI_TOOLS_DEBUG_H__
#define __CI_TOOLS_DEBUG_H__

#define CI_LOG_E(x)       x              /* errors      */
#define CI_LOG_W(x)       x              /* warnings    */
#define CI_LOG_I(x)       x              /* information */
#define CI_LOG_V(x)       x              /* verbose     */

/* Build time asserts. We paste a counter into the type name so that
 * the macro can be used more than once per file. */
#ifndef CI_BUILD_ASSERT
#define __CI_BUILD_ASSERT_NAME(_x) __CI_BUILD_ASSERT_ILOATHECPP(_x)
#define __CI_BUILD_ASSERT_ILOATHECPP(_x)  __CI_BUILD_ASSERT__ ##_x
#define CI_BUILD_ASSERT(e)\
 typedef char  __CI_BUILD_ASSERT_NAME(__COUNTER__)[(e)?1:-1] \
    __attribute__((unused))
#endif

/* verifies compile time expression is 0 or positive -
 * no-op for runtime expressions */
#if defined(__clang__) || __GNUC__ * 100 + __GNUC_MINOR__ >= 409
#define CI_BUILD_ASSERT_CONSTANT_NON_NEGATIVE(c) \
  do {                                                              \
    char __CI_BUILD_ASSERT_NAME(__LINE__)                           \
         [ __builtin_choose_expr(__builtin_constant_p(c), (c), 0)]  \
         __attribute__((unused));                                   \
  } while(0)
#else
  /* RHEL6 and RHEL7 complain on the code above:
   * error: first argument to ‘__builtin_choose_expr’ not a constant
   */
#define CI_BUILD_ASSERT_CONSTANT_NON_NEGATIVE(c) \
  do {(void) sizeof(struct { int x[(int)(c)]; });} while(0)
#endif

#ifdef _PREFAST_

# define _ci_check(e, f, l)                   __analysis_assume(e)
# define _ci_assert(e, f, l)                  __analysis_assume(e)
# define _ci_assert2(e, x, y, f, l)           __analysis_assume(e)
# define _ci_assert_equal(x, y, f, l)         __analysis_assume((x)==(y))
# define _ci_assert_nequal(x, y, f, l)        __analysis_assume((x)!=(y))
# define _ci_assert_le(x, y, f, l)            __analysis_assume((x)<=(y))
# define _ci_assert_lt(x, y, f, l)            __analysis_assume((x)< (y))
# define _ci_assert_ge(x, y, f, l)            __analysis_assume((x)>=(y))
# define _ci_assert_gt(x, y, f, l)            __analysis_assume((x)> (y))
# define _ci_assert_or(x, y, f, l)            __analysis_assume((x)||(y))
# define _ci_assert_impl(x, y, f, l)          __analysis_assume(!(x) || (y))
# define _ci_assert_equiv(x, y, f, l)         __analysis_assume((!(x)== !(y))
# define _ci_assert_flags(x, y, f, l)         __analysis_assume((((x)&(y)) \
                                                                == (y)))
# define _ci_assert_nflags(x, y, f, l)        __analysis_assume((((x)&(y))==0))
# define _ci_assert_addrs_equal(x, y, f, l)   \
  __analysis_assume(CI_IPX_ADDR_EQ((x),(y)))
# define _ci_assert_equal_msg(x, y, m, f, l)  __analysis_assume((x)==(y))

# define _ci_verify(exp, file, line) \
  do { \
    (void)(exp); \
  } while (0)

# define CI_DEBUG_TRY(exp) \
  do { \
    (void)(exp); \
  } while (0)

# define CI_TRACE(exp,fmt)
# define CI_TRACE_INT(integer)
# define CI_TRACE_INT32(integer)
# define CI_TRACE_INT64(integer)
# define CI_TRACE_UINT(integer)
# define CI_TRACE_UINT32(integer)
# define CI_TRACE_UINT64(integer)
# define CI_TRACE_HEX(integer)
# define CI_TRACE_HEX32(integer)
# define CI_TRACE_HEX64(integer)
# define CI_TRACE_PTR(pointer)
# define CI_TRACE_STRING(string)
# define CI_TRACE_MAC(mac)
# define CI_TRACE_IP(ip_be32)
# define CI_TRACE_ARP(arp_pkt)

#elif defined(NDEBUG)

# define _ci_check(exp, file, line)                  do{}while(0)
# define _ci_assert2(e, x, y, file, line)            do{}while(0)
# define _ci_assert(exp, file, line)                 do{}while(0)
# define _ci_assert_equal(exp1, exp2, file, line)    do{}while(0)
# define _ci_assert_equiv(exp1, exp2, file, line)    do{}while(0)
# define _ci_assert_nequal(exp1, exp2, file, line)   do{}while(0)
# define _ci_assert_le(exp1, exp2, file, line)       do{}while(0)
# define _ci_assert_lt(exp1, exp2, file, line)       do{}while(0)
# define _ci_assert_ge(exp1, exp2, file, line)       do{}while(0)
# define _ci_assert_gt(exp1, exp2, file, line)       do{}while(0)
# define _ci_assert_impl(exp1, exp2, file, line)     do{}while(0)
# define _ci_assert_flags(exp1, exp2, file, line)    do{}while(0)
# define _ci_assert_nflags(exp1, exp2, file, line)   do{}while(0)
# define _ci_assert_addrs_equal(exp1, exp2, file, line) do{}while(0)

# define _ci_verify(exp, file, line) \
  do { \
    (void)(exp); \
  } while (0)

# define CI_DEBUG_TRY(exp) \
  do { \
    (void)(exp); \
  } while (0)

#define CI_TRACE(exp,fmt)
#define CI_TRACE_INT(integer)
#define CI_TRACE_INT32(integer)
#define CI_TRACE_INT64(integer)
#define CI_TRACE_UINT(integer)
#define CI_TRACE_UINT32(integer)
#define CI_TRACE_UINT64(integer)
#define CI_TRACE_HEX(integer)
#define CI_TRACE_HEX32(integer)
#define CI_TRACE_HEX64(integer)
#define CI_TRACE_PTR(pointer)
#define CI_TRACE_STRING(string)
#define CI_TRACE_MAC(mac)
#define CI_TRACE_IP(ip_be32)
#define CI_TRACE_ARP(arp_pkt)

#else

# define _CI_ASSERT_FMT   "\nfrom %s:%d"

# define _ci_check(exp, file, line)                             \
  do {                                                          \
    if (CI_UNLIKELY(!(exp)))                                    \
      ci_warn(("ci_check(%s)" _CI_ASSERT_FMT, #exp,              \
               (file), (line)));                                \
  } while (0)

/*
 * NOTE: ci_fail() emits the file and line where the assert is actually
 *       coded.
 */

# define _ci_assert(exp, file, line)                            \
  do {                                                          \
    if (CI_UNLIKELY(!(exp)))                                    \
      ci_fail(("ci_assert(%s)" _CI_ASSERT_FMT, #exp,		\
               (file), (line)));                                \
  } while (0)

#ifdef __cplusplus
/* __builtin_choose_expr isn't allowed in C++ */
extern "C++" {
template<typename T>
static inline ci_uint64 _ci_force_to_u64(T* v)
{
  return reinterpret_cast<ci_uintptr_t>(v);
}

template<typename T>
static inline ci_uint64 _ci_force_to_u64(T v)
{
  return v;
}
}
#else
/* Make 'x' a 64-bit integer for printing it, in a way that doesn't truncate
 * values and doesn't produce -Wpointer-to-int-cast warnings on 32-bit
 * platforms. The mad ternary is to make it work for both void* and
 * bitfields. */
# define _ci_force_to_u64(x) \
    ((ci_uint64)__builtin_choose_expr(sizeof(1 ? (x) : 0) > 4, \
                                      (x), (ci_uintptr_t)(x)))
#endif

/* NB Split one ci_fail() into ci_log+ci_log+ci_fail.  With one ci_fail
 * and long expression, we can get truncated output */
# define _ci_assert2(e, x, y, file, line)  do {     \
    if(CI_UNLIKELY( ! (e) )) {                      \
      ci_log("ci_assert(%s)", #e);                  \
      ci_log("where [%s=%"CI_PRIx64"]",             \
             #x, _ci_force_to_u64((x)));            \
      ci_log("and [%s=%"CI_PRIx64"]",               \
             #y, _ci_force_to_u64((y)));            \
      ci_log("at %s:%d", __FILE__, __LINE__);       \
      ci_fail(("from %s:%d", (file), (line)));      \
    }                                               \
  } while (0)

# define _ci_assert2_addr(e, x, y, file, line)  do {     \
    if(CI_UNLIKELY( ! (e) )) {                      \
      ci_log("ci_assert(%s)", #e);                  \
      ci_log("where [%s="IPX_FMT"]",               \
             #x, IPX_ARG(AF_IP_L3(x)));             \
      ci_log("and [%s="IPX_FMT"]",                 \
             #y, IPX_ARG(AF_IP_L3(y)));             \
      ci_log("at %s:%d", __FILE__, __LINE__);       \
      ci_fail(("from %s:%d", (file), (line)));      \
    }                                               \
  } while (0)

# define _ci_verify(exp, file, line)                            \
  do {                                                          \
    if (CI_UNLIKELY(!(exp)))                                    \
      ci_fail(("ci_verify(%s)" _CI_ASSERT_FMT, #exp,             \
               (file), (line)));                                \
  } while (0)

# define _ci_assert_equal(x, y, f, l)  _ci_assert2((x)==(y), x, y, (f), (l))
# define _ci_assert_nequal(x, y, f, l) _ci_assert2((x)!=(y), x, y, (f), (l))
# define _ci_assert_le(x, y, f, l)     _ci_assert2((x)<=(y), x, y, (f), (l))
# define _ci_assert_lt(x, y, f, l)     _ci_assert2((x)< (y), x, y, (f), (l))
# define _ci_assert_ge(x, y, f, l)     _ci_assert2((x)>=(y), x, y, (f), (l))
# define _ci_assert_gt(x, y, f, l)     _ci_assert2((x)> (y), x, y, (f), (l))
# define _ci_assert_or(x, y, f, l)     _ci_assert2((x)||(y), x, y, (f), (l))
# define _ci_assert_impl(x, y, f, l)   _ci_assert2(!(x) || (y), x, y, (f), (l))
# define _ci_assert_equiv(x, y, f, l)  _ci_assert2(!(x)== !(y), x, y, (f), (l))
# define _ci_assert_flags(x, y, f, l)  _ci_assert2(((x)&(y))== (y), x, y, \
                                                    (f), (l))
# define _ci_assert_nflags(x, y, f, l) _ci_assert2(((x)&(y))== 0, x, y, \
                                                    (f), (l))
# define _ci_assert_addrs_equal(x, y, f, l) \
   _ci_assert2_addr(CI_IPX_ADDR_EQ((x),(y)), x, y, (f), (l))

#define _ci_assert_equal_msg(exp1, exp2, msg, file, line)       \
  do {                                                          \
    if (CI_UNLIKELY((exp1)!=(exp2)))                            \
      ci_fail(("ci_assert_equal_msg(%s == %s) were "            \
               "(%"CI_PRIx64":%"CI_PRIx64") with msg[%c%c%c%c]" \
               _CI_ASSERT_FMT, #exp1, #exp2,                    \
               _ci_force_to_u64((exp1)),                        \
               _ci_force_to_u64((exp2)),                        \
               (((ci_uint32)msg) >> 24) && 0xff,                \
               (((ci_uint32)msg) >> 16) && 0xff,                \
               (((ci_uint32)msg) >> 8 ) && 0xff,                \
               (((ci_uint32)msg)      ) && 0xff,                \
               (file), (line)));                                \
  } while (0)

# define CI_DEBUG_TRY(exp)  CI_TRY(exp)

#define CI_TRACE(exp,fmt)						\
  ci_log("%s:%d:%s] " #exp "=" fmt,                                     \
         __FILE__, __LINE__, __FUNCTION__, (exp))


#define CI_TRACE_INT(integer)						\
  ci_log("%s:%d:%s] " #integer "=%d",                                   \
         __FILE__, __LINE__, __FUNCTION__, (integer))


#define CI_TRACE_INT32(integer)						\
  ci_log("%s:%d:%s] " #integer "=%d",                                   \
         __FILE__, __LINE__, __FUNCTION__, ((ci_int32)integer))


#define CI_TRACE_INT64(integer)						\
  ci_log("%s:%d:%s] " #integer "=%lld",                                 \
         __FILE__, __LINE__, __FUNCTION__, ((ci_int64)integer))


#define CI_TRACE_UINT(integer)						\
  ci_log("%s:%d:%s] " #integer "=%ud",                                  \
         __FILE__, __LINE__, __FUNCTION__, (integer))


#define CI_TRACE_UINT32(integer)			  	        \
  ci_log("%s:%d:%s] " #integer "=%ud",                                  \
         __FILE__, __LINE__, __FUNCTION__, ((ci_uint32)integer))


#define CI_TRACE_UINT64(integer)			  	        \
  ci_log("%s:%d:%s] " #integer "=%ulld",                                \
         __FILE__, __LINE__, __FUNCTION__, ((ci_uint64)integer))


#define CI_TRACE_HEX(integer)						\
  ci_log("%s:%d:%s] " #integer "=0x%x",                                 \
         __FILE__, __LINE__, __FUNCTION__, (integer))


#define CI_TRACE_HEX32(integer)						\
  ci_log("%s:%d:%s] " #integer "=0x%x",                                 \
         __FILE__, __LINE__, __FUNCTION__, ((ci_uint32)integer))


#define CI_TRACE_HEX64(integer)						\
  ci_log("%s:%d:%s] " #integer "=0x%llx",                               \
         __FILE__, __LINE__, __FUNCTION__, ((ci_uint64)integer))


#define CI_TRACE_PTR(pointer)				                \
  ci_log("%s:%d:%s] " #pointer "=0x%p",                                 \
         __FILE__, __LINE__, __FUNCTION__, (pointer))


#define CI_TRACE_STRING(string)					        \
  ci_log("%s:%d:%s] " #string "=%s",                                    \
         __FILE__, __LINE__, __FUNCTION__, (string))


#define CI_TRACE_MAC(mac)						\
  ci_log("%s:%d:%s] " #mac "=" CI_MAC_PRINTF_FORMAT,                    \
         __FILE__, __LINE__, __FUNCTION__, CI_MAC_PRINTF_ARGS(mac))


#define CI_TRACE_IP(ip_be32)						\
  ci_log("%s:%d:%s] " #ip_be32 "=" CI_IP_PRINTF_FORMAT, __FILE__,       \
         __LINE__, __FUNCTION__, CI_IP_PRINTF_ARGS(&(ip_be32)))


#define CI_TRACE_ARP(arp_pkt)                                           \
  ci_log("%s:%d:%s]\n"CI_ARP_PRINTF_FORMAT,                             \
         __FILE__, __LINE__, __FUNCTION__, CI_ARP_PRINTF_ARGS(arp_pkt))

#endif  /* NDEBUG */

#define ci_check(exp) \
        _ci_check(exp, __FILE__, __LINE__)

#define ci_assert(exp) \
        _ci_assert(exp, __FILE__, __LINE__)

#define ci_verify(exp) \
        _ci_verify(exp, __FILE__, __LINE__)

#define ci_assert_equal(exp1, exp2) \
        _ci_assert_equal(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_equal_msg(exp1, exp2, msg) \
        _ci_assert_equal_msg(exp1, exp2, msg, __FILE__, __LINE__)

#define ci_assert_nequal(exp1, exp2) \
        _ci_assert_nequal(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_le(exp1, exp2) \
        _ci_assert_le(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_lt(exp1, exp2) \
        _ci_assert_lt(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_ge(exp1, exp2) \
        _ci_assert_ge(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_gt(exp1, exp2) \
        _ci_assert_gt(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_impl(exp1, exp2) \
        _ci_assert_impl(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_equiv(exp1, exp2) \
        _ci_assert_equiv(exp1, exp2, __FILE__, __LINE__)

#define ci_assert_flags(val, flags) \
        _ci_assert_flags(val, flags, __FILE__, __LINE__)

#define ci_assert_nflags(val, flags) \
        _ci_assert_nflags(val, flags, __FILE__, __LINE__)

#define ci_assert_addrs_equal(exp1, exp2) \
        _ci_assert_addrs_equal(exp1, exp2, __FILE__, __LINE__)

#ifdef NDEBUG
#define ci_assume(exp)                          \
  do{                                           \
    if( CI_UNLIKELY(!(exp)) )                   \
      ci_unreachable();                         \
  }while(0)

#else
#define ci_assume(exp) ci_assert(exp)
#endif


#define CI_TEST(exp)                            \
  do{                                           \
    if( CI_UNLIKELY(!(exp)) )                   \
      ci_fail(("CI_TEST(%s)", #exp));           \
  }while(0)


/* Report -ve return codes and compare to wanted value */
#define CI_TRY_EQ(exp, _want)			\
  do{						\
    int _trc;					\
    int want = (int)(_want);			\
    _trc=(exp);					\
    if( CI_UNLIKELY(_trc < 0) )			\
      ci_sys_fail(#exp, _trc);			\
    if( CI_UNLIKELY(_trc != (want)) )		\
      ci_fail(("CI_TRY_EQ(('%s')%d != %d)", #exp, _trc, want)); \
  }while(0)


#define CI_TRY(exp)				\
  do{						\
    int _trc;					\
    _trc=(exp);					\
    if( CI_UNLIKELY(_trc < 0) )			\
      ci_sys_fail(#exp, _trc);			\
  }while(0)


#define CI_TRY_RET(exp)							 \
  do{									 \
    int _trc;								 \
    _trc=(exp);								 \
    if( CI_UNLIKELY(_trc < 0) ) {					 \
      ci_log("%s returned %d at %s:%d", #exp, _trc, __FILE__, __LINE__); \
      return _trc;							 \
    }									 \
  }while(0)

#define CI_LOGLEVEL_TRY_RET(logfn, exp)                                    \
  do{									 \
    int _trc;								 \
    _trc=(exp);								 \
    if( CI_UNLIKELY(_trc < 0) ) {					 \
      logfn (ci_log("%s returned %d at %s:%d", #exp, _trc, __FILE__, __LINE__)); \
      return _trc;							 \
    }									 \
  }while(0)


#define CI_SOCK_TRY(exp)			\
  do{						\
    ci_sock_err_t _trc;				\
    _trc=(exp);					\
    if( CI_UNLIKELY(!ci_sock_errok(_trc)) )	\
      ci_sys_fail(#exp, _trc.val);		\
  }while(0)


#define CI_SOCK_TRY_RET(exp)						     \
  do{									     \
    ci_sock_err_t _trc;							     \
    _trc=(exp);								     \
    if( CI_UNLIKELY(!ci_sock_errok(_trc)) ) {		  		     \
      ci_log("%s returned %d at %s:%d", #exp, _trc.val, __FILE__, __LINE__); \
      return ci_sock_errcode(_trc);					     \
    }									     \
  }while(0)


#define CI_SOCK_TRY_SOCK_RET(exp)					     \
  do{									     \
    ci_sock_err_t _trc;							     \
    _trc=(exp);								     \
    if( CI_UNLIKELY(!ci_sock_errok(_trc)) ) {		  		     \
      ci_log("%s returned %d at %s:%d", #exp, _trc.val, __FILE__, __LINE__); \
      return _trc;							     \
    }									     \
  }while(0)

#endif  /* __CI_TOOLS_DEBUG_H__ */

/*! \cidoxg_end */
