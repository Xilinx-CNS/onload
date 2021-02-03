/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2014-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  as
**  \brief  Dump state of all Onload stacks in json format to stdout.
**   \date  2014/12/01
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

#define _GNU_SOURCE

#include <ci/internal/ip.h>
#include <ci/efhw/common.h>
#include <onload/ioctl.h>
#include <onload/driveraccess.h>
#include <onload/debug_intf.h>
#include <onload/version.h>

#include "ftl_defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "../ip/sockbuf_filter.h"
#include <ci/internal/more_stats.h>
#include "orm_json_lib.h"


/* output formats for the datatypes we support */
#define ci_uint64_fmt   "\"%llu\"" /* use string 
                                      as JSON can't cope with 64-bit int */
#define uint64_t_fmt    "\"%llu\""
#define ci_uint32_fmt   "%u"
#define uint32_t_fmt    "%u"
#define ci_uint16_fmt   "%u"
#define ci_uint8_fmt    "%u"
#define unsigned_fmt    "%u"
#define ci_int64_fmt    "\"%lld\""
#define ci_int32_fmt    "%d"
#define ci_int16_fmt    "%d"
#define ci_int8_fmt     "%d"
#define int_fmt         "%d"
#define ci_iptime_t_fmt "%u"
#define ef_eventq_ptr_fmt "%u"
#define CI_IP_STATS_TYPE_fmt "%u"
#define ci_iptime_callback_param_t_fmt "%u"
#define char_fmt        "%d"
#define ci_iptime_callback_fn_t_fmt "%u"
#define __TIME_TYPE___fmt "%u"
#define uid_t_fmt "%u"
#define ci_verlock_value_t_fmt "%u"
#define ci_ip_addr_t_fmt "%u"
#define ci_mtu_t_fmt "%u"
#define ci_ifid_t_fmt "%d"
#define cicp_hwport_mask_t_fmt "%u"
#define cicp_encap_t_fmt "%u"
#define ci_hwport_id_t_fmt "%u"
#define ci_pkt_priority_t_fmt "%u"
#define oo_p_fmt "%d"
#define oo_pkt_p_fmt "%d"
#define oo_sp_fmt "\"%p\"" /* pointer - typically 64 bit */
#define oo_waitable_lock_fmt "%u"
#define oo_atomic_t_fmt "%u"
#define ci_string256_fmt "\"%s\""


#define LOG(...) fprintf(stderr, __VA_ARGS__)

/**********************************************************/
/* Manage stack mappings */
/**********************************************************/

struct orm_stack {
  ci_netif os_ni;
  int      os_id;
};

typedef struct {
  struct orm_stack** stacks;
  int n_stacks;
} orm_state_t;


static int orm_map_stack(orm_state_t* state, unsigned stack_id)
{
  int rc;
  struct orm_stack** new_stacks =
    realloc(state->stacks, (state->n_stacks + 1) * sizeof(*state->stacks));

  if( ! new_stacks ) {
    LOG("ERROR: orm_stacks failed at %s:%d\n", __FILE__, __LINE__);
    return -ENODEV;
  }

  struct orm_stack* orm_stack = calloc(1, sizeof(*orm_stack));

  if( ! orm_stack ) {
    LOG("ERROR: orm_stack failed at %s:%d\n", __FILE__, __LINE__);
    return -ENODEV;
  }

  state->stacks = new_stacks;
  state->stacks[state->n_stacks++] = orm_stack;
  orm_stack->os_id = stack_id;
  if( (rc = ci_netif_restore_id(&orm_stack->os_ni, stack_id, true)) != 0 )
    LOG("%s: Fail: ci_netif_restore_id(%d)=%d\n", __func__,
            stack_id, rc);
  return rc;
}


static int orm_map_stacks(orm_state_t* state)
{
  int rc, i;
  oo_fd fd;
  if( (rc = oo_fd_open(&fd)) != 0 ) {
    LOG("%s: Fail: oo_fd_open()=%d.  Onload drivers loaded?",
            __func__, rc);
    return rc;
  }

  ci_netif_info_t info;
  memset(&info, 0, sizeof(ci_netif_info_t));
  i = 0;
  while( i >= 0 ) {
    info.ni_index = i;
    info.ni_orphan = 0;
    info.ni_subop = CI_DBG_NETIF_INFO_GET_NEXT_NETIF;
    if( (rc = oo_ioctl(fd, OO_IOC_DBG_GET_STACK_INFO, &info)) != 0 ) {
      LOG("%s: Fail: oo_ioctl(OO_IOC_DBG_GET_STACK_INFO)=%d.",
              __func__, rc);
      goto out;
    }
    if( info.ni_exists ) {
      int stack_id = info.ni_index;
      if( (rc = orm_map_stack(state, stack_id)) != 0 )
        goto out;
    }
    else if( info.ni_no_perms_exists ) {
      LOG("User %d:%d cannot access full details of stack %d(%s) "
              "owned by %d:%d share_with=%d\n", (int) getuid(), (int) geteuid(),
              info.ni_no_perms_id, info.ni_no_perms_name,
              (int) info.ni_no_perms_uid, (int) info.ni_no_perms_euid,
              info.ni_no_perms_share_with);
    }
    i = info.u.ni_next_ni.index;
  }

 out:
  oo_fd_close(fd);
  return rc;
}


static void orm_unmap_stacks(orm_state_t* state)
{
  int i;
  for( i = 0; i < state->n_stacks; ++i ) {
    struct orm_stack* orm_stack = state->stacks[i];
    free(orm_stack);
  }
  free(state->stacks);
  state->stacks = NULL;
}


/**********************************************************/
/* dump_buf mgmt */
/**********************************************************/

struct dump_buf {
  FILE* f;
  int   pending_comma;
  char  buf[1024];
  size_t buflev;
  int   rc;
};

static __thread struct dump_buf db;


static void dump_buf_init(void)
{
  db.f = NULL;
  db.pending_comma = 0;
  db.buflev = 0;
  db.rc = 0;
}


static void __dump_buf_flush_buf(void)
{
  if( db.buflev ) {
    fwrite_unlocked(db.buf, 1, db.buflev, db.f);
    db.buflev = 0;
  }
}


static inline void __dump_buf_cat0(const char* buf, int len)
{
  if( db.buflev + len > sizeof(db.buf) )
    __dump_buf_flush_buf();
  if( len >= sizeof(db.buf) )
    fwrite_unlocked(buf, 1, len, db.f);
  else {
    if( len == 1 )    /* getting in and out of memcpy takes a long time */
      db.buf[db.buflev] = *buf;
    else
      memcpy(db.buf + db.buflev, buf, len);
    db.buflev += len;
  }
}


/* force inline because the string is almost always a compile-time constant
 * and hence the strlen can be elided */
__attribute__((always_inline))
static inline void dump_buf_literal(const char* str)
{
  if( db.pending_comma ) {
    db.pending_comma = 0;
    __dump_buf_cat0(",", 1);
  }
  __dump_buf_cat0(str, strlen(str));
}


__attribute__((always_inline))
static inline void dump_buf_literal_comma(const char* str)
{
  dump_buf_literal(str);
  db.pending_comma = 1;
}


__attribute__((always_inline))
static inline void dump_buf_label(const char* prefix, const char* label,
                                    const char* suffix)
{
  dump_buf_literal(prefix);
  dump_buf_literal(label);
  dump_buf_literal(suffix);
}


static void dump_buf_catv(const char* fmt, va_list va)
{
  int rc;

  if( db.pending_comma ) {
    db.pending_comma = 0;
    __dump_buf_cat0(",", 1);
  }
  __dump_buf_flush_buf();
  rc = vfprintf(db.f, fmt, va);
  if( rc < 0 && ! db.rc ) {
    db.rc = -errno;
    LOG("ERROR: at %s:%d\n", __FILE__, __LINE__);
    LOG("ERROR: rc=%d errno=%d (%s)\n",
            rc, errno, strerror(errno));
  }
}


static void dump_buf_cat(const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  dump_buf_catv(fmt, va);
  va_end(va);
}

static void dump_buf_cat_comma(const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  dump_buf_catv(fmt, va);
  va_end(va);
  db.pending_comma = 1;
}

static const char hex_digits[] = "0123456789ABCDEF";

/* Append to dump_buf a correctly-quoted and -escaped string literal */
static void dump_buf_str(const char *str)
{
  const char* begin = str;
  const char* p;
  __dump_buf_cat0("\"", 1);
  for( p = str; *p; ++p ) {
    if( *p == '"' || *p == '\\' || *p < ' ' ) {
      char esc[6];
      int len = 2;
      __dump_buf_cat0(begin, p - begin);
      esc[0] = '\\';
      switch( *p ) {
        case '"':  esc[1] = '"'; break;
        case '\\': esc[1] = '\\'; break;
        case '\b': esc[1] = 'b'; break;
        case '\f': esc[1] = 'f'; break;
        case '\n': esc[1] = 'n'; break;
        case '\r': esc[1] = 'r'; break;
        case '\t': esc[1] = 't'; break;
        default:
          /* JSON does not officially support \x00 encoding */
          esc[1] = 'u';
          esc[2] = '0';
          esc[3] = '0';
          esc[4] = hex_digits[(*p >> 4) & 15];
          esc[5] = hex_digits[*p & 15];
          len = 6;
          break;
      }
      __dump_buf_cat0(esc, len);
      begin = p + 1;
    }
  }
  __dump_buf_cat0(begin, p - begin);
  __dump_buf_cat0("\"", 1);
}

static void dump_buf_cleanup(void)
{
  db.pending_comma = 0;
}


/**********************************************************/
/* Dump ci_netif_opts */
/**********************************************************/

static int orm_oo_opts_dump(ci_netif* ni)
{
  ci_netif_config_opts* opts = &ni->state->opts;
  dump_buf_literal("\"opts\":{");

#ifdef NDEBUG
  dump_buf_literal_comma("\"NDEBUG\":1");
#else
  dump_buf_literal_comma("\"NDEBUG\":0");
#endif


#undef CI_CFG_OPTFILE_VERSION
#undef CI_CFG_OPT
#undef CI_CFG_STR_OPT
#undef CI_CFG_OPTGROUP

#define CI_CFG_OPTFILE_VERSION(version)
#define CI_CFG_OPTGROUP(group, category, expertise)
#define CI_CFG_OPT(env, name, type, doc, bits, group, default, min, max, presentation) \
  if( strlen(env) != 0 ) {                                              \
    dump_buf_cat_comma("\"%s\":" type##_fmt, env, opts->name);          \
  }
#define CI_CFG_STR_OPT CI_CFG_OPT

#include <ci/internal/opts_netif_def.h>

  dump_buf_cleanup();
  dump_buf_literal_comma("}");
  return 0;
}

/**********************************************************/
/* Dump ci_netif_stats */
/**********************************************************/

#define OO_STAT(desc, type, name, kind)                                 \
  dump_buf_cat_comma("\"%s\":" type##_fmt, #name, stats->name);

static int orm_oo_stats_dump(const char* label, const ci_netif_stats* stats)
{
  dump_buf_label("\"", label, "\":{");
#include <ci/internal/stats_def.h>
  dump_buf_cleanup();
  dump_buf_literal_comma("}");
  return 0;
}


static void orm_dump_struct_ci_netif_stats(char* label, const ci_netif_stats* stats, int flags)
{
  if( ~flags & ORM_OUTPUT_STACK )
    return;
  orm_oo_stats_dump(label, stats);
}


static int orm_oo_more_stats_dump(const char* label, const more_stats_t* stats)
{
  dump_buf_label("\"", label, "\":{");
#include <ci/internal/more_stats_def.h>
  dump_buf_cleanup();
  dump_buf_literal_comma("}");
  return 0;
}


static int orm_oo_tcp_stats_count_dump(const char* label, const ci_tcp_stats_count* stats)
{
  dump_buf_label("\"", label, "\":{");
#include <ci/internal/tcp_stats_count_def.h>
  dump_buf_cleanup();
  dump_buf_literal_comma("}");
  return 0;
}


static void orm_dump_struct_ci_tcp_stats_count(char* label, const ci_tcp_stats_count* stats, int flags)
{
  if( ~flags & ORM_OUTPUT_STACK )
    return;
  orm_oo_tcp_stats_count_dump(label, stats);
}


static int orm_oo_tcp_ext_stats_count_dump(const char* label, const ci_tcp_ext_stats_count* stats)
{
  dump_buf_label("\"", label, "\":{");
#include <ci/internal/tcp_ext_stats_count_def.h>
  dump_buf_cleanup();
  dump_buf_literal_comma("}");
  return 0;
}


static void orm_dump_struct_ci_tcp_ext_stats_count(char* label, const ci_tcp_ext_stats_count* stats, int flags)
{
  if( ~flags & ORM_OUTPUT_STACK )
    return;
  orm_oo_tcp_ext_stats_count_dump(label, stats);
}


#undef  OO_STAT


#define OO_STAT(desc, type, name, kind)                                 \
  stats_sum->name += stats->name;

static void orm_oo_stats_sum(ci_netif_stats* stats_sum, ci_netif_stats* stats)
{
#include <ci/internal/stats_def.h>
}


static void orm_oo_more_stats_sum(more_stats_t* stats_sum, more_stats_t* stats)
{
#include <ci/internal/more_stats_def.h>
}

#undef OO_STAT

/* Metadata contains description of the stats.
 * The format is Performance-Co-Pilot compilant
 * The 'pointer' paths refer to summary statistics only.
 */
#define OO_STAT(desc, datatype, name, kind)     \
  OO_STAT_##kind(name, (desc))
#define OO_STAT_count_zero(name, desc) /* ignore always 0 counters */
#define OO_STAT_count(name, desc)  \
  dump_buf_cat( "{"                \
"\"name\":\"%s%s%s\","             \
"\"pointer\":\"%s/%s/%s\","        \
"\"type\":\"integer\","            \
"\"units\":\"count\","             \
"\"semantics\":\"counter\","       \
"\"description\":",                \
  (cfg_flat ? "" : OO_STAT_key), (cfg_flat ? "": "."), #name, xpath, \
   OO_STAT_key, #name);            \
  dump_buf_str(desc);              \
  dump_buf_literal_comma("}");

#define OO_STAT_val(name, desc)    \
  dump_buf_cat( "{"                \
"\"name\":\"%s%s%s\","             \
"\"pointer\":\"%s/%s/%s\","        \
"\"type\":\"integer\","            \
"\"semantics\":\"instant\","       \
"\"description\":",                \
  (cfg_flat ? "" : OO_STAT_key), (cfg_flat ? "": "."), #name, xpath, \
   OO_STAT_key, #name);      \
  dump_buf_str(desc);              \
  dump_buf_literal_comma("}");

static int orm_oo_stats_meta_dump(bool cfg_flat, const char* xpath)
{
#define OO_STAT_key "stats"
#include <ci/internal/stats_def.h>
#undef OO_STAT_key
  return 0;
}


static int orm_oo_more_stats_meta_dump(bool cfg_flat, const char* xpath)
{
#define OO_STAT_key "more_stats"
#include <ci/internal/more_stats_def.h>
#undef OO_STAT_key
  return 0;
}


static int orm_oo_tcp_stats_count_meta_dump(bool cfg_flat, const char* xpath)
{
#define OO_STAT_key "tcp_stats"
#include <ci/internal/tcp_stats_count_def.h>
#undef OO_STAT_key
  return 0;
}


static int orm_oo_tcp_ext_stats_count_meta_dump(bool cfg_flat, const char* xpath)
{
#define OO_STAT_key "tcp_ext_stats"
#include <ci/internal/tcp_ext_stats_count_def.h>
#undef OO_STAT_key
  return 0;
}


#undef  OO_STAT
#undef  OO_STAT_count_zero
#undef  OO_STAT_count
#undef  OO_STAT_val


/*********************************************************/
/* Dump most structs using ftl definitions */
/*********************************************************/

static void dump_buf_uint_comma(uint64_t value)
{
  char buf[21];
  int pos = sizeof(buf);
  do {
    buf[--pos] = '0' + value % 10;
    value /= 10;
  } while( value );
  __dump_buf_cat0(buf + pos, sizeof(buf) - pos);
  db.pending_comma = 1;
}

static void dump_buf_int_comma(int64_t value)
{
  if( value >= 0 )
    dump_buf_uint_comma(value);
  else {
    dump_buf_literal("-");
    dump_buf_uint_comma(-value);
  }
}

static void dump_buf_quoted_uint_comma(uint64_t value)
{
  __dump_buf_cat0("\"", 1);
  dump_buf_uint_comma(value);
  __dump_buf_cat0("\"", 1);
}

#if 0
/* Unused for now, but looks potentially useful */
static void dump_buf_int_comma_oo_sp(oo_sp value)
{
  dump_buf_cat_comma("\"%p\"", value);
}
#endif

#define REDISPATCH_INT_DUMP(from, to, member) \
  static void dump_buf_int_comma_##from(from value)         \
  {                                                         \
    dump_buf_##to##_comma(value member);               \
  }

REDISPATCH_INT_DUMP(ci_uint64, quoted_uint, )
REDISPATCH_INT_DUMP(uint64_t, quoted_uint, )
REDISPATCH_INT_DUMP(ci_uint32, uint, )
REDISPATCH_INT_DUMP(ef_eventq_ptr, uint, )
REDISPATCH_INT_DUMP(ci_iptime_t, uint, )
REDISPATCH_INT_DUMP(unsigned, uint, )
REDISPATCH_INT_DUMP(oo_atomic_t, uint, .n)
REDISPATCH_INT_DUMP(ci_pkt_priority_t, uint, )
REDISPATCH_INT_DUMP(ci_hwport_id_t, uint, )
REDISPATCH_INT_DUMP(cicp_hwport_mask_t, uint, )
REDISPATCH_INT_DUMP(cicp_encap_t, uint, .type)  /* NB: misdeclared as int */
REDISPATCH_INT_DUMP(oo_waitable_lock, uint, .wl_val)
REDISPATCH_INT_DUMP(CI_IP_STATS_TYPE, uint, )
REDISPATCH_INT_DUMP(__TIME_TYPE__, uint, )
REDISPATCH_INT_DUMP(uid_t, uint, )
REDISPATCH_INT_DUMP(ci_mtu_t, uint, )
REDISPATCH_INT_DUMP(ci_ifid_t, uint, )
REDISPATCH_INT_DUMP(ci_iptime_callback_fn_t, uint, )
REDISPATCH_INT_DUMP(ci_uint16, uint, )
REDISPATCH_INT_DUMP(ci_uint8, uint, )

REDISPATCH_INT_DUMP(ci_int32, int, )
REDISPATCH_INT_DUMP(int, int, )
REDISPATCH_INT_DUMP(oo_p, int, )
#if CI_CFG_INJECT_PACKETS
REDISPATCH_INT_DUMP(oo_pkt_p, int, )
#endif
REDISPATCH_INT_DUMP(ci_int16, int, )
REDISPATCH_INT_DUMP(ci_int8, int, )

/* manually create as config opts are defined separately
   TODO consider reordering */
static void orm_dump_struct_ci_netif_config_opts(char* label, ci_netif_config_opts* ignore, int flags)
{
  /* could fill in later if needed */
}

#undef FTL_TSTRUCT_BEGIN
#undef FTL_TUNION_BEGIN
#undef FTL_TFIELD_INT
#undef FTL_TFIELD_CONSTINT
#undef FTL_TFIELD_STRUCT
#undef FTL_TSTRUCT_END
#undef FTL_TUNION_END
#undef FTL_TFIELD_ARRAYOFINT
#undef FTL_TFIELD_ARRAYOFSTRUCT
#undef FTL_TFIELD_KINT
#undef FTL_TFIELD_ANON_STRUCT
#undef FTL_TFIELD_ANON_UNION
#undef FTL_TFIELD_ANON_ARRAYOFSTRUCT

#undef FTL_DECLARE

#define FTL_TSTRUCT_BEGIN(ctx, name, tag)                               \
  static void orm_dump_struct_body_##name(name*, int);                  \
  static void __attribute__((unused))                                   \
  orm_dump_struct_##name(const char* label, name* stats, int output_flags) \
  {                                                                     \
    dump_buf_literal("\"");                                             \
    dump_buf_literal(label);                                            \
    dump_buf_literal("\":");                                            \
    orm_dump_struct_body_##name(stats, output_flags);                   \
  }                                                                     \
  static void orm_dump_struct_body_##name(name* stats, int output_flags) \
  {                                                                     \
    dump_buf_literal("{");                                              \
  /* don't close block here as rest of function is defined by macros
     below. FTL_TSTRUCT_END generates the corresponding closing brace */

#define FTL_TUNION_BEGIN(ctx, name, tag)        \
  FTL_TSTRUCT_BEGIN(ctx, name, tag)

#define FTL_TFIELD_INT(ctx, type, field_name, display_flags) \
  if (output_flags & display_flags) {                                   \
    dump_buf_literal("\"" #field_name "\":");                           \
    dump_buf_int_comma_##type(stats->field_name);                       \
  }

#define FTL_TFIELD_CONSTINT(ctx, type, field_name, display_flags) \
  FTL_TFIELD_INT(ctx, type, field_name, display_flags)

#define FTL_TFIELD_KINT(ctx, type, field_name, display_flags) \
  FTL_TFIELD_INT(ctx, type, field_name, display_flags)

#define FTL_TFIELD_IPADDR(ctx, uname, flags) \
    FTL_TFIELD_INTBE(ctx, ci_uint32, uname, "\"" OOF_IP4 "\"", OOFA_IP4, flags)

#define FTL_TFIELD_IPXADDR(ctx, uname, flags) \
    FTL_TFIELD_INT2(ctx, ci_addr_t, uname, "\"" OOF_IPX "\"", OOFA_IPX_L3, flags)

#define FTL_TFIELD_PORT(ctx, name, flags) \
    FTL_TFIELD_INTBE(ctx, ci_uint16, name, OOF_PORT, OOFA_PORT, flags) \

#define FTL_TFIELD_INTBE16(ctx, name, flags) \
    FTL_TFIELD_INTBE(ctx, ci_uint16, name, "%u", (unsigned) CI_BSWAP_BE16, flags)

#define FTL_TFIELD_INTBE32(ctx, name, flags) \
    FTL_TFIELD_INTBE(ctx, ci_uint32, name, "%u", (unsigned) CI_BSWAP_BE32, flags)

/* the _INT2 variant is to cope for specials like IP addresses which are
   stored in one format, but need converting to another format for output */
#define FTL_TFIELD_INT2(ctx, type, field_name, format_string, conversion_function, display_flags) \
  if (output_flags & display_flags) {                                   \
    dump_buf_literal("\"" #field_name "\":");                           \
    dump_buf_cat_comma(format_string, conversion_function(stats->field_name)); \
  }

/* the _INT3 comparing to _INT2 allows to truncate display name e.g. to remove suffix */
#define FTL_TFIELD_INT3(ctx, type, field_name, name_display_len, format_string, conversion_function, display_flags) \
  if (output_flags & display_flags) {                                   \
    dump_buf_cat("\"%.*s\":", name_display_len, #field_name);                              \
    dump_buf_cat_comma(format_string, conversion_function(stats->field_name)); \
  }

/* function that truncates _bexx suffixes automatically from the display field name */
#define FTL_TFIELD_INTBE(ctx, type, field_name, format_string, conversion_function, display_flags) \
  { \
    int new_len = strlen(#field_name); \
    if( new_len > 5 && ( \
        strcmp(#field_name + new_len - 5, "_be32") == 0 || \
        strcmp(#field_name + new_len - 5, "_be16") == 0) ) \
      new_len -= 5; \
    FTL_TFIELD_INT3(ctx, type, field_name, new_len, format_string, conversion_function, display_flags) \
  }

#define FTL_TFIELD_STRUCT(ctx, type, field_name, display_flags) \
  if (output_flags & display_flags) {                                   \
    orm_dump_struct_##type(#field_name, &stats->field_name, output_flags); \
  }

#define FTL_TFIELD_ARRAYOFINT(ctx, type, field_name, len, display_flags) \
  if (output_flags & display_flags) {                                   \
    {                                                                   \
      int i;                                                            \
      dump_buf_literal("\"" #field_name "\":");                         \
      dump_buf_literal("[");                                            \
      for( i = 0; i < (len); ++i ) {                                    \
        dump_buf_cat_comma(type##_fmt, stats->field_name[i]);           \
      }                                                                 \
      dump_buf_cleanup();                                               \
      dump_buf_literal_comma("]");                                      \
    }                                                                   \
  }

#define FTL_TFIELD_SSTR(ctx, field_name, display_flags)    \
  if (output_flags & display_flags) {                                   \
    dump_buf_literal("\"" #field_name "\":");                           \
    dump_buf_cat_comma("\"%.*s\"", sizeof(stats->field_name),           \
                               stats->field_name);                      \
  }

#define FTL_TFIELD_ARRAYOFSTRUCT(ctx, type, field_name, len, display_flags, field_cond) \
  if (output_flags & display_flags) {                                   \
    {                                                                   \
      int i;                                                            \
      dump_buf_literal("\"" #field_name "\":[");                        \
      for( i = 0; i < (len); ++i ) {                                    \
        if( field_cond ) \
          orm_dump_struct_body_##type(&stats->field_name[i], output_flags); \
       else \
          dump_buf_literal_comma("{}");                                 \
       } \
      dump_buf_cleanup();                                               \
      dump_buf_literal_comma("]");                                      \
    }                                                                   \
  }

#define FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, field_name, display_flags) \
     if (output_flags & display_flags) {                                \
      dump_buf_literal("\"" #field_name "\":{");

#define FTL_TFIELD_ANON_STRUCT(ctx, type, field_name, child) \
      dump_buf_literal("\"" #child "\":");                              \
      dump_buf_cat_comma(type##_fmt, stats->field_name.child);

#define FTL_TFIELD_ANON_STRUCT_END(ctx, field_name)        \
      dump_buf_cleanup();                                               \
      dump_buf_literal_comma("}");                                      \
    }

/* anon union not yet implemented (only used for TCP/UDP headers) */
#define FTL_TFIELD_ANON_UNION_BEGIN(ctx, field_name, display_flags)
#define FTL_TFIELD_ANON_UNION(ctx, type, field_name, child)
#define FTL_TFIELD_ANON_UNION_END(ctx, field_name)

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT_BEGIN(ctx, field_name, len, display_flags) \
    if (output_flags & display_flags) {                                 \
      int i;                                                            \
      dump_buf_literal("\"" #field_name "\":[");                        \
      for( i = 0; i < (len); ++i ) {                                    \
        dump_buf_literal("{");

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT(ctx, type, field_name, child, len) \
        dump_buf_literal("\"" #child "\":");                             \
        dump_buf_cat_comma(type##_fmt, stats->field_name[i].child);

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT_END(ctx, field_name, len) \
        dump_buf_cleanup();                                             \
        dump_buf_literal_comma("}");                                    \
      }                                                                 \
      dump_buf_cleanup();                                               \
      dump_buf_literal_comma("]");                                      \
    }

#define FTL_TSTRUCT_END(ctx)                                            \
    dump_buf_cleanup();                                                 \
    dump_buf_literal_comma("}");                                        \
  }

#define FTL_TUNION_END(ctx)                                             \
  FTL_TSTRUCT_END(ctx)

#define FTL_DECLARE(a) a(DECL)

#include "ftl_decls.h"


static void orm_waitable_dump(ci_netif* ni, const char* sock_type,
                              int output_flags, const sockbuf_filter_t* sft)
{
  ci_netif_state* ns = ni->state;
  unsigned id;

  dump_buf_label("\"", sock_type, "\":{");
  for( id = 0; id < ns->n_ep_bufs; ++id ) {
    citp_waitable_obj* wo = ID_TO_WAITABLE_OBJ(ni, id);
    if( wo->waitable.state != CI_TCP_STATE_FREE ) {
      citp_waitable* w = &wo->waitable;

      if( (strcmp(sock_type, "tcp_listen") == 0) &&
          (w->state == CI_TCP_LISTEN) &&
          sockbuf_filter_matches(sft, wo) ) {
        dump_buf_cat("\"%d\":{", W_FMT(w));
        orm_dump_struct_ci_tcp_socket_listen("tcp_listen_sockets", &wo->tcp_listen, output_flags);
        dump_buf_cleanup();
        dump_buf_literal_comma("}");
      }
      else if( (strcmp(sock_type, "tcp") == 0) &&
               (w->state & CI_TCP_STATE_TCP) &&
               sockbuf_filter_matches(sft, wo) ) {
        dump_buf_cat("\"%d\":{", W_FMT(w));
        orm_dump_struct_ci_tcp_state("tcp_state", &wo->tcp, output_flags);
        dump_buf_cleanup();
        dump_buf_literal_comma("}");
      }
      else if( (strcmp(sock_type, "udp") == 0) &&
               (w->state == CI_TCP_STATE_UDP) &&
               sockbuf_filter_matches(sft, wo) ) {
        dump_buf_cat("\"%d\":{", W_FMT(w));
        orm_dump_struct_ci_udp_state("udp_state", &wo->udp, output_flags);
        dump_buf_cleanup();
        dump_buf_literal_comma("}");
      }

      else if( (strcmp(sock_type, "pipe") == 0) &&
               (w->state == CI_TCP_STATE_PIPE) ) {
        dump_buf_cat("\"%d\":{", W_FMT(w));
        orm_dump_struct_oo_pipe("oo_pipe", &wo->pipe, output_flags);
        dump_buf_cleanup();
        dump_buf_literal_comma("}");
      }
    }
  }
  dump_buf_cleanup();
  dump_buf_literal_comma("}");
}


static int orm_shared_state_dump(ci_netif* ni, int output_flags,
                                 const sockbuf_filter_t* sft)
{
  ci_netif_state* ns = ni->state;

  dump_buf_literal("\"stack\":{");
  if( output_flags & ORM_OUTPUT_STACK )
    orm_dump_struct_ci_netif_state("stack_state", ns, output_flags);
  if( output_flags & ORM_OUTPUT_SOCKETS ) {
    orm_waitable_dump(ni, "tcp_listen", output_flags, sft);
    orm_waitable_dump(ni, "tcp", output_flags, sft);
    orm_waitable_dump(ni, "udp", output_flags, sft);
    orm_waitable_dump(ni, "pipe", output_flags, sft);
  }
  dump_buf_cleanup();
  dump_buf_literal_comma("}");

  return 0;
}


static int orm_vis_dump(ci_netif* ni, int output_flags)
{
  int intf_i;

  dump_buf_literal("\"vis\":[");
  OO_STACK_FOR_EACH_INTF_I(ni, intf_i) {
    dump_buf_literal("{");
    orm_dump_struct_ef_vi_rxq_state("rxq",
                                    &ci_netif_vi(ni, intf_i)->ep_state->rxq,
                                    output_flags);
    orm_dump_struct_ef_vi_txq_state("txq",
                                    &ci_netif_vi(ni, intf_i)->ep_state->txq,
                                    output_flags);
    orm_dump_struct_ef_eventq_state("evq",
                                    &ci_netif_vi(ni, intf_i)->ep_state->evq,
                                    output_flags);
    dump_buf_cleanup();
    dump_buf_literal_comma("}");
  }
  dump_buf_cleanup();
  dump_buf_literal_comma("]");

  return 0;
}


/**********************************************************/
/* Main */
/**********************************************************/

static int orm_netif_dump(ci_netif* ni, int id, int output_flags, bool cfg_flat,
                          const char* stackname, const sockbuf_filter_t* sft)
{
  int rc;

  if (stackname != NULL)
    if ( strcmp(stackname, ni->state->name) != 0 )
      return 0;

  if( ! cfg_flat ) {
    if (stackname != NULL)
      dump_buf_label("{\"", stackname, "\":{");
    else
      dump_buf_cat("{\"%d\":{", id);
  }
  else {
    const char* pname = ni->state->pretty_name;
    const char* name = ni->state->name;
    char index[CI_CFG_STACK_NAME_LEN + 1];
    dump_buf_literal("{");
    dump_buf_cat("\"id\":%d,", id);
    if( name && name[0] ) {
      const char* s = name;
      char* d = index;
      for( ; *s; ++s, ++d )
        *d = isalnum(*s) ? *s : '_';
      *d = 0;
      dump_buf_cat("\"index\":\"%s\",", index);
    }
    else {
      dump_buf_cat("\"index\":\"%d\",", id);
    }
    dump_buf_cat("\"name\":\"%s\",", name ? name : "");
    dump_buf_cat_comma("\"pretty_name\":\"%s\"", pname);
  }

  if (output_flags & ORM_OUTPUT_VIS) {
    if( (rc = orm_vis_dump(ni, output_flags)) != 0 ) {
      LOG("VIs error code %d\n",rc);
      return rc;
    }
  }
  if (output_flags & (ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS)) {
    if( (rc = orm_shared_state_dump(ni, output_flags, sft)) != 0 ) {
      LOG("stack error code %d\n",rc);
      return rc;
    }
  }
  if (output_flags & ORM_OUTPUT_STATS) {
    if( (rc = orm_oo_stats_dump("stats", &ni->state->stats)) != 0 ) {
      LOG("stats error code %d\n",rc);
      return rc;
    }
  }
  if (output_flags & ORM_OUTPUT_MORE_STATS) {
    more_stats_t more_stats;
    get_more_stats(ni, &more_stats);
    if( (rc = orm_oo_more_stats_dump("more_stats", &more_stats)) != 0 ) {
      LOG("more stats error code %d\n",rc);
      return rc;
    }
  }
  if (output_flags & ORM_OUTPUT_TCP_STATS_COUNT) {
    ci_tcp_stats_count* tcp = &ni->state->stats_snapshot.tcp;
    if( (rc = orm_oo_tcp_stats_count_dump("tcp_stats", tcp)) != 0 ) {
      LOG("tcp stats error code %d\n",rc);
      return rc;
    }
  }
  if (output_flags & ORM_OUTPUT_TCP_EXT_STATS_COUNT) {
    ci_tcp_ext_stats_count* tcp_ext = &ni->state->stats_snapshot.tcp_ext;
    if( (rc = orm_oo_tcp_ext_stats_count_dump("tcp_ext_stats", tcp_ext)) != 0 ) {
      LOG("tcp ext stats error code %d\n",rc);
      return rc;
    }
  }
  if (output_flags & ORM_OUTPUT_OPTS) {
    if( (rc = orm_oo_opts_dump(ni)) != 0 ) {
      LOG("opts error code %d\n",rc);
      return rc;
    }
  }
  dump_buf_cleanup();
  if( ! cfg_flat )
    dump_buf_literal("}}");
  else
    dump_buf_literal("}");
  dump_buf_literal_comma("");

  return 0;
}

static void orm_oo_stats_meta_all(int output_flags, bool cfg_flat, const char* xpath)
{
  if( output_flags & ORM_OUTPUT_STATS )
    orm_oo_stats_meta_dump(cfg_flat, xpath);
  if( output_flags & ORM_OUTPUT_MORE_STATS )
    orm_oo_more_stats_meta_dump(cfg_flat, xpath);
  if( output_flags & ORM_OUTPUT_TCP_STATS_COUNT )
    orm_oo_tcp_stats_count_meta_dump(cfg_flat, xpath);
  if( output_flags & ORM_OUTPUT_TCP_EXT_STATS_COUNT )
    orm_oo_tcp_ext_stats_count_meta_dump(cfg_flat, xpath);
}

int orm_parse_output_flags(int argc, const char* const* argv)
{
  int i;
  int output_flags = ORM_OUTPUT_NONE;
  bool valid = true;

  if (argc == 0)
    output_flags = ORM_OUTPUT_LOTS;

  for (i=0; i<argc; i++) {
    if ( !strcmp(argv[i], "stats") )
      output_flags |= ORM_OUTPUT_STATS;
    else if ( !strcmp(argv[i], "more_stats") )
      output_flags |= ORM_OUTPUT_MORE_STATS;
    else if ( !strcmp(argv[i], "tcp_stats") )
      output_flags |= ORM_OUTPUT_TCP_STATS_COUNT;
    else if ( !strcmp(argv[i], "tcp_ext_stats") )
      output_flags |= ORM_OUTPUT_TCP_EXT_STATS_COUNT;
    else if ( !strcmp(argv[i], "stack_state") )
      output_flags |= ORM_OUTPUT_STACK;
    else if ( !strcmp(argv[i], "sockets") )
      output_flags |= ORM_OUTPUT_SOCKETS;
    else if ( !strcmp(argv[i], "stack") )
      output_flags |= ORM_OUTPUT_STACK | ORM_OUTPUT_SOCKETS;
    else if ( !strcmp(argv[i], "vis") )
      output_flags |= ORM_OUTPUT_VIS;
    else if ( !strcmp(argv[i], "opts") )
      output_flags |= ORM_OUTPUT_OPTS;
    else if ( !strcmp(argv[i], "lots") )
      output_flags |= ORM_OUTPUT_LOTS;
    else if ( !strcmp(argv[i], "extra") )
      output_flags |= ORM_OUTPUT_EXTRA;
    else if ( !strcmp(argv[i], "all") )
      output_flags |= ORM_OUTPUT_LOTS | ORM_OUTPUT_EXTRA;
    else
      valid = false;
  }

  return valid ? output_flags : -EINVAL;
}

int orm_do_dump(const struct orm_cfg* cfg, int output_flags,
                FILE* output_stream)
{
  sockbuf_filter_t sft = { };
  orm_state_t state = { };

  /* for now, reset globals on each run */
  dump_buf_init();

  int i;
  int rc = 0;

  if( output_flags < 0 )
    return -EINVAL;

  if( ! output_stream )
    return -ENOSTR;
  db.f = output_stream;

  if( cfg->filter )
    if( ! sockbuf_filter_prepare(&sft, cfg->filter) )
      return -EINVAL;

  if( cfg->meta ) {
    const char* xpath = cfg->flat ? "/all" : "/json/0/all";
    dump_buf_literal("{");
    dump_buf_literal("\"metrics\":[");
    orm_oo_stats_meta_all(output_flags, cfg->flat, xpath);
    if( cfg->flat ) {
      xpath = "";
      dump_buf_literal( "{"
        "\"name\":\"stacks\","
        "\"pointer\":\"/stacks\","
        "\"type\":\"array\","
        "\"description\":\"List of stacks and their stats\","
        "\"index\":\"/index\","
        "\"metrics\":[");

      /* include per stack stats */
      orm_oo_stats_meta_all(output_flags, cfg->flat, xpath);
      dump_buf_cleanup();
      dump_buf_literal_comma("]}");
    }
    dump_buf_cleanup();
    dump_buf_literal("]}");
    goto done;
  }

  if( orm_map_stacks(&state) != 0 ) {
    rc = -EFAULT;
    goto done;
  }

  dump_buf_cat_comma("{\"onload_version\":\"%s\"", ONLOAD_VERSION);
  if( ! cfg->flat )
    dump_buf_literal("\"json\":[");

  if( cfg->sum && (output_flags & ORM_OUTPUT_SUM) ) {
    ci_netif_stats stats_sum = {};
    more_stats_t more_stats_sum = {};
    ci_tcp_stats_count tcp_stats_sum = {};
    ci_tcp_ext_stats_count tcp_ext_stats_sum = {};

    /* this needs to be printed before stacks to be at fixed index 0
     * in the json array to match *_meta_dump() functions above. */
    for( i = 0; i < state.n_stacks; ++i ) {
      ci_netif* ni = &state.stacks[i]->os_ni;
      if( output_flags & ORM_OUTPUT_STATS )
        orm_oo_stats_sum(&stats_sum, &ni->state->stats);
      if( output_flags & ORM_OUTPUT_MORE_STATS ) {
        more_stats_t more_stats;
        get_more_stats(ni, &more_stats);
        orm_oo_more_stats_sum(&more_stats_sum, &more_stats);
      }
      if( output_flags & ORM_OUTPUT_TCP_STATS_COUNT ) {
        ci_tcp_stats_count_update(&tcp_stats_sum, &ni->state->stats_snapshot.tcp);
      }
      if( output_flags & ORM_OUTPUT_TCP_EXT_STATS_COUNT ) {
        ci_tcp_ext_stats_count_update(&tcp_ext_stats_sum,
                                      &ni->state->stats_snapshot.tcp_ext);
      }
    }
    if( ! cfg->flat )
      dump_buf_literal("{\"all\":{");
    else
      dump_buf_literal("\"all\":{");
    if( output_flags & ORM_OUTPUT_STATS ) {
      if( (rc = orm_oo_stats_dump("stats", &stats_sum)) != 0 ) {
        LOG("stats error code %d\n",rc);
        goto done;
      }
    }
    if( output_flags & ORM_OUTPUT_MORE_STATS ) {
      if( (rc = orm_oo_more_stats_dump("more_stats", &more_stats_sum)) != 0 ) {
        LOG("more_stats error code %d\n",rc);
        goto done;
      }
    }
    if( output_flags & ORM_OUTPUT_TCP_STATS_COUNT ) {
      if( (rc = orm_oo_tcp_stats_count_dump("tcp_stats", &tcp_stats_sum)) != 0 ) {
        LOG("tcp stats error code %d\n",rc);
        goto done;
      }
    }
    if( output_flags & ORM_OUTPUT_TCP_EXT_STATS_COUNT ) {
      if( (rc = orm_oo_tcp_ext_stats_count_dump("tcp_ext_stats", &tcp_ext_stats_sum)) != 0 ) {
        LOG("tcp ext stats error code %d\n",rc);
        goto done;
      }
    }
    dump_buf_cleanup();
    if( ! cfg->flat )
      dump_buf_literal("}}");
    else
      dump_buf_literal("}");
    dump_buf_literal_comma("");
  }
  if( cfg->flat )
    dump_buf_literal("\"stacks\":[");
  for( i = 0; i < state.n_stacks; ++i ) {
    ci_netif* ni = &state.stacks[i]->os_ni;
    int id       = state.stacks[i]->os_id;

    if( (rc = orm_netif_dump(ni, id, output_flags, cfg->flat, cfg->stackname, &sft)) != 0 )
      goto done;
  }

  dump_buf_cleanup();
  dump_buf_literal("]}");

done:

  __dump_buf_flush_buf();
  sockbuf_filter_free(&sft);
  orm_unmap_stacks(&state);

  if( db.rc )
    rc = db.rc;

  return rc;
}
