/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2018 Xilinx, Inc. */

/************************************************************************** \
 *//*! \file
   ** <L5_PRIVATE L5_SOURCE>
   ** \author  mjr
   **  \brief  Basic tests that ftl definitions and data structures match
   **   \date  2017/03/14
   **    \cop  (c) Solarflare Communications Limited.
   ** </L5_PRIVATE>
 *//*
\**************************************************************************/

/* Possible future ideas:
 * confirm consistent names for multiple lines of a struct definition
 * detect missing entries from ftl e.g. check sizeof ftl against real struct
 */

#include <ci/internal/ip.h>
#include <ci/efhw/common.h>
#include <ci/app/testapp.h>
#include <onload/ioctl.h>
#include <onload/driveraccess.h>
#include <onload/debug_intf.h>
#include <onload/version.h>
#include <ci/internal/ip.h>

#include "../../../tap/tap.h"
#include "../../../../tools/onload_remote_monitor/ftl_defs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CI_BUILD_ASSERT2(x) { CI_BUILD_ASSERT(x); }

#define TYPE_TEST(variable, type)                                   \
  (__builtin_types_compatible_p( typeof(variable), typeof(type)))

#define CHECK_ANON_BEGIN(t)                                                \
{({ \
  static const int entity = ANON | t; \

#define CHECK_ANON_END(t)                                                  \
  CI_BUILD_ASSERT2(entity == (ANON | t)); \
});}


int main(int argc, char* argv[])
{
  enum { STRUCT = 1, UNION = 2, ANON = 4, ARRAY = 8 };

  plan(NO_PLAN);

#define FTL_TSTRUCT_BEGIN(ctx, name, tag)                               \
{({ \
  static const int entity = STRUCT; \
  diag("Testing struct %s", #name);                                     \
  name v;                                                        \
  __attribute__((unused)) const char* struct_name = #name;

#define FTL_TUNION_BEGIN(ctx, name, tag)                        \
{({ \
  static const int entity = UNION; \
  diag("Testing union %s", #name);                              \
  name v;                                                \
  __attribute__((unused)) const char* struct_name = #name;

#define FTL_TFIELD_INT(ctx, type, field_name, flag)        \
  CI_BUILD_ASSERT2( TYPE_TEST(v.field_name, type) );

/* check for static string.
 * The second check might give false positive if static char array is actually defined
 * to be the size of a pointer */
#define FTL_TFIELD_SSTR(ctx, field_name, flag)        \
  CI_BUILD_ASSERT2(TYPE_TEST(v.field_name, char[])); \
  CI_BUILD_ASSERT2(sizeof(v.field_name) != sizeof(char*));

#define FTL_TFIELD_IPADDR(ctx, field_name, flags) \
   ok(strcmp(#field_name, "nexthop") == 0 || strstr(#field_name, "addr"), \
     "judging by name %s.%s looks like ip addr field", struct_name, #field_name); \
   FTL_TFIELD_INTBE32(ctx, field_name, flags)

#define FTL_TFIELD_IPXADDR(ctx, field_name, flags) \
  CI_BUILD_ASSERT2( TYPE_TEST(v.field_name, ci_addr_t) );

#define FTL_TFIELD_PORT FTL_TFIELD_INTBE16

/* for now the only direct use is BE16 */
#define FTL_TFIELD_INTBE(ctx, type, field_name, fmt, transform, flags) \
  CI_BUILD_ASSERT2(sizeof(transform(v.field_name)) >= sizeof(ci_uint16)); \
  FTL_TFIELD_INTBE16(ctx, field_name, flags)

#define FTL_TFIELD_INTBE16(ctx, field_name, flags) \
  CI_BUILD_ASSERT2(TYPE_TEST((v.field_name), ci_uint16)); \
  ok(strcmp(#field_name + sizeof(#field_name) - 6, "_be16") == 0 || \
     strcmp(#field_name, "ether_type") == 0, \
     "confirm that the field %s.%s 's name matches pattern or is valid. " \
     "Add name exception if needed.", \
     struct_name, #field_name);

#define FTL_TFIELD_INTBE32(ctx, field_name, flags) \
  CI_BUILD_ASSERT2(sizeof(v.field_name) == sizeof(ci_uint32)); \
  ok(strcmp(#field_name + sizeof(#field_name) - 6, "_be32") == 0 || \
     strcmp(#field_name, "nexthop") == 0, \
     "confirm that the field %s.%s 's name matches pattern or is valid. " \
     "Add name exception if needed.", \
     struct_name, #field_name);

#define FTL_TFIELD_INT2(ctx, type, field_name, format_string, conversion_function, flag) \
  FTL_TFIELD_INT(ctx, type, field_name, flag)

#define FTL_TFIELD_CONSTINT(ctx, type, field_name, flag)   \
  FTL_TFIELD_INT(ctx, type, field_name, flag)

#define FTL_TFIELD_ANON_STRUCT_BEGIN(ctx, field_name, flag) \
  CHECK_ANON_BEGIN(STRUCT)

#define FTL_TFIELD_ANON_STRUCT_END(ctx, field_name)        \
  CHECK_ANON_END(STRUCT)

#define FTL_TFIELD_ANON_UNION_BEGIN(ctx, field_name, flag) \
  CHECK_ANON_BEGIN(UNION)

#define FTL_TFIELD_ANON_UNION_END(ctx, field_name)         \
  CHECK_ANON_END(UNION)

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT_BEGIN(ctx, field_name, len, flag) \
  CHECK_ANON_BEGIN(ARRAY | STRUCT)

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT_END(ctx, field_name, len) \
  CHECK_ANON_END(ARRAY | STRUCT)

#define FTL_TFIELD_ANON_STRUCT(ctx, type, field_name, child) \
  CI_BUILD_ASSERT2( TYPE_TEST((v.field_name.child), type) );

#define FTL_TFIELD_ANON_UNION(ctx, type, field_name, child) \
  FTL_TFIELD_ANON_STRUCT(ctx, type, field_name, child)

#define FTL_TFIELD_ANON_ARRAYOFSTRUCT(ctx, type, field_name, child, len) \
  CI_BUILD_ASSERT2( TYPE_TEST((v.field_name[0].child), type) );

#define FTL_TFIELD_STRUCT(ctx, type, field_name, flag)     \
  FTL_TFIELD_INT(ctx, type, field_name, flag)

#define FTL_TSTRUCT_END(ctx)                                            \
  CI_BUILD_ASSERT2(entity == STRUCT); \
});}

#define FTL_TUNION_END(ctx)                                             \
  CI_BUILD_ASSERT2(entity == UNION); \
});}

#define FTL_TFIELD_ARRAYOFINT(ctx, type, field_name, len, flag) \
  CI_BUILD_ASSERT2( TYPE_TEST((v.field_name), type[len]) );

#define FTL_TFIELD_FLEXARRAYOFSTRUCT(ctx, type, field_name, len, flag, cond) \
  CI_BUILD_ASSERT2( TYPE_TEST((v.field_name), type[]) );

#define FTL_TFIELD_ARRAYOFSTRUCT(ctx, type, field_name, len, flag, cond) \
  FTL_TFIELD_ARRAYOFINT(ctx, type, field_name, len, flag)

#define FTL_TFIELD_KINT(ctx, type, field_name, flag)       \
  FTL_TFIELD_INT(ctx, type, field_name, flag)

#define FTL_DECLARE(a) a(DECL)

#include "../../../../tools/onload_remote_monitor/ftl_decls.h"

  done_testing();
}
