/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __OOF_NAT_H__
#define __OOF_NAT_H__

#include <ci/tools.h>
#include <ci/net/ipvx.h>

struct oof_nat_table;
struct oof_nat_lookup_result;
struct oof_nat_filter;

extern struct oof_nat_table* oof_nat_table_alloc(ci_uint32 size);

extern void oof_nat_table_free(struct oof_nat_table* table);

extern int
oof_nat_table_add(struct oof_nat_table* table, ci_addr_t orig_addr,
                  ci_uint16 orig_port, ci_addr_t xlated_addr,
                  ci_uint16 xlated_port);

extern int
oof_nat_table_lookup(struct oof_nat_table* table, ci_addr_t xlated_addr,
                     ci_uint16 xlated_port,
                     struct oof_nat_lookup_result* results);

extern void oof_nat_table_lookup_free(struct oof_nat_lookup_result* results);

extern int
oof_nat_table_del(struct oof_nat_table* table, ci_addr_t orig_addr,
                  ci_uint16 orig_port);

extern int oof_nat_table_reset(struct oof_nat_table* table);

extern void
oof_nat_table_dump(struct oof_nat_table* table,
                   void (*log)(void* opaque, const char* fmt, ...), void* loga);

extern struct oof_nat_filter*
oof_nat_table_filter_get(struct oof_nat_table* table);

extern void
oof_nat_table_filter_put(struct oof_nat_table*, struct oof_nat_filter* filter);

#endif /* ! defined(__OOF_NAT_H__) */
