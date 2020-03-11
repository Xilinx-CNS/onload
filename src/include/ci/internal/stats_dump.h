/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifdef __KERNEL__
  #define LOG_PRINT(...) logger(log_arg, __VA_ARGS__ )
#else
  #include <ctype.h>
  #define LOG_PRINT(...) ci_log(__VA_ARGS__ )
#endif /* __KERNEL__ */

typedef struct stat_desc_s {
  unsigned	offset;
  unsigned	size;
  const char*	name;
  const char*   description;
# define STAT_COUNT     0x1
# define STAT_TCP       0x2
# define STAT_UDP       0x4
  unsigned	flags;
} stat_desc_t;

typedef struct dstats_s {
  unsigned        rx_evs_per_poll;
  unsigned        tx_evs_per_poll;
} dstats_t;


#define stat_initialiser(type_t, field, name_, desc_, flags_)   \
  { .offset = CI_MEMBER_OFFSET(type_t, field),                  \
    .size = CI_MEMBER_SIZE(type_t, field),                      \
    .name = (name_),                                            \
    .description = (desc_),                                     \
    .flags = (flags_)                                           \
  }

#define stat_desc_nm(type_t, field, nm, flags)          \
  stat_initialiser(type_t, field, (nm), NULL, (flags))

#define stat_desc(type_t, field, flags)             \
  stat_desc_nm(type_t, field, (#field), (flags))

#undef  OO_STAT
#define OO_STAT(desc, datatype, name, kind)     \
  OO_STAT_##kind(name, (desc)),
/* FIXME: Do we need to print (or store in the first place) always 0 stats */
#define OO_STAT_count_zero OO_STAT_count
#define OO_STAT_count(name, desc)                                       \
  stat_initialiser(OO_STAT_type, name, (#name), (desc), STAT_COUNT)
#define OO_STAT_val(name, desc)                                 \
  stat_initialiser(OO_STAT_type, name, (#name), (desc), 0)

static stat_desc_t netif_stats_fields[] = {
#define OO_STAT_type ci_netif_stats
#include <ci/internal/stats_def.h>
#undef OO_STAT_type
};
#define N_NETIF_STATS_FIELDS                                    \
  (sizeof(netif_stats_fields) / sizeof(netif_stats_fields[0]))

#ifdef __KERNEL__
#else
  static stat_desc_t netif_dstats_fields[] = {
  #define ns(x)  stat_desc_nm(dstats_t, x, (#x), 0)
    ns(rx_evs_per_poll),
    ns(tx_evs_per_poll),
  #undef ns
  };
  #define N_NETIF_DSTATS_FIELDS                                    \
    (sizeof(netif_dstats_fields) / sizeof(netif_dstats_fields[0]))
#endif /* __KERNEL__ */

static stat_desc_t more_stats_fields[] = {
#define OO_STAT_type more_stats_t
#include <ci/internal/more_stats_def.h>
#undef OO_STAT_type
};
#define N_MORE_STATS_FIELDS                                     \
  (sizeof(more_stats_fields) / sizeof(more_stats_fields[0]))


#if CI_CFG_SUPPORT_STATS_COLLECTION

static stat_desc_t ip_stats_fields[] = {
#define OO_STAT_type ci_ip_stats_count
#include <ci/internal/ip_stats_count_def.h>
#undef OO_STAT_type
};
#define N_IP_STATS_FIELDS                                       \
  (sizeof(ip_stats_fields) / sizeof(ip_stats_fields[0]))


static stat_desc_t tcp_stats_fields[] = {
#define OO_STAT_type ci_tcp_stats_count
#include <ci/internal/tcp_stats_count_def.h>
#undef OO_STAT_type
};
#define N_TCP_STATS_FIELDS                                      \
  (sizeof(tcp_stats_fields) / sizeof(tcp_stats_fields[0]))


static stat_desc_t udp_stats_fields[] = {
#define OO_STAT_type ci_udp_stats_count
#include <ci/internal/udp_stats_count_def.h>
#undef OO_STAT_type
};
#define N_UDP_STATS_FIELDS                                      \
  (sizeof(udp_stats_fields) / sizeof(udp_stats_fields[0]))


static stat_desc_t tcp_ext_stats_fields[] = {
#define OO_STAT_type ci_tcp_ext_stats_count
#include <ci/internal/tcp_ext_stats_count_def.h>
#undef OO_STAT_type
};
#define N_TCP_EXT_STATS_FIELDS                                          \
  (sizeof(tcp_ext_stats_fields) / sizeof(tcp_ext_stats_fields[0]))

#endif  /* CI_CFG_SUPPORT_STATS_COLLECTION */


/* Becasue maximum limit of printout line in ci_log is CI_LOG_MAX_LINE, split
 * the long lines into smaller blocks bellow max_line and new line is printed
 * automatically on each ci_log(). */
ci_inline void print_long_lines(const stat_desc_t* s, oo_dump_log_fn_t logger,
                             void* log_arg)
{
  unsigned left_size = strlen(s->description);
  const char* desc = s->description;
  /* After discussion and review limit was set to old legacy line length.*/
  const unsigned max_line = 77;

  while( left_size > max_line ) {
    unsigned print_size = 0;
    const char* next_line = NULL;
    const char* last_char = desc + max_line;
    while( ! isspace(*last_char) && last_char > desc )
      --last_char;

    print_size = last_char - desc;
    if( print_size == 0 )
      print_size = max_line;

    LOG_PRINT("   %.*s", print_size, desc);

    next_line = desc + print_size;
    while( *next_line && isspace(*next_line) )
      ++next_line;

    left_size -= next_line - desc;
    desc = next_line;
  }
  LOG_PRINT("   %s\n", desc);
}


ci_inline void ci_dump_stats(const stat_desc_t* stats_fields,
                             int n_stats_fields, const void* stats,
                             int with_description, oo_dump_log_fn_t logger,
                             void* log_arg)
{
  const stat_desc_t* s;
  for( s = stats_fields; s < stats_fields + n_stats_fields; ++s ) {
    switch( s->size ) {
    case sizeof(ci_uint32):
      LOG_PRINT("%s: %u", s->name,
             *(const ci_uint32*) ((const char*) stats + s->offset));
      break;
    case sizeof(ci_uint64):
      LOG_PRINT("%s: %llu", s->name,
             (unsigned long long)(*(const ci_uint64*)
                                  ((const char*) stats + s->offset)));
      break;
    default:
      LOG_PRINT("%s: unknown",  s->name);
      ci_assert(0);
    }
    if( with_description && s->description )
       print_long_lines(s, logger, log_arg);
  }
}


ci_inline void* get_dstats(void* to, const void* from, size_t len)
{
  ci_netif_stats s = * (const ci_netif_stats*) from;
  dstats_t* d = (dstats_t*) to;
  int polls;

  ci_assert_equal(len, sizeof(dstats_t));

  polls = s.k_polls + s.u_polls;
  d->rx_evs_per_poll = s.rx_evs / polls;
  d->tx_evs_per_poll = s.tx_evs / polls;
  return NULL;
}
