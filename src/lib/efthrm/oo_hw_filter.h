/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __ONLOAD_HW_FILTER_H__
#define __ONLOAD_HW_FILTER_H__


struct tcp_helper_resource_s;


/* Can be used for hwport_mask parameter when filter should be installed
 * for all interfaces in a stack.
 */
#define OO_HW_PORT_ALL ((unsigned) -1)

/* Use when no vlan should be specified for this filter.
 */
#define OO_HW_VLAN_UNSPEC ((ci_uint16) -1)

/* The default vlan.
 */
#define OO_HW_VLAN_DEFAULT (0)

/* Filter manipulation flags */
#define OO_HW_SRC_FLAG_LOOPBACK          (0x1)
#define OO_HW_SRC_FLAG_RSS_DST           (0x2)
#define OO_HW_SRC_FLAG_KERNEL_REDIRECT   (0x4)
#define OO_HW_SRC_FLAG_DROP              (0x8)
#define OO_HW_SRC_FLAG_REDIRECT          (0x10)


/* Initialise filter object. */
extern void oo_hw_filter_init(struct oo_hw_filter* oofilter);
extern void oo_hw_filter_init2(struct oo_hw_filter* oofilter,
                               struct tcp_helper_resource_s* trs,
                               struct tcp_helper_cluster_s* thc);

/* Remove all filters and disassociate with stack. */
extern void oo_hw_filter_clear(struct oo_hw_filter* oofilter);

/* Remove specified filters.  Association with stack remains. */
extern void oo_hw_filter_clear_hwports(struct oo_hw_filter* oofilter,
                                       unsigned hwport_mask, int redirect);

/* Abstraction of the various filter types used by Onload. Used by the oo_hw
 * filter-setting functions. */
struct oo_hw_filter_spec {
#define OO_HW_FILTER_TYPE_MAC            0
#define OO_HW_FILTER_TYPE_ETHERTYPE      1
#define OO_HW_FILTER_TYPE_IP             2
#define OO_HW_FILTER_TYPE_IP_PROTO       3
#define OO_HW_FILTER_TYPE_IP_PROTO_MAC   4
  unsigned type;

  union {
    struct {
      /* IPv4 addresses are passed via saddr[0]/daddr[0]. */
      ci_uint32  saddr[4];
      int        sport;
      ci_uint32  daddr[4];
      unsigned   dport;
      int        af;
      int        protocol;
    } ip;
    struct {
      ci_uint8   mac[6];
    } mac;
    struct {
      /* Ethertype filters are always MAC-qualified in Onload. */
      ci_uint8   mac[6];
      ci_uint16  t;
    } ethertype;
    struct {
      /* IP-protocol filters may be MAC-qualified or not, and have different
       * values of [type] above in each case, but share this union element. */
      ci_uint8   mac[6];
      ci_uint16  ethertype;
      ci_uint8   p;
    } ipproto;
  } addr;

  ci_uint16 vlan_id;
};

/* Add filters on specified hwports, if needed.  Must already be associated
 * with a stack.
 *
 * NB. This call does not clear filters for interfaces not indicated in
 * hwport_mask.  You need to call oo_hw_filter_clear_hwports() as well if
 * you want to do that.
 *
 * Attempts to add a filter to all requested interfaces, even if an error
 * occurs part way through.  Returns error code from first failure
 * encountered, or 0 if all were okay.  On error, use
 * oo_hw_filter_hwports() to determine which interfaces have filters in
 * case of error.
 *
 * A filter specifying vlan_id is used for filters on ports in both hwport_mask
 * and set_vlan_mask.
 */
extern int
oo_hw_filter_add_hwports(struct oo_hw_filter* oofilter,
                         const struct oo_hw_filter_spec* oo_filter_spec,
                         unsigned set_vlan_mask, unsigned hwport_mask,
                         unsigned redirect_mask,
                         unsigned drop_hwport_mask,
                         unsigned src_flags);


/* Insert new filters.
 *
 * filter object needs to be associated with stack (or cluster)
 * and contain no preexisting filters.
 *
 * If we fail to insert any filters the filter is cleared.
 */
extern int oo_hw_filter_set(struct oo_hw_filter* oofilter,
                            const struct oo_hw_filter_spec* oo_filter_spec,
                            unsigned set_vlan_mask, unsigned hwport_mask,
                            unsigned drop_hwport_mask,
                            unsigned src_flags);

/* Redirect filter to direct packets to a different stack.  This is similar
 * to doing clear then set, except that it is guaranteed that (for
 * interfaces common to old and new stacks) no packets will slip through
 * the filter during the redirection.
 *
 * Clustered filters cannot be moved to a new stack. In case a clustered filter
 * is given new_stack needs to be NULL and functionality is limited
 * to setting/removing filters on interfaces where change is required.
 */
extern int oo_hw_filter_update(struct oo_hw_filter* oofilter,
                               struct tcp_helper_resource_s* new_stack,
                               const struct oo_hw_filter_spec* oo_filter_spec,
                               unsigned set_vlan_mask, unsigned hwport_mask,
                               unsigned drop_hwport_mask,
                               unsigned src_flags);


/* Transfer filters on ports in hwport_mask from oofilter_old to oofilter_new.
 * Both oofilter_old and oofilter_new must point to the same stack - this
 * function simply transfers the filters, it does not update them in any way.
 */
extern void oo_hw_filter_transfer(struct oo_hw_filter* oofilter_old,
                              struct oo_hw_filter* oofilter_new,
                              unsigned hwport_mask);


/* Return the set of hwports that this filter is installed on.
 *
 * Result is zero if filter is not set, whether or not it is associated
 * with a stack.
 */
extern unsigned oo_hw_filter_hwports(struct oo_hw_filter* oofilter);

#endif  /* __ONLOAD_HW_FILTER_H__ */
