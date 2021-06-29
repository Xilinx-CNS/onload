/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <sys/syscall.h>
#include <linux/bpf.h>
#include <ci/efhw/common.h>

#include "private.h"
#include <cplane/cplane.h>
#include <cplane/ioctl.h>

static void
__cp_llap_notify_oof(struct cp_session* s, ci_ifid_t ifindex,
                     int flags, ci_uint32 hwport_mask, ci_uint16 vlan_id,
                     ci_mac_addr_t mac)
{
#ifndef CP_ANYUNIT
  struct oo_op_cplane_llapmod op;
  op.ifindex = ifindex;
  op.flags = flags;
  op.hwport_mask = hwport_mask;
  op.vlan_id = vlan_id;
  memcpy(op.mac, mac, sizeof(op.mac));

  cplane_ioctl(s->oo_fd, OO_IOC_OOF_CP_LLAP_MOD, &op);
  s->stats.notify.llap_mod++;

  cplane_ioctl(s->oo_fd, OO_IOC_OOF_CP_LLAP_UPDATE_FILTERS, &op);
  s->stats.notify.llap_update_filters++;
#endif
}

void
cp_llap_notify_oof(struct cp_session* s, cicp_llap_row_t* llap)
{
  ci_assert(! cicp_llap_row_is_free(llap));
  __cp_llap_notify_oof(s, llap->ifindex, !!(llap->flags & CP_LLAP_UP),
                       llap->rx_hwports, llap->encap.vlan_id, llap->mac);
}

void
cp_llap_notify_oof_of_removal(struct cp_session* s, ci_ifid_t ifindex)
{
  ci_mac_addr_t zero_mac = {0};
  /* Since we're removing the interface, we don't need to check the licence
   * before issuing the filter-update ioctl. */
  __cp_llap_notify_oof(s, ifindex, 0, 0, 0, zero_mac);
}

/*
 * Retreive MIB table index in cp_session structure to pass it into ioctl call
 * withing oo_op_cplane_ipmod structure mib_id parameter.
 */
static inline int cp_get_mib_index(struct cp_session* s, struct cp_mibs* mib)
{
  if( &s->mib[0] == mib )
    return 0;
  else if( &s->mib[1] == mib )
    return 1;
  else
    return -1;
}

void
__cp_ipif_notify_oof(struct cp_session* s, int af,
                     struct cp_ip_with_prefix* laddr, bool add)
{
  struct oo_op_cplane_ipmod op;
  op.af = af;
  op.addr = laddr->addr;
  op.ifindex = laddr->prefix;
  op.add = add;
  cplane_ioctl(s->oo_fd, OO_IOC_OOF_CP_IP_MOD, &op);
  s->stats.notify.ip_mod++;
}

void
cp_laddr_add(struct cp_session* s, int af,
             ci_addr_sh_t addr, ci_ifid_t ifindex)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t llap_id = cp_llap_find_row(mib, ifindex);

  /* When an address is assigned to 2 interfaces (accelarated and
   * non-accelerated), then it is important to avoid adding it with
   * non-accelerated interface, because oof thinks the address is being
   * deleted.
   */
  if( mib->llap[llap_id].rx_hwports == 0 )
    return;

  struct cp_ip_with_prefix ipp = {
    .addr = addr,
    .prefix = ifindex,
  };
  ci_assert(!CI_IPX_ADDR_IS_ANY(addr));
  if( cp_ippl_add(&s->laddr, &ipp, NULL) )
    __cp_ipif_notify_oof(s, af, &ipp, true);
}

void
cp_ipif_notify_oof(struct cp_session* s, struct cp_mibs* mib, int af,
                   cicp_rowid_t ipif_id)
{
  ci_addr_sh_t addr;
  ci_ifid_t ifindex;

  if( (af == AF_INET && mib->ipif[ipif_id].scope >= RT_SCOPE_HOST) ||
      (af == AF_INET6 && mib->ip6if[ipif_id].scope >= RT_SCOPE_HOST) )
    return;
  if( af == AF_INET ) {
    addr = CI_ADDR_FROM_IP4(mib->ipif[ipif_id].net_ip);
    ifindex = mib->ipif[ipif_id].ifindex;
  }
  else {
    addr = CI_ADDR_FROM_IP6(mib->ip6if[ipif_id].net_ip6);
    ifindex = mib->ip6if[ipif_id].ifindex;
  }
  cp_laddr_add(s, af, addr, ifindex);
}

static void
laddr_del_cb(struct cp_session* s, struct cp_ip_with_prefix* laddr)
{
  __cp_ipif_notify_oof(s, CI_ADDR_AF(laddr->addr), laddr, false);
}

/* Look through ipif and route tables and remove all laddr entries which
 * were not seen. */
void
cp_laddr_refresh(struct cp_session* s)
{
  struct cp_mibs* mib = cp_get_active_mib(s);

  cp_ippl_start_dump(&s->laddr);

  cicp_rowid_t ipif_id;
  for( ipif_id = 0; ipif_id < mib->dim->ipif_max; ipif_id++ ) {
    if( ! cicp_ipif_row_is_free(&mib->ipif[ipif_id]) )
      cp_ipif_notify_oof(s, mib, AF_INET, ipif_id);
  }
  for( ipif_id = 0; ipif_id < mib->dim->ip6if_max; ipif_id++ ) {
    if( ! cicp_ip6if_row_is_free(&mib->ip6if[ipif_id]) )
      cp_ipif_notify_oof(s, mib, AF_INET6, ipif_id);
  }
  if( s->flags & CP_SESSION_LADDR_USE_PREF_SRC ) {
    cp_routes_update_laddr(s, s->rt_table, AF_INET);
    cp_routes_update_laddr(s, s->rt6_table, AF_INET6);
  }
  
  /* look through route tables, call cp_laddr_add */
  cp_ippl_finalize(s, &s->laddr, laddr_del_cb);
  s->flags &=~ CP_SESSION_LADDR_REFRESH_NEEDED;
}


static bool
llap_update_rx_hwports(struct cp_session* s, struct cp_mibs* mib,
                       cicp_rowid_t llap_id, cicp_hwport_mask_t hwports)
{
  cicp_llap_row_t* llap = &mib->llap[llap_id];
  if( llap->rx_hwports == hwports )
    return false;
  cp_mibs_llap_under_change(s);
  llap->rx_hwports = hwports;

  cp_llap_notify_oof(s, llap);

  return true;
}

static bool
llap_update_tx_hwports(struct cp_session* s, struct cp_mibs* mib,
                       cicp_rowid_t llap_id, cicp_hwport_mask_t hwports)
{
  if( mib->llap[llap_id].tx_hwports == hwports )
    return false;

  ci_assert_impl(! (mib->llap[llap_id].encap.type & CICP_LLAP_TYPE_USES_HASH),
                 CI_IS_POW2(hwports) || hwports == 0);

  cp_mibs_llap_under_change(s);
  mib->llap[llap_id].tx_hwports = hwports;
  return true;
}

static bool
llap_update_type(struct cp_session* s, struct cp_mibs* mib,
                 cicp_rowid_t llap_id, cicp_llap_type_t type)
{
  if( mib->llap[llap_id].encap.type == type )
    return false;
  cp_mibs_llap_under_change(s);
  mib->llap[llap_id].encap.type = type;
  return true;
}

static void
fix_upper_layers(struct cp_session* s, struct cp_mibs* mib,
                 const cicp_llap_row_t* base, int imported, bool notify)
{
  cicp_rowid_t id;

  /* Update all vlans and macvlans over this interface */
  for( id = 0; id < mib->dim->llap_max; id++ ) {
    if( cicp_llap_row_is_free(&mib->llap[id]) )
      break;
    if( mib->llap[id].ifindex == base->ifindex )
      continue;

    if( ! (mib->llap[id].encap.type & CICP_LLAP_TYPE_CHILD) ||
        mib->llap[id].encap.link_ifindex != base->ifindex ) {
      continue;
    }

    /* Do not update vlan-over-vlan */
    if( s->llap_priv[id].immediate_type == CICP_LLAP_TYPE_VLAN &&
        (base->encap.type & CICP_LLAP_TYPE_VLAN) ) {
      continue;
    }

    if( ! imported != ! (mib->llap[id].flags & CP_LLAP_IMPORTED) ) {
      cp_mibs_llap_under_change(s);
      mib->llap[id].flags ^= CP_LLAP_IMPORTED;
    }

    if( base->encap.type & CICP_LLAP_TYPE_VLAN ) {
       /* Dodge existing vlan_id - note we do the same when processing
        * netlink messages */
       mib->llap[id].encap.vlan_id = base->encap.vlan_id;
    }

    /* This is recursion, but we believe it is a limited recursion:
     * vlan-over-macvlan or vise-versa. */
    cp_llap_set_hwports(
        s, mib, id,
        base->rx_hwports,
        base->tx_hwports,
        (mib->llap[id].encap.type & ~CICP_LLAP_TYPE_USES_HASH) |
                                        base->encap.type,
        notify);
  }

  /* Bond-over-bond is not supported */
  if( base->encap.type & CICP_LLAP_TYPE_BOND )
    return;

  /* Update all bonds over this interface; they will care about upper vlans
   * and macvlans */
  for( id = 0; id < s->bond_max; id++ ) {
    if( s->bond[id].type == CICP_BOND_ROW_TYPE_SLAVE &&
        s->bond[id].ifid == base->ifindex ) {
      cicp_rowid_t master = s->bond[id].slave.master;
      cicp_rowid_t llap_bond;
      ci_assert_nequal(master, CICP_ROWID_BAD);

      cp_bond_slave_set_hwport(&s->bond[id], base);

      llap_bond = cp_llap_find_row(mib, s->bond[master].ifid);
      if( llap_bond == CICP_ROWID_BAD )
        continue;
      if( s->bond[master].master.mode == CICP_BOND_MODE_UNSUPPORTED )
        continue;

      /* Update hwports of this aggregation, but do not change the type: */
      cp_team_update_hwports(s, mib, master, notify);
    }
  }
}

void cp_llap_set_hwports(struct cp_session* s, struct cp_mibs* mib,
                         cicp_rowid_t llap_id,
                         cicp_hwport_mask_t rx_hwports,
                         cicp_hwport_mask_t tx_hwports,
                         cicp_llap_type_t type, bool notify)
{
  cicp_hwport_mask_t old_rx_hwports = mib->llap[llap_id].rx_hwports;
  if( notify )
    s->flags |= CP_SESSION_LADDR_REFRESH_NEEDED;

  /* NOTE: Use arithmetic | to ensure all functions get executed.  It's also
   * important to update the type before updating the hwports, in order to
   * avoid upsetting assertions. */
  if( llap_update_type(s, mib, llap_id, type) |
      llap_update_rx_hwports(s, mib, llap_id, rx_hwports) |
      llap_update_tx_hwports(s, mib, llap_id, tx_hwports) ) {
    cp_fwd_llap_update(s, mib, llap_id, old_rx_hwports);
    fix_upper_layers(s, mib, &mib->llap[llap_id], 0, notify);
    if( notify && !rx_hwports != !old_rx_hwports ) {
      if( rx_hwports )
        ci_log("Accelerating %s: RX %x TX %x",
               mib->llap[llap_id].name, rx_hwports, tx_hwports);
      else
        ci_log("Not accelerating %s", mib->llap[llap_id].name);
    }
  }
}


/* For the specified LLAP row, populates base_llap_out and foreign_hwports_out
 * with properties of a base LLAP entry.  This is not an actual entry from the
 * LLAP table, but is synthesised, as it might refer to an interface in another
 * namespace.  Returns false if no such base interface exists, and true
 * otherwise. */
static bool
find_base_properties(struct cp_session* s, cicp_rowid_t llap_id,
                     cicp_llap_row_t* base_llap_out,
                     cicp_hwport_mask_t* foreign_hwports_out)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  const cicp_llap_row_t* llap = &mib->llap[llap_id];

  memset(base_llap_out, 0, sizeof(*base_llap_out));
  *foreign_hwports_out = 0;

  if( llap->encap.type & CICP_LLAP_TYPE_CHILD ) {
    cicp_rowid_t lower_id = cp_llap_find_row(mib, llap->encap.link_ifindex);
    if( lower_id != CICP_ROWID_BAD ) {
      /* we have found llap row in the local namepsace */
      cicp_llap_row_t* lower_l = &mib->llap[lower_id];
      *base_llap_out = *lower_l;
    }
    else if( s->main_cp_handle != NULL ) {
      /* There was no interface in the current namespace with the ifindex of
       * the base interface. */
      int rc = oo_cp_find_llap(s->main_cp_handle, llap->encap.link_ifindex,
                               &base_llap_out->mtu, &base_llap_out->tx_hwports,
                               &base_llap_out->rx_hwports, &base_llap_out->mac,
                               &base_llap_out->encap);
      if( rc == 0 ) {
        *foreign_hwports_out = base_llap_out->tx_hwports |
                               base_llap_out->rx_hwports;
        base_llap_out->ifindex = llap->encap.link_ifindex;
      }
    }
  }
  else if( llap->encap.type & CICP_LLAP_TYPE_ROUTE_ACROSS_NS &&
           s->main_cp_handle != NULL ) {
    /* We want to import all of the hwports from the peer's namespace. */
    *foreign_hwports_out = CICP_ALL_HWPORTS;
  }

  return base_llap_out->ifindex != CI_IFID_BAD || *foreign_hwports_out != 0;
}


/* We'd better type `#ifdef BPF_PROG_GET_FD_BY_ID`, but it is a enum, not
 * a macro.  So we check the kernel version  we are compiling with.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,18,0)
#define DO_XDP 1
#endif

void cp_set_hwport_xdp_prog_id(struct cp_session* s, struct cp_mibs* mib,
                               ci_hwport_id_t hwport, ci_ifid_t ifindex,
                               cp_xdp_prog_id_t xdp_prog_id)
{
  struct cp_hwport_row* hwp = &mib->hwport[hwport];
#ifdef DO_XDP
  union bpf_attr attr = {};
  struct oo_cp_xdp_change op;
#endif

  if( hwp->xdp_prog_id == xdp_prog_id )
    return;

  hwp->xdp_prog_id = xdp_prog_id;
  ci_wmb();

#ifdef DO_XDP
  if( s->flags & CP_SESSION_TRACK_XDP ) {
    op.hwport = hwport;
    op.fd = -1;
    attr.prog_id = xdp_prog_id;
    if( xdp_prog_id != 0 ) {
      op.fd = syscall(SYS_bpf, BPF_PROG_GET_FD_BY_ID, &attr, sizeof(attr));
      if( op.fd < 0 )
        ci_log("%s: failed to notify about XDP program change, "
             "ifindex=%d rc=%d", __func__, ifindex, op.fd);
    }
    cplane_ioctl(s->oo_fd, OO_IOC_CP_XDP_PROG_CHANGE, &op);
    if( op.fd >= 0 )
      close(op.fd);
  }
#endif
}


/* Imports hwports specified in *hwports_in_out from the main namespace, and
 * inserts them into the current control plane.  The mask is updated to be
 * equal to the hwports actually imported.  The function returns one if
 * licence-resolution is still pending, and zero otherwise. */
static void
import_main_hwports(struct cp_session* s, cicp_hwport_mask_t* hwports_in_out)
{
  cicp_hwport_mask_t hwports = *hwports_in_out;
  struct cp_hwport_row hwp;

  /* Start by clearing the mask of hwports that we've actually imported, and
   * build it up as we go. */
  *hwports_in_out = 0;

  for( ; hwports != 0; hwports &= (hwports - 1) ) {
    ci_hwport_id_t hwport = cp_hwport_mask_first(hwports);
    int rc = oo_cp_get_hwport_properties(s->main_cp_handle, hwport,
                                         &hwp.flags, &hwp.nic_flags);
    if( rc != 0 ) {
      continue;
    }
    if( (hwp.flags & CP_HWPORT_ROW_IN_USE) == 0 ) {
      continue;
    }
    struct cp_mibs* mib = cp_get_active_mib(s);
    if( hwport >= mib->dim->hwport_max ) {
      continue;
    }

    *hwports_in_out |= (1ull << hwport);

    int mib_i;
    MIB_UPDATE_LOOP(mib, s, mib_i)
      if( (hwp.flags | CP_LLAP_IMPORTED) !=
          (mib->hwport[hwport].flags | CP_LLAP_IMPORTED) ) {
        cp_mibs_llap_under_change(s);
        mib->hwport[hwport].flags = hwp.flags | CP_LLAP_IMPORTED;
        mib->hwport[hwport].nic_flags = hwp.nic_flags;
      }
    MIB_UPDATE_LOOP_END(mib, s)
  }
}


static void
propagate_base_properties(struct cp_session* s, cicp_rowid_t llap_id,
                          const cicp_llap_row_t* base_llap,
                          cicp_hwport_mask_t foreign_hwports)
{
  if( base_llap->ifindex == CI_IFID_BAD )
    ci_assert_nequal(foreign_hwports, 0);

  /* Pull in hwports from the main cplane.  The mask of hwports will be updated
   * to be equal to the set of hwports actually imported. */
  import_main_hwports(s, &foreign_hwports);

  struct cp_mibs* mib;
  int mib_i;

  MIB_UPDATE_LOOP(mib, s, mib_i)
    cp_mibs_llap_under_change(s);
    /* There are two possible cases here:
      *  - If the interface has a base interface, then we need to propagate
      *    properties from that base interface to other interfaces.
      *  - On the other hand, if there is no base interface, then (since we're
      *    on this path at all) we must be in the cross-namespace-routing
      *    case, and so the right thing to do is to apply the imported hwports
      *    to the current interface only. */
    if( base_llap->ifindex != CI_IFID_BAD )
      fix_upper_layers(s, mib, base_llap, foreign_hwports != 0, mib_i != 0);
    else
      /* The zero argument is the set of TX hwports.  For cross-namespace
        * routing, TX will happen on some other interface, not on this one. */
      cp_llap_set_hwports(s, mib, llap_id, foreign_hwports, 0,
                          mib->llap[llap_id].encap.type, mib_i != 0);
  MIB_UPDATE_LOOP_END(mib, s)

}


/* Resolves all dependencies between interfaces.  Called once all the licences
 * have been resolved and before the cplane server signals to the client that
 * it is ready, and whenever the main namespace's control plane tells us that
 * something has changed. */
void cp_llap_fix_upper_layers(struct cp_session* s)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t id;

  /* Propagate to each LLAP any properties arising from other interfaces,
   * possibly across namespaces. */
  for( id = 0;
       id < mib->dim->llap_max && ! cicp_llap_row_is_free(&mib->llap[id]);
       ++id ) {
    cicp_llap_row_t base_llap;
    cicp_hwport_mask_t foreign_hwports;

    if( find_base_properties(s, id, &base_llap, &foreign_hwports) )
      propagate_base_properties(s, id, &base_llap, foreign_hwports);
  }
}


/* Calls into the Onload driver to check whether we can accelerate traffic over
 * the specified veth interface. */
bool cp_llap_can_accelerate_veth(struct cp_session* s, ci_ifid_t ifindex)
{
  int rc = cplane_ioctl(s->oo_fd, OO_IOC_CP_CHECK_VETH_ACCELERATION, &ifindex);
  return rc == 0;
}

/* Sets the fwd-table ID associated with a veth interface. */
void cp_veth_fwd_table_id_do(struct cp_session* s, ci_ifid_t veth_ifindex,
                             cp_fwd_table_id fwd_table_id)
{
  struct cp_mibs* mib;
  int mib_i;

  MIB_UPDATE_LOOP(mib, s, mib_i)
    cicp_rowid_t veth_rowid = cp_llap_find_row(mib, veth_ifindex);
    if( veth_rowid != CICP_MAC_ROWID_BAD ) {
      cicp_llap_row_t* veth = &mib->llap[veth_rowid];
      cp_mibs_llap_under_change(s);
      veth->iif_fwd_table_id = fwd_table_id;
    }
    else {
      /* Failing to find the interface is not completely unexpected: races
       * versus network-config changes are possible, for example. */
      ++s->stats.llap.veth_peer_missing;
      ci_assert_equal(mib_i, 0);
      MIB_UPDATE_LOOP_UNCHANGED(mib, s, return);
    }
  MIB_UPDATE_LOOP_END(mib, s)
}


void cp_populate_llap_hwports(struct cp_session* s, ci_ifid_t ifindex,
                              ci_hwport_id_t hwport, ci_uint64 nic_flags)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  int mib_i;

  MIB_UPDATE_LOOP(mib, s, mib_i)
    struct cp_hwport_row* hwp = NULL;
    int new_flags;
    if( hwport != CI_HWPORT_ID_BAD && hwport < mib->dim->hwport_max ) {
      hwp = &mib->hwport[hwport];
      new_flags = (hwp->flags & CP_LLAP_UP) |
                  CP_HWPORT_ROW_IN_USE;
      if( new_flags != hwp->flags || nic_flags != hwp->nic_flags ) {
        cp_mibs_llap_under_change(s);
        mib->hwport[hwport].flags = new_flags;
        mib->hwport[hwport].nic_flags = nic_flags;
      }
    }
    else {
      if( hwport != CI_HWPORT_ID_BAD ) {
        ci_log("ERROR: got hwport=%d while hwport_max=%d",
               hwport, mib->dim->hwport_max);
        hwport = CI_HWPORT_ID_BAD;
      }
    }

    /* If this hwport doesn't support Onload, don't propagate it to any LLAP
     * entries.  This will cause routes over the hwport to appear
     * unacceleratable. */
    if( nic_flags & NIC_FLAG_ONLOAD_UNSUPPORTED )
      continue;

    cicp_hwport_mask_t hwports = cp_hwport_make_mask(hwport);
    cicp_rowid_t llap_id = cp_llap_find_row(mib, ifindex);
    if( llap_id == CICP_ROWID_BAD ) {
      /* We can't store the hwport information in the llap table.  It can
       * happen at startup, when we have not dumped llaps yet.  It is OK;
       * we'll re-dump hwports as a normal startup routine.  It also can
       * happen if the llap table is too small; let's complain in such
       * a case to the log. */
      if( mib_i == 0 && ((s->flags & CP_SESSION_NETLINK_DUMPED) ||
                         s->state > CP_DUMP_LLAP) ) {
        ci_log("ERROR: failed to store hwport=%d <-> ifindex=%d relationship",
               hwport, ifindex);
        ci_log("Is the llap table size %d too small?", s->mib->dim->llap_max);
      }
      continue;
    }
    cp_llap_set_hwports(s, mib, llap_id, hwports, hwports,
                        mib->llap[llap_id].encap.type, ! mib_i);
    cp_set_hwport_xdp_prog_id(s, mib, hwport, mib->llap[llap_id].ifindex,
                              mib->llap[llap_id].xdp_prog_id);
  MIB_UPDATE_LOOP_END(mib, s)
}
