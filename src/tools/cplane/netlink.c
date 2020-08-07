/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <linux/if_link.h>
#include <linux/if_bonding.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#include <ci/compat.h>
#include <ci/tools/sysdep.h>
#include <ci/net/ipv4.h>
#include <ci/net/ethernet.h>
#include <ci/tools/utils.h>
#include "private.h"

/***** Generic NETLINK helpers *****/

int cp_nl_send_dump_req(struct cp_session* s, int sock,
                        struct nlmsghdr* nlh, int nlmsg_type,
                        int nlmsg_flags, size_t bytes)
{
  int rc;

  nlh->nlmsg_type = nlmsg_type;
  nlh->nlmsg_flags = NLM_F_REQUEST | nlmsg_flags;
  nlh->nlmsg_len = bytes;
  nlh->nlmsg_seq = CP_FWD_FLAG_DUMP;
  nlh->nlmsg_pid = 0;

  rc = send(sock, nlh, bytes, 0);
  if( rc != bytes ) {
    if( rc < 0 ) {
      ci_log("Failed to send netlink dump request %d: %s",
             nlh->nlmsg_type, strerror(errno));
      return -errno;
    }
    else {
      ci_log("Partial send when sending dump request %d to netlink socket: "
             "sending %d bytes, but only %d bytes were sent",
             nlh->nlmsg_type, (int)bytes, rc);
      return -EAGAIN;
    }
  }
  return 0;
}

/***** LLAP table update *****/

static cicp_rowid_t
llap_find_free(struct cp_mibs* mib)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->llap_max; i++ ) {
    if( cicp_llap_row_is_free(&mib->llap[i]) )
      return i;
  }
  return CICP_ROWID_BAD;
}

static void
llap_compact_one(struct cp_session* s, struct cp_mibs* mib,
                 cicp_rowid_t id, bool move_priv)
{
  cicp_rowid_t next;

  for( next = id; next + 1 < mib->dim->llap_max; next++ ) {
    if( cicp_llap_row_is_free(&mib->llap[next + 1]) )
      break;
    memcpy(&mib->llap[next], &mib->llap[next + 1], sizeof(cicp_llap_row_t));
    if( move_priv ) {
      memcpy(&s->llap_priv[next], &s->llap_priv[next + 1],
             sizeof(struct cp_llap_priv));
    }
  }
  cicp_llap_row_free(&mib->llap[next]);
}
static void
llap_compact(struct cp_session* s, struct cp_mibs* mib, bool move_priv)
{
  cicp_rowid_t free, move;

  free = llap_find_free(mib);

  /* Return if there is nothing to compact: */
  if( free == CICP_ROWID_BAD )
    return;

  /* Move all occupied rows above the current free row down into the free row.
   * Note that, immediately after a move, row [free + 1] is always free. */
  for( move = free + 1; move < mib->dim->llap_max; move++ ) {
    if( ! cicp_llap_row_is_free(&mib->llap[move]) ) {
      memcpy(&mib->llap[free], &mib->llap[move], sizeof(cicp_llap_row_t));
      if( move_priv ) {
        memcpy(&s->llap_priv[free], &s->llap_priv[move],
               sizeof(struct cp_llap_priv));
      }
      free++;
    }
  }

  /* We have moved all occupied rows down below row [free], so all remaining
   * rows now should be marked as free. */
  for( ; free < mib->dim->llap_max; free++ )
    cicp_llap_row_free(&mib->llap[free]);
}

/* TODO: For now, we handle one %s parameter in the format.  Only.
 * And it is supposed to fit into IFNAMSIZ.
 * It is possible to build up better API! */
static int
proc_file_read(const char* format, char* param, int def_val)
{
#ifndef CP_UNIT
  char filename[strlen(format) + IFNAMSIZ + 1];
  int fd;
  char val[12];
  int ival;
  int rc;

  snprintf(filename, sizeof(filename), format, param);
  filename[sizeof(filename) - 1] = '\0';
  fd = open(filename, O_RDONLY);
  if( fd == -1 )
    return def_val;
  val[sizeof(val) - 1] = '\0';
  rc = read(fd, val, sizeof(val) - 1);
  close(fd);
  if( rc <= 0 )
    return def_val;
  ival = atoi(val);
  if( ival == 0 )
    return def_val;
  return ival;
#else
  return def_val;
#endif
}


static bool
rta_str_match(const char* str, const struct rtattr* attr)
{
  /* The buffer size of [attr] may be equal to or larger than the length of
   * the string carried.  If longer, then the buffer is zero-padded.
   */
  size_t str_len = strlen(str);
  size_t attr_len = RTA_PAYLOAD(attr);
  return attr_len >= str_len &&
         memcmp(str, RTA_DATA(attr), CI_MIN(attr_len, str_len + 1)) == 0;
}


static void
llap_handle(struct cp_session* s, uint16_t nlmsg_type,
            struct ifinfomsg* ifinfomsg, size_t bytes)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  ci_ifid_t ifindex;
  bool up;
  ci_mtu_t mtu = 0;
  ci_mac_addr_t mac;
  char name[IFNAMSIZ];
  cicp_llap_type_t type = 0;
  cicp_llap_type_t immediate_type;
  ci_ifid_t link_ifindex;
  cicp_llap_type_t master_type;
  ci_ifid_t master_ifindex;
  int8_t bond_mii_status = -1;
  uint16_t aggregator_id = 0;
  uint16_t vlan;
  int mib_i;
  bool is_team = false;
  bool changed = false;
  struct cp_bond_netlink_state bond_state;
  cicp_rowid_t id;

  bool unsupported = 0;

  /* we are only interested in ethernet interfaces and in the loopback */
  switch( ifinfomsg->ifi_type ) {
    case ARPHRD_ETHER:
      immediate_type = CICP_LLAP_TYPE_NONE;
      break;
    case ARPHRD_LOOPBACK:
      immediate_type = CICP_LLAP_TYPE_LOOP;
      break;
    default:
      unsupported = 1;
      s->stats.llap.unsupported_ifi_type++;
      immediate_type = CICP_LLAP_TYPE_NONE;
  }
  /* IFF_RUNNING encompasses both the operational state and admin state of the
   * link. See Documentation/networking/operstates.txt. Here we are explicitly
   * testing the operational state, however the kernel will consider it
   * operationally down if it adminally down, so it's implicitly testing the
   * admin state too. */
  up = !! (ifinfomsg->ifi_flags & IFF_RUNNING);
  ifindex = ifinfomsg->ifi_index;
  link_ifindex = 0;
  vlan = 0;
  master_type = CICP_LLAP_TYPE_NONE;
  master_ifindex = CI_IFID_BAD;
  bond_state.attributes_seen = 0;

  RTA_LOOP(ifinfomsg, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case IFLA_ADDRESS:
        memcpy(mac, RTA_DATA(attr), sizeof(mac));
        break;

      case IFLA_IFNAME:
        memcpy(name, RTA_DATA(attr), sizeof(name));
        name[IFNAMSIZ - 1] = '\0';
        break;

      case IFLA_MTU:
        mtu = (ci_mtu_t) *((uint32_t *)RTA_DATA(attr));
        break;

      case IFLA_LINK:
        link_ifindex = *((uint32_t *)RTA_DATA(attr));
        break;

      case IFLA_MASTER:
        master_ifindex = *((uint32_t *)RTA_DATA(attr));
        break;

      case IFLA_LINKINFO:
      {
        RTA_NESTED_LOOP(attr, attr1, bytes1) {
          switch( attr1->rta_type & NLA_TYPE_MASK ) {
            case IFLA_INFO_KIND:
              /* Note: in theory this is a non-zero-terminated string,
               * in practice it is zero-padded one of bit a random size.
               * We handle both cases. */
              if( rta_str_match("vlan", attr1) ) {
                immediate_type = CICP_LLAP_TYPE_VLAN;
              }
              else if( rta_str_match("macvlan", attr1) ) {
                immediate_type = CICP_LLAP_TYPE_MACVLAN;
              }
              else if( rta_str_match("ipvlan", attr1) ) {
                immediate_type = CICP_LLAP_TYPE_IPVLAN;
              }
              else if( rta_str_match("team", attr1) ) {
                immediate_type = CICP_LLAP_TYPE_BOND;
                is_team = true;
              }
              else if( rta_str_match("bond", attr1) ) {
                immediate_type = CICP_LLAP_TYPE_BOND;
              }
              else if( rta_str_match("veth", attr1) ) {
                immediate_type = CICP_LLAP_TYPE_VETH;
              }
#ifdef CP_SYSUNIT
              else if( rta_str_match("dummy", attr1)) {
                  int i;
                  /* In cplane tests one of the following capital letters
                   * makes interface an SFC interface */
                  unsupported = 1;
                  for( i = 0; i < strlen(name); ++i )
                    if( strchr("NSTOP", name[i]) != NULL )
                       unsupported = 0;
              }
#endif
              else {
                unsupported = 1;
                s->stats.llap.unsupported_info_kind++;
              }
              break;
            case IFLA_INFO_DATA:
            {
              RTA_NESTED_LOOP(attr1, attr2, bytes2) {
                if( immediate_type == CICP_LLAP_TYPE_VLAN ) {
                  switch( attr2->rta_type & NLA_TYPE_MASK ) {

                    case IFLA_VLAN_PROTOCOL:
                      if( *(uint16_t*)RTA_DATA(attr2) != htons(ETH_P_8021Q) ) {
                        unsupported = 1;
                        s->stats.llap.unsupported_vlan++;
                      }
                      break;

                    case IFLA_VLAN_ID:
                      vlan = *(uint16_t*)RTA_DATA(attr2);
                      break;
                  };
                }
                else if( immediate_type == CICP_LLAP_TYPE_IPVLAN ) {
                  switch( attr2->rta_type & NLA_TYPE_MASK ) {
                    case IFLA_IPVLAN_MODE:
                    {
                      uint16_t mode = *(uint16_t*)RTA_DATA(attr2);
                      /* only IPVLAN L2 mode is supported,
                       * disable acceleration of other modes,
                       * note: default is L3 */
                      if( mode != IPVLAN_MODE_L2 )
                        immediate_type = CICP_LLAP_TYPE_NONE;
                    }
                    break;
                  };
                }
                else if( immediate_type == CICP_LLAP_TYPE_MACVLAN ) {
                  switch( attr2->rta_type & NLA_TYPE_MASK ) {
                    case IFLA_MACVLAN_MODE:
                    {
                      uint16_t mode = *(uint16_t*)RTA_DATA(attr2);
                      /* TODO: likely, we should only support private mode,
                       * for now, that is one with no loopback, nor port
                       * remapping.  However, the default mode is VEPA,
                       * for now we live with it.
                       *
                       * If we ever do something with this, we should
                       * restrict IPVLANs to private mode as well (the
                       * default is bridge).
                       */
                      (void)mode;
                      break;
                    }
                  }
                }
                else if( immediate_type == CICP_LLAP_TYPE_BOND && ! is_team ) {
                  int bond_ifindex = link_ifindex == 0 ? ifindex : link_ifindex;
                  cp_bond_handle_netlink_info(s, bond_ifindex, attr2,
                                              &bond_state);
                }
              }
            }

            break;

            case IFLA_INFO_SLAVE_KIND:
              if( ! ( s->llap_type_os_mask & CICP_LLAP_TYPE_SLAVE ) )
                s->llap_type_os_mask |= CICP_LLAP_TYPE_SLAVE;
              /* This attribute identifies the interface as a bond-slave.
               * We'll use it when processing IFLA_INFO_SLAVE_DATA below.
               * We also need the ifindex of the master, and that is
               * in the IFLA_MASTER attribute. */
              if( rta_str_match("bond", attr1) ) {
                master_type = CICP_LLAP_TYPE_BOND;
                type |= CICP_LLAP_TYPE_SLAVE;
              }
              else if( rta_str_match("team", attr1) ) {
                type |= CICP_LLAP_TYPE_SLAVE;
              }
              break;

            case IFLA_INFO_SLAVE_DATA:
              if( master_type != CICP_LLAP_TYPE_BOND )
                break;
              RTA_NESTED_LOOP(attr1, attr2, bytes2) {
                switch( attr2->rta_type & NLA_TYPE_MASK ) {
                  case IFLA_BOND_SLAVE_MII_STATUS:
                    bond_mii_status = *(int8_t*)RTA_DATA(attr2);
                    break;

                  case IFLA_BOND_SLAVE_AD_AGGREGATOR_ID:
                    aggregator_id = *(int16_t*)RTA_DATA(attr2);
                    break;
                }
              }
              break;
          }
        }
        break;
      }

      default:
        break;
    }
  }
  type |= immediate_type;

  /* On linux>=3.14 (and possibly earlier) loopback interface
   * has no mtu; let's set a safe default. */
  if( mtu == 0 )
    mtu = (ci_mtu_t) (-1);

  /* If this interface was but is no longer a bond-slave, we get no explicit
   * notification, but instead the RTM_NEWLINK message will be missing its
   * slave parameters.  So if we se a message for a non-slave, we need to check
   * whether we think it is currently a slave, and take the slave-update path
   * if so.  Note that, while this is only necessary for bonding and not for
   * teaming, it's harmless in the latter case, and it's not worth going to the
   * effort of making the distinction. */
  if( master_ifindex == CI_IFID_BAD &&
      CICP_ROWID_IS_VALID(cp_bond_find_slave(s, ifindex)) )
    master_type = CICP_LLAP_TYPE_BOND;

  if( link_ifindex == 0)
    link_ifindex = ifindex;

  cicp_rowid_t vlan_rowid = CICP_ROWID_BAD;
  const cicp_llap_row_t* lower_llap = NULL;
  if( link_ifindex != ifindex &&
      (vlan_rowid = cp_llap_find_row(mib, link_ifindex)) != CICP_ROWID_BAD ) {
    lower_llap = &mib->llap[vlan_rowid];
    type |= (lower_llap->encap.type & s->llap_type_os_mask);
  }
  if( immediate_type == CICP_LLAP_TYPE_VLAN &&
      (lower_llap != NULL &&
       (lower_llap->encap.type & CICP_LLAP_TYPE_VLAN)) ) {
    unsupported = true;
    s->stats.llap.unsupported_vlan++;
  }

  /* When the configuration is favourable, Onload can accelerate traffic that
   * routes over veth interfaces by considering the routing that applies in the
   * veth-peer's namespace.  We mark such interfaces with a flag. */
  if( immediate_type == CICP_LLAP_TYPE_VETH ) {
    if( cp_llap_can_accelerate_veth(s, ifindex) )
      type |= CICP_LLAP_TYPE_ROUTE_ACROSS_NS;
    else
      unsupported = true;
  }

  struct cp_llap_priv* llap_priv = NULL;
  cicp_hwport_mask_t old_rx_hwports = 0;
  bool was_up = true; /* placate compiler */

  bool populate_llap = false;
  bool dump_hwports = false;
  MIB_UPDATE_LOOP(mib, s, mib_i)
    cicp_llap_row_t* llap;
    id = cp_llap_find_row(mib, ifindex);

    if( nlmsg_type == RTM_NEWLINK ) {

      if( id == CICP_ROWID_BAD ) {
        /* Ensure we'll know about hwports of this new llap. */
        dump_hwports = true;

        id = llap_find_free(mib);
        if( id == CICP_ROWID_BAD ) {
          static bool printed = false;
          s->stats.llap.full++;
          if( ! printed ) {
            ci_log("ERROR: no free rows in the llap table; please increase "
                   "llap-max parameter (currently llap-max=%d).",
                   mib->dim->llap_max);
            printed = true;
          }
          MIB_UPDATE_LOOP_UNCHANGED(mib, s, return);
        }
        llap = &mib->llap[id];
        llap_priv = &s->llap_priv[id];

        cp_mibs_llap_under_change(s);
        llap->tx_hwports = 0;
        llap->rx_hwports = 0;
        llap->flags = 0;
        llap->iif_fwd_table_id = CP_FWD_TABLE_ID_INVALID;

        cicp_rowid_t bond_rowid = cp_bond_find_master(s, ifindex);
        if( bond_rowid != CICP_ROWID_BAD ) {
          llap->encap.type &=~ CICP_LLAP_TYPE_USES_HASH;
          llap->encap.type |= s->bond[bond_rowid].master.hash_policy;
        }

        if( mib_i == 0 ) {
          llap_priv->arp_base_reachable = proc_file_read(
                      "/proc/sys/net/ipv4/neigh/%s/base_reachable_time_ms",
                      name, 30000);
        }
      }
      else {
        llap = &mib->llap[id];
        llap_priv = &s->llap_priv[id];
      }

      if( llap->ifindex != ifindex ||
          ! (llap->flags & CP_LLAP_UP) != ! up ||
          llap->mtu != mtu ||
          strcmp(llap->name, name) != 0 ||
          memcmp(llap->mac, mac, sizeof(mac)) != 0 ||
          ((llap->flags & CP_LLAP_IMPORTED) == 0 &&
            (llap->encap.type & s->llap_type_os_mask) != type) ||
          /* with CP_LLAP_IMPORTED rows some OS types
           * are imported from the main cplane */
          ((llap->flags & CP_LLAP_IMPORTED) != 0 &&
            (llap->encap.type & type) != type) ||
          llap->encap.link_ifindex != link_ifindex ) {
        changed = true;
        old_rx_hwports = llap->rx_hwports;
        was_up = !!(llap->flags & CP_LLAP_UP);
        cp_mibs_llap_under_change(s);
        if( up )
          llap->flags |= CP_LLAP_UP;
        else
          llap->flags &=~ CP_LLAP_UP;
        strcpy(llap->name, name);
        memcpy(llap->mac, mac, sizeof(mac));
        llap->mtu = mtu;

        ci_assert_equal(type, type & s->llap_type_os_mask);
        llap->encap.type |= type;
        llap->encap.type &=~ (s->llap_type_os_mask & ~type);

        llap->encap.link_ifindex = link_ifindex;
        llap->encap.vlan_id = vlan;
        if( vlan_rowid != CICP_ROWID_BAD ) {
          if( ! unsupported ) {
            llap->tx_hwports = lower_llap->tx_hwports;
            llap->rx_hwports = lower_llap->rx_hwports;
          }
          llap->encap.type |= lower_llap->encap.type;
          if( lower_llap->encap.type & CICP_LLAP_TYPE_VLAN )
            llap->encap.vlan_id = lower_llap->encap.vlan_id;
        }
        else if( type & CICP_LLAP_TYPE_CHILD ) {
          /* It is a child of a foreign interface.  Let's call
           * cp_llap_fix_upper_layers() to discover foreign properties. */
          populate_llap = true;
        }
        llap->ifindex = ifindex;

        /* If we're not going to update the hwports later, just notify OOF,
         * but only on the second mib-iteration. */
        if( mib_i && ! populate_llap )
          cp_llap_notify_oof(s, llap);
      }
      if( s->state == CP_DUMP_LLAP )
        cp_row_mask_set(s->seen, id);
    }
    else {
      ci_assert_equal(nlmsg_type, RTM_DELLINK);
      if( id != CICP_ROWID_BAD ) {
        cp_mibs_llap_under_change(s);
        llap = &mib->llap[id];
        cicp_llap_row_free(llap);
        if( ! mib_i )
          cp_llap_notify_oof_of_removal(s, ifindex);
        llap_compact_one(s, mib, id, mib_i);
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
      }
    }
  MIB_UPDATE_LOOP_END(mib, s);

  /* Propagate hwports up from base interfaces to child interfaces, across
   * namespaces if necessary. */
  if( populate_llap )
    cp_llap_fix_upper_layers(s);

  if( nlmsg_type == RTM_NEWLINK ) {
    if( changed ) {
      llap_priv->immediate_type = immediate_type;

      /* If it is a simple change (mtu change, mac change) then we can
       * update all the fwd entries right away.
       * If the interface have been brought up or down, we'd better
       * re-resolve all the routes instead of assuming that they go the old
       * paths. */
      if( up == was_up )
        cp_fwd_llap_update(s, cp_get_active_mib(s), id, old_rx_hwports);
      else
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
      if( type & CICP_LLAP_TYPE_ROUTE_ACROSS_NS )
        cp_llap_fix_upper_layers(s);
    }

    /* If this is a team network interface, then we should dump its
     * teaming state.  If we are receiving this as a regular update, then
     * teaming state will come as a similar update, so we call for
     * cp_team_dump() in CP_DUMP_LLAP state only. */
    if( s->state == CP_DUMP_LLAP && is_team )
      cp_team_dump_one(s, ifindex);

    /* The teaming/bonding common implementation does its own
     * MIB_UPDATE_LOOP()s, so call these functions after exiting our own loop.
     * This also ensures that the LLAP entries are in the state in which the
     * bonding/teaming layer expects them.
     */
    else if( type == CICP_LLAP_TYPE_BOND && ! is_team )
      cp_bond_master_update(s, ifindex, &bond_state);

    /* If we are member of a bond, or we were a member of a bond, then
     * we have to update the master aggregation about the current status.
     * - Call this if master_ifindex is CI_IFID_BAD, i.e. this interface is
     *   not (any more) a member of any bond or team.  We must remove it
     *   from any bonds (and we will also remove it from teams, which is
     *   harmless).
     * - Call this if bond_mii_status is set, i.e. this interface has
     *   IFLA_BOND_SLAVE_MII_STATUS, so it must be a bond member.
     */
    if( master_ifindex == CI_IFID_BAD || bond_mii_status != -1 ) {
      cp_bond_slave_update(s, master_ifindex, ifindex,
                           bond_mii_status == BOND_LINK_UP, aggregator_id);
    }
  }

  /* New llap, and we've already dumped all hwports, so have to ask about
   * this one.
   */
  if( dump_hwports && (s->flags & CP_SESSION_HWPORT_DUMPED) )
    cplane_ioctl(s->oo_fd, OO_IOC_CP_DUMP_HWPORTS, &ifindex);
}

void cp_llap_dump_done(struct cp_session* s)
{
  struct cp_mibs* mib;
  int mib_i;
  bool msg_init = false;

  struct {
    struct nlmsghdr nlhdr;
    struct ifinfomsg ifinfomsg;
  } __attribute__((__packed__)) msg;
  CI_BUILD_ASSERT(sizeof(msg) == sizeof(struct nlmsghdr) +
                  sizeof(struct ifinfomsg));

  MIB_UPDATE_LOOP(mib, s, mib_i)
    cicp_rowid_t id = -1;

    while( (id =
            cp_row_mask_iter_set(s->seen, ++id, mib->dim->llap_max, false) ) !=
           CICP_MAC_ROWID_BAD ) {
      if( cicp_llap_row_is_free(&mib->llap[id]) )
        break;

      if( mib_i == 0 ) {
        /* We're removing this line, but give it a chance to resurrect if we've
         * missed the line when dumping.  Ignore any errors. */
        if( ! msg_init ) {
          msg_init = true;
          memset(&msg, 0, sizeof(msg));
          msg.nlhdr.nlmsg_type = RTM_GETLINK;
          msg.nlhdr.nlmsg_len = sizeof(msg);
          msg.nlhdr.nlmsg_flags = NLM_F_REQUEST;
          msg.nlhdr.nlmsg_seq = 0;
          msg.ifinfomsg.ifi_family = AF_INET;
          s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;

        }

        int ifindex = mib->llap[id].ifindex;
        msg.ifinfomsg.ifi_index = ifindex;
        send(s->sock_net, &msg, sizeof(msg), 0);

        /* Notify OOF */
        cp_llap_notify_oof_of_removal(s, ifindex);
      }

      cp_mibs_llap_under_change(s);
      cicp_llap_row_free(&mib->llap[id]);
    }

    if( msg_init )
      llap_compact(s, mib, mib_i);
  MIB_UPDATE_LOOP_END(mib, s);

  /* Ensure that we remove all teaming interfaces which do not have
   * a corresponding llap entry.  We have to do this after every dump,
   * because team-modifying messages can be reordered badly, so that they
   * add the team when it have been already removed. */
  cp_team_purge_unknown(s, cp_get_active_mib(s));

  /* If we are not usable yet, then let's ask module to dump all the known
   * hwports. */
  if( ! (s->flags & CP_SESSION_NETLINK_DUMPED) ) {
    ci_ifid_t ifindex = CI_IFID_BAD;
    cplane_ioctl(s->oo_fd, OO_IOC_CP_DUMP_HWPORTS, &ifindex);
  }
}



/***** IPIF table update *****/

static cicp_rowid_t
ipif_find_row(ci_ifid_t ifindex, ci_ip_addr_t net_ip,
              cicp_prefixlen_t net_ipset, struct cp_mibs* mib)
{
  cicp_rowid_t i;

  /* This function must not be called if ipif table
   * may be uncompressed. */

  for( i = 0; i < mib->dim->ipif_max; i++ ) {
    if( mib->ipif[i].ifindex == ifindex &&
        mib->ipif[i].net_ip == net_ip &&
        mib->ipif[i].net_ipset == net_ipset )
      return i;
    if( cicp_ipif_row_is_free(&mib->ipif[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}
static cicp_rowid_t
ipif_find_free(struct cp_mibs* mib)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->ipif_max; i++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[i]) )
      return i;
  }
  return CICP_ROWID_BAD;
}

static void
ipif_compact_one(struct cp_mibs* mib, cicp_rowid_t id)
{
  cicp_rowid_t next;

  for( next = id; next + 1 < mib->dim->ipif_max; next++ ) {
    if( cicp_ipif_row_is_free(&mib->ipif[next + 1]) )
      break;
    memcpy(&mib->ipif[next], &mib->ipif[next + 1], sizeof(mib->ipif[0]));
  }
  cicp_ipif_row_free(&mib->ipif[next]);
}
static void
ipif_compact(struct cp_mibs* mib)
{
  cicp_rowid_t free, move;

  free = ipif_find_free(mib);

  /* Return if there is nothing to compact: */
  if( free == CICP_ROWID_BAD )
    return;

  /* Move all occupied rows above the current free row down into the free row.
   * Note that, immediately after a move, row [free + 1] is always free. */
  for( move = free + 1; move < mib->dim->ipif_max; move++ )
    if( ! cicp_ipif_row_is_free(&mib->ipif[move]) )
      memcpy(&mib->ipif[free++], &mib->ipif[move], sizeof(mib->ipif[0]));

  /* We have moved all occupied rows down below row [free], so all remaining
   * rows now should be marked as free. */
  for( ; free < mib->dim->ipif_max; free++ )
    cicp_ipif_row_free(&mib->ipif[free]);
}

static void
ipif_handle(struct cp_session* s, uint16_t nlmsg_type,
            struct ifaddrmsg* ifmsg, size_t bytes)
{
  struct cp_mibs* mib;
  ci_ifid_t ifindex;
  ci_ip_addr_t net_ip;
  cicp_prefixlen_t net_ipset;
  ci_ip_addr_t net_bcast;
  cicp_rowid_t id;
  cicp_ipif_row_t* ipif;
  int mib_i;

  /* We record AF_INET addresses only */
  if (ifmsg->ifa_family != AF_INET)
    return;

  ifindex = ifmsg->ifa_index;
  net_ipset = ifmsg->ifa_prefixlen;
  net_ip = net_bcast = INADDR_ANY;

  RTA_LOOP(ifmsg, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case IFA_ADDRESS:
        /* From linux-3.6.32/include/linux/if_addr.h:
         * IFA_ADDRESS is prefix address, rather than local
         * interface address.  It makes no difference for normally
         * configured broadcast interfaces, but for point-to-point
         * IFA_ADDRESS is DESTINATION address, local address is
         * supplied in IFA_LOCAL attribute.
         */
        break;

      case IFA_LOCAL:
        net_ip = *(uint32_t*)RTA_DATA(attr);
        break;

      case IFA_BROADCAST:
        net_bcast = *(uint32_t*)RTA_DATA(attr);
        break;

      default:
        /* We are not interested in any other parameters */
        break;
    }
  }

  ci_assert_nequal(net_ip, INADDR_ANY);
  MIB_UPDATE_LOOP(mib, s, mib_i)
    id = ipif_find_row(ifindex, net_ip, net_ipset, mib);

    if( nlmsg_type == RTM_NEWADDR ) {
      if( id != CICP_ROWID_BAD ) {
        ipif = &mib->ipif[id];
      }
      else {
        id = ipif_find_free(mib);
        if( id == CICP_ROWID_BAD ) {
          static bool printed = false;
          s->stats.ipif.full++;
          if( ! printed ) {
            ci_log("ERROR: no free rows in the ipif table; please increase "
                   "ipif-max parameter (currently ipif-max=%d).",
                   mib->dim->ipif_max);
            printed = true;
          }
          MIB_UPDATE_LOOP_UNCHANGED(mib, s, return);
        }
        ipif = &mib->ipif[id];
        cp_mibs_under_change(s);
        ipif->ifindex = ifindex;
        ipif->net_ip = net_ip;
        if( ! mib_i )
          cp_ipif_notify_oof(s, mib, AF_INET, id);
      }

      struct cp_ip_with_prefix src_rule;
      src_rule.addr = CI_ADDR_SH_FROM_IP4(net_ip);
      src_rule.prefix = 32;

      if( ipif->scope != ifmsg->ifa_scope ||
          ipif->bcast_ip != net_bcast ||
          ipif->net_ipset != net_ipset ) {
        cp_mibs_under_change(s);
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
        ipif->scope = ifmsg->ifa_scope;
        ipif->bcast_ip = net_bcast;
        ci_wmb();
        ipif->net_ipset = net_ipset;

        if( cp_ippl_add(&s->rule_src, &src_rule, NULL) )
          s->flags |= CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
      }
      if( s->state == CP_DUMP_IPIF ) {
        cp_row_mask_set(s->seen, id);
        /* Mark this "rule" as seen. */
        cp_ippl_add(&s->rule_src, &src_rule, NULL);
      }
    }
    else {
      ci_assert_equal(nlmsg_type, RTM_DELADDR);
      if( id != CICP_ROWID_BAD ) {
        cp_mibs_under_change(s);
        cicp_ipif_row_free(&mib->ipif[id]);
        ipif_compact_one(mib, id);
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                    CP_SESSION_LADDR_REFRESH_NEEDED;
      }
    }
  MIB_UPDATE_LOOP_END(mib, s)
}

void cp_ipif_dump_done(struct cp_session* s)
{
  struct cp_mibs* mib;
  int mib_i;
  bool has_unseen = false;
  cicp_ipif_row_t* ipif;

  MIB_UPDATE_LOOP(mib, s, mib_i)
    cicp_rowid_t id = -1;
    if( has_unseen )
      cp_mibs_under_change(s);

    /* Unlike RTM_GETLINK, the RTM_GETADDR message type is not able to
     * request a specific address.  So we just remove all unseen rows. */
    while( (id = cp_row_mask_iter_set(s->seen, ++id,
                                      mib->dim->ipif_max, false) ) !=
           CICP_MAC_ROWID_BAD ) {
      ipif = &mib->ipif[id];
      if( cicp_ipif_row_is_free(ipif) )
        break;
      if( ! has_unseen ) {
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
        cp_mibs_under_change(s);
        has_unseen = true;
      }

      s->flags |= CP_SESSION_LADDR_REFRESH_NEEDED;
      cicp_ipif_row_free(ipif);
    }

    if( has_unseen )
      ipif_compact(mib);
  MIB_UPDATE_LOOP_END(mib, s);
}

static cicp_rowid_t
ip6if_find_row(ci_ifid_t ifindex, ci_ip6_addr_t net_ip,
               cicp_prefixlen_t net_ipset, const struct cp_mibs* mib)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->ip6if_max; i++ ) {
    if( mib->ip6if[i].ifindex == ifindex &&
        !memcmp(mib->ip6if[i].net_ip6, net_ip, sizeof(ci_ip6_addr_t)) &&
        mib->ip6if[i].net_ipset == net_ipset )
      return i;
    if( cicp_ip6if_row_is_free(&mib->ip6if[i]) )
      return CICP_ROWID_BAD;
  }
  return CICP_ROWID_BAD;
}

static cicp_rowid_t
ip6if_find_free(const struct cp_mibs* mib)
{
  cicp_rowid_t i;

  for( i = 0; i < mib->dim->ip6if_max; i++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[i]) )
      return i;
  }
  return CICP_ROWID_BAD;
}

static void
ip6if_compact_one(struct cp_mibs* mib, cicp_rowid_t id)
{
  cicp_rowid_t next;

  for( next = id; next + 1 < mib->dim->ip6if_max; next++ ) {
    if( cicp_ip6if_row_is_free(&mib->ip6if[next + 1]) )
      break;
    memcpy(&mib->ip6if[next], &mib->ip6if[next + 1], sizeof(mib->ip6if[0]));
  }
  cicp_ip6if_row_free(&mib->ip6if[next]);
}

static void
ip6if_compact(struct cp_mibs* mib)
{
  cicp_rowid_t free, move;

  free = ip6if_find_free(mib);

  if( free == CICP_ROWID_BAD )
    return;

  for( move = free + 1; move < mib->dim->ip6if_max; move++ )
    if( ! cicp_ip6if_row_is_free(&mib->ip6if[move]) )
      memcpy(&mib->ip6if[free++], &mib->ip6if[move], sizeof(mib->ip6if[0]));

  for( ; free < mib->dim->ip6if_max; free++ )
    cicp_ip6if_row_free(&mib->ip6if[free]);
}

static void
ip6if_handle(struct cp_session* s, uint16_t nlmsg_type,
             struct ifaddrmsg* ifmsg, size_t bytes)
{
  struct cp_mibs* mib;
  ci_ifid_t ifindex;
  ci_ip6_addr_t net_ip;
  cicp_prefixlen_t net_ipset;
  cicp_rowid_t id;
  cicp_ip6if_row_t* ip6if;
  int mib_i;

  if (ifmsg->ifa_family != AF_INET6)
    return;

  ifindex = ifmsg->ifa_index;
  net_ipset = ifmsg->ifa_prefixlen;
  memcpy(net_ip, in6addr_any.s6_addr, sizeof(net_ip));

  RTA_LOOP(ifmsg, attr, bytes) {
    if( (attr->rta_type & NLA_TYPE_MASK) == IFA_ADDRESS ) {
      memcpy(net_ip, (uint8_t*)RTA_DATA(attr), sizeof(net_ip));
      break;
    }
  }

  ci_assert(memcmp(net_ip, in6addr_any.s6_addr, sizeof(net_ip)));
  MIB_UPDATE_LOOP(mib, s, mib_i)
    id = ip6if_find_row(ifindex, net_ip, net_ipset, mib);

    if( nlmsg_type == RTM_NEWADDR ) {
      if( id != CICP_ROWID_BAD ) {
        ip6if = &mib->ip6if[id];
      }
      else {
        id = ip6if_find_free(mib);
        if( id == CICP_ROWID_BAD ) {
          static bool printed = false;
          if( ! printed ) {
            ci_log("ERROR: no free rows in the ip6if table; please increase "
                   "ipif-max parameter (currently ipif-max=%d).",
                   mib->dim->ip6if_max);
            printed = true;
          }
          MIB_UPDATE_LOOP_UNCHANGED(mib, s, return);
        }
        ip6if = &mib->ip6if[id];
        cp_mibs_under_change(s);
        ip6if->ifindex = ifindex;
        memcpy(ip6if->net_ip6, net_ip, sizeof(net_ip));
        if( ! mib_i )
          cp_ipif_notify_oof(s, mib, AF_INET6, id);
      }

      struct cp_ip_with_prefix src_rule;
      memcpy(src_rule.addr.ip6, net_ip, sizeof(src_rule.addr.ip6));
      src_rule.prefix = 128;

      if( ip6if->scope != ifmsg->ifa_scope ||
          ip6if->net_ipset != net_ipset ) {
        cp_mibs_under_change(s);
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
        ip6if->scope = ifmsg->ifa_scope;
        ci_wmb();
        ip6if->net_ipset = net_ipset;

        if( cp_ippl_add(&s->ip6_rule_src, &src_rule, NULL) )
          s->flags |= CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
      }
      if( s->state == CP_DUMP_IP6IF ) {
        cp_row_mask_set(s->seen, id);
        /* Mark this "rule" as seen. */
        cp_ippl_add(&s->ip6_rule_src, &src_rule, NULL);
      }
    }
    else {
      ci_assert_equal(nlmsg_type, RTM_DELADDR);
      if( id != CICP_ROWID_BAD ) {
        cp_mibs_under_change(s);
        cicp_ip6if_row_free(&mib->ip6if[id]);
        ip6if_compact_one(mib, id);
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                    CP_SESSION_LADDR_REFRESH_NEEDED;
      }
    }
  MIB_UPDATE_LOOP_END(mib, s)
}

void cp_ip6if_dump_done(struct cp_session* s)
{
  struct cp_mibs* mib;
  int mib_i;
  bool has_unseen = false;
  cicp_ip6if_row_t* ip6if;

  MIB_UPDATE_LOOP(mib, s, mib_i)
    cicp_rowid_t id = -1;
    if( has_unseen )
      cp_mibs_under_change(s);

    while( (id = cp_row_mask_iter_set(s->seen, ++id,
                                      mib->dim->ip6if_max, false) ) !=
           CICP_MAC_ROWID_BAD ) {
      ip6if = &mib->ip6if[id];
      if( cicp_ip6if_row_is_free(ip6if) )
        break;
      if( ! has_unseen ) {
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
        cp_mibs_under_change(s);
        has_unseen = true;
      }
      s->flags |= CP_SESSION_LADDR_REFRESH_NEEDED;
      cicp_ip6if_row_free(ip6if);
    }

    if( has_unseen )
      ip6if_compact(mib);
  MIB_UPDATE_LOOP_END(mib, s);
}

void cp_oof_req_do(struct cp_session* s)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  cicp_rowid_t i;

  /* Tell Onload about all llaps */
  for( i = 0; i < mib->dim->llap_max; i++ ) {
    cicp_llap_row_t* llap = &mib->llap[i];
    if( cicp_llap_row_is_free(llap) )
      break;
    cp_llap_notify_oof(s, llap);
  }

  /* Tell Onload about all local addresses */
  cicp_rowid_t id;
  for( id = 0; id < s->laddr.used; id++ ) {
    struct cp_ip_with_prefix* laddr = cp_ippl_entry(&s->laddr, id);
    if( laddr->prefix >= 0 )
      __cp_ipif_notify_oof(s, CI_ADDR_AF(laddr->addr), laddr, true);
  }

  ci_wmb();
  (*s->mib->oof_version)++;
  ci_wmb();
  cp_ready_usable(s);
}

static inline void
ipif_handle_generic(struct cp_session* s, uint16_t nlmsg_type,
                    struct ifaddrmsg* ifmsg, size_t bytes)
{
  if ( ifmsg->ifa_family == AF_INET )
    ipif_handle(s, nlmsg_type, ifmsg, bytes);
  else
    ip6if_handle(s, nlmsg_type, ifmsg, bytes);
}

/***** MAC table update *****/

static cicp_mac_rowid_t
mac_row_add(struct cp_session* s, int af, ci_addr_t addr, ci_ifid_t ifindex)
{
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_mac_hash(s, &addr, ifindex, &hash1, &hash2);
  hash = hash1;

  ci_assert(ifindex);

  do {
    cicp_mac_row_t* mac = &cp_get_mac_p(s, af)[hash];
    cp_row_mask_t mac_used = cp_get_mac_used(s, af);

    ci_assert_impl(cp_row_mask_get(mac_used, hash), mac->ifindex != 0);
    ci_assert_impl(cp_row_mask_get(mac_used, hash),
                   ! ( CI_IPX_ADDR_EQ(mac->addr, addr) && mac->ifindex == ifindex));
    mac->use++;
    if( ! cp_row_mask_get(mac_used, hash) ) {
      cp_row_mask_set(mac_used, hash);
      ci_assert_equal(mac->ifindex, 0);
      mac->addr = addr;
      ci_wmb(); /* favour for mibdump, so it has chance printing coherent ip */
      mac->ifindex = ifindex;
      return hash;
    }
    s->stats.mac.collision++;
    ci_assert_gt(mac->use, 1);
    hash = (hash + hash2) & s->mac_mask;
  } while( ++iter < CP_REHASH_LIMIT(s->mac_mask) && hash != hash1 );

  if( hash == hash1 ) {
#ifndef NDEBUG
    ci_log("%s: hash loop of length %d detected", __func__, iter);
#endif
    s->stats.mac.hash_loop++;
  }
  s->stats.mac.full++;

  cicp_mac_rowid_t end = hash;
  hash = hash1;
  iter = 0;
  do {
    cicp_mac_row_t* mac = &cp_get_mac_p(s, af)[hash];
    ci_assert_gt(mac->use, 1);
    mac->use--;
    hash = (hash + hash2) & s->mac_mask;
  } while( hash != end );

  return CICP_MAC_ROWID_BAD;
}

static void
mac_row_del(struct cp_session* s, int af, ci_addr_t addr,
            ci_ifid_t ifindex, cicp_mac_rowid_t rowid)
{
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_mac_hash(s, &addr, ifindex, &hash1, &hash2);
  hash = hash1;

  do {
    cicp_mac_row_t* mac = &cp_get_mac_p(s, af)[hash];
    cp_row_mask_t mac_used = cp_get_mac_used(s, af);

    ci_assert_gt(mac->use, 0);
    mac->use--;
    if( CI_IPX_ADDR_EQ(mac->addr, addr) && mac->ifindex == ifindex ) {
      /* use may be non-zero if other paths go through this entry.  Ensure
       * that user will not find this entry via cp_mac_find_row(). */
      ci_assert(cp_row_mask_get(mac_used, hash));
      ci_assert_nequal(mac->ifindex, 0);
      mac->ifindex = 0;
      cp_row_mask_unset(mac_used, hash);
      ci_assert_equal(hash, rowid);
      cp_fwd_mac_update(s, af, addr, ifindex, rowid, 0);
      return;
    }
    hash = (hash + hash2) & s->mac_mask;
  } while( ++iter < CP_REHASH_LIMIT(s->mac_mask) );

  /* We've already found this entry with cp_mac_find_row(),
   * so can't fail. */
  ci_assert(0);
}

static void
neigh_handle(struct cp_session* s, uint16_t nlmsg_type,
             struct ndmsg* ndmsg, size_t bytes)
{
  struct cp_mibs* mib = cp_get_active_mib(s);
  ci_addr_t addr = addr_any;
  ci_mac_addr_t mac;
  cicp_mac_rowid_t hash;
  ci_uint32 reachable_for_ms = 0;
  const int af = ndmsg->ndm_family;

  if( af != AF_INET && af != AF_INET6 )
    return;

  ci_assert_nequal(ndmsg->ndm_ifindex, CI_IFID_BAD);
  /* We are not interested in "ARP" on loopback interface */
  if( ndmsg->ndm_ifindex == CI_IFID_BAD ||
      ndmsg->ndm_ifindex == CI_IFID_LOOP )
    return;

  cicp_rowid_t llap_id = cp_llap_find_row(mib, ndmsg->ndm_ifindex);

  if( llap_id == CICP_ROWID_BAD )
    return;

  RTA_LOOP(ndmsg, attr, bytes) {
    switch( attr->rta_type & NLA_TYPE_MASK ) {
      case NDA_DST:
        if( af == AF_INET6 )
          memcpy(addr.ip6, (uint8_t*)RTA_DATA(attr), sizeof(addr.ip6));
        else
          addr = CI_ADDR_FROM_IP4(*((uint32_t *)RTA_DATA(attr)));
        break;

      case NDA_LLADDR:
        memcpy(mac, RTA_DATA(attr), sizeof(mac));
        break;

      case NDA_CACHEINFO:
        if( ndmsg->ndm_state == NUD_REACHABLE ) {
          struct nda_cacheinfo *cacheinfo = RTA_DATA(attr);
          reachable_for_ms = cacheinfo->ndm_confirmed * s->user_hz;
          /* MAC entry is guaranteed to be valid for arp_base_reachable/2.
           * We'd rather avoid NUD_STALE state, so we are asking Onload to
           * update the entry before "arp_base_reachable/3 - ndm_confirmed". */
          if( reachable_for_ms <
              s->llap_priv[llap_id].arp_base_reachable / 3 ) {
            reachable_for_ms =
                        s->llap_priv[llap_id].arp_base_reachable / 3 -
                        reachable_for_ms;
          }
          else {
            reachable_for_ms = 0;
          }
        }
        break;
    }
  }

  /* MAC addresses for multicast IPs are synthesised directly into the fwd
   * table, so they don't need any MAC-table entries.  Indeed, we mustn't add
   * any such entries, otherwise they'll break the corresponding fwd-table
   * entries when they're removed. */
  if( CI_IPX_IS_MULTICAST(addr) )
    return;

  hash = cp_mac_find_row(s, af,  addr, ndmsg->ndm_ifindex);
  if( nlmsg_type == RTM_NEWNEIGH ) {
    ci_uint64 frc = cp_frc64_get();
    int need_arp_refresh = (ndmsg->ndm_state == NUD_REACHABLE &&
                            reachable_for_ms == 0) ?
                           CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE : 0;

    if( hash == CICP_MAC_ROWID_BAD ) {
      hash = mac_row_add(s, af, addr, ndmsg->ndm_ifindex);
      if( hash == CICP_MAC_ROWID_BAD ) {
        CI_RLLOG(10,
                 "ERROR: failed to store entry for %s via %s",
                 AF_IP_L3(addr), mib->llap[llap_id].name);
        return;
      }
      cicp_mac_row_t* mr = &cp_get_mac_p(s, af)[hash];
      memcpy(mr->mac, mac, sizeof(mac));
      mr->state = ndmsg->ndm_state;
      mr->flags = 0;
      if( ndmsg->ndm_state == NUD_REACHABLE )
        mr->frc_reconfirm = frc + reachable_for_ms * s->khz;
      cp_fwd_mac_update(s, af, addr, ndmsg->ndm_ifindex, hash, need_arp_refresh);
    }
    else {
      /* We are updating the existing entry. */
      cicp_mac_row_t* mr = &cp_get_mac_p(s, af)[hash];
      ci_uint16 old_state = mr->state;
      int old_need_arp_refresh = cp_mac_need_refresh(mr, frc) ?
                                 CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE : 0;
      int old_flag_failed = (mr->flags & CP_MAC_ROW_FLAG_FAILED);

      /* If we get FAILED after INCOMPLETE, then it is a real FAILED.
       * Otherwise we will ask kernel re-resolve it to be sure provided any
       * fwd entry uses it.
       *
       * AF_INET6: it is ugly, but Linux behaves differently in IPv4 and
       * IPv6 cases.  This check (1) makes Onload to work as Linux and
       * (2) allows the Socket Tester to remove permanent neighbour entires
       * (see bug 88584).
       */
      if( ndmsg->ndm_state == NUD_FAILED ) {
        if( af == AF_INET6 || (old_state & NUD_INCOMPLETE) )
          mr->flags |= CP_MAC_ROW_FLAG_FAILED;
        /* else we keep the old value of CP_MAC_ROW_FLAG_FAILED */
      }
      else {
        mr->flags &=~ CP_MAC_ROW_FLAG_FAILED;
      }

      mr->state = ndmsg->ndm_state;

      if( !(old_state & NUD_VALID) != !(ndmsg->ndm_state & NUD_VALID) ||
          memcmp(mr->mac, mac, sizeof(mac)) != 0 ||
          old_flag_failed != (mr->flags & CP_MAC_ROW_FLAG_FAILED) ) {
        /* The entry is really changing */
        if( ndmsg->ndm_state & NUD_VALID )
          memcpy(mr->mac, mac, sizeof(mac));
        cp_fwd_mac_update(s, af, addr, ndmsg->ndm_ifindex, hash, need_arp_refresh);
      }
      else if( old_need_arp_refresh != need_arp_refresh) {
        cp_fwd_mac_update(s, af, addr, ndmsg->ndm_ifindex, hash,
                          need_arp_refresh |
                          CP_FWD_MAC_UPDATE_FLAG_NEED_UPDATE_ONLY);
      }

      switch( ndmsg->ndm_state ) {
        case NUD_STALE:
          /* The entry is good, but it should be re-resolved if in use. */
          cp_fwd_mac_is_stale(s, af, hash);
          break;

        case NUD_REACHABLE:
          mr->frc_reconfirm = frc + reachable_for_ms * s->khz;
      }
    }
    if( ( af == AF_INET6 && s->state == CP_DUMP_MAC6) ||
        (af == AF_INET && s->state == CP_DUMP_MAC) )
      cp_row_mask_set(s->seen, hash);
  }
  else if( hash != CICP_MAC_ROWID_BAD ) {
    mac_row_del(s, af, addr, ndmsg->ndm_ifindex, hash);
    cp_fwd_mac_update(s, af, addr, ndmsg->ndm_ifindex, CICP_MAC_ROWID_BAD, 0);
  }
}

void cp_mac_dump_done(struct cp_session* s, int af)
{
  cicp_mac_rowid_t id = -1;
  cp_row_mask_t mac_used = cp_get_mac_used(s, af);

  /* Mark all unused rows as "seen": seen |= ~mac_mask */
  cp_row_mask_do_or_not(s->seen, mac_used, s->mac_mask + 1);

  while( (id = cp_row_mask_iter_set(s->seen, ++id,
                                    s->mac_mask + 1, false) ) !=
         CICP_MAC_ROWID_BAD ) {
    cicp_mac_row_t* mac = &cp_get_mac_p(s, af)[id];
    if( mac->ifindex == 0 )
      continue;

    /* Unlike llap of ipif, we do not try to re-establish these MAC entries;
     * we believe they will show up soon if they are really in use. */
    mac_row_del(s, af, mac->addr, mac->ifindex, id);
  }
}


/***** Generic netlink helpers *****/

static void error_handle(struct cp_session* s,
                         struct nlmsgerr* err, size_t bytes)
{
  switch( err->msg.nlmsg_type ) {
    case RTM_GETROUTE:
      s->stats.nlmsg_error.route++;
      /* Route subsystem wants to know about any errors: */
      cp_nl_error_route_handle(s, err, bytes);
      return;
    case RTM_GETLINK:
      if( err->error == -ENODEV ) {
        /* It is probably the result of "llap remove because of dump". */
        s->stats.nlmsg_error.link_nodev++;
        return;
      }
      else {
        s->stats.nlmsg_error.link++;
      }
      break;
    case RTM_GETADDR:
      s->stats.nlmsg_error.addr++;
      break;
    case RTM_GETNEIGH:
      s->stats.nlmsg_error.neigh++;
      break;
    case RTM_GETRULE:
      /* The kernel does not support IP rules, not an error */
      if( err->error == -ENOTSUP ) {
        ci_assert(s->state == CP_DUMP_RULE || s->state == CP_DUMP_RULE6);
        cp_do_dump(s);
        return;
      }
      s->stats.nlmsg_error.rule++;
      break;
    default:
      s->stats.nlmsg_error.other++;
  }
  /* We do not expect any other errors, so let's log them. */
  ci_log("NLMSG_ERROR message type %d: %s",
         err->msg.nlmsg_type, strerror(-err->error));
}

ssize_t cp_sock_recv(struct cp_session* s, int sock)
{
  char small_buf[1];
  ssize_t bytes;

  /* FIONREAD does not work for netlink sockets, so we use MSG_PEEK. */
  bytes = recv(sock, &small_buf, sizeof(small_buf), MSG_PEEK | MSG_TRUNC);
  if( bytes <= 0 )
    return bytes;
  if( s->buf_size < bytes ) {
    s->buf = realloc(s->buf, bytes);
    if( s->buf == NULL ) {
      s->buf_size = 0;
      errno = ENOMEM;
      return -1;
    }
    s->buf_size = bytes;
  }
  return recv(sock, s->buf, s->buf_size, 0);
}

CP_UNIT_EXTERN void
cp_nl_net_handle_msg(struct cp_session* s, struct nlmsghdr* nlhdr,
                     ssize_t bytes)
{
  while( NLMSG_OK(nlhdr, bytes) ) {
    switch( nlhdr->nlmsg_type ) {
      case NLMSG_ERROR:
        error_handle(s, NLMSG_DATA(nlhdr),
                     NLMSG_PAYLOAD(nlhdr, sizeof(struct nlmsgerr)));
        break;

      case NLMSG_NOOP:
        break;

      case NLMSG_DONE:
        cp_do_dump(s);
        break;

      case RTM_NEWNEIGH:
      case RTM_DELNEIGH:
        neigh_handle(s, nlhdr->nlmsg_type, NLMSG_DATA(nlhdr),
                     NLMSG_PAYLOAD(nlhdr, sizeof(struct ndmsg)));
        break;

      case RTM_NEWRULE:
        cp_newrule_handle(s, nlhdr->nlmsg_type, NLMSG_DATA(nlhdr),
                          NLMSG_PAYLOAD(nlhdr,
                                        sizeof(struct fib_rule_hdr)));
        /* cp_newrule_handle() sets
         * CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED if really needed,
         * but we have to set CP_SESSION_FLAG_FWD_REFRESH_NEEDED unless we
         * are in a dump. */
        if( s->state != CP_DUMP_RULE )
          s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
        break;
      case RTM_DELRULE:
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                    CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
        break;

      case RTM_NEWROUTE:
      {
        struct rtmsg* rtm = NLMSG_DATA(nlhdr);

        switch( rtm->rtm_family ) {
          case AF_INET:
            if( rtm->rtm_src_len != 32 && rtm->rtm_src_len != 0 )
              goto bad_newroute;
            break;
          case AF_INET6:
            if( rtm->rtm_src_len != 128 && rtm->rtm_src_len != 0)
              goto bad_newroute;
            break;
          default:
            goto bad_newroute;
        }
        if( nlhdr->nlmsg_pid == s->sock_net_name.nl_pid &&
            nlhdr->nlmsg_seq != CP_FWD_FLAG_DUMP ) {
          /* this is an answer to our request for a particular /32 route */
          cp_nl_route_handle(s, nlhdr, rtm,
                             NLMSG_PAYLOAD(nlhdr, sizeof(struct rtmsg)));
          break;
        }

        /* We use the same parser for RTM_NEWRULE and RTM_NEWROUTE,
         * because the netlink messages are really structured in the same
         * way. */
        CI_BUILD_ASSERT(sizeof(struct fib_rule_hdr) == sizeof(struct rtmsg));
        cp_newrule_handle(s, nlhdr->nlmsg_type, NLMSG_DATA(nlhdr),
                          NLMSG_PAYLOAD(nlhdr, sizeof(struct rtmsg)));

        /* Maintain our mirror of the route tables */
        cp_nl_route_table_update(s, nlhdr, rtm,
                                 NLMSG_PAYLOAD(nlhdr, sizeof(struct rtmsg)));

        /* We need to refresh fwd cache if it is a new route.
         * We always refresh fwd cache during full dump.
         * So we do not check if it is a new route or re-dump of existing
         * route; let's refresh in any case. */
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED;
        break;
      bad_newroute:
        ci_log("ERROR: unknown address family %d or unexpected source "
               "address length %d in a RTM_NEWROUTE message",
               rtm->rtm_family, rtm->rtm_src_len);
        ci_assert(0);
        break;
      }
      case RTM_DELROUTE:
        /* Maintain our mirror of the route tables */
        cp_nl_route_table_update(s, nlhdr, NLMSG_DATA(nlhdr),
                                 NLMSG_PAYLOAD(nlhdr, sizeof(struct rtmsg)));
        s->flags |= CP_SESSION_FLAG_FWD_REFRESH_NEEDED |
                    CP_SESSION_FLAG_FWD_PREFIX_CHECK_NEEDED;
        break;

      case RTM_NEWADDR:
      case RTM_DELADDR:
        ipif_handle_generic(s, nlhdr->nlmsg_type, NLMSG_DATA(nlhdr),
                            NLMSG_PAYLOAD(nlhdr, sizeof(struct ifaddrmsg)));
        break;

      case RTM_NEWLINK:
      case RTM_DELLINK:
        llap_handle(s, nlhdr->nlmsg_type, NLMSG_DATA(nlhdr),
                    NLMSG_PAYLOAD(nlhdr, sizeof(struct ifinfomsg)));
        break;

      default:
        ci_log("ERROR: unknown RTM message type %d", nlhdr->nlmsg_type);
        ci_assert(0);
        break;
    }
    nlhdr = NLMSG_NEXT(nlhdr, bytes);
  }
}


void nl_net_handle(struct cp_session* s, struct cp_epoll_state* state)
{
  ssize_t bytes;

  while ( (bytes = cp_sock_recv(s, s->sock_net)) > 0 )
    cp_nl_net_handle_msg(s, s->buf, bytes);
}


static const char*
nud_state_str(int state)
{
  switch(state) {
  case NUD_INCOMPLETE: return "incomplete";
  case NUD_REACHABLE:  return "reachable";
  case NUD_STALE:      return "stale";
  case NUD_DELAY:      return "delay";
  case NUD_PROBE:      return "probe";
  case NUD_FAILED:     return "failed";
  case NUD_NOARP:      return "noarp";
  case NUD_PERMANENT:  return "permanent";
  case NUD_NONE:       return "none";
  default:             return "<other>";
  }
}

static void
cp_mac_print_generic(struct cp_session* s, int af)
{
  cicp_mac_rowid_t id = -1;
  ci_uint64 frc = ci_frc64_get();
  cp_row_mask_t mac_used = cp_get_mac_used(s, af);

  while( (id = cp_row_mask_iter_set(mac_used, ++id,
                                    s->mac_mask + 1, true) ) !=
         CICP_MAC_ROWID_BAD ) {
    cicp_mac_row_t* mac = &cp_get_mac_p(s, af)[id];

    if( mac->ifindex == 0 ) {
      cp_print(s, "mac[%d]: in use by %d paths", id, mac->use);
      continue;
    }

    cp_print(s, "mac[%03d]: if %d ip %s"
             " mac " CI_MAC_PRINTF_FORMAT " %s (%d refs) "
             CP_MAC_ROW_FLAGS_FMT,
             id, mac->ifindex, AF_IP_L3(mac->addr),
             CI_MAC_PRINTF_ARGS(&mac->mac),
             nud_state_str(mac->state), mac->use,
             CP_MAC_ROW_FLAGS_ARGS(mac->flags));
    if( mac->state == NUD_REACHABLE ) {
      cp_print(s, "\tto be re-confirmed after %d msec",
               ci_frc64_after(frc, mac->frc_reconfirm) ?
               (int)((mac->frc_reconfirm - frc) / s->khz) : 0);
    }
  }
}

void cp_mac_print(struct cp_session* s)
{
  cp_print(s, "%s:", __func__);
  cp_mac_print_generic(s, AF_INET);
}

void cp_mac6_print(struct cp_session* s)
{
  cp_print(s, "%s:", __func__);

  if( s->flags & CP_SESSION_NO_IPV6 ) {
    cp_print(s, "IPv6 support disabled");
    return;
  }

  cp_mac_print_generic(s, AF_INET6);
}

void cp_llap_print(struct cp_session* s)
{
  cicp_rowid_t id = -1;

  cp_print(s, "%s:", __func__);

  for( id = 0; id < s->mib->dim->llap_max; id++ ) {
    if( cicp_llap_row_is_free(&s->mib->llap[id]) )
      return;

    cp_print(s, "llap[%03d]: "CICP_ENCAP_NAME_FMT" arp_base %dms",
             id,
             cicp_encap_name(s->llap_priv[id].immediate_type),
             (int)s->llap_priv[id].arp_base_reachable);
  }
}

