/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2018-2020 Xilinx, Inc. */

CP_STAT_GROUP_START("NLMSG_ERROR messsages", nlmsg_error)
CP_STAT("Expected error (ENODEV) for RTM_GETLINK", int, link_nodev)
CP_STAT("Other errors for RTM_GETLINK", int, link);
CP_STAT("For RTM_GETADDR", int, addr);
CP_STAT("For RTM_GETNEIGH", int, neigh);
CP_STAT("For RTM_GETROUTE", int, route);
CP_STAT("For RTM_GETRULE", int, rule);
CP_STAT("For other message types", int, other);
CP_STAT_GROUP_END(nlmsg_error)

CP_STAT_GROUP_START("FWD table", fwd)
CP_STAT("Overall number of collisions", int, collision)
CP_STAT("Number of hash loops", int, hash_loop)
CP_STAT("Failed to insert a row because the table is full", int, full)
CP_STAT("Number of 'Fwd resolve request complete' events", int, req_complete)
CP_STAT("Failed to enqueue a route request", int, req_enqueue_fail)
CP_STAT("Failed to dequeue a matching route request", int, req_dequeue_fail)
CP_STAT("Current length of fwd queue", int, req_queue_len)
CP_STAT("High watermark of fwd-queue length", int, req_queue_hiwat)
CP_STAT("Failed to find fwd table for a request", int, table_missing)
CP_STAT("Failed to map fwd table", int, table_map_fail)
CP_STAT("How many times a netlink message had a wrong id when "
        "updating an existing entry", int, nlmsg_mismatch)
CP_STAT("How many times an NLMSG_ERROR message had a wrong id when "
        "updating an existing entry", int, error_mismatch)
CP_STAT_GROUP_END(fwd)

CP_STAT_GROUP_START("ARP table", mac)
CP_STAT("Overall number of collisions", int, collision)
CP_STAT("Number of hash loops", int, hash_loop)
CP_STAT("Failed to insert a row because the table is full", int, full)
CP_STAT_GROUP_END(mac)

CP_STAT_GROUP_START("LLAP table", llap)
CP_STAT("Number of times we handled unuspported ARPHRD_* in ifi_type",
        int, unsupported_ifi_type)
CP_STAT("Number of times we saw unknown value in IFLA_INFO_KIND attribute",
        int, unsupported_info_kind)
CP_STAT("Number of times we saw vlan-over-something", int,
        unsupported_vlan)
CP_STAT("Number of times when the table was full", int, full)
CP_STAT("Number of times a veth-peer was missing", int, veth_peer_missing)
CP_STAT_GROUP_END(llap)

CP_STAT_GROUP_START("IPIF table", ipif)
CP_STAT("Number of times when the table was full", int, full)
CP_STAT_GROUP_END(ipif)

CP_STAT_GROUP_START("Notifications", notify)
CP_STAT("Number of OOF_CP_LLAP_MOD notifications", int, llap_mod)
CP_STAT("Number of OOF_CP_LLAP_UPDATE_FILTERS notifications",
        int, llap_update_filters)
CP_STAT("Number of OOF_CP_IP_MOD notifications", int, ip_mod)
CP_STAT("Number of CP_READY notifications", int, ready)
CP_STAT("Number of Kubernetes external-service additions", int, svc_add)
CP_STAT("Number of Kubernetes external-service deletions", int, svc_del)
CP_STAT("Number of Kubernetes external-service resets", int, svc_erase_all)
CP_STAT_GROUP_END(notify)

CP_STAT_GROUP_START("Licensing", license)
CP_STAT("Number of good Onload licenses", int, onload)
CP_STAT("Number of good Onload UDP licenses", int, onload_udp)
CP_STAT("Number of good Onload ULL licenses", int, onload_ull)
CP_STAT("Number of NICs without any Onload license", int, non_onload)
CP_STAT("Number of good TCP Direct licenses", int, tcp_direct)
CP_STAT("Number of 7000-series NICs", int, ef10)
CP_STAT("Number of 8000-series NICs", int, medford)
CP_STAT("Number of times we detected rename of a network interface",
        int, rename)
CP_STAT("Number of times we failed to find network interface name "
        "because of too many renames",
        int, too_many_renames)
CP_STAT("Number of network interfaces with sfc driver", int, sfc_driver)
CP_STAT("Number of network interfaces with non-sfc driver",
        int, non_sfc_driver)
CP_STAT_GROUP_END(license)

CP_STAT_GROUP_START("Multipath routing", route)
CP_STAT("Netlink refers to unknown table", int, unknown_table)
CP_STAT("No matching route in the given table", int, no_match)
CP_STAT("Failed to find any suitable source address", int, no_source)
CP_STAT("Data mismatch between netlink info and route tables, used when "
        "--verify-routes is specified or multipath route is present",
        int, mismatch)
CP_STAT_GROUP_END(route)
