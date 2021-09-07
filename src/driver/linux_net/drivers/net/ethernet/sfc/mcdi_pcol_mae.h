/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2019 Solarflare Communications Inc.
 * Copyright 2019 Xilinx, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */


#ifndef MCDI_PCOL_MAE_H
#define MCDI_PCOL_MAE_H

/* DEVEL_PCIE_INTERFACE enum: From EF100 onwards, SFC products can have
 * multiple PCIe interfaces. There is a need to refer to interfaces explicitly
 * from drivers (for example, a management driver on one interface
 * administering a function on another interface). This enumeration provides
 * stable identifiers to all interfaces present on a product. Product
 * documentation will specify which interfaces exist and their associated
 * identifier. In general, drivers, should not assign special meanings to
 * specific values. Instead, behaviour should be determined by NIC
 * configuration, which will identify interfaces where appropriate.
 */
/* enum: Primary host interfaces. Typically (i.e. for all known SFC products)
 * the interface exposed on the edge connector (or form factor equivalent).
 */
#define          DEVEL_PCIE_INTERFACE_HOST_PRIMARY 0x1
/* enum: Riverhead and keystone products have a second PCIe interface to which
 * an on-NIC ARM module is expected to be connecte.
 */
#define          DEVEL_PCIE_INTERFACE_NIC_EMBEDDED 0x2
/* enum: For MCDI commands issued over a PCIe interface, this value is
 * translated into the interface over which the command was issued. Not
 * meaningful for other MCDI transports.
 */
#define          DEVEL_PCIE_INTERFACE_CALLER 0xffffffff

/***********************************/
/* MC_CMD_MAE_COUNTER_LIST_ALLOC
 * Allocate a list of match-action-engine counters
 */
#define MC_CMD_MAE_COUNTER_LIST_ALLOC 0x145
#undef MC_CMD_0x145_PRIVILEGE_CTG

#define MC_CMD_0x145_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_COUNTER_LIST_ALLOC_IN msgrequest */
#define    MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_LENMIN 8
#define    MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_LENMAX 252
#define    MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_LENMAX_MCDI2 1020
#define    MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_LEN(num) (4+4*(num))
#define    MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_IDS_NUM(len) (((len)-4)/4)
/* Number of elements in the COUNTER_IDS field. */
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_ID_COUNT_OFST 0
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_ID_COUNT_LEN 4
/* An array containing the IDs for the counters that should comprise this
 * counter list.
 */
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_IDS_OFST 4
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_IDS_LEN 4
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_IDS_MINNUM 1
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_IDS_MAXNUM 62
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_IN_COUNTER_IDS_MAXNUM_MCDI2 254

/* MC_CMD_MAE_COUNTER_LIST_ALLOC_OUT msgresponse */
#define    MC_CMD_MAE_COUNTER_LIST_ALLOC_OUT_LEN 4
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_OUT_COUNTER_LIST_ID_OFST 0
#define       MC_CMD_MAE_COUNTER_LIST_ALLOC_OUT_COUNTER_LIST_ID_LEN 4
/* enum: A counter ID that is guaranteed never to represent a real counter */
#define          MC_CMD_MAE_COUNTER_LIST_ALLOC_OUT_COUNTER_LIST_ID_NULL 0xffffffff


/***********************************/
/* MC_CMD_MAE_COUNTER_LIST_FREE
 * Free match-action-engine counter lists
 */
#define MC_CMD_MAE_COUNTER_LIST_FREE 0x146
#undef MC_CMD_0x146_PRIVILEGE_CTG

#define MC_CMD_0x146_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_COUNTER_LIST_FREE_IN msgrequest */
#define    MC_CMD_MAE_COUNTER_LIST_FREE_IN_LENMIN 4
#define    MC_CMD_MAE_COUNTER_LIST_FREE_IN_LENMAX 128
#define    MC_CMD_MAE_COUNTER_LIST_FREE_IN_LENMAX_MCDI2 128
#define    MC_CMD_MAE_COUNTER_LIST_FREE_IN_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_COUNTER_LIST_FREE_IN_FREE_COUNTER_LIST_ID_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_COUNTER_LIST_FREE_IN_FREE_COUNTER_LIST_ID_OFST 0
#define       MC_CMD_MAE_COUNTER_LIST_FREE_IN_FREE_COUNTER_LIST_ID_LEN 4
#define       MC_CMD_MAE_COUNTER_LIST_FREE_IN_FREE_COUNTER_LIST_ID_MINNUM 1
#define       MC_CMD_MAE_COUNTER_LIST_FREE_IN_FREE_COUNTER_LIST_ID_MAXNUM 32
#define       MC_CMD_MAE_COUNTER_LIST_FREE_IN_FREE_COUNTER_LIST_ID_MAXNUM_MCDI2 32

/* MC_CMD_MAE_COUNTER_LIST_FREE_OUT msgresponse */
#define    MC_CMD_MAE_COUNTER_LIST_FREE_OUT_LENMIN 4
#define    MC_CMD_MAE_COUNTER_LIST_FREE_OUT_LENMAX 128
#define    MC_CMD_MAE_COUNTER_LIST_FREE_OUT_LENMAX_MCDI2 128
#define    MC_CMD_MAE_COUNTER_LIST_FREE_OUT_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_COUNTER_LIST_FREE_OUT_FREED_COUNTER_LIST_ID_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_COUNTER_LIST_FREE_OUT_FREED_COUNTER_LIST_ID_OFST 0
#define       MC_CMD_MAE_COUNTER_LIST_FREE_OUT_FREED_COUNTER_LIST_ID_LEN 4
#define       MC_CMD_MAE_COUNTER_LIST_FREE_OUT_FREED_COUNTER_LIST_ID_MINNUM 1
#define       MC_CMD_MAE_COUNTER_LIST_FREE_OUT_FREED_COUNTER_LIST_ID_MAXNUM 32
#define       MC_CMD_MAE_COUNTER_LIST_FREE_OUT_FREED_COUNTER_LIST_ID_MAXNUM_MCDI2 32

/***********************************/
/* MC_CMD_MAE_OR_CLASS_REG
 * Register an outer rule class. For rule allocation to succeed, the rule's
 * class must be supported and allocated (rule allocation includes an implicit
 * attempt to allocate the rule's class, which will fail if the class is not
 * supported), there must be sufficient rule resources, and rule's actions must
 * be supported (which a driver can determine ahead of time). Where rule
 * allocation is only permitted to fail to due lack of rule resources, drivers
 * register the relevent rule resource, guaranteeing that it is supported and
 * remains allocated until unregistered by the driver. The class to be
 * registered is identified by the priority and fields mask/value pairs of an
 * outer rule, those being the properties of an outer rule that can affect the
 * mapping from outer rule to outer rule class. See SF-122526-TC-A for further
 * details.
 */
#define MC_CMD_MAE_OR_CLASS_REG 0x156
#undef MC_CMD_0x156_PRIVILEGE_CTG

#define MC_CMD_0x156_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_OR_CLASS_REG_IN msgrequest */
#define    MC_CMD_MAE_OR_CLASS_REG_IN_LENMIN 4
#define    MC_CMD_MAE_OR_CLASS_REG_IN_LENMAX 252
#define    MC_CMD_MAE_OR_CLASS_REG_IN_LENMAX_MCDI2 1020
#define    MC_CMD_MAE_OR_CLASS_REG_IN_LEN(num) (4+1*(num))
#define    MC_CMD_MAE_OR_CLASS_REG_IN_FIELDS_NUM(len) (((len)-4)/1)
#define       MC_CMD_MAE_OR_CLASS_REG_IN_PRIO_OFST 0
#define       MC_CMD_MAE_OR_CLASS_REG_IN_PRIO_LEN 4
/* Structure of the format MAE_ENC_FIELD_PAIRS */
#define       MC_CMD_MAE_OR_CLASS_REG_IN_FIELDS_OFST 4
#define       MC_CMD_MAE_OR_CLASS_REG_IN_FIELDS_LEN 1
#define       MC_CMD_MAE_OR_CLASS_REG_IN_FIELDS_MINNUM 0
#define       MC_CMD_MAE_OR_CLASS_REG_IN_FIELDS_MAXNUM 248
#define       MC_CMD_MAE_OR_CLASS_REG_IN_FIELDS_MAXNUM_MCDI2 1016

/* MC_CMD_MAE_OR_CLASS_REG_OUT msgresponse */
#define    MC_CMD_MAE_OR_CLASS_REG_OUT_LEN 4
#define       MC_CMD_MAE_OR_CLASS_REG_OUT_ORC_HANDLE_OFST 0
#define       MC_CMD_MAE_OR_CLASS_REG_OUT_ORC_HANDLE_LEN 4
/* enum: An outer rule class handle that is guaranteed never to represent an
 * outer rule class
 */
#define          MC_CMD_MAE_OR_CLASS_REG_OUT_OUTER_RULE_CLASS_HANDLE_NULL 0xffffffff


/***********************************/
/* MC_CMD_MAE_OR_CLASS_UNREG
 */
#define MC_CMD_MAE_OR_CLASS_UNREG 0x157
#undef MC_CMD_0x157_PRIVILEGE_CTG

#define MC_CMD_0x157_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_OR_CLASS_UNREG_IN msgrequest */
#define    MC_CMD_MAE_OR_CLASS_UNREG_IN_LENMIN 4
#define    MC_CMD_MAE_OR_CLASS_UNREG_IN_LENMAX 128
#define    MC_CMD_MAE_OR_CLASS_UNREG_IN_LENMAX_MCDI2 128
#define    MC_CMD_MAE_OR_CLASS_UNREG_IN_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_OR_CLASS_UNREG_IN_ORC_HANDLE_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_OR_CLASS_UNREG_IN_ORC_HANDLE_OFST 0
#define       MC_CMD_MAE_OR_CLASS_UNREG_IN_ORC_HANDLE_LEN 4
#define       MC_CMD_MAE_OR_CLASS_UNREG_IN_ORC_HANDLE_MINNUM 1
#define       MC_CMD_MAE_OR_CLASS_UNREG_IN_ORC_HANDLE_MAXNUM 32
#define       MC_CMD_MAE_OR_CLASS_UNREG_IN_ORC_HANDLE_MAXNUM_MCDI2 32

/* MC_CMD_MAE_OR_CLASS_UNREG_OUT msgresponse */
#define    MC_CMD_MAE_OR_CLASS_UNREG_OUT_LENMIN 4
#define    MC_CMD_MAE_OR_CLASS_UNREG_OUT_LENMAX 128
#define    MC_CMD_MAE_OR_CLASS_UNREG_OUT_LENMAX_MCDI2 128
#define    MC_CMD_MAE_OR_CLASS_UNREG_OUT_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_OR_CLASS_UNREG_OUT_UNREGD_ORC_HANDLE_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_OR_CLASS_UNREG_OUT_UNREGD_ORC_HANDLE_OFST 0
#define       MC_CMD_MAE_OR_CLASS_UNREG_OUT_UNREGD_ORC_HANDLE_LEN 4
#define       MC_CMD_MAE_OR_CLASS_UNREG_OUT_UNREGD_ORC_HANDLE_MINNUM 1
#define       MC_CMD_MAE_OR_CLASS_UNREG_OUT_UNREGD_ORC_HANDLE_MAXNUM 32
#define       MC_CMD_MAE_OR_CLASS_UNREG_OUT_UNREGD_ORC_HANDLE_MAXNUM_MCDI2 32

/***********************************/
/* MC_CMD_MAE_AR_CLASS_REG
 * Same semantics as MC_CMD_MAE_OR_CLASS_REG
 */
#define MC_CMD_MAE_AR_CLASS_REG 0x158
#undef MC_CMD_0x158_PRIVILEGE_CTG

#define MC_CMD_0x158_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_AR_CLASS_REG_IN msgrequest */
#define    MC_CMD_MAE_AR_CLASS_REG_IN_LENMIN 4
#define    MC_CMD_MAE_AR_CLASS_REG_IN_LENMAX 252
#define    MC_CMD_MAE_AR_CLASS_REG_IN_LENMAX_MCDI2 1020
#define    MC_CMD_MAE_AR_CLASS_REG_IN_LEN(num) (4+1*(num))
#define    MC_CMD_MAE_AR_CLASS_REG_IN_FIELDS_NUM(len) (((len)-4)/1)
#define       MC_CMD_MAE_AR_CLASS_REG_IN_PRIO_OFST 0
#define       MC_CMD_MAE_AR_CLASS_REG_IN_PRIO_LEN 4
/* Structure of the format MAE_FIELD_MASK_VALUE_PAIRS */
#define       MC_CMD_MAE_AR_CLASS_REG_IN_FIELDS_OFST 4
#define       MC_CMD_MAE_AR_CLASS_REG_IN_FIELDS_LEN 1
#define       MC_CMD_MAE_AR_CLASS_REG_IN_FIELDS_MINNUM 0
#define       MC_CMD_MAE_AR_CLASS_REG_IN_FIELDS_MAXNUM 248
#define       MC_CMD_MAE_AR_CLASS_REG_IN_FIELDS_MAXNUM_MCDI2 1016

/* MC_CMD_MAE_AR_CLASS_REG_OUT msgresponse */
#define    MC_CMD_MAE_AR_CLASS_REG_OUT_LEN 4
#define       MC_CMD_MAE_AR_CLASS_REG_OUT_ARC_HANDLE_OFST 0
#define       MC_CMD_MAE_AR_CLASS_REG_OUT_ARC_HANDLE_LEN 4
/* enum: An action rule class handle that is guaranteed never to represent an
 * action rule class
 */
#define          MC_CMD_MAE_AR_CLASS_REG_OUT_ACTION_RULE_CLASS_HANDLE_NULL 0xffffffff


/***********************************/
/* MC_CMD_MAE_AR_CLASS_UNREG
 */
#define MC_CMD_MAE_AR_CLASS_UNREG 0x159
#undef MC_CMD_0x159_PRIVILEGE_CTG

#define MC_CMD_0x159_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_AR_CLASS_UNREG_IN msgrequest */
#define    MC_CMD_MAE_AR_CLASS_UNREG_IN_LENMIN 4
#define    MC_CMD_MAE_AR_CLASS_UNREG_IN_LENMAX 128
#define    MC_CMD_MAE_AR_CLASS_UNREG_IN_LENMAX_MCDI2 128
#define    MC_CMD_MAE_AR_CLASS_UNREG_IN_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_AR_CLASS_UNREG_IN_ARC_HANDLE_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_AR_CLASS_UNREG_IN_ARC_HANDLE_OFST 0
#define       MC_CMD_MAE_AR_CLASS_UNREG_IN_ARC_HANDLE_LEN 4
#define       MC_CMD_MAE_AR_CLASS_UNREG_IN_ARC_HANDLE_MINNUM 1
#define       MC_CMD_MAE_AR_CLASS_UNREG_IN_ARC_HANDLE_MAXNUM 32
#define       MC_CMD_MAE_AR_CLASS_UNREG_IN_ARC_HANDLE_MAXNUM_MCDI2 32

/* MC_CMD_MAE_AR_CLASS_UNREG_OUT msgresponse */
#define    MC_CMD_MAE_AR_CLASS_UNREG_OUT_LENMIN 4
#define    MC_CMD_MAE_AR_CLASS_UNREG_OUT_LENMAX 128
#define    MC_CMD_MAE_AR_CLASS_UNREG_OUT_LENMAX_MCDI2 128
#define    MC_CMD_MAE_AR_CLASS_UNREG_OUT_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_AR_CLASS_UNREG_OUT_UNREGD_ARC_HANDLE_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_AR_CLASS_UNREG_OUT_UNREGD_ARC_HANDLE_OFST 0
#define       MC_CMD_MAE_AR_CLASS_UNREG_OUT_UNREGD_ARC_HANDLE_LEN 4
#define       MC_CMD_MAE_AR_CLASS_UNREG_OUT_UNREGD_ARC_HANDLE_MINNUM 1
#define       MC_CMD_MAE_AR_CLASS_UNREG_OUT_UNREGD_ARC_HANDLE_MAXNUM 32
#define       MC_CMD_MAE_AR_CLASS_UNREG_OUT_UNREGD_ARC_HANDLE_MAXNUM_MCDI2 32

/* MAE_ACTION_RULE_RESPONSE structuredef */
#define    MAE_ACTION_RULE_RESPONSE_LEN 16
#define       MAE_ACTION_RULE_RESPONSE_ASL_ID_OFST 0
#define       MAE_ACTION_RULE_RESPONSE_ASL_ID_LEN 4
#define       MAE_ACTION_RULE_RESPONSE_ASL_ID_LBN 0
#define       MAE_ACTION_RULE_RESPONSE_ASL_ID_WIDTH 32
/* Only one of ASL_ID or AS_ID may have a non-NULL value. */
#define       MAE_ACTION_RULE_RESPONSE_AS_ID_OFST 4
#define       MAE_ACTION_RULE_RESPONSE_AS_ID_LEN 4
#define       MAE_ACTION_RULE_RESPONSE_AS_ID_LBN 32
#define       MAE_ACTION_RULE_RESPONSE_AS_ID_WIDTH 32
/* Controls lookup flow when this rule is hit. See sub-fields for details. More
 * info on the lookup sequence can be found in SF-122976-TC. It is an error to
 * set both DO_CT and DO_RECIRC.
 */
#define       MAE_ACTION_RULE_RESPONSE_LOOKUP_CONTROL_OFST 8
#define       MAE_ACTION_RULE_RESPONSE_LOOKUP_CONTROL_LEN 4
#define        MAE_ACTION_RULE_RESPONSE_DO_CT_OFST 8
#define        MAE_ACTION_RULE_RESPONSE_DO_CT_LBN 0
#define        MAE_ACTION_RULE_RESPONSE_DO_CT_WIDTH 1
#define        MAE_ACTION_RULE_RESPONSE_DO_RECIRC_OFST 8
#define        MAE_ACTION_RULE_RESPONSE_DO_RECIRC_LBN 1
#define        MAE_ACTION_RULE_RESPONSE_DO_RECIRC_WIDTH 1
#define        MAE_ACTION_RULE_RESPONSE_CT_VNI_MODE_OFST 8
#define        MAE_ACTION_RULE_RESPONSE_CT_VNI_MODE_LBN 2
#define        MAE_ACTION_RULE_RESPONSE_CT_VNI_MODE_WIDTH 2
/*             Enum values, see field(s): */
/*                MAE_CT_VNI_MODE */
#define        MAE_ACTION_RULE_RESPONSE_RECIRC_ID_OFST 8
#define        MAE_ACTION_RULE_RESPONSE_RECIRC_ID_LBN 8
#define        MAE_ACTION_RULE_RESPONSE_RECIRC_ID_WIDTH 8
#define        MAE_ACTION_RULE_RESPONSE_CT_DOMAIN_OFST 8
#define        MAE_ACTION_RULE_RESPONSE_CT_DOMAIN_LBN 16
#define        MAE_ACTION_RULE_RESPONSE_CT_DOMAIN_WIDTH 16
#define       MAE_ACTION_RULE_RESPONSE_LOOKUP_CONTROL_LBN 64
#define       MAE_ACTION_RULE_RESPONSE_LOOKUP_CONTROL_WIDTH 32
/* Counter ID to increment if DO_CT or DO_RECIRC is set. Must be set to
 * COUNTER_ID_NULL otherwise.
 */
#define       MAE_ACTION_RULE_RESPONSE_COUNTER_ID_OFST 12
#define       MAE_ACTION_RULE_RESPONSE_COUNTER_ID_LEN 4
#define       MAE_ACTION_RULE_RESPONSE_COUNTER_ID_LBN 96
#define       MAE_ACTION_RULE_RESPONSE_COUNTER_ID_WIDTH 32

/***********************************/
/* MC_CMD_MAE_MPORT_REUUID
 * Replace the UUID for an existing m-port.
 */
#define MC_CMD_MAE_MPORT_REUUID 0x170
#undef MC_CMD_0x170_PRIVILEGE_CTG

#define MC_CMD_0x170_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_MAE_MPORT_REUUID_IN msgrequest */
#define    MC_CMD_MAE_MPORT_REUUID_IN_LEN 20
/* MPORT_ID as returned by MC_CMD_MAE_MPORT_ALLOC. */
#define       MC_CMD_MAE_MPORT_REUUID_IN_MPORT_ID_OFST 0
#define       MC_CMD_MAE_MPORT_REUUID_IN_MPORT_ID_LEN 4
/* 128-bit value for use by the driver. */
#define       MC_CMD_MAE_MPORT_REUUID_IN_UUID_OFST 4
#define       MC_CMD_MAE_MPORT_REUUID_IN_UUID_LEN 16

/* MC_CMD_MAE_MPORT_REUUID_OUT msgresponse */
#define    MC_CMD_MAE_MPORT_REUUID_OUT_LEN 0

/***********************************/
/* MC_CMD_MAE_TRACK_CONNECTION
 * Insert an entry into the connection tracking table. The lookup sequence is
 * described in SF-122976-TC.
 */
#define MC_CMD_MAE_TRACK_CONNECTION 0x17a
#undef MC_CMD_0x17a_PRIVILEGE_CTG

#define MC_CMD_0x17a_PRIVILEGE_CTG SRIOV_CTG_ADMIN

/* MC_CMD_MAE_TRACK_CONNECTION_IN msgrequest */
#define    MC_CMD_MAE_TRACK_CONNECTION_IN_LEN 54
/* See following fields. All other bits must be set to zero. */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_FLAGS_OFST 0
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_FLAGS_LEN 2
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_IS_IPV6_OFST 0
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_IS_IPV6_LBN 0
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_IS_IPV6_WIDTH 1
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_IS_UDP_OFST 0
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_IS_UDP_LBN 1
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_IS_UDP_WIDTH 1
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_DIR_IS_DST_OFST 0
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_DIR_IS_DST_LBN 2
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_DIR_IS_DST_WIDTH 1
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_PRIVATE_FLAGS_OFST 0
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_PRIVATE_FLAGS_LBN 8
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_PRIVATE_FLAGS_WIDTH 8
/* Domain as given when CT was requested. Analogous to ct_zone software field.
 */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_DOMAIN_OFST 2
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_DOMAIN_LEN 2
/* Source IP address to match, as bytes in network order. IPv4 should be in
 * first 4 bytes with other bytes zero.
 */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_SRC_ADDR_OFST 4
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_SRC_ADDR_LEN 16
/* Destination IP address to match, as bytes in network order. IPv4 should be
 * in first 4 bytes with other bytes zero.
 */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_DST_ADDR_OFST 20
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_DST_ADDR_LEN 16
/* Source TCP or UDP port to match as bytes in network order. */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_SRC_PORT_OFST 36
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_SRC_PORT_LEN 2
/* Destination TCP or UDP port to match as bytes in network order. */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_DST_PORT_OFST 38
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_DST_PORT_LEN 2
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_NETWORK_OFST 40
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_NETWORK_LEN 4
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_VNI_OR_VLANS_OR_ZERO_OFST 40
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_VNI_OR_VLANS_OR_ZERO_LBN 0
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_VNI_OR_VLANS_OR_ZERO_WIDTH 24
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_CT_VNI_MODE_OFST 40
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_CT_VNI_MODE_LBN 24
#define        MC_CMD_MAE_TRACK_CONNECTION_IN_CT_VNI_MODE_WIDTH 2
/*             Enum values, see field(s): */
/*                MAE_CT_VNI_MODE */
/* Mark output, will be given to following ACTION_RULE lookup. */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_CT_MARK_OFST 44
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_CT_MARK_LEN 4
/* If subsequent ACTION_RULE hit enables NAT, this IP will be used. */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_IP_OFST 48
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_IP_LEN 4
/* If subsequent ACTION_RULE hit enables NAT, this port will be used. */
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_PORT_OFST 52
#define       MC_CMD_MAE_TRACK_CONNECTION_IN_NAT_PORT_LEN 2

/* MC_CMD_MAE_TRACK_CONNECTION_OUT msgresponse */
#define    MC_CMD_MAE_TRACK_CONNECTION_OUT_LEN 4
/* ID to use for deletion. */
#define       MC_CMD_MAE_TRACK_CONNECTION_OUT_CONN_ID_OFST 0
#define       MC_CMD_MAE_TRACK_CONNECTION_OUT_CONN_ID_LEN 4
/* enum: A connection ID that is guaranteed never to represent a connection. */
#define          MC_CMD_MAE_TRACK_CONNECTION_OUT_CONN_ID_NULL 0xffffffff


/***********************************/
/* MC_CMD_MAE_FORGET_CONNECTION
 */
#define MC_CMD_MAE_FORGET_CONNECTION 0x17b
#undef MC_CMD_0x17b_PRIVILEGE_CTG

#define MC_CMD_0x17b_PRIVILEGE_CTG SRIOV_CTG_ADMIN

/* MC_CMD_MAE_FORGET_CONNECTION_IN msgrequest */
#define    MC_CMD_MAE_FORGET_CONNECTION_IN_LENMIN 4
#define    MC_CMD_MAE_FORGET_CONNECTION_IN_LENMAX 128
#define    MC_CMD_MAE_FORGET_CONNECTION_IN_LENMAX_MCDI2 128
#define    MC_CMD_MAE_FORGET_CONNECTION_IN_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_FORGET_CONNECTION_IN_CONN_ID_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_FORGET_CONNECTION_IN_CONN_ID_OFST 0
#define       MC_CMD_MAE_FORGET_CONNECTION_IN_CONN_ID_LEN 4
#define       MC_CMD_MAE_FORGET_CONNECTION_IN_CONN_ID_MINNUM 1
#define       MC_CMD_MAE_FORGET_CONNECTION_IN_CONN_ID_MAXNUM 32
#define       MC_CMD_MAE_FORGET_CONNECTION_IN_CONN_ID_MAXNUM_MCDI2 32

/* MC_CMD_MAE_FORGET_CONNECTION_OUT msgresponse */
#define    MC_CMD_MAE_FORGET_CONNECTION_OUT_LENMIN 4
#define    MC_CMD_MAE_FORGET_CONNECTION_OUT_LENMAX 128
#define    MC_CMD_MAE_FORGET_CONNECTION_OUT_LENMAX_MCDI2 128
#define    MC_CMD_MAE_FORGET_CONNECTION_OUT_LEN(num) (0+4*(num))
#define    MC_CMD_MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID_NUM(len) (((len)-0)/4)
/* Same semantics as MC_CMD_MAE_COUNTER_FREE */
#define       MC_CMD_MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID_OFST 0
#define       MC_CMD_MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID_LEN 4
#define       MC_CMD_MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID_MINNUM 1
#define       MC_CMD_MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID_MAXNUM 32
#define       MC_CMD_MAE_FORGET_CONNECTION_OUT_REMOVED_CONN_ID_MAXNUM_MCDI2 32


#endif /* MCDI_PCOL_MAE_H */
