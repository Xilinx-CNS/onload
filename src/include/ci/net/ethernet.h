/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  Ethernet protocol definitions.
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_net  */

#ifndef __CI_NET_ETHERNET_H__
#define __CI_NET_ETHERNET_H__

#include <ci/compat.h>

#ifndef __ci_driver__
# include <net/ethernet.h>
#else
# define ETH_ALEN	6
# define ETH_ZLEN	60
# define ETH_HLEN	14
# define ETH_DATA_LEN	1500
# define ETH_FRAME_LEN	1514
#endif

#define ETH_VLAN_HLEN 4

#define CI_MAX_ETH_FRAME_LEN 9022 /* 9000 + 14 (ethhdr) + 4 (vlan) + 4 (snap) */
#define CI_MAX_ETH_DATA_LEN (CI_MAX_ETH_FRAME_LEN - ETH_HLEN)

#define CI_MAC_PRINTF_FORMAT  "%02X:%02X:%02X:%02X:%02X:%02X"
#define CI_MAC_PRINTF_ARGS(p) ((unsigned) ((ci_uint8*)(p))[0]),	\
                              ((unsigned) ((ci_uint8*)(p))[1]),	\
                              ((unsigned) ((ci_uint8*)(p))[2]),	\
                              ((unsigned) ((ci_uint8*)(p))[3]),	\
                              ((unsigned) ((ci_uint8*)(p))[4]),	\
                              ((unsigned) ((ci_uint8*)(p))[5])

/*! Beware!  This header is 14 bytes long (ie. ends on a 2-byte aligned
** boundary).  If you layout data fields after it the compiler may insert
** padding, depending on size and alignment of the fields that follow.
*/
typedef struct ci_ether_hdr_s {
  ci_uint8   ether_dhost[ETH_ALEN];
  ci_uint8   ether_shost[ETH_ALEN];
  ci_uint16  ether_type;
} ci_ether_hdr;


typedef ci_ether_hdr  ci_ethhdr_t;


typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_type;             /* packet type ID field   */
} ci_ethhdr_vlan_t;


typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  ci_uint8  ether_shost[ETH_ALEN];	/* source ether addr	*/
  ci_uint16 ether_len;
  ci_uint8  ether_dsap;            /* 802.3 LLC: */
  ci_uint8  ether_ssap;            /* 802.3 LLC: */
  ci_uint8  ether_ctrl;            /* 802.3 LLC: */
  ci_uint8  ether_org[3];          /* SNAP: */
  ci_uint16 ether_type;	           /* SNAP: packet type ID field */
} ci_ethhdr_snap_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];
  ci_uint8  ether_shost[ETH_ALEN];
  ci_uint16 ether_len;
  ci_uint8  ether_dsap;            /* 802.3 LLC: */
  ci_uint8  ether_ssap;            /* 802.3 LLC: */
  ci_uint8  ether_ctrl;            /* 802.3 LLC: */
} ci_ethhdr_llc_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  ci_uint8  ether_shost[ETH_ALEN];	/* source ether addr	*/
  ci_uint16 ether_vtype;		/* 0x8100 (or 0x9100) */
  ci_uint16 ether_vtag;                 /* vlan tag */ 
  ci_uint16 ether_len;		      
  ci_uint8  ether_dsap;
  ci_uint8  ether_ssap;
  ci_uint8  ether_ctrl;
  ci_uint8  ether_org[3];
  ci_uint16 ether_type;		/* packet type ID field	*/
} ci_ethhdr_vlan_snap_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];	/* destination eth addr	*/
  ci_uint8  ether_shost[ETH_ALEN];	/* source ether addr	*/
  ci_uint16 ether_vtype;		/* 0x8100 (or 0x9100) */
  ci_uint16 ether_vtag;                 /* vlan tag */ 
  ci_uint16 ether_len;		      
  ci_uint8  ether_dsap;
  ci_uint8  ether_ssap;
  ci_uint8  ether_ctrl;
} ci_ethhdr_vlan_llc_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_vtype2;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag2;            /* vlan tag               */ 
  ci_uint16 ether_type;             /* packet type ID field   */
} ci_ethhdr_double_vlan_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_vtype2;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag2;            /* vlan tag               */ 
  ci_uint16 ether_len;
  ci_uint8  ether_dsap;
  ci_uint8  ether_ssap;
  ci_uint8  ether_ctrl;
  ci_uint8  ether_org[3];
  ci_uint16 ether_type;             /* packet type ID field   */
} ci_ethhdr_double_vlan_snap_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_vtype2;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag2;            /* vlan tag               */ 
  ci_uint16 ether_len;
  ci_uint8  ether_dsap;
  ci_uint8  ether_ssap;
  ci_uint8  ether_ctrl;
} ci_ethhdr_double_vlan_llc_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_vtype2;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag2;            /* vlan tag               */ 
  ci_uint16 ether_vtype3;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag3;            /* vlan tag               */ 
  ci_uint16 ether_type;             /* packet type ID field   */
} ci_ethhdr_triple_vlan_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_vtype2;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag2;            /* vlan tag               */ 
  ci_uint16 ether_vtype3;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag3;            /* vlan tag               */ 
  ci_uint16 ether_len;
  ci_uint8  ether_dsap;
  ci_uint8  ether_ssap;
  ci_uint8  ether_ctrl;
  ci_uint8  ether_org[3];
  ci_uint16 ether_type;             /* packet type ID field   */
} ci_ethhdr_triple_vlan_snap_t;

typedef struct {
  ci_uint8  ether_dhost[ETH_ALEN];  /* destination eth addr   */
  ci_uint8  ether_shost[ETH_ALEN];  /* source ether addr      */
  ci_uint16 ether_vtype;            /* vlan type field 0x8100 */
  ci_uint16 ether_vtag;             /* vlan tag               */ 
  ci_uint16 ether_vtype2;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag2;            /* vlan tag               */ 
  ci_uint16 ether_vtype3;           /* vlan type field 0x8100 */
  ci_uint16 ether_vtag3;            /* vlan tag               */ 
  ci_uint16 ether_len;
  ci_uint8  ether_dsap;
  ci_uint8  ether_ssap;
  ci_uint8  ether_ctrl;
} ci_ethhdr_triple_vlan_llc_t;

#define CI_ETHERTYPE_IP    CI_BSWAPC_BE16(0x0800)
#define CI_ETHERTYPE_IP6   CI_BSWAPC_BE16(0x86DD)
#define CI_ETHERTYPE_ARP   CI_BSWAPC_BE16(0x0806)
#define CI_ETHERTYPE_8021Q CI_BSWAPC_BE16(0x8100) /*VLAN*/
#define CI_ETHERTYPE_JUMBO CI_BSWAPC_BE16(0x8870)


ci_inline int ci_eth_addr_is_zero(const ci_uint8 *mac)
{
    return ! (mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
}


ci_inline int ci_eth_addr_is_broadcast(const ci_uint8 *mac)
{
  return ((mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == (ci_uint8)0xFF);
}


ci_inline int ci_eth_addr_is_multicast(const ci_uint8 *mac)
{
  return (mac[0] & (ci_uint8)0x01);
}


ci_inline int ci_eth_addr_is_locally_administered(const ci_uint8 *mac)
{
  return (mac[0] & (ci_uint8)0x02);
}

#endif  /* __CI_NET_ETHERNET_H__ */
/*! \cidoxg_end */
