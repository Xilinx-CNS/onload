/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
  /**************************************************************************\
*//*! \file
   ** <L5_PRIVATE L5_HEADER >
   ** \author  slp
   **  \brief  EtherFabric NIC - Intel IXF1002 definitions
   **     $Id$
   **   \date  2004/08
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
      *//*
        \************************************************************************* */

/*! \cidoxg_include_ci_driver_efab_hardware  */

#ifndef __CI_DRIVER_EFAB_HARDWARE_IXF1002_H__
#define __CI_DRIVER_EFAB_HARDWARE_IXF1002_H__

 /*----------------------------------------------------------------------------
 *
 * MAC chip: Intel IXF1002 
 *
 *---------------------------------------------------------------------------*/

/* IXF1002 registers: use _L _M _H for lower, medium, and uppper 16 bits 
   quad word aligned */
#define IXF1002_INT_STT      0x000	//Interrupt status reg                  RO
#define IXF1002_INT_EN       0x008	//Interrupt enable reg                  R/W
#define IXF1002_PORT_CTR     0x010	//Port control reg                      R/W
#define IXF1002_ID_REV       0x018	//Identification and rev                RO
#define IXF1002_TX_RX_STT    0x020	//Transmit and receive status reg       RO
#define IXF1002_TX_OV_STT_L  0x028	//Transmit counter overflow status reg  RO
#define IXF1002_TX_OV_STT_H  0x030	//Transmit counter overflow status reg  RO
#define IXF1002_RX_OV_STT_L  0x038	//Receive counter overflow status reg   RO
#define IXF1002_RX_OV_STT_H  0x040	//Receive counter overflow status reg   RO

#define IXF1002_TX_RX_ERR    0x080	//Transmit and receive error mode reg   R/W
#define IXF1002_FFO_TSHD     0x088	//FIFO threshold reg                    R/W
#define IXF1002_PORT_MODE    0x090	//Port working mode reg                 R/W
#define IXF1002_TX_RX_PARAM  0x098	//Transmit and receive parameter reg    R/W
#define IXF1002_TX_TSHD      0x0a0	//Transmit threshold reg                R/W
#define IXF1002_PAUSE_TIME   0x0a8	//Transmit flow-control pause time reg  R/W
#define IXF1002_PKT_MAX_SIZE 0x0b0	//Max pkt size reg                      R/W
#define IXF1002_IPG_VAL      0x0b8	//Inter-packet gap value reg            R/W
#define IXF1002_MAC_ADD_L    0x0c0	//MAC address reg                       R/W
#define IXF1002_MAC_ADD_M    0x0c8	//MAC address reg                       R/W
#define IXF1002_MAC_ADD_H    0x0d0	//MAC address reg                       R/W
#define IXF1002_VLAN_TAG     0x0d8	//VLAN tag length/type reg              R/W
#define IXF1002_TX_OV_MSK_L  0x0e0	//Transmit ctr overflow mask reg        R/W
#define IXF1002_TX_OV_MSK_H  0x0e8	//Transmit ctr overflow mask reg        R/W
#define IXF1002_RX_OV_MSK_L  0x0f0	//Receive ctr overflow mask reg         R/W
#define IXF1002_RX_OV_MSK_H  0x0f8	//Receive ctr overflow mask reg         R/W

/* MNG_ACC MNG_DAT port 0 only */
#define IXF1002_GMII_MNG_ACC 0x128	//GMII management access reg            R/W
#define IXF1002_GMII_MNG_DAT 0x130	//GMII management data reg              R/W

#define IXF1002_GMII_CTL     0x140	//GMII Control reg     R/W    (some bits RO)
#define IXF1002_GMII_STT     0x148	//GMII Status reg                       RO

#define IXF1002_AN_ADV       0x160	//AN advertisement reg R/W    (some bits RO)
#define IXF1002_AN_PRT_ABL   0x168	//AN link partner ability base page reg RO
#define IXF1002_AN_EXP       0x170	//AN expansion reg                      RO
#define IXF1002_AN_NP_TR     0x178	//AN next page transmit reg R/W (one bit RO)
#define IXF1002_AN_PRT_NP    0x180	//AN link partner receive next page reg RO

#define IXF1002_GMII_EXT_STT 0x1b8	//Extended status reg                   RO
#define IXF1002_GPCS_STT     0x1c0	//GPCS status reg                       RO

#define IXF1002_STATS_NRST   0x800	// Counter block no reset
#define IXF1002_STATS_RST    0x400	// Counter block with reset

/* TX unicast packet count */
#define IXF1002_TX_UNI_OK_CNT_STAT_MAC    0x00
/* TX multicast packet count */
#define IXF1002_TX_MLT_OK_CNT_STAT_MAC    0x04
/* TX broadcast packet count */
#define IXF1002_TX_BRD_OK_CNT_STAT_MAC    0x08
/* TX 64-byte packet count */
#define IXF1002_TX_PKT_64_CNT_STAT_MAC    0x24
/* TX 65-byte to 127-byte packet count */
#define IXF1002_TX_PKT_65_CNT_STAT_MAC    0x28
/* TX 128-byte to 255-byte packet count */
#define IXF1002_TX_PKT_128_CNT_STAT_MAC   0x2c
/* TX 256-byte to 511-byte packet count */
#define IXF1002_TX_PKT_256_CNT_STAT_MAC   0x30
/* TX 512-byte to 1023-byte packet count */
#define IXF1002_TX_PKT_512_CNT_STAT_MAC   0x34
/* TX 1024-byte to 1518-byte packet count */
#define IXF1002_TX_PKT_1024_CNT_STAT_MAC  0x38
/* TX 1519-byte and above packet count */
#define IXF1002_TX_PKT_1519_CNT_STAT_MAC  0x3c
/* TX pause packet count */
#define IXF1002_TX_PAUSE_CNT_STAT_MAC     0x40
/* TX error packet count */
#define IXF1002_TX_ERR_CNT_STAT_MAC       0x44
/* TX good octet count */
#define IXF1002_TX_OCT_OK_CNT_STAT_MAC    0x60
/* TX bad octet count */
#define IXF1002_TX_OCT_BAD_CNT_STAT_MAC   0x68
/* RX good octet count */
#define IXF1002_RX_OCT_OK_CNT_STAT_MAC    0x70
/* RX bad octet count */
#define IXF1002_RX_OCT_BAD_CNT_STAT_MAC   0x78
/* RX overflow packet count */
#define IXF1002_RX_OVF_CNT_STAT_MAC       0x84
/* RX less than 64-byte good packet count */
#define IXF1002_RX_SHORT_OK_CNT_STAT_MAC  0x88
/* RX less than 64-byte bad packet count */
#define IXF1002_RX_SHORT_CRC_CNT_STAT_MAC 0x8c
/* RX unicast packet count */
#define IXF1002_RX_UNI_OK_CNT_STAT_MAC    0x90
/* RX multicast packet count */
#define IXF1002_RX_MLT_OK_CNT_STAT_MAC    0x94
/* RX broadcast packet count */
#define IXF1002_RX_BRD_OK_CNT_STAT_MAC    0x98
/* RX 64-byte to jumbo bad packet count */
#define IXF1002_RX_NORM_CRC_CNT_STAT_MAC  0x9c
/* RX greater than jumbo good packet count */
#define IXF1002_RX_LONG_OK_CNT_STAT_MAC   0xa4
/* RX greater than jumbo bad packet count */
#define IXF1002_RX_LONG_CRC_CNT_STAT_MAC  0xa8
/* RX 64-byte packet count */
#define IXF1002_RX_PKT_64_CNT_STAT_MAC    0xac
/* RX 65-byte to 127-byte packet count */
#define IXF1002_RX_PKT_65_CNT_STAT_MAC    0xb0
/* RX 128-byte to 255-byte packet count */
#define IXF1002_RX_PKT_128_CNT_STAT_MAC   0xb4
/* RX 256-byte to 511-byte packet count */
#define IXF1002_RX_PKT_256_CNT_STAT_MAC   0xb8
/* RX 512-byte to 1023-byte packet count */
#define IXF1002_RX_PKT_512_CNT_STAT_MAC   0xbc
/* RX 1024-byte to 1518-byte packet count */
#define IXF1002_RX_PKT_1024_CNT_STAT_MAC  0xc0
/* RX 1519-byte and above packet count */
#define IXF1002_RX_PKT_1519_CNT_STAT_MAC  0xc4
/* RX pause packet count */
#define IXF1002_RX_PAUSE_CNT_STAT_MAC     0xc8
/* RX false carrier event count */
#define IXF1002_RX_FALS_CRS_CNT_STAT_MAC  0xcc
/* RX GPCS symbol error packet count */
#define IXF1002_RX_GPCS_ERR_CNT_STAT_MAC  0xd0

/* IX Bus Receive Packet Status - returned as last word of packet */
#define IXF1002_STS_LEN_MASK	0xffff0000u
#define IXF1002_STS_LEN_SHIFT	16
#define IXF1002_STS_OK   	0x00000100u

#endif /* __CI_DRIVER_EFAB_HARDWARE_IXF1002_H__ */
/*! \cidoxg_end */
