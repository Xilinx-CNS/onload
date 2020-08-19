/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2004-2019 Xilinx, Inc. */
  /**************************************************************************\
*//*! \file
   ** <L5_PRIVATE L5_HEADER >
   ** \author  slp
   **  \brief  EtherFabric NIC - Marvell Alaska 8080111 definitions
   **     $Id$
   **   \date  2004/08
   **    \cop  (c) Level 5 Networks Limited.
   ** </L5_PRIVATE>
      *//*
        \************************************************************************* */

/*! \cidoxg_include_ci_driver_efab_hardware  */

#ifndef __CI_DRIVER_EFAB_HARDWARE_ALASKA808011_H__
#define __CI_DRIVER_EFAB_HARDWARE_ALASKA808011_H__

/*----------------------------------------------------------------------------
 *
 * Marvell Alaska 80801111 
 *
 *---------------------------------------------------------------------------*/

/* Note Decimal register access */
#define ALASKA_CONTROL		0	/* control  */
#define ALASKA_STATUS		1	/* status   */
#define ALASKA_PHY_ID0		2	/* PHY identifier */
#define ALASKA_PHY_ID1		3	/* PHY identifier */
#define ALASKA_AN_ADV       	4	/* auto-negotiation advertisement */
#define ALASKA_AN_PRT_ABL   	5	/* link partner ability */
#define ALASKA_AN_EXP       	6	/* auto-negotiation expansion */
#define ALASKA_AN_NP_TR     	7	/* next page transmit */
#define ALASKA_AN_PRT_NP    	8	/* link partner next page */
#define ALASKA_1000T_CONTROL	9	/* 1000Base-T control */
#define ALASKA_1000T_STATUS	10	/* 1000Base-T status */
#define ALASKA_EXT_STATUS	15	/* extended status */
#define ALASKA_PHY_CONTROL	16	/* PHY specific control */
#define ALASKA_PHY_STATUS	17	/* PHY specific status */
#define ALASKA_INT_ENABLE	18	/* interrupt enable */
#define ALASKA_INT_STATUS	19	/* interrupt status */
#define ALASKA_EXT_PHY_CONTROL  20	/* extended PHY specific control */
#define ALASKA_RX_ERR_COUNT	21	/* receive error counter */
#define ALASKA_ADDR_CABLE_DIAG	22	/* extended address for cable diag */
#define ALASKA_GLOBAL_STATUS	23	/* global status */
#define ALASKA_LED_CONTROL	24	/* LED control */
#define ALASKA_LED_OVERRIDE	25	/* manual LED override registers */
#define ALASKA_EXT_PHY_CONTROL2 26	/* extended PHY specific control2 */
#define ALASKA_EXT_PHY_STATUS	27	/* extended PHY specific status */
#define ALASKA_CABLE_DIAG	28	/* cable dignostics */
#define ALASKA_EXT_ADDRESS	29	/* extended address */
#define ALASKA_MISC_CTRL 	30	/* misc control plane */
#define ALASKA_REG_NUM		31

/* Interrupts */
#define ALASKA_IRQ_LINK_STATUS	0x400

#endif /* __CI_DRIVER_EFAB_HARDWARE_ALASKA808011_H__ */
/*! \cidoxg_end */
