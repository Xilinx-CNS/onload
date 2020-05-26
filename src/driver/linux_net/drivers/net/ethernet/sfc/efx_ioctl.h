/****************************************************************************
 * Driver for Solarflare network controllers
 *           (including support for SFE4001 10GBT NIC)
 *
 * Copyright 2005-2006: Fen Systems Ltd.
 * Copyright 2006-2012: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Initially developed by Michael Brown <mbrown@fensystems.co.uk>
 * Maintained by Solarflare Communications <linux-net-drivers@solarflare.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef EFX_IOCTL_H
#define EFX_IOCTL_H

#if defined(__KERNEL__)
#include <linux/if.h>
#include <linux/types.h>
#else
#include <net/if.h>
#ifndef _LINUX_IF_H
#define _LINUX_IF_H /* prevent <linux/if.h> from conflicting with <net/if.h> */
#endif
#include "efx_linux_types.h"
#endif
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>

/**
 * DOC: sfc driver private ioctl
 *
 * Various driver features can be controlled through a private ioctl,
 * which has multiple sub-commands.
 *
 * Most of these features are also available through the ethtool API
 * or other standard kernel API on a sufficiently recent kernel
 * version.  Userland tools should generally use the standard API
 * first and fall back to the private ioctl in case of an error code
 * indicating the standard API is not implemented (e.g. %EOPNOTSUPP,
 * %ENOSYS, or %ENOTTY).
 *
 * A few features are intended for driver debugging and are not
 * included in the production driver.
 *
 * The private ioctl is numbered %SIOCEFX and is implemented on
 * both sockets and a char device (/dev/sfc_control).  Sockets are
 * more reliable as they do not depend on a device node being
 * created on disk.
 */

/* Efx private ioctl number */
/* We do not use the first 3 private ioctls because some utilities expect
 * them to be the old MDIO ioctls. */
#define SIOCEFX (SIOCDEVPRIVATE + 3)

/*
 * Efx private ioctls
 */

#ifdef EFX_NOT_EXPORTED

#include "enum.h"

/* Testing/QA: perform full reset while running *****************************/
#define EFX_RESET 0xef01

/* Parameters for EFX_RESET */
struct efx_reset_ioctl {
	enum reset_type method;
};

/* Testing/QA: re-acknowledge specified event queue *************************/
#define EFX_EVQ_ACK 0xef02

/* Parameters for EFX_EVQ_ACK */
struct efx_evq_ack_ioctl {
	/** Channel number */
	__u16 channel;
};

/* Testing/QA: set loopback mode ********************************************/
#define EFX_SET_LOOPBACK 0xef03

/* Parameters for EFX_SET_LOOPBACK */
struct efx_set_loopback_ioctl {
	/** Loopback mode */
	enum efx_loopback_mode mode;
};

#define LOOPBACK_NEAR	(LOOPBACK_MAX + 1)	/* loopback nearest to bus */
#define LOOPBACK_FAR	(LOOPBACK_MAX + 2)	/* loopback furthest from bus */

/* Testing/QA: debug MDIO access ********************************************/
#define EFX_MDIO 0xef05

/* Parameters for EFX_MDIO */
struct efx_mdio_ioctl {
	/** MDIO access */
	__u16 read;
	__u16 clause45;
	__u32 value;
	__u16 addr;
	__u8 dev;
	int prt;
} __attribute__ ((packed));

/* For setting the netif carrier on/off *************************************/
#define EFX_SET_CARRIER 0xef09

struct efx_set_carrier_ioctl {
	__u8 on;
};


/* For setting the PHY power state ******************************************/
#define EFX_SET_PHY_POWER 0xef0b

struct efx_set_phy_power {
	__u8 on;
};

#endif /* EFX_NOT_EXPORTED */

/* For talking MCDI to siena ************************************************/

/* Deprecated */
#define EFX_MCDI_REQUEST 0xef0c
/**
 * struct efx_mcdi_request - Parameters for %EFX_MCDI_REQUEST sub-command
 * @payload: On entry, the MCDI command parameters.  On return, if
 *	@rc == 0, this is the response.
 * @cmd: MCDI command type number.
 * @len: On entry, the length of command parameters, in bytes.  On
 *	return, if @rc == 0, this is the length of the response.
 * @rc: Linux error code for the request.  This may be based on an
 *	error code reported by the MC or a communication failure
 *	detected by the driver.
 *
 * If the driver detects invalid parameters, e.g. @len is out of
 * range, the ioctl() call will return -1, errno will be set
 * accordingly, and none of the fields will be valid.  All other
 * errors are reported by setting @rc.
 *
 * %EFX_MCDI_REQUEST does not support the larger command type numbers,
 * error codes and payload lengths of MCDIv2.
 */
struct efx_mcdi_request {
	__u32 payload[63];
	__u8 cmd;
	__u8 len;
	__u8 rc;
};

#define EFX_MCDI_REQUEST2 0xef21
/**
 * struct efx_mcdi_request2 - Parameters for %EFX_MCDI_REQUEST2 sub-command
 * @cmd: MCDI command type number.
 * @inlen: The length of command parameters, in bytes.
 * @outlen: On entry, the length available for the response, in bytes.
 *	On return, the length used for the response, in bytes.
 * @flags: Flags for the command or response.  The only flag defined
 *	at present is %EFX_MCDI_REQUEST_ERROR.  If this is set on return,
 *	the MC reported an error.
 * @host_errno: On return, if %EFX_MCDI_REQUEST_ERROR is included in @flags,
 *	the suggested Linux error code for the error.
 * @payload: On entry, the MCDI command parameters.  On return, the response.
 *
 * If the driver detects invalid parameters or a communication failure
 * with the MC, the ioctl() call will return -1, errno will be set
 * accordingly, and none of the fields will be valid.  If the MC reports
 * an error, the ioctl() call will return 0 but @flags will include the
 * %EFX_MCDI_REQUEST_ERROR flag.  The MC error code can then be found in
 * @payload (if @outlen was sufficiently large) and a suggested Linux
 * error code can be found in @host_errno.
 *
 * %EFX_MCDI_REQUEST2 fully supports both MCDIv1 and v2.
 */
struct efx_mcdi_request2 {
	__u16 cmd;
	__u16 inlen;
	__u16 outlen;
	__u16 flags;
	__u32 host_errno;
	/*
	 * The maximum payload length is 0x400 (MCDI_CTL_SDU_LEN_MAX_V2) - 4 bytes
	 * = 255 x 32 bit words as MCDI_CTL_SDU_LEN_MAX_V2 doesn't take account of
	 * the space required by the V1 header, which still exists in a V2 command.
	 */
	__u32 payload[255];
};
#define EFX_MCDI_REQUEST_ERROR	0x0001

/* Reset selected components, like ETHTOOL_RESET ****************************/
#define EFX_RESET_FLAGS 0xef0d
struct efx_reset_flags {
	__u32 flags;
};
#ifndef ETH_RESET_SHARED_SHIFT
	enum ethtool_reset_flags {
		/* These flags represent components dedicated to the interface
		 * the command is addressed to.  Shift any flag left by
		 * ETH_RESET_SHARED_SHIFT to reset a shared component of the
		 * same type.
		 */
		ETH_RESET_MGMT		= 1 << 0,	/* Management processor */
		ETH_RESET_IRQ		= 1 << 1,	/* Interrupt requester */
		ETH_RESET_DMA		= 1 << 2,	/* DMA engine */
		ETH_RESET_FILTER	= 1 << 3,	/* Filtering/flow direction */
		ETH_RESET_OFFLOAD	= 1 << 4,	/* Protocol offload */
		ETH_RESET_MAC		= 1 << 5,	/* Media access controller */
		ETH_RESET_PHY		= 1 << 6,	/* Transceiver/PHY */
		ETH_RESET_RAM		= 1 << 7,	/* RAM shared between
							 * multiple components */

		ETH_RESET_DEDICATED	= 0x0000ffff,	/* All components dedicated to
							 * this interface */
		ETH_RESET_ALL		= 0xffffffff,	/* All components used by this
							 * interface, even if shared */
	};
	#define ETH_RESET_SHARED_SHIFT	16
#endif
#ifndef ETHTOOL_RESET
	#define ETHTOOL_RESET           0x00000034
#endif

/* Get RX flow hashing capabilities, like ETHTOOL_GRX{RINGS,FH} *************/
#define EFX_RXNFC 0xef0e
#ifndef ETHTOOL_GRXFH
	#define ETHTOOL_GRXFH		0x00000029
#endif
#ifndef ETHTOOL_GRXRINGS
	#define ETHTOOL_GRXRINGS	0x0000002d
#endif
#ifndef ETHTOOL_GRXCLSRULE
	struct ethtool_tcpip4_spec {
		__be32	ip4src;
		__be32	ip4dst;
		__be16	psrc;
		__be16	pdst;
		__u8    tos;
	};

	struct ethtool_usrip4_spec {
		__be32  ip4src;
		__be32  ip4dst;
		__be32  l4_4_bytes;
		__u8    tos;
		__u8    ip_ver;
		__u8    proto;
	};

	#define ETH_RX_NFC_IP4  1
	#define RX_CLS_FLOW_DISC	0xffffffffffffffffULL
	#define ETHTOOL_GRXCLSRLCNT	0x0000002e
	#define ETHTOOL_GRXCLSRULE	0x0000002f
	#define ETHTOOL_GRXCLSRLALL	0x00000030
	#define ETHTOOL_SRXCLSRLDEL     0x00000031
	#define ETHTOOL_SRXCLSRLINS	0x00000032
#endif
#ifndef EFX_HAVE_EFX_ETHTOOL_RXNFC
	union efx_ethtool_flow_union {
		struct ethtool_tcpip4_spec		tcp_ip4_spec;
		struct ethtool_tcpip4_spec		udp_ip4_spec;
		struct ethtool_tcpip4_spec		sctp_ip4_spec;
		struct ethtool_usrip4_spec		usr_ip4_spec;
		struct ethhdr				ether_spec;
		/* unneeded members omitted... */
		__u8					hdata[60];
	};
	struct efx_ethtool_flow_ext {
		__be16	vlan_etype;
		__be16	vlan_tci;
		__be32	data[2];
	};
	struct efx_ethtool_rx_flow_spec {
		__u32		flow_type;
		union efx_ethtool_flow_union h_u;
		struct efx_ethtool_flow_ext h_ext;
		union efx_ethtool_flow_union m_u;
		struct efx_ethtool_flow_ext m_ext;
		__u64		ring_cookie;
		__u32		location;
	};
	struct efx_ethtool_rxnfc {
		__u32				cmd;
		__u32				flow_type;
		__u64				data;
		struct efx_ethtool_rx_flow_spec	fs;
		union {
			__u32			rule_cnt;
			__u32			rss_context;
		};
		__u32				rule_locs[0];
	};
	#define EFX_HAVE_EFX_ETHTOOL_RXNFC yes
#endif
#ifndef RX_CLS_LOC_SPECIAL
	#define RX_CLS_LOC_SPECIAL	0x80000000
	#define RX_CLS_LOC_ANY		0xffffffff
	#define RX_CLS_LOC_FIRST	0xfffffffe
	#define RX_CLS_LOC_LAST		0xfffffffd
#endif

/* Get/set RX flow hash indirection table, like ETHTOOL_{G,S}RXFHINDIR} *****/
#define EFX_RXFHINDIR 0xef10
#ifndef ETHTOOL_GRXFHINDIR
	struct ethtool_rxfh_indir {
		__u32	cmd;
		/* On entry, this is the array size of the user buffer.  On
		 * return from ETHTOOL_GRXFHINDIR, this is the array size of
		 * the hardware indirection table. */
		__u32	size;
		__u32	ring_index[0];	/* ring/queue index for each hash value */
	};
	#define ETHTOOL_GRXFHINDIR	0x00000038
	#define ETHTOOL_SRXFHINDIR	0x00000039
#endif
struct efx_rxfh_indir {
	struct ethtool_rxfh_indir head;
	__u32 table[128];
};

/* PTP support for NIC time disciplining ************************************/

struct efx_timespec {
	__s64	tv_sec;
	__s32	tv_nsec;
};

/* Set/get hardware timestamp config, like SIOC{S,G}HWTSTAMP ****************/
#define EFX_TS_INIT 0xef12
#define EFX_GET_TS_CONFIG 0xef25

#define EFX_TS_INIT_FLAGS_PTP_V2_ENHANCED 0x80000000

#if !defined(__KERNEL__)

enum {
	SOF_TIMESTAMPING_TX_HARDWARE = (1<<0),
	SOF_TIMESTAMPING_TX_SOFTWARE = (1<<1),
	SOF_TIMESTAMPING_RX_HARDWARE = (1<<2),
	SOF_TIMESTAMPING_RX_SOFTWARE = (1<<3),
	SOF_TIMESTAMPING_SOFTWARE = (1<<4),
	SOF_TIMESTAMPING_SYS_HARDWARE = (1<<5),
	SOF_TIMESTAMPING_RAW_HARDWARE = (1<<6),
	SOF_TIMESTAMPING_MASK =
	(SOF_TIMESTAMPING_RAW_HARDWARE - 1) |
	SOF_TIMESTAMPING_RAW_HARDWARE
};

enum hwtstamp_tx_types {
	HWTSTAMP_TX_OFF,
	HWTSTAMP_TX_ON,
	HWTSTAMP_TX_ONESTEP_SYNC,
};

enum hwtstamp_rx_filters {
	HWTSTAMP_FILTER_NONE,
	HWTSTAMP_FILTER_ALL,
	HWTSTAMP_FILTER_SOME,
	HWTSTAMP_FILTER_PTP_V1_L4_EVENT,
	HWTSTAMP_FILTER_PTP_V1_L4_SYNC,
	HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ,
	HWTSTAMP_FILTER_PTP_V2_L4_EVENT,
	HWTSTAMP_FILTER_PTP_V2_L4_SYNC,
	HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ,
	HWTSTAMP_FILTER_PTP_V2_L2_EVENT,
	HWTSTAMP_FILTER_PTP_V2_L2_SYNC,
	HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ,
	HWTSTAMP_FILTER_PTP_V2_EVENT,
	HWTSTAMP_FILTER_PTP_V2_SYNC,
	HWTSTAMP_FILTER_PTP_V2_DELAY_REQ,
};

struct hwtstamp_config {
	int flags;
	int tx_type;
	int rx_filter;
};

#endif /* !__KERNEL__ */

#if !defined(EFX_HAVE_NET_TSTAMP)

/* Read any transmit or receive timestamps since the last call **************/
#define EFX_TS_READ 0xef13

struct efx_ts_read {
	__u32 tx_valid;
	struct efx_timespec tx_ts;
	struct efx_timespec tx_ts_hw;
	__u32 rx_valid;
	struct efx_timespec rx_ts;
	struct efx_timespec rx_ts_hw;
	__u8 uuid[6];
	__u8 seqid[2];
};
#endif

/* Set the NIC time clock offset ********************************************/
#define EFX_TS_SETTIME 0xef14
struct efx_ts_settime {
	struct efx_timespec ts;	/* In and out */
	__u32 iswrite;		/* 1 == write, 0 == read (only) */
};

/* Adjust the NIC time frequency ********************************************/
#define EFX_TS_ADJTIME 0xef15
struct efx_ts_adjtime {
	__s64 adjustment;	/* Parts per billion, In and out */
	__u32 iswrite;		/* 1 == write, 0 == read (only) */
};

/* Get the NIC-system time skew *********************************************/
#define EFX_TS_SYNC 0xef16
struct efx_ts_sync {
	struct efx_timespec ts;
};

/* Set the NIC-system synchronization status ********************************/
#define EFX_TS_SET_SYNC_STATUS 0xef27
struct efx_ts_set_sync_status {
	__u32 in_sync;		/* 0 == not in sync, 1 == in sync */
	__u32 timeout;		/* Seconds until no longer in sync */
};

/* Get the clock/timestamp capabilities, like ETHTOOL_GET_TS_INFO ***********/
#define EFX_GET_TS_INFO 0xef24
#ifndef ETHTOOL_GET_TS_INFO
	struct ethtool_ts_info {
		__u32	cmd;
		__u32	so_timestamping;
		__s32	phc_index;
		__u32	tx_types;
		__u32	tx_reserved[3];
		__u32	rx_filters;
		__u32	rx_reserved[3];
	};
	#define ETHTOOL_GET_TS_INFO	0x00000041 /* Get time stamping and PHC info */
#endif

/* Get pluging module eeprom if not availble via ethtool ********************/
#define EFX_MODULEEEPROM 0xef17
#define EFX_GMODULEINFO 0xef18
#ifndef ETHTOOL_GMODULEEEPROM
	struct ethtool_modinfo {
		__u32   cmd;
		__u32   type;
		__u32   eeprom_len;
		__u32   reserved[8];
	};

	#define ETH_MODULE_SFF_8079     0x1
	#define ETH_MODULE_SFF_8079_LEN 256
	#define ETH_MODULE_SFF_8472     0x2
	#define ETH_MODULE_SFF_8472_LEN 512

	#define ETHTOOL_GMODULEINFO     0x00000042
	#define ETHTOOL_GMODULEEEPROM   0x00000043
#endif
struct efx_get_module_eeprom {
	struct ethtool_eeprom ee;
};

struct efx_get_module_info {
	struct ethtool_modinfo info;
};

/* Set the VLAN tags for PTP receive packet filtering ***********************/
#define EFX_TS_SET_VLAN_FILTER 0xef19
struct efx_ts_set_vlan_filter {
#define TS_MAX_VLAN_TAGS 3                   /* Maximum supported VLAN tags */
	__u32 num_vlan_tags;                 /* Number of VLAN tags */
	__u16 vlan_tags[TS_MAX_VLAN_TAGS];   /* VLAN tag list */
};

/* Set the UUID for PTP receive packet filtering ****************************/
#define EFX_TS_SET_UUID_FILTER 0xef1a
struct efx_ts_set_uuid_filter {
	__u32 enable;                        /* 1 == enabled, 0 == disabled */
	__u8 uuid[8];                        /* UUID to filter against */
};

/* Set the Domain for PTP receive packet filtering **************************/
#define EFX_TS_SET_DOMAIN_FILTER 0xef1b
struct efx_ts_set_domain_filter {
	__u32 enable;                        /* 1 == enabled, 0 == disabled */
	__u32 domain;                        /* Domain number to filter against */
};

/* Return a PPS timestamp ***************************************************/
#define EFX_TS_GET_PPS 0xef1c
struct efx_ts_get_pps {
	__u32 sequence;				/* seq. num. of assert event */
	__u32 timeout;
	struct efx_timespec sys_assert;		/* time of assert in system time */
	struct efx_timespec nic_assert;		/* time of assert in nic time */
	struct efx_timespec delta;		/* delta between NIC and system time */
};

#define EFX_TS_ENABLE_HW_PPS 0xef1d
struct efx_ts_hw_pps {
	__u32 enable;
};

/* Reprogram the CPLD on an AOE NIC *****************************************/
#define EFX_UPDATE_CPLD 0xef1e
struct efx_update_cpld {
	__u32 update;
};

/* License key operations on AOE or EF10 NIC ********************************/

/* Deprecated - only supports AOE */
#define EFX_LICENSE_UPDATE 0xef1f
struct efx_update_license {
	__u32 valid_keys;
	__u32 invalid_keys;
	__u32 blacklisted_keys;
};

#define EFX_LICENSE_UPDATE2 0xef23
struct efx_update_license2 {
	__u32 valid_keys;
	__u32 invalid_keys;
	__u32 blacklisted_keys;
	__u32 unverifiable_keys;
	__u32 wrong_node_keys;
};

#define EFX_LICENSED_APP_STATE 0xef26
struct efx_licensed_app_state {
	__u32 app_id;
	__u32 state;
};

/* Reset the AOE application and controller *********************************/
#define EFX_RESET_AOE 0xef20
struct efx_aoe_reset {
	__u32 flags;
};

/* Get device identity ******************************************************/
#define EFX_GET_DEVICE_IDS 0xef22
struct efx_device_ids {
	__u16 vendor_id, device_id;		/* PCI device ID */
	__u16 subsys_vendor_id, subsys_device_id; /* PCI subsystem ID */
	__u32 phy_type;				/* PHY type code */
	__u8 port_num;				/* port number (0-based) */
	__u8 perm_addr[6];			/* non-volatile MAC address */
};

/* Dump support *************************************************************/
#define EFX_DUMP 0xef28
#if !defined (ETHTOOL_SET_DUMP) || defined (EFX_NEED_STRUCT_ETHTOOL_DUMP)
	struct ethtool_dump {
		__u32 cmd;
		__u32 version;
		__u32 flag;
		__u32 len;
		__u8  data[0];
	};
#elif !defined (__KERNEL__)
	struct efx_ethtool_dump {
		__u32 cmd;
		__u32 version;
		__u32 flag;
		__u32 len;
		__u8  data[0];
	};
	#define ethtool_dump efx_ethtool_dump
#endif
#ifndef ETHTOOL_SET_DUMP
	#define ETHTOOL_SET_DUMP	0x0000003e
#endif
#ifndef ETHTOOL_GET_DUMP_FLAG
	#define ETHTOOL_GET_DUMP_FLAG	0x0000003f
#endif
#ifndef ETHTOOL_GET_DUMP_DATA
	#define ETHTOOL_GET_DUMP_DATA	0x00000040
#endif

/* sfctool2 shadow ethtool interface ****************************************/
#define EFX_SFCTOOL 0xef29
struct efx_sfctool {
	/* This can be any ethtool command struct from include/linux/ethtool.h.
	 * The first element will always be __u32 cmd.
	 */
	void __user *data;
};

/* Next available cmd number is 0xef2a */

/* Efx private ioctl command structures *************************************/

union efx_ioctl_data {
#ifdef EFX_NOT_EXPORTED
	struct efx_reset_ioctl reset;
	struct efx_evq_ack_ioctl evq_ack;
	struct efx_set_loopback_ioctl set_loopback;
	struct efx_mdio_ioctl mdio;
	struct efx_set_carrier_ioctl set_carrier;
	struct efx_set_phy_power set_phy_power;
#endif
	struct efx_mcdi_request mcdi_request;
	struct efx_mcdi_request2 mcdi_request2;
	struct efx_reset_flags reset_flags;
	struct efx_ethtool_rxnfc rxnfc;
	struct efx_rxfh_indir rxfh_indir;
	struct hwtstamp_config ts_init;
#if !defined(EFX_HAVE_NET_TSTAMP)
	struct efx_ts_read ts_read;
#endif
	struct efx_ts_settime ts_settime;
	struct efx_ts_adjtime ts_adjtime;
	struct efx_ts_sync ts_sync;
	struct efx_ts_set_sync_status ts_set_sync_status;
	struct ethtool_ts_info ts_info;
	struct efx_get_module_eeprom eeprom;
	struct efx_get_module_info modinfo;
	struct efx_ts_set_vlan_filter ts_vlan_filter;
	struct efx_ts_set_uuid_filter ts_uuid_filter;
	struct efx_ts_set_domain_filter ts_domain_filter;
	struct efx_ts_get_pps pps_event;
	struct efx_ts_hw_pps pps_enable;
	struct efx_update_cpld cpld;
	struct efx_update_license key_stats;
	struct efx_update_license2 key_stats2;
	struct efx_aoe_reset aoe_reset;
	struct efx_device_ids device_ids;
	struct efx_licensed_app_state app_state;
	struct ethtool_dump dump;
	struct efx_sfctool sfctool;
};

/**
 * struct efx_ioctl - Parameters for sfc private ioctl on char device
 * @if_name: Name of the net device to control
 * @cmd: Command number
 * @u: Command-specific parameters
 *
 * Usage:
 *     struct efx_ioctl efx;
 *
 *     fd = open("/dev/sfc_control", %O_RDWR);
 *
 *     strncpy(efx.if_name, if_name, %IFNAMSIZ);
 *
 *     efx.cmd = %EFX_FROBNOSTICATE;
 *
 *     efx.u.frobnosticate.magic = 42;
 *
 *     ret = ioctl(fd, %SIOCEFX, & efx);
 */
struct efx_ioctl {
	char if_name[IFNAMSIZ];
	/* Command to run */
	__u16 cmd;
	/* Parameters */
	union efx_ioctl_data u;
} __attribute__ ((packed));

/**
 * struct efx_sock_ioctl - Parameters for sfc private ioctl on socket
 * @cmd: Command number
 * @u: Command-specific parameters
 *
 * Usage:
 *     struct ifreq ifr;
 *
 *     struct efx_sock_ioctl efx;
 *
 *     fd = socket(%AF_INET, %SOCK_STREAM, 0);
 *
 *     strncpy(ifr.ifr_name, if_name, %IFNAMSIZ);
 *
 *     ifr.ifr_data = (caddr_t) & efx;
 *
 *     efx.cmd = %EFX_FROBNOSTICATE;
 *
 *     efx.u.frobnosticate.magic = 42;
 *
 *     ret = ioctl(fd, %SIOCEFX, & ifr);
 */
struct efx_sock_ioctl {
	/* Command to run */
	__u16 cmd;
	__u16 reserved;
	/* Parameters */
	union efx_ioctl_data u;
} __attribute__ ((packed));

#ifdef __KERNEL__
int efx_private_ioctl(struct efx_nic *efx, u16 cmd,
		      union efx_ioctl_data __user *data);
int efx_control_init(void);
void efx_control_fini(void);
#endif /* __KERNEL__ */

#endif /* EFX_IOCTL_H */
