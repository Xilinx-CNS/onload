/* SPDX-License-Identifier: GPL-2.0 */
/*
 * efx_auxbus.h - Solarflare auxiliary bus interface
 *
 * Copyright 2023-2024, Advanced Micro Devices, Inc.
 */
#ifndef _EFX_AUXBUS_H
#define _EFX_AUXBUS_H

#ifdef EFX_NOT_UPSTREAM
/* This is part of the device name exposed in the auxiliary bus. */
#define EFX_ONLOAD_DEVNAME	"onload"
#endif

/* Driver API */
/**
 * enum efx_auxdev_event_type - Events a driver can get.
 *
 * Drivers must not close a client when the hardware is resetting.
 *
 * @EFX_AUXDEV_EVENT_IN_RESET: Hardware is resetting.
 * @EFX_AUXDEV_EVENT_LINK_CHANGE: Physical link has changed state.
 * @EFX_AUXDEV_EVENT_POLL: Events need processing. Called from NAPI context.
 */
enum efx_auxdev_event_type {
	EFX_AUXDEV_EVENT_IN_RESET,
	EFX_AUXDEV_EVENT_LINK_CHANGE,
	EFX_AUXDEV_EVENT_POLL,
};

#define EFX_AUXDEV_ALL_EVENTS	(BIT(EFX_AUXDEV_EVENT_IN_RESET) | \
				 BIT(EFX_AUXDEV_EVENT_LINK_CHANGE) | \
				 BIT(EFX_AUXDEV_EVENT_POLL))

/**
 * struct efx_auxdev_event - One event for an auxiliary bus driver.
 *
 * @type: Event type as defined in enum efx_event_type.
 * @value: Event specific value. For %EFX_EVENT_IN_RESET this is 1 when the
 *	hardware is resetting, and 0 during normal operation.
 *	For %EFX_EVENT_LINK_CHANGE this is 1 when the physical link is up,
 *	and 0 when the physical link is down.
 *	For %EFX_EVENT_POLL this is the channel number for which events need
 *	to be processed.
 * @budget: Only used for %EFX_EVENT_POLL. This is the number of packets that
 *	may be processed.
 */
struct efx_auxdev_event {
	enum efx_auxdev_event_type	type;
	unsigned int			value;
	unsigned int			budget;
#ifdef EFX_NOT_UPSTREAM
	/** @p_event: Raw event to handle. */
	void				*p_event;
#endif
};

struct efx_auxdev_client;
/**
 * typedef efx_auxdev_event_handler - Event handler for an auxiliary bus device
 * @client: the client for which the event is invoked.
 * @event:  even details as a &struct efx_auxdev_event.
 *
 * An event handler is defined in the auxiliary bus drivers, and provides
 * a mechanism for the core driver to inform bus drivers of notable changes.
 * Drivers can request the different event types they are interested in as
 * part of the struct_efx_auxdev_ops->open call.
 *
 * Return: For @EFX_AUXDEV_EVENT_POLL the event handler should return the
 * amount of budget that is left. For other event types the handler should
 * return 0.
 * The handler can return negative values as well, but that has no functional
 * effect on the core driver.
 *
 */
typedef int efx_auxdev_event_handler(struct efx_auxdev_client *client,
				     const struct efx_auxdev_event *event);
struct efx_auxdev;

/**
 * struct efx_design_params - Design parameters.
 *
 * @rx_stride: stride between entries in receive window.
 * @rx_buffer_len: Length of each receive buffer.
 * @rx_queues: Maximum Rx queues available.
 * @tx_apertures: Maximum Tx apertures available.
 * @rx_buf_fifo_size: Maximum number of receive buffers can be posted.
 * @frame_offset_fixed: Fixed offset to the frame.
 * @rx_metadata_len: Receive metadata length.
 * @tx_max_reorder: Largest window of reordered writes to the CTPIO.
 * @tx_aperture_size: CTPIO aperture length.
 * @tx_fifo_size: Size of packet FIFO per CTPIO aperture.
 * @ts_subnano_bit: partial time stamp in sub nano seconds.
 * @unsol_credit_seq_mask: Width of sequence number in EVQ_UNSOL_CREDIT_GRANT
 *	register.
 * @l4_csum_proto: L4 csum fields.
 * @max_runt: Max length of frame data when LEN_ERR indicates runt.
 * @evq_sizes: Event queue sizes.
 * @num_filter: Number of filters.
 */
struct efx_design_params {
	u32 rx_stride;
	u32 rx_buffer_len;
	u32 rx_queues;
	u32 tx_apertures;
	u32 rx_buf_fifo_size;
	u32 frame_offset_fixed;
	u32 rx_metadata_len;
	u32 tx_max_reorder;
	u32 tx_aperture_size;
	u32 tx_fifo_size;
	u32 ts_subnano_bit;
	u32 unsol_credit_seq_mask;
	u32 l4_csum_proto;
	u32 max_runt;
	u32 evq_sizes;
	u32 num_filter;
};

/**
 * struct efx_auxdev_client - Information for attached drivers.
 *
 * This is also used for device operations.
 *
 * @auxdev: Auxiliary device in use.
 * @event_handler: Driver callback for device events.
 * @events_requested: Bitmap of events reported to the driver.
 * @client_id: Unique identifier to manage resources for this client.
 * @driver_data: For private use by the attached driver.
 * @net_dev: Optional, set if the client's parent has a network device.
 * @channels: All channels allocated to this client. Each entry is a pointer to
 *	a struct efx_client_channel.
 * @design_params: Hardware design parameters.
 */
struct efx_auxdev_client {
	struct efx_auxdev *auxdev;
	efx_auxdev_event_handler *event_handler;
	unsigned int events_requested;
	u32 client_id;
	void *driver_data;
	struct net_device *net_dev;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
	struct xarray channels;
#endif
	struct efx_design_params design_params;
};

/* Device API */

/**
 * struct efx_auxdev_rpc - Remote Procedure Call to the firmware.
 *
 * @cmd: MCDI command to perform.
 * @inlen: Size of @inbuf, in bytes.
 * @inbuf: Input parameters to the MCDI command. This may be %NULL if @inlen
 *	is 0.
 * @outlen: Size of @outbuf (provided by the caller), in bytes.
 * @outlen_actual: The number of bytes in @outbuf that have been populated by
 *	the firmware. On older firmware this could be less than @outlen, so
 *	output beyond @outlen_actual must not be used. This may be %NULL if
 *	@outlen is 0.
 * @outbuf: Output results from the MCDI command. This buffer must be provided
 *	by the caller. This may be %NULL if @outlen is 0.
 */
struct efx_auxdev_rpc {
	unsigned int cmd;
	size_t inlen;
	const u32 *inbuf;
	size_t outlen;
	size_t outlen_actual;
	u32 *outbuf;
};

#ifdef EFX_NOT_UPSTREAM
/* Provide backward compatibility for upstream commit 04c04725c1d0. */
#include <uapi/linux/ethtool.h>
#if !defined(RXH_XFRM_SYM_XOR)
/* Keep this definition in sync with that in kernel_compat.h */
struct ethtool_rxfh_param {
	u8	hfunc;
	u32	indir_size;
	u32	*indir;
	u32	key_size;
	u8	*key;
	u32	rss_context;
	u8	rss_delete;
	u8	input_xfrm;
};

#define RXH_XFRM_SYM_XOR	BIT(0)
#endif
struct ethtool_rxfh_param;
/* Defined in filter.h */
struct efx_filter_spec;

/**
 * struct efx_auxdev_dl_vi_resources - Driverlink VI information
 *
 * @vi_base: Absolute index of first VI in this function.  This may change
 *	after a reset.  Clients that cache this value will need to update
 *	the cached value in their reset_resume() function.
 * @vi_min: Relative index of first available VI
 * @vi_lim: Relative index of last available VI + 1
 * @rss_channel_count: Number of receive channels used for RSS.
 * @vi_shift: Shift value for absolute VI number computation.
 * @vi_stride: size in bytes of a single VI.
 */
struct efx_auxdev_dl_vi_resources {
	unsigned int vi_base;
	unsigned int vi_min;
	unsigned int vi_lim;
	unsigned int rss_channel_count;
	unsigned int vi_shift;
	unsigned int vi_stride;
};

/**
 * enum efx_auxiliary_param - Device parameters
 *
 * @EFX_NETDEV: Optional, set if the client's parent has an ethernet device.
 *	Get only.
 *	Returned through @net_dev.
 * @EFX_MEMBASE: Kernel virtual address of the start of the memory BAR.
 *	Get only.
 *	Returned through @membase_addr.
 * @EFX_MEMBAR: PCIe memory BAR index. Get only.
 *	Returned through @value to be interpreted as unsigned.
 * @EFX_USE_MSI: Hardware only has an MSI interrupt, no MSI-X.
 *	Get only.
 *	Returned through @b.
 * @EFX_CHANNELS: All channels allocated to this client. Each entry is a
 *	pointer to a struct efx_client_channel. Get only.
 *	Returned through @channels.
 * @EFX_RXFH_DEFAULT_FLAGS: Default RSS flags. Get only.
 *	Returned through @value.
 * @EFX_DESIGN_PARAM: Hardware design parameters. Get only.
 *	Returned through @design_params.
 * @EFX_PCI_DEV: The PCI device, as `struct pci_dev`. Get only.
 *	Value passed via @pci_dev.
 * @EFX_PCI_DEV_DEVICE: The underlying PCI device, as `pci_dev->device`.
 *	Get only.
 *	Value passed via @value.
 * @EFX_DEVICE_REVISION: Device revision. Get only. Value passed via @value.
 * @EFX_TIMER_QUANTUM_NS: Timer quantum (nominal period between timer ticks)
 *      for wakeup timers, in nanoseconds. Get only.
 *      Value passed via @value.
 * @EFX_DRIVER_DATA: Private data used by the attached driver. Get or set.
 *	Returned through @driver_data.
 * @EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST: Block unicast traffic. Get or set.
 *	Value passed via @b.
 * @EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST: Block multicast traffic. Get or set.
 *	Value passed via @b.
 */
enum efx_auxiliary_param {
	EFX_NETDEV,
	EFX_MEMBASE,
	EFX_MEMBAR,
	EFX_USE_MSI,
	EFX_CHANNELS,
	EFX_RXFH_DEFAULT_FLAGS,
	EFX_DESIGN_PARAM,
	EFX_PCI_DEV,
	EFX_PCI_DEV_DEVICE,
	EFX_DEVICE_REVISION,
	EFX_TIMER_QUANTUM_NS,
	EFX_DRIVER_DATA,
	EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST,
	EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST,
};

/** Possible values for device parameters */
union efx_auxiliary_param_value {
	struct net_device *net_dev;
	void __iomem *membase_addr;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
	struct xarray channels;
#endif
	int value;
	bool b;
	struct efx_design_params *design_params;
	void *driver_data;
	struct pci_dev *pci_dev;
};
#endif

/**
 * struct efx_auxdev_ops - Device operations.
 *
 * @open: Clients need to open a device before using it. This allocates a
 *	client ID used for further operations, and can register a callback
 *	function for events. events_requested is a bitmap of
 *	enum efx_event_type.
 *	Returns an error pointer for a failure.
 * @close: Closing a device stops it from getting events and frees client
 *	resources.
 * @fw_rpc: Remote procedure call to the firmware. Returns a negative error
 *	code or 0 on success.
 *
 * @create_rxfh_context: Allocate an RSS context.
 * @modify_rxfh_context: Modify an RSS context.
 * @remove_rxfh_context: Free an RSS context.
 */
struct efx_auxdev_ops {
	struct efx_auxdev_client *(*open)(struct auxiliary_device *auxdev,
					  efx_auxdev_event_handler *func,
					  unsigned int events_requested);
	void (*close)(struct efx_auxdev_client *handle);

	int (*fw_rpc)(struct efx_auxdev_client *handle,
		      struct efx_auxdev_rpc *rpc);

	int (*create_rxfh_context)(struct efx_auxdev_client *handle,
				   struct ethtool_rxfh_param *ctx,
				   u8 num_queues);
	int (*modify_rxfh_context)(struct efx_auxdev_client *handle,
				   struct ethtool_rxfh_param *ctx);
	int (*remove_rxfh_context)(struct efx_auxdev_client *handle,
				   struct ethtool_rxfh_param *ctx);

#ifdef EFX_NOT_UPSTREAM
	/** @filter_insert: Insert an RX filter. */
	int (*filter_insert)(struct efx_auxdev_client *handle,
			     const struct efx_filter_spec *spec,
			     bool replace_equal);
	/** @filter_remove: Remove an RX filter. */
	int (*filter_remove)(struct efx_auxdev_client *handle,
			     int filter_id);
	/** @filter_redirect: Redirect an RX filter */
	int (*filter_redirect)(struct efx_auxdev_client *handle,
			       int filter_id, int rxq_i, u32 *rss_context,
			       int stack_id);
	/** @get_param: Obtain the setting for an @efx_auxiliary_param. */
	int (*get_param)(struct efx_auxdev_client *handle,
			 enum efx_auxiliary_param p,
			 union efx_auxiliary_param_value *arg);
	/** @set_param: Set an @efx_auxiliary_param. */
	int (*set_param)(struct efx_auxdev_client *handle,
			 enum efx_auxiliary_param p,
			 union efx_auxiliary_param_value *arg);
	/**
	 * @dl_publish: Do driverlink-compatible VI allocation. Also brings up
	 *	the netdev interface. Each call to this function must be paired
	 *	with a corresponding @dl_unpublish call, and this function may
	 *	not be called again before @dl_unpublish.
	 */
	struct efx_auxdev_dl_vi_resources *
		(*dl_publish)(struct efx_auxdev_client *handle);
	/**
	 * @dl_unpublish: Free driverlink-compatible VIs. Also brings down the
	 *	netdev interface.
	 */
	void (*dl_unpublish)(struct efx_auxdev_client *handle);
	/**
	 * @set_multicast_loopback_suppression: Configure if multicast loopback
	 *	traffic should be suppressed.
	 */
	int (*set_multicast_loopback_suppression)(struct efx_auxdev_client *handle,
						  bool suppress, u16 vport_id,
						  u8 stack_id);
	/** @set_rxfh_flags: Set RSS flags for an RSS context. */
	int (*set_rxfh_flags)(struct efx_auxdev_client *handle, u32 rss_context,
			      u32 flags);
	/* @vport_new: Allocate a vport. */
	int (*vport_new)(struct efx_auxdev_client *handle, u16 vlan,
			 bool vlan_restrict);
	/* @vport_free: Free a vport. */
	int (*vport_free)(struct efx_auxdev_client *handle, u16 port_id);
	/* @vport_id_get Return underlying vport id handle in lower 32
	 * bits. On failure, return a negative rc.
	 */
	s64 (*vport_id_get)(struct efx_auxdev_client *handle, u16 port_id);
#endif
};

/**
 * struct efx_auxdev - Auxiliary device interface.
 *
 * @auxdev: The parent auxiliary bus device.
 * @ops: Device API.
 */
struct efx_auxdev {
	struct auxiliary_device auxdev;
	const struct efx_auxdev_ops *ops;
};

static inline struct efx_auxdev *to_efx_auxdev(struct auxiliary_device *adev)
{
	return container_of(adev, struct efx_auxdev, auxdev);
}
#endif /* _EFX_AUXBUS_H */
