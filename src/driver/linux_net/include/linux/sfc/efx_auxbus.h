/* SPDX-License-Identifier: GPL-2.0 */
/*
 * efx_auxbus.h - Solarflare auxiliary bus interface
 *
 * Copyright 2023-2024, Advanced Micro Devices, Inc.
 */
#ifndef _EFX_AUXBUS_H
#define _EFX_AUXBUS_H

#include "efx_design_params.h"

/* This is part of the device name exposed in the auxiliary bus. */
#ifdef EFX_NOT_UPSTREAM
#define EFX_ONLOAD_DEVNAME	"onload"
#endif
#define EFX_LLCT_DEVNAME	"llct"

/* Auxbus ABI major version. This is incremented whenever the ABI is changed
 * such that it is not backwards compatible with the previous ABI version. For
 * example, this is so when the offsets of fields in &struct efx_auxdev are
 * changed.
 */
#define EFX_AUX_ABI_VERSION_MAJOR 1
/* Auxbus ABI minor version. This is incremented when the ABI is changed such
 * that it is backwards compatible with the previous ABI version. For example,
 * this is so when fields in &struct efx_auxdev are added to the end of the
 * struct.
 */
#define EFX_AUX_ABI_VERSION_MINOR 0
#define EFX_AUX_ABI_VERSION ((EFX_AUX_ABI_VERSION_MAJOR << 16) | \
			     EFX_AUX_ABI_VERSION_MINOR)
#define EFX_AUX_ABI_VERSION_MAJOR_GET(ver) (ver >> 16)
#define EFX_AUX_ABI_VERSION_MINOR_GET(ver) (ver & 0xffff)

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

/* Current state for an EFX_EVENT_IN_RESET event. */
#define EFX_NOT_IN_RESET	0
#define EFX_IN_RESET		1
#define EFX_HARDWARE_DISABLED	2

/**
 * struct efx_auxdev_event - One event for an auxiliary bus driver.
 *
 * @type: Event type as defined in enum efx_event_type.
 * @value: Event specific value. For %EFX_EVENT_IN_RESET this is 1 when the
 *	hardware is resetting, and 0 during normal operation. The value 2
 *	indicates the hardware can not be recovered and has been disabled.
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
 * @txqs: Xarray mapping a txq QUEUE_NUM to a QUEUEHANDLE.
 * @rxqs: Xarray mapping a rxq QUEUE_NUM to a QUEUEHANDLE.
 * @evqs: Xarray mapping an evq QUEUE_NUM to a QUEUEHANDLE.
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
	struct xarray txqs;
	struct xarray rxqs;
	struct xarray evqs;
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

/** Location of an IO area associated with a queue.
 * @qid_in: Queue ID which the returned region is for.
 * @base: bus address of base of the region.
 * @size: size of this queue's region.
 */
struct efx_auxiliary_io_window {
	int qid_in;
	resource_size_t base;
	size_t size;
};

/**
 * enum efx_auxiliary_param - Device parameters
 *
 * @EFX_NETDEV: Optional, set if the client's parent has an ethernet device.
 *	Get only.
 *	Returned through @net_dev.
 * @EFX_MEMBASE: Kernel virtual address of the start of the memory BAR.
 *	Get only.
 *	Returned through @iomem_addr.
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
 * @EFX_AUXILIARY_INT_PRIME: The location of the EVQ_INT_PRIME register.
 *      Get only.
 *      Returned through @iomem_addr.
 * @EFX_AUXILIARY_EVQ_WINDOW: The location of control area for event queues.
 *      The base address is for the event queue evq_min provided through
 *      EFX_AUXILIARY_NIC_RESOURCES. The stride can be used to calculate the
 *      offset of each subsequent event queue from this base.
 *      Get only.
 *      Returned through @queue_io_wnd.
 * @EFX_AUXILIARY_CTPIO_WINDOW: The bus address of the CTPIO region for a TXQ
 *      On successful return the provided addr will refer to the IO region, and
 *      size will provide the size of the region.
 *      The returned address should be IO mapped for access to the region.
 *	Get only.
 *	Return through @queue_io_wnd
 * @EFX_AUXILIARY_RXQ_WINDOW: The bus address of the IO region for an RXQ
 *      On successful return the provided addr will refer to the IO region, and
 *      size will provide the size of the region.
 *      The returned address should be IO mapped for access to the region.
 *	Get only.
 *	Return through @queue_io_wnd
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
	EFX_AUXILIARY_INT_PRIME,
	EFX_AUXILIARY_EVQ_WINDOW,
	EFX_AUXILIARY_CTPIO_WINDOW,
	EFX_AUXILIARY_RXQ_WINDOW,
};

/** Possible values for device parameters */
union efx_auxiliary_param_value {
	struct net_device *net_dev;
	void __iomem *iomem_addr;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_HAVE_XARRAY)
	struct xarray channels;
#endif
	int value;
	bool b;
	struct efx_design_params *design_params;
	void *driver_data;
	struct pci_dev *pci_dev;
	struct efx_auxiliary_io_window queue_io_wnd;
};
#endif

/**
 * struct efx_auxdev_ops - Base device operations, common across multiple
 *	device types.
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
 */
struct efx_auxdev_ops {
	struct efx_auxdev_client *(*open)(struct auxiliary_device *auxdev,
					  efx_auxdev_event_handler *func,
					  unsigned int events_requested);
	void (*close)(struct efx_auxdev_client *handle);

	int (*fw_rpc)(struct efx_auxdev_client *handle,
		      struct efx_auxdev_rpc *rpc);
#ifdef EFX_NOT_UPSTREAM
	/** @get_param: Obtain the setting for an @efx_auxiliary_param. */
	int (*get_param)(struct efx_auxdev_client *handle,
			 enum efx_auxiliary_param p,
			 union efx_auxiliary_param_value *arg);
	/** @set_param: Set an @efx_auxiliary_param. */
	int (*set_param)(struct efx_auxdev_client *handle,
			 enum efx_auxiliary_param p,
			 union efx_auxiliary_param_value *arg);
#endif
};

/**
 * struct efx_auxdev_onload_ops - Device operations on the full-featured
 *	device type.
 *
 * @base_ops: Common device operations.
 * @create_rxfh_context: Allocate an RSS context.
 * @modify_rxfh_context: Modify an RSS context.
 * @remove_rxfh_context: Free an RSS context.
 */
struct efx_auxdev_onload_ops {
	const struct efx_auxdev_ops *base_ops;

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
	/**
	 * @dl_publish: Do driverlink-compatible VI allocation. Also brings up
	 *	the netdev interface. Each call to this function must be paired
	 *	with a corresponding @dl_unpublish call, and this function may
	 *	not be called again before @dl_unpublish. The returned pointer remains
	 *	valid after %EFX_AUXDEV_EVENT_IN_RESET though the contents may
	 *	be non-atomically updated during this event. The contents should therefore
	 *	only be read after dl_publish or %EFX_AUXDEV_EVENT_IN_RESET.
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
	/** @vport_new: Allocate a vport. */
	int (*vport_new)(struct efx_auxdev_client *handle, u16 vlan,
			 bool vlan_restrict);
	/** @vport_free: Free a vport. */
	int (*vport_free)(struct efx_auxdev_client *handle, u16 port_id);
	/**
	 * @vport_id_get: Return underlying vport id handle in lower 32
	 * bits. On failure, return a negative rc.
	 */
	s64 (*vport_id_get)(struct efx_auxdev_client *handle, u16 port_id);
#endif
};

/**
 * struct efx_auxdev_irq - A struct that describes an interrupt vector
 *	in OS and NIC vector tables.
 *
 * @os_vector: An MSI-X interrupt number.
 * @nic_nr: An IRQ number to put into MCDI command to initialise an EVQ.
 */
struct efx_auxdev_irq {
	int os_vector;
	int nic_nr;
};
/**
 * struct efx_auxdev_llct_ops - Device operations on the low-latency device
 *	type.
 *
 *	This API is meant to be flexible to allow various Q configurations
 *	with optional interrupt handling and sharing. It assumes that one
 *	client can allocate resources for independent use, i.e. serving
 *	different applications.
 *
 * @base_ops: Common device operations.
 *
 * @channel_alloc: Create a new channel. Returns an error (< 0) or the channel
 *	number. A channel is a software construct, but it encapsulates one EVQ.
 * @channel_free: Release a channel.
 *
 * @irq_alloc: Allocate an interrupt vector. Return an error pointer on fail.
 * @irq_free: Release an interrupt vector.
 *
 * @txq_alloc: Allocate a TXQ. Return an error (< 0) or TXQ number.
 * @txq_free: Release a TXQ.
 *
 * @rxq_alloc: Allocate an RXQ. Return an error (< 0) or RXQ number.
 * @rxq_free: Release an RXQ.
 */
struct efx_auxdev_llct_ops {
	const struct efx_auxdev_ops *base_ops;

	int (*channel_alloc)(struct efx_auxdev_client *handle);
	void (*channel_free)(struct efx_auxdev_client *handle, int channel_nr);

	struct efx_auxdev_irq *(*irq_alloc)(struct efx_auxdev_client *handle);
	void (*irq_free)(struct efx_auxdev_client *handle,
			 struct efx_auxdev_irq *);

	int (*txq_alloc)(struct efx_auxdev_client *handle);
	void (*txq_free)(struct efx_auxdev_client *handle, int txq_nr);

	int (*rxq_alloc)(struct efx_auxdev_client *handle);
	void (*rxq_free)(struct efx_auxdev_client *handle, int rxq_nr);
};

/**
 * struct efx_auxdev - Auxiliary device interface.
 *
 * @auxdev: The parent auxiliary bus device.
 * @abi_version: ABI version of this auxbus interface. Offset may not change.
 * @onload_ops: Device API.
 * @llct_ops: LLCT device API.
 */
struct efx_auxdev {
	struct auxiliary_device auxdev;
	u32 abi_version;
	const struct efx_auxdev_onload_ops *onload_ops;
	const struct efx_auxdev_llct_ops *llct_ops;
};

static inline struct efx_auxdev *to_efx_auxdev(struct auxiliary_device *adev)
{
	return container_of(adev, struct efx_auxdev, auxdev);
}

static inline bool efx_aux_abi_version_is_compat(u32 abi_version)
{
	u32 major_ver = EFX_AUX_ABI_VERSION_MAJOR_GET(abi_version);
	u32 minor_ver = EFX_AUX_ABI_VERSION_MINOR_GET(abi_version);
	/* Majors must match. Provided minor must be newer or equal to the
	 * client's.
	 */
	return major_ver == EFX_AUX_ABI_VERSION_MAJOR &&
	       minor_ver >= EFX_AUX_ABI_VERSION_MINOR;
}
#endif /* _EFX_AUXBUS_H */
