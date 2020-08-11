/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2005-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DRIVERLINK_API_H
#define EFX_DRIVERLINK_API_H

#include <linux/list.h>
#include <linux/module.h>
#include "filter.h"

/* Forward declarations */
struct pci_dev;
struct net_device;
struct efx_dl_device;
struct efx_dl_device_info;

/* Driverlink API source compatibility version.  This is incremented
 * whenever a definition is added, removed or changed such that a
 * client might need to guard its use with a compile-time check.  It
 * is not used for binary compatibility checking, as that is done by
 * kbuild and the module loader using symbol versions.
 */
#define EFX_DRIVERLINK_API_VERSION 29
#define EFX_DRIVERLINK_API_VERSION_MINOR_MAX 0

/* If the client didn't define their VERSION_MINOR, default to 0 */
#ifndef EFX_DRIVERLINK_API_VERSION_MINOR
#define EFX_DRIVERLINK_API_VERSION_MINOR 0
#endif

/**
 * enum efx_dl_ev_prio - Driverlink client's priority level for event handling
 * @EFX_DL_EV_HIGH: Client driver wants to handle events first
 * @EFX_DL_EV_MED: Client driver is not particular about priority
 * @EFX_DL_EV_LOW: Client driver wants to handle events last
 */
enum efx_dl_ev_prio {
	EFX_DL_EV_HIGH = 0,
	EFX_DL_EV_MED,
	EFX_DL_EV_LOW,
};

/**
 * enum efx_dl_driver_flags - flags for Driverlink client driver behaviour
 * @EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE: Set by drivers that
 *	promise to use the RX buffer size programmed by the net driver
 *	on Falcon and Siena.  Defined from API version 8.
 * @EFX_DL_DRIVER_REQUIRES_MINOR_VER: Set by client drivers to indicate the
 *      minor_ver entry us present in their struct. Defined from API 22.1.
 * @EFX_DL_DRIVER_SUPPORTS_MINOR_VER: Set by the device driver to
 *      indicate the minor version supplied by the client is supported.
 * @EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE: Set by client drivers that
 *	promise to use the VI stride and memory BAR supplied by the net
 *	driver on Medford2.  If this flag is not set, the client driver
 *	will not be probed for Medford2 (or newer) NICs.  Defined from API 22.5.
 * @EFX_DL_DRIVER_NO_STACK: Set by client drivers to indicate they are only
 *      interested in querying interfaces and are not a stack.
 *      This will cause the driver not to allocate resources for them, but
 *      they cannot insert filters or create queues.
 */
enum efx_dl_driver_flags {
	EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE = 0x1,
	EFX_DL_DRIVER_REQUIRES_MINOR_VER = 0x2,
	EFX_DL_DRIVER_SUPPORTS_MINOR_VER = 0x4,
	EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE = 0x8,
	EFX_DL_DRIVER_NO_PUBLISH = 0x10,
};

/**
 * struct efx_dl_driver - Driverlink client driver
 *
 * A driverlink client defines and initializes as many instances of
 * efx_dl_driver as required, registering each one with
 * efx_dl_register_driver().
 *
 * @name: Name of the driver
 * @priority: Priority of this driver in event handling
 * @flags: Flags describing driver behaviour.  Defined from API version 8.
 * @probe: Called when device added
 *	The client should use the @dev_info linked list to determine
 *	if they wish to attach to this device.  (@silicon_rev is a
 *	dummy parameter.)
 *	Context: process, rtnl_lock held
 * @remove: Called when device removed
 *	The client must ensure the finish all operations with this
 *	device before returning from this method.
 *	Context: process, rtnl_lock held
 * @reset_suspend: Called before device is reset
 *	Called immediately before a hardware reset. The client must stop all
 *	hardware processing before returning from this method. Callbacks will
 *	be inactive when this method is called.
 *	Context: process, rtnl_lock held
 * @reset_resume: Called after device is reset
 *	Called after a hardware reset. If @ok is true, the client should
 *	state and resume normal operations. If @ok is false, the client should
 *	abandon use of the hardware resources. remove() will still be called.
 *	Context: process, rtnl_lock held
 * @handle_event: Called when an event on a single-function port may
 *	need to be handled by a client.  May be %NULL if the client
 *	driver does not handle events.  Returns %true if the event is
 *	recognised and handled, else %false.  If multiple clients
 *	registered for a device implement this operation, they will be
 *	called in priority order from high to low, until one returns
 *	%true.  Context: NAPI.
 *
 * Prior to API version 7, only one driver with non-null @handle_event
 * could be registered for each device.  The @priority field was not
 * defined and the return type of @handle_event was void.
 */
struct efx_dl_driver {
/* public: */
	const char *name;
	enum efx_dl_ev_prio priority;
	enum efx_dl_driver_flags flags;

	int (*probe)(struct efx_dl_device *efx_dev,
		     const struct net_device *net_dev,
		     const struct efx_dl_device_info *dev_info,
		     const char *silicon_rev);
	void (*remove)(struct efx_dl_device *efx_dev);
	void (*reset_suspend)(struct efx_dl_device *efx_dev);
	void (*reset_resume)(struct efx_dl_device *efx_dev, int ok);
	int (*handle_event)(struct efx_dl_device *efx_dev,
			    void *p_event, int budget);

	unsigned int minor_ver;

/* private: */
	struct list_head driver_node;
	struct list_head device_list;
};

/**
 * enum efx_dl_device_info_type - Device information identifier.
 *
 * Used to identify each item in the &struct efx_dl_device_info linked list
 * provided to each driverlink client in the probe() @dev_info member.
 *
 * @EFX_DL_FALCON_RESOURCES: Information type is &struct efx_dl_falcon_resources
 * @EFX_DL_HASH_INSERTION: Information type is &struct efx_dl_hash_insertion
 * @EFX_DL_SIENA_SRIOV: Information type is &struct efx_dl_siena_sriov
 * @EFX_DL_AOE_RESOURCES: Information type is &struct efx_dl_aoe_resources.
 *	Defined from API version 6.
 * @EFX_DL_EF10_RESOURCES: Information type is &struct efx_dl_ef10_resources.
 *	Defined from API version 9.
 */
enum efx_dl_device_info_type {
	EFX_DL_FALCON_RESOURCES = 0,
	EFX_DL_HASH_INSERTION = 1,
	EFX_DL_SIENA_SRIOV = 2,
	EFX_DL_MCDI_RESOURCES = 3,
	EFX_DL_AOE_RESOURCES = 4,
	EFX_DL_EF10_RESOURCES = 5,
	EFX_DL_IRQ_RESOURCES = 6,
};

/**
 * struct efx_dl_device_info - device information structure
 *
 * @next: Link to next structure, if any
 * @type: Type code for this structure
 */
struct efx_dl_device_info {
	struct efx_dl_device_info *next;
	enum efx_dl_device_info_type type;
};

/**
 * enum efx_dl_falcon_resource_flags - Falcon/Siena resource information flags.
 *
 * Flags that describe hardware variations for the current Falcon or
 * Siena device.
 *
 * @EFX_DL_FALCON_DUAL_FUNC: Port is dual-function. (obsolete)
 * @EFX_DL_FALCON_USE_MSI: Port is initialised to use MSI/MSI-X interrupts.
 *	Falcon supports traditional legacy interrupts and MSI/MSI-X
 *	interrupts. The choice is made at run time by the sfc driver, and
 *	notified to the clients by this enumeration
 * @EFX_DL_FALCON_ONLOAD_UNSUPPORTED: OpenOnload unsupported on this port.
 * @EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT: %rss_channel_count member is valid.
 * @EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS: %timer_quantum_ns member is valid.
 */
enum efx_dl_falcon_resource_flags {
	EFX_DL_FALCON_DUAL_FUNC = 0x1,
	EFX_DL_FALCON_USE_MSI = 0x2,
	EFX_DL_FALCON_ONLOAD_UNSUPPORTED = 0x4,
	EFX_DL_FALCON_WRITE_COMBINING = 0x8,
	EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT = 0x10,
	EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS = 0x20,
};

/**
 * struct efx_dl_falcon_resources - Falcon/Siena resource information.
 *
 * This structure describes Falcon or Siena hardware resources available for
 * use by a driverlink driver.
 *
 * @hdr: Resource linked list header
 * @biu_lock: Register access lock. Access to configuration registers on
 *	the underlying PCI function must be serialised using this spinlock.
 * @buffer_table_min: First available buffer table entry
 * @buffer_table_lim: Last available buffer table entry + 1
 * @evq_timer_min: First available event queue with timer
 * @evq_timer_lim: Last available event queue with timer + 1
 * @evq_int_min: First available event queue with interrupt
 * @evq_int_lim: Last available event queue with interrupt + 1
 * @rxq_min: First available RX queue
 * @rxq_lim: Last available RX queue + 1
 * @txq_min: First available TX queue
 * @txq_lim: Last available TX queue + 1
 * @flags: Hardware variation flags
 * @rss_channel_count: Number of receive channels used for RSS. This member is
 *	only present if %EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT is set.
 * @timer_quantum_ns: Timer quantum (nominal period between timer ticks)
 *	for wakeup timers, in nanoseconds. This member is only present if
 *	%EFX_DL_FALCON_HAVE_TIMER_QUANTUM_NS is set.
 * @rx_usr_buf_size: RX buffer size for user-mode queues and kernel-mode
 *	queues with scatter enabled, in bytes.  Defined from API version 8.
 * @rx_channel_count: Number of receive channels available for use.
 */
struct efx_dl_falcon_resources {
	struct efx_dl_device_info hdr;
	spinlock_t *biu_lock;
	unsigned int buffer_table_min;
	unsigned int buffer_table_lim;
	unsigned int evq_timer_min;
	unsigned int evq_timer_lim;
	unsigned int evq_int_min;
	unsigned int evq_int_lim;
	unsigned int rxq_min;
	unsigned int rxq_lim;
	unsigned int txq_min;
	unsigned int txq_lim;
	enum efx_dl_falcon_resource_flags flags;
	unsigned int rss_channel_count;
	unsigned int timer_quantum_ns;
	unsigned int rx_usr_buf_size;
	unsigned int rx_channel_count;
};

/**
 * enum efx_dl_hash_type_flags - Hash insertion type flags
 *
 * @EFX_DL_HASH_TOEP_TCPIP4: Toeplitz hash of TCP/IPv4 4-tuple
 * @EFX_DL_HASH_TOEP_IP4: Toeplitz hash of IPv4 addresses
 * @EFX_DL_HASH_TOEP_TCPIP6: Toeplitz hash of TCP/IPv6 4-tuple
 * @EFX_DL_HASH_TOEP_IP6: Toeplitz hash of IPv6 addresses
 */
enum efx_dl_hash_type_flags {
	EFX_DL_HASH_TOEP_TCPIP4 = 0x1,
	EFX_DL_HASH_TOEP_IP4 = 0x2,
	EFX_DL_HASH_TOEP_TCPIP6 = 0x4,
	EFX_DL_HASH_TOEP_IP6 = 0x8,
};

/**
 * struct efx_dl_hash_insertion - Hash insertion behaviour
 *
 * @hdr: Resource linked list header
 * @data_offset: Offset of packet data relative to start of buffer
 * @hash_offset: Offset of hash relative to start of buffer
 * @flags: Flags for hash type(s) enabled
 */
struct efx_dl_hash_insertion {
	struct efx_dl_device_info hdr;
	unsigned int data_offset;
	unsigned int hash_offset;
	enum efx_dl_hash_type_flags flags;
};

/**
 * struct efx_dl_siena_sriov - Siena SRIOV information - UNUSED
 *
 * This structure is initialised before pci_enable_sriov() is called,
 * which mail fail. Therefore the consumer should cope with the fact
 * that there may be fewer than %vf_count VFs.
 *
 * @hdr: Resource linked list header
 * @vi_base: The zeroth VI mapped into VFs
 * @vi_scale: Log2 of the number of VIs per VF
 * @vf_count: Number of VFs intended to be enabled
 */
struct efx_dl_siena_sriov {
	struct efx_dl_device_info hdr;
	unsigned int vi_base;
	unsigned int vi_scale;
	unsigned int vf_count;
};

/**
 * struct efx_dl_aoe - Information about an AOE attached to the NIC
 *
 * @hdr: Resource linked list header
 * @internal_macs: Number of internal MACs (connected to the NIC)
 * @external_macs: Number of external MACs
 *
 * Defined from API version 6.
 */
struct efx_dl_aoe_resources {
	struct efx_dl_device_info hdr;
	unsigned internal_macs;
	unsigned int external_macs;
};

/**
 * enum efx_dl_ef10_resource_flags - EF10 resource information flags.
 *
 * Flags that describe hardware variations for the current EF10 or
 * Siena device.
 *
 * @EFX_DL_EF10_USE_MSI: Port is initialised to use MSI/MSI-X interrupts.
 *      EF10 supports traditional legacy interrupts and MSI/MSI-X
 *      interrupts. The choice is made at run time by the sfc driver, and
 *      notified to the clients by this enumeration
 */
enum efx_dl_ef10_resource_flags {
	EFX_DL_EF10_USE_MSI = 0x2,
};

/**
 * struct efx_dl_ef10_resources - EF10 resource information
 *
 * @hdr: Resource linked list header
 * @vi_base: Absolute index of first VI in this function.  This may change
 *	after a reset.  Clients that cache this value will need to update
 *	the cached value in their reset_resume() function.
 * @vi_min: Relative index of first available VI
 * @vi_lim: Relative index of last available VI + 1
 * @timer_quantum_ns: Timer quantum (nominal period between timer ticks)
 *      for wakeup timers, in nanoseconds.
 * @rss_channel_count: Number of receive channels used for RSS.
 * @rx_channel_count: Number of receive channels available for use.
 * @vi_shift: Shift value for absolute VI number computation.
 * @vi_stride: size in bytes of a single VI.
 * @mem_bar: PCIe memory BAR index.
 */
struct efx_dl_ef10_resources {
	struct efx_dl_device_info hdr;
	unsigned int vi_base;
	unsigned int vi_min;
	unsigned int vi_lim;
	unsigned int timer_quantum_ns;
	unsigned int rss_channel_count;
	enum efx_dl_ef10_resource_flags flags;
	unsigned int rx_channel_count;
	unsigned int vi_shift;
	unsigned int vi_stride;
	unsigned int mem_bar;
};

/**
 * struct efx_dl_irq_resources - interrupt resource information
 *
 * @hdr: Resource linked list header
 * @flags: currently none
 * @n_ranges: Number of entries in irq_ranges. Must be > 0.
 * @int_prime: Address of the INT_PRIME register.
 * @channel_base: Base channel number.
 * @irq_ranges: Array of interrupts, specified as base vector + range.
 */
struct efx_dl_irq_resources {
	struct efx_dl_device_info hdr;
	u16 flags;
	u16 n_ranges;
	void __iomem *int_prime;
	int channel_base;
	struct efx_dl_irq_range {
		int vector;
		int range;
	} irq_ranges[1];
};

/**
 * enum efx_dl_filter_block_kernel_type
 * @EFX_DL_FILTER_BLOCK_KERNEL_UCAST: Unicast
 * @EFX_DL_FILTER_BLOCK_KERNEL_MCAST: Multicast
 */
enum efx_dl_filter_block_kernel_type {
	EFX_DL_FILTER_BLOCK_KERNEL_UCAST = 0,
	EFX_DL_FILTER_BLOCK_KERNEL_MCAST,
	EFX_DL_FILTER_BLOCK_KERNEL_MAX,
};

/**
 * struct efx_dl_ops - Operations for driverlink clients to use
 * on a driverlink nic.
 */
struct efx_dl_ops {
	bool (*hw_unavailable)(struct efx_dl_device *efx_dev);
	void (*pause)(struct efx_dl_device *efx_dev);
	void (*resume)(struct efx_dl_device *efx_dev);
	void (*schedule_reset)(struct efx_dl_device *efx_dev);
	u32 (*rss_flags_default)(struct efx_dl_device *efx_dev);
	int (*rss_context_new)(struct efx_dl_device *efx_dev,
			       const u32 *indir, const u8 *key,
			       u32 flags, u8 num_queues,
			       u32 *rss_context);
	int (*rss_context_set)(struct efx_dl_device *efx_dev,
			       const u32 *indir, const u8 *key,
			       u32 flags, u32 rss_context);
	int (*rss_context_free)(struct efx_dl_device *efx_dev,
			       u32 rss_context);
	int (*filter_insert)(struct efx_dl_device *efx_dev,
			       const struct efx_filter_spec *spec,
			       bool replace_equal);
	int (*filter_remove)(struct efx_dl_device *efx_dev, int filter_id);
	int (*filter_redirect)(struct efx_dl_device *efx_dev,
			       int filter_id, int rxq_i, u32 *rss_context,
			       int stack_id);
	int (*vport_new)(struct efx_dl_device *efx_dev, u16 vlan,
			 bool vlan_restrict);
	int (*vport_free)(struct efx_dl_device *efx_dev, u16 port_id);
	int (*init_txq)(struct efx_dl_device *efx_dev, dma_addr_t *dma_addrs,
			int n_dma_addrs, u16 vport_id, u8 stack_id, u32 owner_id,
			bool timestamp, u8 crc_mode, bool tcp_udp_only,
			bool tcp_csum_dis, bool ip_csum_dis, bool inner_tcp_csum,
			bool inner_ip_csum, bool buff_mode, bool pacer_bypass,
			bool ctpio, bool ctpio_uthresh, u32 instance, u32 label,
			u32 target_evq, u32 num_entries);
	int (*init_rxq)(struct efx_dl_device *efx_dev, dma_addr_t *dma_addrs,
			int n_dma_addrs, u16 vport_id, u8 stack_id,
			u32 owner_id, u8 crc_mode, bool timestamp,
			bool hdr_split, bool buff_mode, bool rx_prefix,
			u8 dma_mode, u32 instance, u32 label, u32 target_evq,
			u32 num_entries, u8 ps_buf_size, bool force_rx_merge,
			int ef100_rx_buffer_size);
	int (*set_multicast_loopback_suppression)(struct efx_dl_device *efx_dev,
						  bool suppress, u16 vport_id,
						  u8 stack_id);
	int (*filter_block_kernel)(struct efx_dl_device *dl_dev,
				   enum efx_dl_filter_block_kernel_type block);
	void (*filter_unblock_kernel)(struct efx_dl_device *dl_dev,
				      enum efx_dl_filter_block_kernel_type type);
	int (*mcdi_rpc)(struct efx_dl_device *dl_dev,
			unsigned int cmd, size_t inlen, size_t outlen,
			size_t *outlen_actual,
			const u8 *inbuf, u8 *outbuf);
	int (*publish)(struct efx_dl_device *dl_dev);
	void (*unpublish)(struct efx_dl_device *dl_dev);
};

/**
 * struct efx_dl_nic - An Efx driverlink nic.
 *
 * @pci_dev: Underlying PCI function
 * @net_dev: Underlying net device
 * @ops: Operations struct for
 * @dl_info: hardware parameters
 * @msg_enable: netdev log level for netif_* messages.
 *
 * @nic_node: node for global nic list
 * @device_list: Head of list of efx_dl_devices
 *	for this nic
 */
struct efx_dl_nic {
	struct pci_dev *pci_dev;
	struct net_device *net_dev;
	struct efx_dl_ops *ops;

	struct efx_dl_device_info *dl_info;

	int msg_enable;

/* private: */
	struct list_head nic_node;
	struct list_head device_list;
};

/**
 * struct efx_dl_device - An Efx driverlink device.
 * There is one of these for each (driver, nic) tuple.
 *
 * @pci_dev: Underlying PCI function
 * @priv: Driver private data
 *	Driverlink clients can use this to store a pointer to their
 *	internal per-device data structure. Each (driver, device)
 *	tuple has a separate &struct efx_dl_device, so clients can use
 *	this @priv field independently.
 * @driver: Efx driverlink driver for this device
 * @nic: Efx driverlink nic for this device
 */
struct efx_dl_device {
	struct pci_dev *pci_dev;
	void *priv;
	struct efx_dl_driver *driver;
	struct efx_dl_nic *nic;
};

/**
 * efx_dl_unregister_driver() - Unregister a client driver
 * @driver: Driver operations structure
 *
 * This acquires the rtnl_lock and therefore must be called from
 * process context.
 */
void efx_dl_unregister_driver(struct efx_dl_driver *driver);

/* Include API version number in symbol used for efx_dl_register_driver
 * and efx_dl_register_nic
 */
#define efx_dl_stringify_1(x, y) x ## y
#define efx_dl_stringify_2(x, y) efx_dl_stringify_1(x, y)
#define efx_dl_register_driver					\
	efx_dl_stringify_2(efx_dl_register_driver_api_ver_,	\
			   EFX_DRIVERLINK_API_VERSION)
#define efx_dl_register_nic					\
	efx_dl_stringify_2(efx_dl_register_nic_api_ver_,	\
			   EFX_DRIVERLINK_API_VERSION)

/**
 * efx_dl_register_driver() - Register a client driver
 * @driver: Driver operations structure
 *
 * This acquires the rtnl_lock and therefore must be called from
 * process context.
 */
int efx_dl_register_driver(struct efx_dl_driver *driver);

/**
 * efx_dl_netdev_is_ours() - Check whether netdevice is a driverlink nic
 *
 * @net_dev: Net device to be checked
 */
bool efx_dl_netdev_is_ours(const struct net_device *net_dev);

/**
 * efx_dl_dev_from_netdev() - Find Driverlink device structure for net device
 * @net_dev: Net device to be checked
 * @driver: Driver structure for the device to be found
 *
 * Caller must hold the rtnl_lock.
 */
struct efx_dl_device *
efx_dl_dev_from_netdev(const struct net_device *net_dev,
		       struct efx_dl_driver *driver);

/* Schedule a reset without grabbing any locks */
static inline void efx_dl_schedule_reset(struct efx_dl_device *efx_dev)
{
	efx_dev->nic->ops->schedule_reset(efx_dev);
}

int efx_dl_publish(struct efx_dl_device *efx_dev);
void efx_dl_unpublish(struct efx_dl_device *efx_dev);

/**
 * efx_dl_rss_flags_default() - return appropriate default RSS flags for NIC
 * @efx_dev: NIC on which to act
 */
static inline u32 efx_dl_rss_flags_default(struct efx_dl_device *efx_dev)
{
	return efx_dev->nic->ops->rss_flags_default(efx_dev);
}

/**
 * efx_dl_rss_context_new() - allocate and configure a new RSS context
 * @efx_dev: NIC on which to act
 * @indir: initial indirection table, or %NULL to use default
 * @key: initial hashing key, or %NULL to use default
 * @flags: initial hashing flags (as defined by MCDI)
 * @num_queues: number of queues spanned by this context, in the range 1-64
 * @rss_context: location to store user_id of newly allocated RSS context
 */
static inline int efx_dl_rss_context_new(struct efx_dl_device *efx_dev,
					 const u32 *indir, const u8 *key,
					 u32 flags, u8 num_queues,
					 u32 *rss_context)
{
	return efx_dev->nic->ops->rss_context_new(efx_dev, indir, key, flags,
						  num_queues, rss_context);
}

/**
 * efx_dl_rss_context_set() - update the configuration of existing RSS context
 * @efx_dev: NIC on which to act
 * @indir: new indirection table, or %NULL for no change
 * @key: new hashing key, or %NULL for no change
 * @flags: new hashing flags (as defined by MCDI)
 * @rss_context: user_id of RSS context on which to act.  Should be a value
 *	previously written by efx_dl_rss_context_new().
 */
static inline int efx_dl_rss_context_set(struct efx_dl_device *efx_dev,
					 const u32 *indir, const u8 *key,
					 u32 flags, u32 rss_context)
{
	return efx_dev->nic->ops->rss_context_set(efx_dev, indir, key, flags,
						  rss_context);
}

/**
 * efx_dl_rss_context_free() - remove an existing RSS context
 * @efx_dev: NIC on which to act
 * @rss_context: user_id of RSS context to be removed.  Should be a value
 *	previously written by efx_dl_rss_context_new().
 */
static inline int efx_dl_rss_context_free(struct efx_dl_device *efx_dev,
					  u32 rss_context)
{
	return efx_dev->nic->ops->rss_context_free(efx_dev, rss_context);
}

/* From API version 23, @spec->rss_context is a user_id allocated by the driver,
 * as per comments in filter.h.  In older Driverlink versions, it was an MCFW-
 * facing ID, but that behaviour caused problems around resets (bug 74758).
 */
static inline int efx_dl_filter_insert(struct efx_dl_device *efx_dev,
				       const struct efx_filter_spec *spec,
				       bool replace_equal)
{
	return efx_dev->nic->ops->filter_insert(efx_dev, spec, replace_equal);
}

static inline int efx_dl_filter_remove(struct efx_dl_device *efx_dev,
				       int filter_id)
{
	return efx_dev->nic->ops->filter_remove(efx_dev, filter_id);
}

/**
 * efx_dl_filter_redirect() - update the queue for an existing RX filter
 * @efx_dev: NIC in which to update the filter
 * @filter_id: ID of filter, as returned by @efx_dl_filter_insert
 * @rxq_i: Index of RX queue
 *
 * If filter previously had %EFX_FILTER_FLAG_RX_RSS and an associated RSS
 * context, the flag will be cleared and the RSS context deassociated.  (This
 * behaviour is new in API version 23 and is only supported by EF10; farch will
 * return -EINVAL in this case.)
 */
static inline int efx_dl_filter_redirect(struct efx_dl_device *efx_dev,
					 int filter_id, int rxq_i, int stack_id)
{
	return efx_dev->nic->ops->filter_redirect(efx_dev, filter_id, rxq_i,
						  NULL, stack_id);
}

/**
 * efx_dl_filter_redirect_rss() - update the queue and RSS context for an existing RX filter
 * @efx_dev: NIC in which to update the filter
 * @filter_id: ID of filter, as returned by @efx_dl_filter_insert
 * @rxq_i: Index of RX queue
 * @rss_context: user_id of RSS context.  Either a value supplied by
 *	efx_dl_rss_context_new(), or 0 to use default RSS context.
 *
 * If filter previously did not have %EFX_FILTER_FLAG_RX_RSS, it will be set
 * (EF10) or -EINVAL will be returned (farch).
 */
static inline int efx_dl_filter_redirect_rss(struct efx_dl_device *efx_dev,
					     int filter_id, int rxq_i,
					     u32 rss_context, int stack_id)
{
	return efx_dev->nic->ops->filter_redirect(efx_dev, filter_id, rxq_i,
					     &rss_context, stack_id);
}

/**
 * efx_dl_vport_new() - allocate and configure a new vport
 * @efx_dev: NIC on which to act
 * @vlan: VID of VLAN to place this vport on, or %EFX_FILTER_VID_UNSPEC for none
 * @vlan_restrict: as per corresponding flag in MCDI
 *
 * Returns user_id of new vport, or negative error.
 */
static inline int efx_dl_vport_new(struct efx_dl_device *efx_dev,
				   u16 vlan, bool vlan_restrict)
{
	return efx_dev->nic->ops->vport_new(efx_dev, vlan, vlan_restrict);
}

/**
 * efx_dl_vport_free() - remove an existing vport
 * @efx_dev: NIC on which to act
 * @port_id: user_id of vport to be removed.  Should be a value previously
 *	returned by efx_dl_vport_new().
 */
static inline int efx_dl_vport_free(struct efx_dl_device *efx_dev, u16 port_id)
{
	return efx_dev->nic->ops->vport_free(efx_dev, port_id);
}


/**
 * efx_dl_init_txq() - initialise a TXQ
 * @efx_dev: NIC on which to act
 * @dma_addrs: array of DMA addresses of buffer space for TX descriptors
 * @n_dma_addrs: count of elements in @dma_addrs
 * @vport_id: user_id of vport (returned by efx_dl_vport_new(), or 0)
 * @stack_id: stack ID to OR into bits 23-16 of HW vport ID
 * @owner_id: Owner ID to use if in buffer mode (zero if physical)
 * @timestamp: flag as per MCDI
 * @crc_mode: as per MCDI
 * @tcp_udp_only: flag as per MCDI
 * @tcp_csum_dis: disable TCP/UDP checksum offload
 * @ip_csum_dis: disable IP header checksum offload
 * @inner_tcp_csum: enable inner TCP/UDP checksum offload
 * @inner_ip_csum: enable inner IP header checksum offload
 * @buff_mode: flag as per MCDI
 * @pacer_bypass: flag as per MCDI
 * @ctpio: flag as per MCDI
 * @ctpio_uthresh: flag as per MCDI
 * @instance: as per MCDI
 * @label: queue label to put in events
 * @target_evq: the EVQ to send events to
 * @num_entries: size of the TX ring in entries
 *
 * Available from API version 25.1.
 */
static inline
int efx_dl_init_txq(struct efx_dl_device *efx_dev, dma_addr_t *dma_addrs,
		    int n_dma_addrs, u16 vport_id, u8 stack_id, u32 owner_id,
		    bool timestamp, u8 crc_mode, bool tcp_udp_only,
		    bool tcp_csum_dis, bool ip_csum_dis, bool inner_tcp_csum,
		    bool inner_ip_csum, bool buff_mode, bool pacer_bypass,
		    bool ctpio, bool ctpio_uthresh, u32 instance, u32 label,
		    u32 target_evq, u32 num_entries)
{
	return efx_dev->nic->ops->init_txq(efx_dev, dma_addrs, n_dma_addrs,
				      vport_id, stack_id, owner_id,
				      timestamp, crc_mode, tcp_udp_only,
				      tcp_csum_dis, ip_csum_dis,
				      inner_tcp_csum, inner_ip_csum,
				      buff_mode, pacer_bypass, ctpio,
				      ctpio_uthresh, instance, label,
				      target_evq, num_entries);
}

/**
 * efx_dl_init_rxq() - initialise an RXQ
 * @efx_dev: NIC on which to act
 * @dma_addrs: array of DMA addresses of buffer space for RX descriptors
 * @n_dma_addrs: count of elements in @dma_addrs
 * @vport_id: user_id of vport (returned by efx_dl_vport_new(), or 0)
 * @stack_id: stack ID to OR into bits 23-16 of HW vport ID
 * @owner_id: Owner ID to use if in buffer mode (zero if physical)
 * @crc_mode: as per MCDI
 * @timestamp: flag as per MCDI
 * @hdr_split: flag as per MCDI
 * @buff_mode: flag as per MCDI
 * @rx_prefix: flag as per MCDI
 * @dma_mode: enum as per MCDI
 * @instance: as per MCDI
 * @label: queue label to put in events
 * @target_evq: the EVQ to send events to
 * @num_entries: size of the TX ring in entries
 * @ps_buf_size: enum as per MCDI (PACKED_STREAM_BUFF_SIZE)
 * @force_rx_merge: flag as per MCDI
 * @ef100_rx_buffer_size: RX buffer size (in bytes) for EF100.
 *
 * Available from API version 25.1.
 */
static inline
int efx_dl_init_rxq(struct efx_dl_device *efx_dev, dma_addr_t *dma_addrs,
		    int n_dma_addrs, u16 vport_id, u8 stack_id, u32 owner_id,
		    u8 crc_mode, bool timestamp, bool hdr_split, bool buff_mode,
		    bool rx_prefix, u8 dma_mode, u32 instance, u32 label,
		    u32 target_evq, u32 num_entries, u8 ps_buf_size,
		    bool force_rx_merge, int ef100_rx_buffer_size)
{
	return efx_dev->nic->ops->init_rxq(efx_dev, dma_addrs, n_dma_addrs,
				      vport_id, stack_id, owner_id,
				      crc_mode, timestamp, hdr_split, buff_mode,
				      rx_prefix, dma_mode, instance, label,
				      target_evq, num_entries, ps_buf_size,
				      force_rx_merge, ef100_rx_buffer_size);
}

/**
 * efx_dl_set_multicast_loopback_suppression() - configure multicast loopback
 * @efx_dev: NIC on which to act
 * @suppress: whether to suppress multicast loopback
 * @vport_id: user_id of vport (returned by efx_dl_vport_new(), or 0)
 * @stack_id: stack ID to OR into bits 23-16 of HW vport ID
 *
 * Available from API version 25.1.
 */
static inline
int efx_dl_set_multicast_loopback_suppression(struct efx_dl_device *efx_dev,
					      bool suppress, u16 vport_id,
					      u8 stack_id)
{
	return efx_dev->nic->ops->set_multicast_loopback_suppression(efx_dev,
			suppress, vport_id, stack_id);
}

/**
 * efx_dl_filter_block_kernel - Block the kernel from receiving packets
 * @dl_dev: Driverlink client device context
 * @type: Type (unicast or multicast) of kernel block to insert
 *
 * This increments the kernel block count for the client.  So long as
 * any client has a non-zero count, all filters with priority HINT or
 * AUTO will be removed (or pointed to a drop queue).  The kernel
 * stack and upper devices will not receive packets except through
 * explicit configuration (e.g. ethtool -U or PTP on Siena).  The net
 * driver's loopback self-test will also fail.
 */
int efx_dl_filter_block_kernel(struct efx_dl_device *dl_dev,
			       enum efx_dl_filter_block_kernel_type type);

/**
 * efx_dl_filter_unblock_kernel - Reverse efx_filter_block_kernel()
 * @dl_dev: Driverlink client device context
 * @type: Type (unicast or multicast) of kernel block to insert
 *
 * This decrements the kernel block count for the client.
 */
void efx_dl_filter_unblock_kernel(struct efx_dl_device *dl_dev,
				  enum efx_dl_filter_block_kernel_type type);

/**
 * efx_dl_mcdi_rpc - Issue an MCDI command and wait for completion
 * @dl_dev: Driverlink client device context
 * @cmd: Command type number
 * @inbuf: Command parameters
 * @inlen: Length of command parameters, in bytes.  Must be a multiple
 *	of 4 and no greater than %MC_SMEM_PDU_LEN.
 * @outbuf: Response buffer.  May be %NULL if @outlen is 0.
 * @outlen: Length of response buffer, in bytes.  If the actual
 *	reponse is longer than @outlen & ~3, it will be truncated
 *	to that length.
 * @outlen_actual: Pointer through which to return the actual response
 *	length.  May be %NULL if this is not needed.
 *
 * This function may sleep and therefore must be called in process
 * context.  Defined from API version 6.
 */
static inline int efx_dl_mcdi_rpc(struct efx_dl_device *dl_dev,
				  unsigned int cmd, size_t inlen, size_t outlen,
				  size_t *outlen_actual,
				  const u8 *inbuf, u8 *outbuf)
{
	return dl_dev->nic->ops->mcdi_rpc(dl_dev, cmd, inlen,
					  outlen, outlen_actual,
					  inbuf, outbuf);
}

/**
 * efx_dl_for_each_device_info_matching - iterate an efx_dl_device_info list
 * @_dev_info: Pointer to first &struct efx_dl_device_info
 * @_type: Type code to look for
 * @_info_type: Structure type corresponding to type code
 * @_field: Name of &struct efx_dl_device_info field in the type
 * @_p: Iterator variable
 *
 * Example:
 *	struct efx_dl_falcon_resources *res;
 *	efx_dl_for_each_device_info_matching(dev_info, EFX_DL_FALCON_RESOURCES,
 *					     struct efx_dl_falcon_resources,
 *					     hdr, res) {
 *		if (res->flags & EFX_DL_FALCON_HAVE_RSS_CHANNEL_COUNT)
 *			....
 *	}
 */
#define efx_dl_for_each_device_info_matching(_dev_info, _type,		\
					     _info_type, _field, _p)	\
	for ((_p) = container_of((_dev_info), _info_type, _field);	\
	     (_p) != NULL;						\
	     (_p) = container_of((_p)->_field.next, _info_type, _field))\
		if ((_p)->_field.type != _type)				\
			continue;					\
		else

/**
 * efx_dl_search_device_info - search an efx_dl_device_info list
 * @_dev_info: Pointer to first &struct efx_dl_device_info
 * @_type: Type code to look for
 * @_info_type: Structure type corresponding to type code
 * @_field: Name of &struct efx_dl_device_info member in this type
 * @_p: Result variable
 *
 * Example:
 *	struct efx_dl_falcon_resources *res;
 *	efx_dl_search_device_info(dev_info, EFX_DL_FALCON_RESOURCES,
 *				  struct efx_dl_falcon_resources, hdr, res);
 *	if (res)
 *		....
 */
#define efx_dl_search_device_info(_dev_info, _type, _info_type,		\
				  _field, _p)				\
	efx_dl_for_each_device_info_matching((_dev_info), (_type),	\
					     _info_type, _field, (_p))	\
		break;

void efx_dl_register_nic(struct efx_dl_nic *device);
void efx_dl_unregister_nic(struct efx_dl_nic *device);

void efx_dl_reset_suspend(struct efx_dl_nic *device);
void efx_dl_reset_resume(struct efx_dl_nic *device, int ok);

int efx_dl_handle_event(struct efx_dl_nic *device, void *event, int budget);

#endif /* EFX_DRIVERLINK_API_H */

