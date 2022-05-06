/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
#ifndef __EFRM_NIC_H__
#define __EFRM_NIC_H__

#include <ci/efhw/efhw_types.h>
#include <ci/efrm/buddy.h>


struct efrm_nic_per_vi {
	atomic_t state;
	struct efrm_vi *vi;
};


/* Per-nic state for the VI resource manager. */
struct efrm_nic_vi {

	/* We keep VI resources which need flushing on these lists.  The VI
	 * is put on the outstanding list when the flush request is issued
	 * to the hardware and removed when the flush event arrives.  The
	 * hardware can only handle a limited number of RX flush requests at
	 * once, so VIs are placed in the waiting list until the flush can
	 * be issued.  Flushes can be requested by the client or internally
	 * by the VI resource manager.  In the former case, the reference
	 * count must be non-zero for the duration of the flush and in the
	 * later case, the reference count must be zero. */
	struct list_head rx_flush_waiting_list;
	struct list_head rx_flush_outstanding_list;
	struct list_head tx_flush_outstanding_list;
	int              rx_flush_outstanding_count;

	/* once the flush has happened we push the close into the work queue
	 * so its OK on Windows to free the resources (Bug 3469).  Resources
	 * on this list have zero reference count.
	 */
	struct list_head   close_pending;
	struct work_struct work_item;
	struct delayed_work flush_work_item;
};


#define EFRM_MAX_STACK_ID 255

struct efrm_nic {
	struct efhw_nic efhw_nic;
	spinlock_t lock;
	struct list_head link;
	struct list_head clients;
	struct efrm_pd_owner_ids *owner_ids;
	struct efrm_nic_per_vi *vis;
        int max_vis;
	struct efrm_nic_vi      nvi;
	struct efrm_buddy_allocator vi_allocator;
	unsigned rss_channel_count;
	const struct efx_dl_device_info *dl_dev_info;
	unsigned stack_id_usage[(EFRM_MAX_STACK_ID + sizeof(unsigned) * 8)
				/ (sizeof(unsigned) * 8)];

	/* We store the RXQ at which any sniff filter is directed, so we can
         * check that a) a sniff filter isn't already in place when someone
         * tries to add a new one, and b) the remover of the sniff filter is
         * the same as the adder.
	 */
	int32_t rx_sniff_rxq;
	int32_t tx_sniff_rxq;

	/* Flags protected by [lock]. */
	unsigned rnic_flags;
#define EFRM_NIC_FLAG_DRIVERLINK_PROHIBITED      0x00000001u
	/* NIC is administratively enabled/disabled for acceleration in procfs */
#define EFRM_NIC_FLAG_ADMIN_ENABLED              0x00000002u

	/* Counter incrementing with each reset/hotplug, to avoid races between
	 * failing operations and resets that would fix them. */
	unsigned driverlink_generation;

        struct {
          struct mutex lock;
          /* indicates that efrm nic is going to be removed
           * Currently, this blocks further evq/dmaq init mcdi
           * operations from being issued */
          int unplugging;
          /* list of initialized queues by type
           * used at time of hotplug.
           * Linked by efrm_vi_q::init_link field.
           */
	  struct list_head q[EFHW_N_Q_TYPES];
        } dmaq_state;

	struct mutex irq_list_lock;
	struct list_head irq_list;
	/* Buffer used to back the individual entries on the above list. */
	void *irq_vectors_buffer;
};


#define efrm_nic(_efhw_nic)				\
  container_of(_efhw_nic, struct efrm_nic, efhw_nic)



#endif  /* __EFRM_NIC_H__ */
