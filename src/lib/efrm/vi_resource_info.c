/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/efrm/nic_table.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efrm/private.h>
#include <ci/efrm/vi_resource_private.h>
#include <ci/efhw/nic.h>
#include "efrm_internal.h"


static void common_vi_get_mappings(struct efrm_vi* vi_rs, struct efhw_nic* nic,
                                   struct efrm_vi_mappings* vm)
{
  memset(vm, 0, sizeof(*vm));

  vm->evq_size = vi_rs->q[EFHW_EVQ].capacity;
  if( vm->evq_size != 0 )
    vm->evq_base = efhw_iopages_ptr(&vi_rs->q[EFHW_EVQ].pages);

  vm->timer_quantum_ns = nic->timer_quantum_ns;
  vm->rxq_prefix_len = vi_rs->rx_prefix_len;

  vm->rxq_size = vi_rs->q[EFHW_RXQ].capacity;
  if( vm->rxq_size != 0 )
    vm->rxq_descriptors = efhw_iopages_ptr(&vi_rs->q[EFHW_RXQ].pages);
  vm->rx_ts_correction = nic->rx_ts_correction;
  vm->tx_ts_correction = nic->tx_ts_correction;
  vm->ts_format = nic->ts_format;

  vm->txq_size = vi_rs->q[EFHW_TXQ].capacity;
  if( vm->txq_size != 0 )
    vm->txq_descriptors = efhw_iopages_ptr(&vi_rs->q[EFHW_TXQ].pages);

  vm->out_flags = vi_rs->out_flags;
}


static void ef10_vi_get_mappings(struct efrm_vi* vi_rs, struct efhw_nic* nic,
				 struct efrm_vi_mappings* vm)
{
  vm->io_page = (void*) vi_rs->io_page;
}

/* FIXME: just copy from ef10 */
static void ef100_vi_get_mappings(struct efrm_vi* vi_rs, struct efhw_nic* nic,
				 struct efrm_vi_mappings* vm)
{
  vm->io_page = (void*) vi_rs->io_page;
}

static void af_xdp_vi_get_mappings(struct efrm_vi* vi_rs, struct efhw_nic* nic,
				   struct efrm_vi_mappings* vm)
{
  vm->io_page = NULL;
  vm->evq_base = nic->efhw_func->af_xdp_mem(nic, vi_rs->allocation.instance);
}

void efrm_vi_get_mappings(struct efrm_vi* vi, struct efrm_vi_mappings* vm)
{
  struct efhw_nic *nic = vi->rs.rs_client->nic;

  EFRM_RESOURCE_ASSERT_VALID(&vi->rs, 0);

  common_vi_get_mappings(vi, nic, vm);

  switch( nic->devtype.arch ) {
  case EFHW_ARCH_EF10:
    ef10_vi_get_mappings(vi, nic, vm);
    break;
  case EFHW_ARCH_EF100:
    ef100_vi_get_mappings(vi, nic, vm);
    break;
  case EFHW_ARCH_AF_XDP:
    af_xdp_vi_get_mappings(vi, nic, vm);
    break;
  default:
    EFRM_ASSERT(0);
    break;
  }
}
EXPORT_SYMBOL(efrm_vi_get_mappings);


struct efrm_pd *efrm_vi_get_pd(struct efrm_vi *virs)
{
	return virs->pd;
}
EXPORT_SYMBOL(efrm_vi_get_pd);


/* Returns the struct pci_dev for the VI, taking out a reference to it.
 * Callers should call pci_dev_put() on the returned pointer to release that
 * reference when they're finished. */
struct pci_dev *efrm_vi_get_pci_dev(struct efrm_vi *virs)
{
	struct pci_dev* dev;

		dev = efhw_nic_get_pci_dev(virs->rs.rs_client->nic);

	return dev;
}
EXPORT_SYMBOL(efrm_vi_get_pci_dev);

int efrm_vi_get_channel(struct efrm_vi *virs)
{
	struct efrm_nic *nic = efrm_nic(virs->rs.rs_client->nic);
	return virs->net_drv_wakeup_channel >= 0 ?
		virs->net_drv_wakeup_channel :
		nic->rss_channel_count == 0 ? 0 :
		virs->rs.rs_instance % nic->rss_channel_count;
}
EXPORT_SYMBOL(efrm_vi_get_channel);

int efrm_vi_get_rx_error_stats(struct efrm_vi* virs,
			       void* data,
			       size_t data_len,
			       int do_reset)
{
	struct efhw_nic *nic = efrm_client_get_nic(virs->rs.rs_client);
	return efhw_nic_get_rx_error_stats(nic, virs->rs.rs_instance,
					   data, data_len, do_reset);
}
EXPORT_SYMBOL(efrm_vi_get_rx_error_stats);
