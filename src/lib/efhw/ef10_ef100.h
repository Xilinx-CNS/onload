/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */

#ifndef EFHW_EF10_EF100_H
#define EFHW_EF10_EF100_H

/* We base owner ids from 1 within Onload so that we can use owner id 0 as
 * as easy check whether a pd is using physical addressing mode.  However, we
 * don't want to use up part of our actual owner id space, which is 0 based,
 * so subtract back to 0 based when talking to the firmware.
 */
#define REAL_OWNER_ID(owner_id) ((owner_id) ? ((owner_id) - 1) : 0)

extern int ef10_ef100_mcdi_rpc(struct efhw_nic *nic, unsigned int cmd,
			       size_t inlen, size_t outlen, size_t *outlen_actual,
			       const void *inbuf, void *outbuf);

extern void ef10_ef100_mcdi_check_response(const char* caller, const char* failed_cmd,
					   int rc, int expected_len, int actual_len,
					   int rate_limit);

extern int ef10_ef100_mcdi_rpc_client(struct efhw_nic *nic, uint32_t client_id,
			       unsigned int cmd,
			       size_t inlen, size_t outlen, size_t *outlen_actual,
			       void *inbuf, void *outbuf);

#define MCDI_CHECK(op, rc, actual_len, rate_limit)			   \
	ef10_ef100_mcdi_check_response(__func__, #op, (rc), op##_OUT_LEN,  \
				       (actual_len), (rate_limit))

extern void ef10_ef100_nic_check_supported_filters(struct efhw_nic *nic);

extern int ef10_ef100_nic_mac_spoofing_privilege(struct efhw_nic *nic);

extern int ef10_ef100_mcdi_cmd_event_queue_enable(struct efhw_nic *nic,
						  uint32_t client_id,
						  uint evq, /* evq id */
						  uint evq_size, /* Number of events */
						  dma_addr_t *dma_addrs,
						  uint n_pages,
						  uint interrupting,
						  uint enable_dos_p,
						  uint enable_cut_through,
						  uint enable_rx_merging,
						  int wakeup_evq,
						  uint enable_timer);

extern void ef10_ef100_mcdi_cmd_event_queue_disable(struct efhw_nic *nic,
						    uint32_t client_id, uint evq);

extern void ef10_ef100_mcdi_cmd_driver_event(struct efhw_nic *nic, uint64_t data,
					     uint32_t evq);

extern int ef10_ef100_mcdi_cmd_init_txq(struct efhw_nic *nic,
					uint32_t client_id, dma_addr_t *dma_addrs,
					int n_dma_addrs, uint32_t port_id, uint8_t stack_id,
					uint32_t owner_id,
					int flag_timestamp, int crc_mode, int flag_tcp_udp_only,
					int flag_tcp_csum_dis, int flag_ip_csum_dis,
					int flag_buff_mode, int flag_pacer_bypass,
					int flag_ctpio, int flag_ctpio_uthresh, int flag_m2m_d2c,
					uint32_t instance, uint32_t label,
					uint32_t target_evq, uint32_t numentries);

extern int ef10_ef100_mcdi_cmd_init_rxq(struct efhw_nic *nic,
					uint32_t client_id, dma_addr_t *dma_addrs,
					int n_dma_addrs, uint32_t port_id, uint8_t stack_id,
					uint32_t owner_id,
					int crc_mode, int flag_timestamp, int flag_hdr_split,
					int flag_buff_mode, int flag_rx_prefix,
					int flag_packed_stream, uint32_t instance,
					uint32_t label, uint32_t target_evq,
					uint32_t numentries, int ps_buf_size,
					int flag_force_rx_merge, int ef100_rx_buffer_size);

extern void ef10_ef100_dmaq_tx_q_disable(struct efhw_nic *nic, uint dmaq);

extern void ef10_ef100_dmaq_rx_q_disable(struct efhw_nic *nic, uint dmaq);

extern int ef10_ef100_flush_tx_dma_channel(struct efhw_nic *nic,
					   uint32_t client_id, uint dmaq);

extern int ef10_ef100_flush_rx_dma_channel(struct efhw_nic *nic,
					   uint32_t client_id, uint dmaq);
extern int ef10_ef100_translate_dma_addrs(struct efhw_nic* nic,
					  const dma_addr_t *src,
					  dma_addr_t *dst, int n);

extern int ef10_ef100_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
					     struct efhw_buffer_table_block **block_out,
					     int reset_pending);

extern int ef10_ef100_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
					       struct efhw_buffer_table_block *block);

extern void ef10_ef100_nic_buffer_table_free(struct efhw_nic *nic,
					     struct efhw_buffer_table_block *block,
					     int reset_pending);

extern int ef10_ef100_nic_buffer_table_set(struct efhw_nic *nic,
					   struct efhw_buffer_table_block *block,
					   int first_entry, int n_entries,
					   dma_addr_t *dma_addrs);

void ef10_ef100_nic_buffer_table_clear(struct efhw_nic *nic,
				       struct efhw_buffer_table_block *block,
				       int first_entry, int n_entries);

extern int ef10_ef100_rss_alloc(struct efhw_nic *nic, const u32 *indir,
				const u8 *key, u32 nic_rss_flags, int num_qs,
				u32 *rss_context_out);
extern int ef10_ef100_rss_update(struct efhw_nic *nic, const u32 *indir,
				 const u8 *key, u32 nic_rss_flags,
				 u32 rss_context);
extern int ef10_ef100_rss_free(struct efhw_nic *nic, u32 rss_context);
extern int ef10_ef100_rss_flags(struct efhw_nic *nic, u32 *flags_out);

struct efx_filter_spec;
extern int ef10_ef100_filter_insert(struct efhw_nic *nic,
				    struct efx_filter_spec *spec,
				    bool replace);
extern void ef10_ef100_filter_remove(struct efhw_nic *nic, int filter_id);
extern int ef10_ef100_filter_redirect(struct efhw_nic *nic, int filter_id,
				      struct efx_filter_spec *spec);

extern int ef10_ef100_multicast_block(struct efhw_nic *nic, bool block);
extern int ef10_ef100_unicast_block(struct efhw_nic *nic, bool block);

extern int ef10_ef100_vport_alloc(struct efhw_nic *nic, u16 vlan_id,
				  u16 *vport_handle_out);
extern int ef10_ef100_vport_free(struct efhw_nic *nic, u16 vport_handle);

extern struct pci_dev* ef10_ef100_get_pci_dev(struct efhw_nic* nic);

static inline struct efx_dl_device* efhw_nic_acquire_dl_device(struct efhw_nic* nic)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF10 ||
	      nic->devtype.arch == EFHW_ARCH_EF100);
  return efhw_nic_acquire_drv_device(nic);
}

static inline void efhw_nic_release_dl_device(struct efhw_nic* nic,
					      struct efx_dl_device* dl_device)
{
  EFHW_ASSERT(nic->devtype.arch == EFHW_ARCH_EF10 ||
	      nic->devtype.arch == EFHW_ARCH_EF100);
  efhw_nic_release_drv_device(nic, dl_device);
}

#define EFX_DL_PRE(efx_dev, nic, rc) \
{ \
	(efx_dev) = efhw_nic_acquire_dl_device((nic));\
		\
	EFHW_ASSERT(!in_atomic()); \
		\
	/* [nic->resetting] means we have detected that we are in a reset.
	 * There is potentially a period after [nic->resetting] is cleared
	 * but before driverlink is re-enabled, during which time [efx_dev]
	 * will be NULL. */ \
	if ((nic)->resetting || (efx_dev) == NULL) { \
		/* user should not handle any errors */ \
		rc = 0; \
	} \
	else { \
		/* Driverlink handle is valid and we're not resetting, so issue
		 * the call. */ \


#define EFX_DL_POST(efx_dev, nic, rc) \
		\
		/* If we see ENETDOWN here, we must be in the window between
		 * hardware being removed and being informed about this fact by
		 * the kernel. */ \
		if ((rc) == -ENETDOWN) \
			ci_atomic32_or(&(nic)->resetting, \
				       NIC_RESETTING_FLAG_VANISHED); \
	} \
		\
	/* This is safe even if [efx_dev] is NULL. */ \
	efhw_nic_release_dl_device((nic), (efx_dev)); \
}

#endif /* EFHW_EF10_EF100_H */
