/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2003-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  djr
**  \brief  Allocate a VI resource.
**   \date  
**    \cop  (c) Level 5 Networks Limited.
** </L5_PRIVATE>
*//*
\**************************************************************************/
  
/*! \cidoxg_lib_ef */
#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/capabilities.h>
#include <ci/efhw/common.h>
#include "ef_vi_internal.h"
#include "driver_access.h"
#include "logging.h"
#include "efch_intf_ver.h"
#include <stdio.h>
#include <net/if.h>

#define CTPIO_MMAP_LEN CI_PAGE_SIZE

/* ****************************************************************************
 * This set of functions provides the equivalent functionality of the
 * kernel vi resource manager.  They fully resolve the base addresses of
 * the Rx & Tx doorbell & DMA queue.
 */

static unsigned vi_flags_to_efab_flags(unsigned vi_flags)
{
  unsigned efab_flags = 0u;
  if( vi_flags & EF_VI_TX_PHYS_ADDR      ) efab_flags |= EFHW_VI_TX_PHYS_ADDR_EN;
  if( vi_flags & EF_VI_RX_PHYS_ADDR      ) efab_flags |= EFHW_VI_RX_PHYS_ADDR_EN;
  if( vi_flags & EF_VI_TX_IP_CSUM_DIS    ) efab_flags |= EFHW_VI_TX_IP_CSUM_DIS;
  if( vi_flags & EF_VI_TX_TCPUDP_CSUM_DIS) efab_flags |= EFHW_VI_TX_TCPUDP_CSUM_DIS;
  if( vi_flags & EF_VI_TX_TCPUDP_ONLY    ) efab_flags |= EFHW_VI_TX_TCPUDP_ONLY;
  if( vi_flags & EF_VI_TX_FILTER_IP      ) efab_flags |= EFHW_VI_TX_IP_FILTER_EN;
  if( vi_flags & EF_VI_TX_FILTER_MAC     ) efab_flags |= EFHW_VI_TX_ETH_FILTER_EN;
  if( vi_flags & EF_VI_TX_FILTER_MASK_1  ) efab_flags |= EFHW_VI_TX_Q_MASK_WIDTH_0;
  if( vi_flags & EF_VI_TX_FILTER_MASK_2  ) efab_flags |= EFHW_VI_TX_Q_MASK_WIDTH_1;
  if( vi_flags & EF_VI_RX_TIMESTAMPS     ) efab_flags |= EFHW_VI_RX_TIMESTAMPS;
  if( vi_flags & EF_VI_TX_TIMESTAMPS     ) efab_flags |= EFHW_VI_TX_TIMESTAMPS;
  if( vi_flags & EF_VI_ENABLE_EV_TIMER   ) efab_flags |= EFHW_VI_ENABLE_EV_TIMER;
  if( vi_flags & EF_VI_RX_PACKED_STREAM  ) efab_flags |=
                                                   (EFHW_VI_RX_PACKED_STREAM |
                                                    EFHW_VI_NO_EV_CUT_THROUGH);
  if( vi_flags & EF_VI_RX_EVENT_MERGE) efab_flags |= (EFHW_VI_RX_PREFIX |
                                                    EFHW_VI_NO_RX_CUT_THROUGH |
                                                    EFHW_VI_ENABLE_RX_MERGE |
                                                    EFHW_VI_NO_EV_CUT_THROUGH);
  if( vi_flags & EF_VI_TX_ALT            ) efab_flags |= EFHW_VI_TX_ALT;
  if( vi_flags & EF_VI_TX_CTPIO          ) efab_flags |= EFHW_VI_TX_CTPIO;
  if( vi_flags & EF_VI_TX_CTPIO_NO_POISON ) efab_flags |=
                                                    EFHW_VI_TX_CTPIO_NO_POISON;
  if( vi_flags & EF_VI_RX_ZEROCOPY ) efab_flags |= EFHW_VI_RX_ZEROCOPY;
  return efab_flags;
}


/* While Onload always sets a buffer for VI statistics, ef_vi only does so if
 * we need to maintain statistics to track non-errors. */
static int /*bool*/ need_vi_stats_buf(unsigned vi_flags)
{
  /* At present, we don't record any non-errors in the statistics buffer. */
  return 0;
}


/* Certain VI functionalities are only supported on certain NIC types.
 * This function validates that the requested functionality is present
 * on the selected NIC. */
static int check_nic_compatibility(unsigned vi_flags, unsigned ef_vi_arch)
{
  switch (ef_vi_arch) {
  case EFHW_ARCH_EF10:
    return 0;

  case EFHW_ARCH_EF100:
    if (vi_flags & EF_VI_RX_TIMESTAMPS) {
      LOGVV(ef_log("%s: ERROR: RX TIMESTAMPS flag not supported"
                   " on EF100 architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    if (vi_flags & EF_VI_TX_TIMESTAMPS) {
      LOGVV(ef_log("%s: ERROR: TX TIMESTAMPS flag not supported"
                   " on EF100 architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    return 0;

  case EFHW_ARCH_AF_XDP:
    if (vi_flags & EF_VI_TX_PUSH_ALWAYS) {
      LOGVV(ef_log("%s: ERROR: TX PUSH ALWAYS flag not supported"
                   " on AF_XDP architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    if (vi_flags & EF_VI_RX_TIMESTAMPS) {
      LOGVV(ef_log("%s: ERROR: RX TIMESTAMPS flag not supported"
                   " on AF_XDP architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    if (vi_flags & EF_VI_TX_TIMESTAMPS) {
      LOGVV(ef_log("%s: ERROR: TX TIMESTAMPS flag not supported"
                   " on AF_XDP architecture", __FUNCTION__));
      return -EOPNOTSUPP;
    }
    return 0;

  default:
    return -EINVAL;
  }
}


static int get_ts_format(ef_driver_handle vi_dh, int res_id,
                         enum ef_timestamp_format* ts_format)
{
  ci_resource_op_t op;
  int rc;
  op.id = efch_make_resource_id(res_id);
  op.op = CI_RSOP_VI_GET_TS_FORMAT;
  rc = ci_resource_op(vi_dh, &op);
  if( rc == 0 ) {
    *ts_format = op.u.vi_ts_format.out_ts_format;
    return 0;
  }
  /* This driver can't tell us the TX format.  So this must be a Hunti
   * chip, and the appropriate format is...
   */
  *ts_format = TS_FORMAT_SECONDS_27FRACTION;
  return 0;
}


static int get_ts_correction(ef_driver_handle vi_dh, int res_id,
			     int* rx_ts_correction, int* tx_ts_correction)
{
  ci_resource_op_t op;
  int rc;
  op.id = efch_make_resource_id(res_id);
  op.op = CI_RSOP_VI_GET_TS_CORRECTION;
  rc = ci_resource_op(vi_dh, &op);
  if( rc == 0 ) {
    *rx_ts_correction = op.u.vi_ts_correction.out_rx_ts_correction;
    *tx_ts_correction = op.u.vi_ts_correction.out_tx_ts_correction;
    return 0;
  }
  op.op = CI_RSOP_VI_GET_RX_TS_CORRECTION;
  rc = ci_resource_op(vi_dh, &op);
  *rx_ts_correction = op.u.vi_rx_ts_correction.out_rx_ts_correction;
  /* This driver can't tell us the TX correction.  So this must be a Hunti
   * chip, and the appropriate correction is...
   */
  *tx_ts_correction = 178;
  return rc;
}


int ef_vi_transmit_alt_alloc(struct ef_vi* vi, ef_driver_handle vi_dh,
                             int num_alts, size_t buf_space)
{
  ci_resource_op_t op;
  int i, rc;
  unsigned max_hw;

  if( num_alts <= 0 ) {
    LOGVV(ef_log("%s: ERROR: can't allocate < 1 alternative", __func__));
    return -EINVAL;
  }
  if( buf_space == 0 ) {
    LOGVV(ef_log("%s: ERROR: can't allocate 0 buffer space", __func__));
    return -EINVAL;
  }
  if( ! (vi->vi_flags & EF_VI_TX_ALT) ) {
    LOGVV(ef_log("%s: ERROR: EF_VI_TX_ALT flag not set", __func__));
    return -EINVAL;
  }
  if( vi->tx_alt_id2hw != NULL ) {
    LOGVV(ef_log("%s: ERROR: already called", __func__));
    return -EALREADY;
  }
  vi->tx_alt_id2hw = malloc(num_alts * sizeof(vi->tx_alt_id2hw[0]));
  if( vi->tx_alt_id2hw == NULL ) {
    LOGVV(ef_log("%s: ERROR: out of memory (num_alts=%d)", __func__, num_alts));
    return -ENOMEM;
  }

  memset(&op, 0, sizeof(op));
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.op = CI_RSOP_VI_TX_ALT_ALLOC;
  op.u.vi_tx_alt_alloc_in.num_alts = num_alts;
  op.u.vi_tx_alt_alloc_in.buf_space_32b = (buf_space + 31) / 32;
  if( (rc = ci_resource_op(vi_dh, &op)) < 0 ) {
    LOGVV(ef_log("%s: ERROR: driver returned %d", __func__, rc));
    free(vi->tx_alt_id2hw);
    vi->tx_alt_id2hw = NULL;
    return rc;
  }

  vi->tx_alt_num = num_alts;
  max_hw = 0;
  for( i = 0; i < num_alts; ++i ) {
    vi->tx_alt_id2hw[i] = op.u.vi_tx_alt_alloc_out.alt_ids[i];
    if( vi->tx_alt_id2hw[i] > max_hw )
      max_hw = vi->tx_alt_id2hw[i];
  }
  vi->tx_alt_hw2id = calloc(max_hw + 1, sizeof(vi->tx_alt_hw2id[0]));
  if( vi->tx_alt_hw2id == NULL ) {
    LOGVV(ef_log("%s: ERROR: out of memory (max_hw=%u)", __func__, max_hw));
    free(vi->tx_alt_id2hw);
    vi->tx_alt_id2hw = NULL;
    return -ENOMEM;
  }
  for( i = 0; i < num_alts; ++i )
    vi->tx_alt_hw2id[vi->tx_alt_id2hw[i]] = i;
  return 0;
}

int ef_vi_transmit_alt_free(struct ef_vi* vi, ef_driver_handle vi_dh)
{
  ci_resource_op_t op;
  int rc;

  if( ! (vi->vi_flags & EF_VI_TX_ALT) ) {
    LOGVV(ef_log("%s: ERROR: EF_VI_TX_ALT flag not set", __func__));
    return -EINVAL;
  }

  if( vi->tx_alt_id2hw == NULL ) {
    LOGVV(ef_log("%s: ERROR: alloc not called", __func__));
    return -EINVAL;
  }

  free(vi->tx_alt_id2hw);
  vi->tx_alt_id2hw = NULL;

  free(vi->tx_alt_hw2id);
  vi->tx_alt_hw2id = NULL;

  memset(&op, 0, sizeof(op));
  op.id = efch_make_resource_id(vi->vi_resource_id);
  op.op = CI_RSOP_VI_TX_ALT_FREE;
  if( (rc = ci_resource_op(vi_dh, &op)) < 0 ) {
    LOGVV(ef_log("%s: ERROR: driver returned %d", __func__, rc));
    return rc;
  }

  return 0;
}



static int
__ef_vi_transmit_alt_query_buffering(ef_vi * vi,
                                     int ifindex,
                                     ef_driver_handle dh, int pd_id,
                                     ef_driver_handle pd_dh,
                                     int n_alts)

{
  unsigned long buffer_size;
  unsigned long available_buffering;

  if( ! (vi->vi_flags & EF_VI_TX_ALT) ) {
    LOGVV(ef_log("%s: ERROR: EF_VI_TX_ALT flag not set", __func__));
    return -EINVAL;
  }
  int rc = __ef_vi_capabilities_get(dh, ifindex, pd_id, pd_dh,
                                    EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFERS,
                                    &available_buffering);
  if( rc != 0 ) {
    LOGVV(ef_log("%s: ERROR: failed to query buffer count: rc=%d", __func__,
                 rc));
    return rc;
  }

  rc = __ef_vi_capabilities_get(dh, ifindex, pd_id, pd_dh,
                                EF_VI_CAP_TX_ALTERNATIVES_CP_BUFFER_SIZE,
                                &buffer_size);
  if( rc != 0 ) {
    LOGVV(ef_log("%s: ERROR: failed to query buffer size: rc=%d", __func__,
                 rc));
    return rc;
  }

  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_EF10:
    return buffer_size * (available_buffering - 2*n_alts);

  default:
    return -EINVAL;
  }
  
  return 0;
}

int ef_vi_transmit_alt_query_buffering(struct ef_vi* vi,
                                       int ifindex,
                                       ef_driver_handle dh, 
                                       int n_alts)
{
  return __ef_vi_transmit_alt_query_buffering(vi, ifindex, dh, -1, -1, n_alts);
}


int ef_pd_transmit_alt_query_buffering(ef_vi * vi,
                                       ef_driver_handle dh, ef_pd* pd,
                                       ef_driver_handle pd_dh,
                                       int n_alts)
{
  return __ef_vi_transmit_alt_query_buffering(vi, -1, dh, pd->pd_resource_id, pd_dh, n_alts);
}

int ef_vi_transmit_alt_query_overhead(ef_vi* vi,
                                      struct ef_vi_transmit_alt_overhead *out)
{
  /* This holds true on all current hardware. */
  const uint32_t MEDFORD_BYTES_PER_WORD = 32;

  if( (vi->nic_type.arch != EF_VI_ARCH_EF10) ||
      (vi->nic_type.variant == 'A') ||
      ! (vi->vi_flags & EF_VI_TX_ALT) ) {
    LOGVV(ef_log("%s: ERROR: alts not supported on this VI", __func__));
    return -EINVAL;
  }

  out->pre_round = MEDFORD_BYTES_PER_WORD - 1;
  out->mask = ~(MEDFORD_BYTES_PER_WORD - 1);
  out->post_round = MEDFORD_BYTES_PER_WORD;

  return 0;
}


/****************************************************************************/

void ef_vi_set_intf_ver(char* intf_ver, size_t len)
{
  /* Bodge interface requested to match the one used in
   * openonload-201405-u1.  The interface has changed since then, but in
   * ways that are forward and backward compatible with
   * openonload-201405-u1.  (This is almost true: The exception is addition
   * of EFCH_PD_FLAG_MCAST_LOOP).
   */
  strncpy(intf_ver, "1518b4f7ec6834a578c7a807736097ce", len);

  /* This comparison exists as an extra review gate to ensure that we
   * carefully check that the API is backward-compatible, since the above
   * bodge no longer does it automatically. If this breaks then change the
   * checksum (having done human review to ensure that the API hasn't been
   * changed incompatibly).
   * Note that currently the developer build and distribution build have an
   * identical source file; if this should ever change in the future (e.g.
   * due to unifdef or licence string changes) then this test will need
   * enhancement.
   * It'd also be possible to enhance the checksum computation to be smarter
   * (e.g. by ignoring comments, etc.).
   */
  if( strcmp(EFCH_INTF_VER, "ced4a4438f40cfe59d397eaa3698dc10") ) {
    fprintf(stderr, "ef_vi: ERROR: char interface has changed\n");
    abort();
  }
}


int __ef_vi_alloc(ef_vi* vi, ef_driver_handle vi_dh,
                  efch_resource_id_t pd_or_vi_set_id,
                  ef_driver_handle pd_or_vi_set_dh,
                  int index_in_vi_set, int evq_capacity,
                  int rxq_capacity, int txq_capacity,
                  ef_vi* evq, ef_driver_handle evq_dh,
                  int vi_clustered, enum ef_vi_flags vi_flags)
{
  struct ef_vi_nic_type nic_type;
  ci_resource_alloc_t ra;
  char *mem_mmap_ptr_orig, *mem_mmap_ptr;
  char *io_mmap_ptr, *io_mmap_base;
  char* ctpio_mmap_ptr;
  ef_vi_state* state;
  int rc;
  const char* s;
  uint32_t* ids;
  void* p;
  int q_label;

  if( txq_capacity < 0 && (s = getenv("EF_VI_TXQ_SIZE")) )
    txq_capacity = atoi(s);
  if( rxq_capacity < 0 && (s = getenv("EF_VI_RXQ_SIZE")) )
    rxq_capacity = atoi(s);

  EF_VI_BUG_ON((evq == NULL) != (evq_capacity != 0));
  EF_VI_BUG_ON(! evq_capacity && ! rxq_capacity && ! txq_capacity);

  if( pd_or_vi_set_dh < 0 )
    return -EINVAL;
  if( (vi_flags & EF_VI_TX_ALT) && (vi_flags & EF_VI_TX_TIMESTAMPS) ) {
    LOGVV(ef_log("%s: ERROR: EF_VI_TX_ALT and EF_VI_TX_TIMESTAMPS not "
                 "supported together", __func__));
    return -EOPNOTSUPP;
  }

  /* Ensure ef_vi_free() only frees what we allocate. */
  io_mmap_ptr = NULL;
  io_mmap_base = NULL;
  mem_mmap_ptr = mem_mmap_ptr_orig = NULL;
  ctpio_mmap_ptr = NULL;

  if( evq == NULL )
    q_label = 0;
  else if( (q_label = evq->vi_qs_n) == EF_VI_MAX_QS )
    return -EBUSY;

  if( evq_capacity < 0 )
    evq_capacity = -1 - ef_vi_evq_clear_stride();
  else if( evq_capacity > 0 )
    evq_capacity += ef_vi_evq_clear_stride();

  if( evq_capacity < 0 && (s = getenv("EF_VI_EVQ_SIZE")) )
    evq_capacity = atoi(s);
  if( evq_capacity < 0 && (vi_flags & EF_VI_RX_PACKED_STREAM) )
    /* At time of writing we're doing this at user-level as well as in
     * driver.  Utimately we want this default to be applied in the driver
     * so we don't have to know this magic number (which may change in
     * future).  For now we also apply it here so that the default will be
     * applied when running against a 201405-u1 driver.  This can be
     * removed once the driver ABI changes.
     */
    evq_capacity = 32768;

  /* Allocate resource and mmap. */
  memset(&ra, 0, sizeof(ra));
  ef_vi_set_intf_ver(ra.intf_ver, sizeof(ra.intf_ver));
  ra.ra_type = EFRM_RESOURCE_VI;
  ra.u.vi_in.pd_or_vi_set_fd = pd_or_vi_set_dh;
  ra.u.vi_in.pd_or_vi_set_rs_id = pd_or_vi_set_id;
  ra.u.vi_in.vi_set_instance = index_in_vi_set;
  ra.u.vi_in.ps_buf_size_kb = (vi_flags & EF_VI_RX_PS_BUF_SIZE_64K) ? 64 : 1024;
  if( evq != NULL ) {
    ra.u.vi_in.evq_fd = evq_dh;
    ra.u.vi_in.evq_rs_id = efch_make_resource_id(evq->vi_resource_id);
  }
  else {
    ra.u.vi_in.evq_fd = -1;
    evq = vi;
  }
  ra.u.vi_in.evq_capacity = evq_capacity;
  ra.u.vi_in.txq_capacity = txq_capacity;
  ra.u.vi_in.rxq_capacity = rxq_capacity;
  ra.u.vi_in.tx_q_tag = q_label;
  ra.u.vi_in.rx_q_tag = q_label;
  ra.u.vi_in.flags = vi_flags_to_efab_flags(vi_flags);
  /* [ra.u.vi_in.ifindex] is unused as we've ensured that [pd_or_vi_set_dh] is
   * valid. */
  rc = ci_resource_alloc(vi_dh, &ra);
  if( rc < 0 ) {
    LOGVV(ef_log("%s: ci_resource_alloc %d", __FUNCTION__, rc));
    goto fail1;
  }

  evq_capacity = ra.u.vi_out.evq_capacity;
  txq_capacity = ra.u.vi_out.txq_capacity;
  rxq_capacity = ra.u.vi_out.rxq_capacity;

  rc = -ENOMEM;
  state = malloc(ef_vi_calc_state_bytes(rxq_capacity, txq_capacity));
  if( state == NULL )
    goto fail1;

  if( ra.u.vi_out.io_mmap_bytes ) {
    rc = ci_resource_mmap(vi_dh, ra.out_id.index, EFCH_VI_MMAP_IO,
			  ra.u.vi_out.io_mmap_bytes, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (io) %d", __FUNCTION__, rc));
      goto fail2;
    }
    { /* On systems with large pages, multiple VI windows are mapped into
       * each system page.  Therefore the VI window may not appear at the
       * start of the I/O mapping.
       */
      int inst_in_iopage = 0;
      int vi_windows_per_page = CI_PAGE_SIZE / 8192;
      if( vi_windows_per_page > 1 )
        inst_in_iopage = ra.u.vi_out.instance & (vi_windows_per_page - 1);
      io_mmap_base = (char*) p;
      io_mmap_ptr = io_mmap_base + inst_in_iopage * 8192;
    }
  }

  if( ra.u.vi_out.mem_mmap_bytes ) {
    rc = ci_resource_mmap(vi_dh, ra.out_id.index, EFCH_VI_MMAP_MEM,
			  ra.u.vi_out.mem_mmap_bytes, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (mem) %d", __FUNCTION__, rc));
      goto fail3;
    }
    mem_mmap_ptr = mem_mmap_ptr_orig = (char*) p;
  }

  if( vi_flags & EF_VI_TX_CTPIO ) {
    rc = ci_resource_mmap(vi_dh, ra.out_id.index, EFCH_VI_MMAP_CTPIO,
			  CTPIO_MMAP_LEN, &p);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_mmap (ctpio) %d", __FUNCTION__, rc));
      goto fail4;
    }
    ctpio_mmap_ptr = (char*) p;
  }

  rc = ef_vi_arch_from_efhw_arch(ra.u.vi_out.nic_arch);
  EF_VI_BUG_ON(rc < 0);
  nic_type.arch = (unsigned char) rc;
  nic_type.variant = ra.u.vi_out.nic_variant;
  nic_type.revision = ra.u.vi_out.nic_revision;
  nic_type.nic_flags = ra.u.vi_out.nic_flags;

  rc = check_nic_compatibility(vi_flags, nic_type.arch);
  if( rc != 0 )
    goto fail5;

  ids = (void*) (state + 1);

  ef_vi_init(vi, nic_type.arch, nic_type.variant, nic_type.revision,
	     vi_flags, nic_type.nic_flags, state);
  ef_vi_init_out_flags(vi, (ra.u.vi_out.out_flags & EFHW_VI_CLOCK_SYNC_STATUS) ?
                       EF_VI_OUT_CLOCK_SYNC_STATUS : 0);
  ef_vi_init_io(vi, io_mmap_ptr);
  vi->vi_i = ra.u.vi_out.instance;
  vi->abs_idx = ra.u.vi_out.abs_idx;
  ef_vi_init_qs(vi, (void*)mem_mmap_ptr, ids, evq_capacity, rxq_capacity,
                ra.u.vi_out.rx_prefix_len, txq_capacity);

  if( vi_flags & (EF_VI_RX_TIMESTAMPS | EF_VI_TX_TIMESTAMPS) ) {
    int rx_ts_correction, tx_ts_correction;
    enum ef_timestamp_format ts_format;
    rc = get_ts_correction(vi_dh, ra.out_id.index,
                            &rx_ts_correction, &tx_ts_correction);
    if( rc < 0 )
      goto fail5;
    if( rxq_capacity )
      ef_vi_init_rx_timestamping(vi, rx_ts_correction);
    if( txq_capacity )
      ef_vi_init_tx_timestamping(vi, tx_ts_correction);
    rc = get_ts_format(vi_dh, ra.out_id.index,
                        &ts_format);
    if( rc < 0 )
      goto fail5;
    ef_vi_set_ts_format(vi, ts_format);
  }

  if( need_vi_stats_buf(vi_flags) ) {
    ef_vi_stats* stats = calloc(1, sizeof(ef_vi_stats));
    if( stats == NULL )
      goto fail5;
    ef_vi_set_stats_buf(vi, stats);
  }

  vi->vi_io_mmap_ptr = io_mmap_base;
  vi->vi_mem_mmap_ptr = mem_mmap_ptr_orig;
  vi->vi_ctpio_mmap_ptr = ctpio_mmap_ptr;
  vi->vi_io_mmap_bytes = ra.u.vi_out.io_mmap_bytes;
  vi->vi_mem_mmap_bytes = ra.u.vi_out.mem_mmap_bytes;
  vi->vi_resource_id = ra.out_id.index;
  if( ra.u.vi_out.out_flags & EFHW_VI_PS_BUF_SIZE_SET )
    vi->vi_ps_buf_size = ra.u.vi_out.ps_buf_size;
  else
    vi->vi_ps_buf_size = 1024 * 1024;
  BUG_ON(vi->vi_ps_buf_size != 64*1024 &&
         vi->vi_ps_buf_size != 1024*1024);
  vi->vi_clustered = vi_clustered;
  vi->vi_is_packed_stream = !! (vi_flags & EF_VI_RX_PACKED_STREAM);
  ef_vi_init_state(vi);
  rc = ef_vi_add_queue(evq, vi);
  BUG_ON(rc != q_label);

  if( vi->vi_flags & EF_VI_TX_CTPIO )
    ef_vi_ctpio_init(vi);
  if( vi->vi_is_packed_stream )
    ef_vi_packed_stream_update_credit(vi);

  return q_label;

 fail5:
  if( ctpio_mmap_ptr != NULL )
    ci_resource_munmap(vi_dh, ctpio_mmap_ptr, CTPIO_MMAP_LEN);
 fail4:
  if( mem_mmap_ptr_orig != NULL )
    ci_resource_munmap(vi_dh, mem_mmap_ptr_orig, ra.u.vi_out.mem_mmap_bytes);
 fail3:
  if( io_mmap_base != NULL )
    ci_resource_munmap(vi_dh, io_mmap_base, ra.u.vi_out.io_mmap_bytes);
 fail2:
  free(state);
 fail1:
  --evq->vi_qs_n;
  return rc;
}


int ef_vi_alloc_from_pd(ef_vi* vi, ef_driver_handle vi_dh,
			struct ef_pd* pd, ef_driver_handle pd_dh,
			int evq_capacity, int rxq_capacity, int txq_capacity,
			ef_vi* evq_opt, ef_driver_handle evq_dh,
			enum ef_vi_flags flags)
{
  efch_resource_id_t res_id = efch_make_resource_id(pd->pd_resource_id);
  int index_in_vi_set = 0;
  int vi_clustered = 0;

  if( pd->pd_flags & EF_PD_PHYS_MODE )
    flags |= EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR;
  else
    flags &= ~(EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR);

  if( pd->pd_cluster_sock != -1 ) {
    pd_dh = pd->pd_cluster_dh;
    res_id = efch_make_resource_id(
                                   pd->pd_cluster_viset_resource_id);
    index_in_vi_set = pd->pd_cluster_viset_index;
    vi_clustered = 1;
  }
  return __ef_vi_alloc(vi, vi_dh, res_id, pd_dh, index_in_vi_set, evq_capacity,
                       rxq_capacity, txq_capacity,
                       evq_opt, evq_dh, vi_clustered, flags);
}


int ef_vi_alloc_from_set(ef_vi* vi, ef_driver_handle vi_dh,
			 ef_vi_set* vi_set, ef_driver_handle vi_set_dh,
			 int index_in_vi_set, int evq_capacity,
			 int rxq_capacity, int txq_capacity,
			 ef_vi* evq_opt, ef_driver_handle evq_dh,
			 enum ef_vi_flags flags)
{
  if( vi_set->vis_pd->pd_flags & EF_PD_PHYS_MODE )
    flags |= EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR;
  else
    flags &= ~(EF_VI_TX_PHYS_ADDR | EF_VI_RX_PHYS_ADDR);
  return __ef_vi_alloc(vi, vi_dh,
                       efch_make_resource_id(vi_set->vis_res_id),
                       vi_set_dh, index_in_vi_set,
                       evq_capacity, rxq_capacity, txq_capacity,
                       evq_opt, evq_dh, 0, flags);
}


int ef_vi_free(ef_vi* ep, ef_driver_handle fd)
{
  int rc;

  if( ep->vi_ctpio_mmap_ptr != NULL ) {
    rc = ci_resource_munmap(fd, ep->vi_ctpio_mmap_ptr, CTPIO_MMAP_LEN);
    if( rc < 0 ) {
      LOGV(ef_log("%s: ci_resource_munmap CTPIO %d", __FUNCTION__, rc));
      return rc;
    }
  }

  if( ep->vi_io_mmap_ptr != NULL ) {
    rc = ci_resource_munmap(fd, ep->vi_io_mmap_ptr, ep->vi_io_mmap_bytes);
    if( rc < 0 ) {
      LOGV(ef_log("%s: ci_resource_munmap %d", __FUNCTION__, rc));
      return rc;
    }
  }

  if( ep->vi_mem_mmap_ptr != NULL ) {
    /* TODO: support variable sized DMAQ and evq */
    rc = ci_resource_munmap(fd, ep->vi_mem_mmap_ptr, ep->vi_mem_mmap_bytes);
    if( rc < 0 ) {
      LOGVV(ef_log("%s: ci_resource_munmap iobuffer %d", __FUNCTION__, rc));
      return rc;
    }
  }

  free(ep->ep_state);
  free(ep->tx_alt_id2hw);
  free(ep->tx_alt_hw2id);
  free(ep->vi_stats);

  EF_VI_DEBUG(memset(ep, 0, sizeof(*ep)));

  LOGVVV(ef_log("%s: DONE", __FUNCTION__));
  return 0;
}


unsigned ef_vi_mtu(ef_vi* vi, ef_driver_handle fd)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_VI_GET_MTU;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  rc = ci_resource_op(fd, &op);
  if( rc < 0 ) {
    LOGV(ef_log("%s: ci_resource_op %d", __FUNCTION__, rc));
    return 0;
  }
  return op.u.vi_get_mtu.out_mtu;
}


int ef_vi_get_mac(ef_vi* vi, ef_driver_handle dh, void* mac_out)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_VI_GET_MAC;
  op.id = efch_make_resource_id(vi->vi_resource_id);
  rc = ci_resource_op(dh, &op);
  if( rc < 0 )
    LOGV(ef_log("%s: ci_resource_op %d", __FUNCTION__, rc));
  memcpy(mac_out, op.u.vi_get_mac.out_mac, 6);
  return rc;
}


int ef_vi_flush(ef_vi* ep, ef_driver_handle fd)
{
  ci_resource_op_t op;
  int rc;

  op.op = CI_RSOP_PT_ENDPOINT_FLUSH;
  op.id = efch_make_resource_id(ep->vi_resource_id);
  rc = ci_resource_op(fd, &op);
  if( rc < 0 ) {
    LOGV(ef_log("ef_vi_flush: ci_resource_op %d", rc));
    return rc;
  }

  return 0;
}


int ef_vi_pace(ef_vi* ep, ef_driver_handle fd, int val)
{
  LOGV(ef_log("ef_vi_pace: not supported"));
  return -EOPNOTSUPP;
}


int ef_vi_arch_from_efhw_arch(int efhw_arch)
{
  switch( efhw_arch ) {
  case EFHW_ARCH_EF10:
    return EF_VI_ARCH_EF10;
  case EFHW_ARCH_EF100:
    return EF_VI_ARCH_EF100;
  case EFHW_ARCH_AF_XDP:
    return EF_VI_ARCH_AF_XDP;
  default:
    return -1;
  }
}

/*! \cidoxg_end */
