/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */

#include <linux/ethtool.h>

#include <ci/driver/efab/hardware.h>
#include <ci/efhw/debug.h>
#include <ci/efhw/iopage.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/efhw/efhw_buftable.h>
#include <ci/efhw/buddy.h>
#include <ci/efhw/tph.h>

#include <ci/driver/ci_ef10.h>
#include <ci/driver/resource/driverlink.h>

#include <ci/tools/debug.h>

#include <ci/efhw/ef10.h>
#include <ci/efhw/mc_driver_pcol.h>
#include "../aux.h"
#include "../mcdi_common.h"
#include "../ef10_ef100.h"
#include "../tph.h"


int force_ev_timer = 1;
module_param(force_ev_timer, int, S_IRUGO);
MODULE_PARM_DESC(force_ev_timer,
                 "Set to 0 to avoid forcing allocation of event timer with wakeup queue");

#define EFHW_CLIENT_ID_NONE (~0u)

#define MCDI_CHECK(op, rc, actual_len, rate_limit) \
	ef10_mcdi_check_response(__func__, #op, (rc), op##_OUT_LEN, \
				 (actual_len), (rate_limit))

/*----------------------------------------------------------------------------
 *
 * Helper for MCDI operations
 *
 *---------------------------------------------------------------------------*/


static int ef10_mcdi_rpc(struct efhw_nic *nic, unsigned int cmd, size_t inlen,
                         size_t outlen, size_t *outlen_actual, void *inbuf,
                         void *outbuf)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  struct efx_auxdev_rpc rpc = {
    .cmd = cmd,
    .inlen = inlen,
    .inbuf = inbuf,
    .outlen = outlen,
    .outlen_actual = 0,
    .outbuf = outbuf,
  };

  *outlen_actual = 0;
  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->base_ops->fw_rpc(cli, &rpc);
  AUX_POST(dev, auxdev, cli, nic, rc);
  *outlen_actual = rpc.outlen_actual;

  /* For operations that we don't directly use the output from we tolerate
   * the NIC being absent, as if and when it comes back we'll re-init things
   * anyway. */
  if( rc == -ENETDOWN && outlen == 0 )
    rc = 0;

  return rc;
}


static void ef10_mcdi_check_response(const char* caller,
                                     const char* failed_cmd,
                                     int rc, int expected_len, int actual_len,
                                     int rate_limit)
{
  /* The NIC will return error if we gave it invalid arguments
   * or if something has gone wrong in the hardware at which
   * point, we should try to reset the NIC or something similar.
   * At this layer, we assume that the caller has not passed us
   * bogus arguments.  Since we do not have the ability to
   * initiate reset of NICs.  We will just print a scary warning
   * and continue. */
#ifdef NDEBUG
  if (rc == -ENETDOWN) {
  /* ENETDOWN indicates absent hardware. Don't print a warning
   * in NDEBUG builds. */
  }
  else
#endif
  if (rc != 0) {
    if (rate_limit)
      EFHW_ERR_LIMITED("%s: %s failed rc=%d", caller, failed_cmd, rc);
    else
      EFHW_ERR("%s: %s failed rc=%d", caller, failed_cmd, rc);
  }
  else if (actual_len < expected_len) {
    EFHW_ERR("%s: ERROR: '%s' expected response len %d, got %d", caller,
             failed_cmd, expected_len, actual_len);
  }
}


/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/


static int
ef10_mcdi_vport_id(struct efhw_nic *nic, u32 aux_vport_in, u32* mcdi_vport_out)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->vport_id_get(cli, aux_vport_in);
  AUX_POST(dev, auxdev, cli, nic, rc);

  if( rc < 0 )
    return rc;

  *mcdi_vport_out = rc;
  return 0;
}


static struct efhw_buddy_allocator *
ef10_vi_allocator_ctor(int vi_min, int vi_lim)
{
  int rc;
  struct efhw_buddy_allocator *vi_allocator = vzalloc(sizeof(*vi_allocator));
  if( !vi_allocator )
    return NULL;

  rc = efhw_buddy_range_ctor(vi_allocator, vi_min, vi_lim);
  if ( rc < 0 ) {
    EFHW_ERR("%s: efhw_buddy_range_ctor(%d, %d) failed (%d)",
             __FUNCTION__, vi_min, vi_lim, rc);
    vfree(vi_allocator);
    return NULL;
  }
  return vi_allocator;
}


static int ef10_nic_arch_extra_ctor(struct efhw_nic *nic, int min, int lim)
{
  struct ef10_aux_arch_extra *arch_extra;

  EFHW_TRACE("%s:", __FUNCTION__);
  arch_extra = kmalloc(sizeof(struct ef10_aux_arch_extra), GFP_KERNEL);
  if( !arch_extra )
    return -ENOMEM;

  arch_extra->vi_allocator = ef10_vi_allocator_ctor(min, lim);
  if( !arch_extra->vi_allocator ) {
    kfree(arch_extra);
    return -ENOMEM;
  }
  mutex_init(&arch_extra->vi_alloc_lock);

  nic->arch_extra = arch_extra;
  return 0;
}


static int ef10_nic_sw_ctor(struct efhw_nic *nic,
                            const struct vi_resource_dimensions *res)
{
  switch (nic->devtype.variant) {
    case 'C':
      nic->ctr_ap_bar = EF10_MEDFORD2_P_CTR_AP_BAR;
      break;
    default:
      nic->ctr_ap_bar = nic->devtype.function == EFHW_FUNCTION_PF ?
                        EF10_PF_P_CTR_AP_BAR : EF10_VF_P_CTR_AP_BAR;
  }

  if (res->mem_bar != VI_RES_MEM_BAR_UNDEFINED)
    nic->ctr_ap_bar = res->mem_bar;

  nic->ctr_ap_addr = pci_resource_start(res->pci_dev, nic->ctr_ap_bar);

  nic->num_evqs   = 1024;
  nic->num_dmaqs  = 1024;
  nic->num_timers = 1024;
  /* For EF10 we map VIs on demand.  We don't need mappings
   * for any other reason as all control ops go via the net
   * driver and MCDI.
   */
  nic->vi_base = res->vi_base;
  nic->vi_shift = res->vi_shift;
  nic->vi_stride = res->vi_stride;

  return ef10_nic_arch_extra_ctor(nic, res->vi_min, res->vi_lim);
}


static void ef10_nic_sw_dtor(struct efhw_nic *nic)
{
  struct ef10_aux_arch_extra *arch_extra = nic->arch_extra;
  EFHW_TRACE("%s:", __FUNCTION__);

  if( arch_extra ) {
    if( arch_extra->vi_allocator ) {
      efhw_buddy_dtor(arch_extra->vi_allocator);
      vfree(arch_extra->vi_allocator);
      arch_extra->vi_allocator = NULL;
    }
    kfree(arch_extra);
  }
}


static int _ef10_nic_get_35388_workaround(struct efhw_nic *nic)
{
  int rc, enabled;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_WORKAROUNDS_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(out);
  rc = ef10_mcdi_rpc(nic, MC_CMD_GET_WORKAROUNDS, 0, sizeof(out),
                     &out_size, NULL, out);
  MCDI_CHECK(MC_CMD_GET_WORKAROUNDS, rc, out_size, 0);
  if (rc != 0)
    return rc;

  enabled = EFHW_MCDI_DWORD(out, GET_WORKAROUNDS_OUT_ENABLED);
  return (enabled & MC_CMD_GET_WORKAROUNDS_OUT_BUG35388) ? 1 : 0;
}


static int _ef10_nic_read_35388_workaround(struct efhw_nic *nic) 
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_WORKAROUND_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, WORKAROUND_IN_ENABLED, 1);
  EFHW_MCDI_SET_DWORD(in, WORKAROUND_IN_TYPE, MC_CMD_WORKAROUND_BUG35388);

  /* For this workaround, the MC_CMD_WORKAROUND does nothing
   * other than report if the workaround is known by the
   * firmware.  If it is known then it is enabled.  The value of
   * "enabled" is ignored.
   *
   * Try this first rather than just calling
   * MC_CMD_GET_WORKAROUNDS as I think there are some older
   * firmware versions that don't have both
   */
  rc = ef10_mcdi_rpc(nic, MC_CMD_WORKAROUND, sizeof(in), 0, &out_size,
                     in, NULL);

  if ( rc == 0 )
    /* Workaround known => is enabled. */
    return 1;
  else if ( (rc == -ENOENT) || (rc == -ENOSYS) )
    /* Workaround not known => is not enabled. */
    return 0;
  else if ( rc == -EPERM )
    /* Function not permitted, try reading status instead */
    return _ef10_nic_get_35388_workaround(nic);
  else
    /* Other MCDI failure. */
    EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);

  return rc;
}


static int _ef10_nic_check_35388_workaround(struct efhw_nic *nic) 
{
  /* TODO use MC_CMD_PRIVILEGE_MASK to first discover if
   * MC_CMD_WORKAROUND is permitted, and call
   * _read_35388_workaround instead of _set_35388_workaround if
   * not.
   *
   * This will avoid syslog messages about MC_CMD_WORKAROUND
   * failing with EPERM if >2 PFs configured.
   *
   * NB. To acquire arguments for PRIVILEGE_MASK need to call
   * MC_CMD_GET_FUNCTION_INFO.  See efx_ef10_get_[pf,vf]_index()
   */
  return _ef10_nic_read_35388_workaround(nic);
}


void
ef10_nic_check_supported_filters(struct efhw_nic *nic) {
  int rc;
  size_t out_size;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_PARSER_DISP_INFO_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, GET_PARSER_DISP_INFO_IN_OP,
                   MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_RX_MATCHES);

  rc = ef10_mcdi_rpc(nic, MC_CMD_GET_PARSER_DISP_INFO, sizeof(in),
                     sizeof(out), &out_size, in, out);
  if( rc != 0 )
    EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);
  else if ( out_size < MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN )
    EFHW_ERR("%s: failed, expected response min len %d, got %d", __FUNCTION__,
             MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN, (int)out_size);

  EFHW_ASSERT(EFHW_MCDI_VAR_ARRAY_LEN(out_size,
                GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES) ==
              EFHW_MCDI_DWORD(out,
                GET_PARSER_DISP_INFO_OUT_NUM_SUPPORTED_MATCHES));

  nic->filter_flags |= mcdi_parser_info_to_filter_flags(out);

  /* If we have the hardware mismatch filters we can turn them into all filters
   * by blocking kernel traffic, so we can claim the all equivalents too */
  if( nic->filter_flags & NIC_FILTER_FLAG_RX_TYPE_UCAST_MISMATCH )
    nic->filter_flags |= NIC_FILTER_FLAG_RX_TYPE_UCAST_ALL;
  if( nic->filter_flags & NIC_FILTER_FLAG_RX_TYPE_MCAST_MISMATCH )
    nic->filter_flags |= NIC_FILTER_FLAG_RX_TYPE_MCAST_ALL;

  /* All fw variants support IPv6 filters */
  nic->filter_flags |= NIC_FILTER_FLAG_RX_TYPE_IP6;
}


static int ef10_nic_mac_spoofing_privilege(struct efhw_nic *nic)
{
  size_t outlen;
  uint16_t pf, vf;
  int rc;
  uint16_t priv_mask;

  EFHW_MCDI_DECLARE_BUF(fi_outbuf, MC_CMD_GET_FUNCTION_INFO_OUT_LEN);
  EFHW_MCDI_DECLARE_BUF(pm_inbuf, MC_CMD_PRIVILEGE_MASK_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(pm_outbuf, MC_CMD_PRIVILEGE_MASK_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(fi_outbuf);
  EFHW_MCDI_INITIALISE_BUF(pm_inbuf);
  EFHW_MCDI_INITIALISE_BUF(pm_outbuf);

  /* Get our function number */
  rc = ef10_mcdi_rpc(nic, MC_CMD_GET_FUNCTION_INFO, 0, sizeof(fi_outbuf),
                     &outlen, NULL, fi_outbuf);
  MCDI_CHECK(MC_CMD_GET_FUNCTION_INFO, rc, outlen, 0);
  if (rc != 0)
    return rc;

  pf = EFHW_MCDI_DWORD(fi_outbuf, GET_FUNCTION_INFO_OUT_PF);
  vf = EFHW_MCDI_DWORD(fi_outbuf, GET_FUNCTION_INFO_OUT_VF);

  EFHW_MCDI_POPULATE_DWORD_2(pm_inbuf, PRIVILEGE_MASK_IN_FUNCTION,
                             PRIVILEGE_MASK_IN_FUNCTION_PF, pf,
                             PRIVILEGE_MASK_IN_FUNCTION_VF, vf);

  rc = ef10_mcdi_rpc(nic, MC_CMD_PRIVILEGE_MASK, sizeof(pm_inbuf),
                     sizeof(pm_outbuf), &outlen, pm_inbuf, pm_outbuf);
  MCDI_CHECK(MC_CMD_PRIVILEGE_MASK, rc, outlen, 0);
  if (rc != 0)
    return rc;

  priv_mask = EFHW_MCDI_DWORD(pm_outbuf, PRIVILEGE_MASK_OUT_OLD_MASK);
  if( priv_mask & MC_CMD_PRIVILEGE_MASK_IN_GRP_MAC_SPOOFING )
    return 1;
  else
    return 0;
}


static int _ef10_nic_check_capabilities(struct efhw_nic *nic,
                                        uint64_t* nic_capability_flags,
                                        const char* caller)
{
  size_t out_size = 0;
  uint64_t capability_flags;
  unsigned flags;
  int rc;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_CAPABILITIES_V13_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_CAPABILITIES_V13_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  /* Set default queue sizes in case we fail MC_CMD_GET_CAPABILITIES or V10
   * isn't supported. */
  nic->q_sizes[EFHW_EVQ] = 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768;
  nic->q_sizes[EFHW_TXQ] = 512 | 1024 | 2048;
  nic->q_sizes[EFHW_RXQ] = 512 | 1024 | 2048 | 4096;

  /* Older FW ignores the extra in parameter, but such FW only supports a
   * single datapath anyway, so we still get what we want. */
  EFHW_MCDI_SET_DWORD(in, GET_CAPABILITIES_V13_IN_DATAPATH_TYPE,
                      MC_CMD_GET_CAPABILITIES_V13_IN_FF_PATH);
  rc = ef10_mcdi_rpc(nic, MC_CMD_GET_CAPABILITIES, sizeof(in), sizeof(out),
                     &out_size, in, out);
  MCDI_CHECK(MC_CMD_GET_CAPABILITIES, rc, out_size, 0);
  if (rc != 0)
    return rc;

  /* Get the set of flags where there's a simple one to one mapping with nic
   * flags. */
  capability_flags = mcdi_capability_info_to_nic_flags(out, out_size);

  /* If MAC filters are policed then check we've got the right privileges
   * before saying we can do MAC spoofing.
   */
  flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS1);
  if (flags & (1u <<
               MC_CMD_GET_CAPABILITIES_V3_OUT_TX_MAC_SECURITY_FILTERING_LBN)) {
    if( ef10_nic_mac_spoofing_privilege(nic) == 1 )
      capability_flags |= NIC_FLAG_MAC_SPOOFING;
  }
  else {
    capability_flags |= NIC_FLAG_MAC_SPOOFING;
  }

  if( capability_flags & NIC_FLAG_PIO ) {
    nic->pio_num = EFHW_MCDI_WORD(out, GET_CAPABILITIES_V3_OUT_NUM_PIO_BUFFS);
    nic->pio_size = EFHW_MCDI_WORD(out, GET_CAPABILITIES_V3_OUT_SIZE_PIO_BUFF);
  }

  if (out_size >= MC_CMD_GET_CAPABILITIES_V3_OUT_LEN) {
    const uint32_t MEDFORD2_BYTES_PER_BUFFER = 1024;
    const uint32_t MEDFORD_BYTES_PER_BUFFER  =  512;

    /* If TX alternatives are not supported, these can still be
     * set to non-zero values based on whatever MCFW reports.
     */
    nic->tx_alts_vfifos = EFHW_MCDI_BYTE(out,
    GET_CAPABILITIES_V3_OUT_VFIFO_STUFFING_NUM_VFIFOS);
    nic->tx_alts_cp_bufs = EFHW_MCDI_WORD(out,
    GET_CAPABILITIES_V3_OUT_VFIFO_STUFFING_NUM_CP_BUFFERS);
    /* The firmware doesn't report the size of the common-pool
    * buffers, so we infer it from the NIC-type. */
    nic->tx_alts_cp_buf_size = nic->devtype.variant >= 'C' ?
    MEDFORD2_BYTES_PER_BUFFER :
    MEDFORD_BYTES_PER_BUFFER;
  }
  else {
    nic->tx_alts_vfifos = 0;
    nic->tx_alts_cp_bufs = 0;
    nic->tx_alts_cp_buf_size = 0;
  }

  nic->rx_variant = EFHW_MCDI_WORD(out, GET_CAPABILITIES_OUT_RX_DPCPU_FW_ID);
  nic->tx_variant = EFHW_MCDI_WORD(out, GET_CAPABILITIES_OUT_TX_DPCPU_FW_ID);

  if (out_size >= MC_CMD_GET_CAPABILITIES_V10_OUT_LEN) {
    ci_uint32 q_sizes =
      EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V10_OUT_SUPPORTED_QUEUE_SIZES);
    nic->q_sizes[EFHW_EVQ] = q_sizes;
    nic->q_sizes[EFHW_TXQ] = q_sizes;
    nic->q_sizes[EFHW_RXQ] = q_sizes;
  }

  *nic_capability_flags |= capability_flags;

  return rc;
}


static int ef10_nic_get_timestamp_correction(struct efhw_nic *nic,
                                             int *rx_ts_correction,
                                             int *tx_ts_correction,
                                             const char* caller)
{
  int rc;
  size_t out_size;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_GET_TIMESTAMP_CORRECTIONS_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, PTP_IN_OP, MC_CMD_PTP_OP_GET_TIMESTAMP_CORRECTIONS);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);

  rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), sizeof(out), &out_size,
                     in, out);
  if( rc == 0 ) {
    if (out_size >= MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_LEN) {
      *rx_ts_correction =
        EFHW_MCDI_DWORD(out, PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_GENERAL_RX);
      *tx_ts_correction =
        EFHW_MCDI_DWORD(out, PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_GENERAL_TX);
      /* NIC gives TX correction in ticks.  For hunti and
       * medford the caller expects ns, and for medford2
       * the caller expects ticks.
       */
      if( nic->devtype.variant < 'C' )
        *tx_ts_correction = ((uint64_t) *tx_ts_correction * 1000000000) >> 27;
    }
    else {
      *rx_ts_correction =
        EFHW_MCDI_DWORD(out, PTP_OUT_GET_TIMESTAMP_CORRECTIONS_RECEIVE);
      /* This firmware ver can't tell us TX correction, so
       * must be Huntington.  This is the correct val...
       */
      *tx_ts_correction = 178;
    }
  }
  return rc;
}


static int ef10_nic_get_ptp_attributes(struct efhw_nic* nic,
                                       uint32_t* ts_format, const char* caller)
{
  int rc;
  size_t out_size;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_GET_ATTRIBUTES_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_PTP_OUT_GET_ATTRIBUTES_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, PTP_IN_OP, MC_CMD_PTP_OP_GET_ATTRIBUTES);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);

  rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), sizeof(out), &out_size,
                     in, out);
  if( rc != 0 )
    return rc;

  switch( EFHW_MCDI_DWORD(out, PTP_OUT_GET_ATTRIBUTES_TIME_FORMAT) ) {
    case MC_CMD_PTP_OUT_GET_ATTRIBUTES_SECONDS_QTR_NANOSECONDS:
      *ts_format = TS_FORMAT_SECONDS_QTR_NANOSECONDS;
      break;

    case MC_CMD_PTP_OUT_GET_ATTRIBUTES_SECONDS_27FRACTION:
      *ts_format = TS_FORMAT_SECONDS_27FRACTION;
      break;

    default:
      return -EOPNOTSUPP;
  }

  return 0;
}


static void
ef10_nic_tweak_hardware(struct efhw_nic *nic)
{
  /* No need to set RX_USR_BUF_SIZE for ef10, it's done per-descriptor */

  /* Some capabilities are always present on ef10 */
  nic->flags |= NIC_FLAG_HW_MULTICAST_REPLICATION |
                NIC_FLAG_PHYS_MODE | NIC_FLAG_BUFFER_MODE | NIC_FLAG_VPORTS |
                NIC_FLAG_RX_MCAST_REPLICATION | NIC_FLAG_USERSPACE_PRIME |
                NIC_FLAG_SHARED_PD | NIC_FLAG_EXCL_RXQ_ATTACH_IS_DEFAULT;

  /* Determine what the filtering capabilies are */
  ef10_nic_check_supported_filters(nic);

  if( _ef10_nic_check_35388_workaround(nic) == 1 )
    nic->flags |= NIC_FLAG_BUG35388_WORKAROUND;

  /* Determine capabilities reported by firmware */
  _ef10_nic_check_capabilities(nic, &nic->flags, __FUNCTION__);

  nic->rx_prefix_len = (nic->flags & NIC_FLAG_14BYTE_PREFIX) ? 14 : 0;
}

static int
ef10_nic_init_hardware(struct efhw_nic *nic,
                       struct efhw_ev_handler *ev_handlers,
                       const uint8_t *mac_addr)
{
  int rc;
  EFHW_TRACE("%s:", __FUNCTION__);

  memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

  nic->ev_handlers = ev_handlers;
  ef10_nic_tweak_hardware(nic);

  rc = ef10_nic_get_timestamp_correction(nic, &(nic->rx_ts_correction),
                                         &(nic->tx_ts_correction),
                                         __FUNCTION__);
  if( rc < 0 ) {
    if( rc == -EPERM || rc == -ENOSYS )
      EFHW_TRACE("%s: WARNING: failed to get HW timestamp corrections rc=%d",
                 __FUNCTION__, rc);
    else
      EFHW_ERR("%s: ERROR: failed to get HW timestamp corrections rc=%d",
               __FUNCTION__, rc);
    /* This will happen if the NIC does not have a PTP
     * licence.  Without that licence the user is unlikely
     * to be doing such accurate timestamping, but try to
     * do something sensible... these values are correct
     * for Huntington.
     */
    nic->rx_ts_correction = -12;
    nic->tx_ts_correction = 178;
  }

  rc = ef10_nic_get_ptp_attributes(nic, &(nic->ts_format), __FUNCTION__);
  if( rc < 0 ) {
    if( rc == -EPERM || rc == -ENOSYS )
      EFHW_TRACE("%s: WARNING: failed to get PTP attributes rc=%d",
                 __FUNCTION__, rc);
    else
      EFHW_ERR("%s: ERROR: failed to get PTP attributes rc=%d",
               __FUNCTION__, rc);

     /* As above. */
      nic->ts_format = TS_FORMAT_SECONDS_27FRACTION;
  }

  /* No buffer_table_ctor() on EF10 */
  /* No non_irq_evq on EF10 */

  nic->rss_indir_size = EF10_EF100_RSS_INDIRECTION_TABLE_LEN;
  nic->rss_key_size = EF10_EF100_RSS_KEY_LEN;

  return 0;
}


static void ef10_nic_release_hardware(struct efhw_nic *nic)
{
  EFHW_TRACE("%s:", __FUNCTION__);
}


/*--------------------------------------------------------------------
 *
 * Events - MCDI cmds and register interface
 *
 *--------------------------------------------------------------------*/


int ef10_mcdi_cmd_event_queue_enable(struct efhw_nic *nic,
                                     struct efhw_evq_params *params,
                                     uint enable_cut_through,
                                     uint enable_rx_merging, uint enable_timer)
{
  int rc, i;
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_INIT_EVQ_V2_OUT_LEN);
  size_t out_size;
  size_t in_size = MC_CMD_INIT_EVQ_V2_IN_LEN(params->n_pages);
  EFHW_MCDI_DECLARE_BUF(in,
             MC_CMD_INIT_EVQ_V2_IN_LEN(MC_CMD_INIT_EVQ_V2_IN_DMA_ADDR_MAXNUM));
  EFHW_MCDI_INITIALISE_BUF_SIZE(in, in_size);

  EFHW_ASSERT(params->n_pages <= MC_CMD_INIT_EVQ_V2_IN_DMA_ADDR_MAXNUM);

  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_SIZE, params->evq_size);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_INSTANCE, params->evq);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_LOAD, 0);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_RELOAD, 0);

  /* We must explicitly request a timer if we are
   * not interrupting (we'll get one anyway if we are).
   */
  EFHW_MCDI_POPULATE_DWORD_4(in, INIT_EVQ_IN_FLAGS,
  INIT_EVQ_IN_FLAG_USE_TIMER, enable_timer ? 1 : 0,
  INIT_EVQ_IN_FLAG_CUT_THRU, enable_cut_through ? 1 : 0,
  INIT_EVQ_IN_FLAG_RX_MERGE, enable_rx_merging ? 1 : 0,
  INIT_EVQ_IN_FLAG_TX_MERGE, 1);

  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_MODE,
                      MC_CMD_INIT_EVQ_IN_TMR_MODE_DIS);

  /* EF10 TODO We may want to direct the wakeups to another EVQ,
   * but by default do old-style spreading
   */
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TARGET_EVQ, params->wakeup_channel);

  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_COUNT_MODE,
                      MC_CMD_INIT_EVQ_IN_COUNT_MODE_DIS);
  EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_COUNT_THRSHLD, 0);

  for( i = 0; i < params->n_pages; ++i ) {
    EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_EVQ_IN_DMA_ADDR, i,
                              params->dma_addrs[i]);
  }

  EFHW_ASSERT(params->evq >= 0);
  EFHW_ASSERT(params->evq < nic->num_evqs);

  rc = ef10_mcdi_rpc(nic, MC_CMD_INIT_EVQ, in_size, sizeof(out), &out_size,
                     in, &out);
  if( nic->flags & NIC_FLAG_EVQ_V2 )
    MCDI_CHECK(MC_CMD_INIT_EVQ_V2, rc, out_size, 0);
  else
    MCDI_CHECK(MC_CMD_INIT_EVQ, rc, out_size, 0);

  return rc;
}


void ef10_mcdi_cmd_event_queue_disable(struct efhw_nic *nic, uint evq)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_EVQ_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FINI_EVQ_IN_INSTANCE, evq);

  EFHW_ASSERT(evq >= 0);
  EFHW_ASSERT(evq < nic->num_evqs);

  rc = ef10_mcdi_rpc(nic, MC_CMD_FINI_EVQ, MC_CMD_FINI_EVQ_IN_LEN, 0,
                     &out_size, in, NULL);
  MCDI_CHECK(MC_CMD_FINI_EVQ, rc, out_size, 0);
}


static int
ef10_mcdi_cmd_get_vi_tlp_processing(struct efhw_nic *nic, unsigned instance,
                                    struct tlp_state *tlp)
{
  int rc;
  size_t out_size;

  EFHW_MCDI_DECLARE_BUF(get_out, MC_CMD_GET_VI_TLP_PROCESSING_OUT_LEN);
  EFHW_MCDI_DECLARE_BUF(get_in, MC_CMD_GET_VI_TLP_PROCESSING_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(get_in);

  efhw_populate_get_vi_tlp_processing_mcdi_cmd(get_in, instance);
  rc = ef10_mcdi_rpc(nic, MC_CMD_GET_VI_TLP_PROCESSING, sizeof(get_in),
                     sizeof(get_out), &out_size, get_in, &get_out);
  MCDI_CHECK(MC_CMD_GET_VI_TLP_PROCESSING, rc, out_size, 0);

  efhw_extract_get_vi_tlp_processing_mcdi_cmd_result(get_out, tlp);

  EFHW_TRACE("%s: tph now %x (data %x) (rc %d)", __FUNCTION__, tlp->tph,
             tlp->data, rc);

  return rc;
}


static int
ef10_mcdi_cmd_set_vi_tlp_processing(struct efhw_nic *nic, uint instance,
                                    int set, uint8_t tag)
{
  int rc;
  size_t out_size;
  struct tlp_state tlp;

  EFHW_MCDI_DECLARE_BUF(set_in, MC_CMD_SET_VI_TLP_PROCESSING_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(set_in);

  rc = ef10_mcdi_cmd_get_vi_tlp_processing(nic, instance, &tlp);
  EFHW_TRACE("%s: tph was %x (data %x, instance %d) (rc %d)",
             __FUNCTION__, tlp.tph, tlp.data, instance, rc);

  tlp.tph = set ? 1 : 0;
  tlp.tag1 = tlp.tag2 = tag;
  tlp.relaxed = 0;
  tlp.snoop = 0;
  tlp.inorder = 0;

  efhw_populate_set_vi_tlp_processing_mcdi_cmd(set_in, instance, &tlp);

  EFHW_TRACE("%s: setting tph %x (data %x)",
             __FUNCTION__, (tlp.data >> 19) & 1, tlp.data);
  rc = ef10_mcdi_rpc(nic, MC_CMD_SET_VI_TLP_PROCESSING, sizeof(set_in), 0,
                     &out_size, set_in, NULL);
  MCDI_CHECK(MC_CMD_SET_VI_TLP_PROCESSING, rc, out_size, 0);

#if DEBUG_TLP
  /* read back the value to check it had an effect */
  ef10_mcdi_cmd_get_vi_tlp_processing(nic, instance, &tlp);
#endif

  return rc;
}


/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/


static void
ef10_mcdi_cmd_driver_event(struct efhw_nic *nic, uint64_t data, uint32_t evq)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_DRIVER_EVENT_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, DRIVER_EVENT_IN_EVQ, evq);
  EFHW_MCDI_SET_QWORD(in, DRIVER_EVENT_IN_DATA, data);

  rc = ef10_mcdi_rpc(nic, MC_CMD_DRIVER_EVENT, sizeof(in), 0, &out_size,
                     in, NULL);
  MCDI_CHECK(MC_CMD_DRIVER_EVENT, rc, out_size, 0);
}


#ifndef MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_OUT_LEN
#define MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_OUT_LEN	\
	MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_LEN
#endif


static int
_ef10_mcdi_cmd_ptp_time_event_subscribe_v2(struct efhw_nic *nic, uint32_t evq,
                                           unsigned* out_flags,
                                           const char* caller)
{
  int rc;
  size_t out_size;
  int sync_flag = EFHW_VI_CLOCK_SYNC_STATUS;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_V2_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, PTP_IN_OP, MC_CMD_PTP_OP_TIME_EVENT_SUBSCRIBE_V2);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_SUBSCRIBE_V2_QUEUE_ID, evq);
  EFHW_MCDI_POPULATE_DWORD_1(in, PTP_IN_TIME_EVENT_SUBSCRIBE_V2_FLAGS,
    PTP_IN_TIME_EVENT_SUBSCRIBE_V2_REPORT_SYNC_STATUS, 1);

  /* We try subscribing to time sync events and requesting the sync status, but
   * this setting is global so must be set to the same value as was used in the
   * first subscription request. In absence of a way to find out what that was,
   * we try subscribing first requesting time sync and secondly without. */
  rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size, in, NULL);
  if( rc < 0 ) {
    sync_flag = 0;
    EFHW_MCDI_POPULATE_DWORD_1(in, PTP_IN_TIME_EVENT_SUBSCRIBE_V2_FLAGS,
      PTP_IN_TIME_EVENT_SUBSCRIBE_V2_REPORT_SYNC_STATUS, 0);
    rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size, in, NULL);
  }

  /* TODO: uncomment this when we can know which version to call */
  /* MCDI_CHECK(MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE, rc, out_size, 0); */
  if (rc == 0 && out_flags != NULL)
    *out_flags |= sync_flag;
  return rc;
}


static int
_ef10_mcdi_cmd_ptp_time_event_subscribe_v1(struct efhw_nic *nic, uint32_t evq,
                                           unsigned* out_flags,
                                           const char* caller)
{
  int rc;
  size_t out_size;
  static const uint32_t rs =
           (1 << MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_REPORT_SYNC_STATUS_LBN);
  int sync_flag = EFHW_VI_CLOCK_SYNC_STATUS;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_TIME_EVENT_SUBSCRIBE_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, PTP_IN_OP, MC_CMD_PTP_OP_TIME_EVENT_SUBSCRIBE);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE, evq | rs);

  rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size, in, NULL);
  if (rc == -ERANGE) {
    sync_flag = 0;
    EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE, evq);
    rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size, in, NULL);
  }

  MCDI_CHECK(MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE, rc, out_size, 0);
  if (rc == 0 && out_flags != NULL)
    *out_flags |= sync_flag;
  return rc;
}


static int
_ef10_mcdi_cmd_ptp_time_event_subscribe(struct efhw_nic *nic, uint32_t evq,
                                        unsigned* out_flags,
                                        const char* caller)
{
  int rc;

  rc = _ef10_mcdi_cmd_ptp_time_event_subscribe_v2(nic, evq, out_flags, caller);
  if( rc < 0 )
    rc = _ef10_mcdi_cmd_ptp_time_event_subscribe_v1(nic, evq, out_flags,
                                                    caller);

  return rc;
}

static int
_ef10_mcdi_cmd_ptp_time_event_unsubscribe(struct efhw_nic *nic, uint32_t evq,
                                          const char* caller)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, PTP_IN_OP, MC_CMD_PTP_OP_TIME_EVENT_UNSUBSCRIBE);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_UNSUBSCRIBE_CONTROL,
                      MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_SINGLE);
  EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_UNSUBSCRIBE_QUEUE, evq);

  rc = ef10_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size, in, NULL);

#ifndef MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_OUT_LEN
#define MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_OUT_LEN	\
	MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_LEN
#endif
  MCDI_CHECK(MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE, rc, out_size, 0);
  return rc;
}


static int
ef10_nic_evq_requires_time_sync(struct efhw_nic *nic, uint flags)
{
  return !!(flags & (EFHW_VI_RX_TIMESTAMPS | EFHW_VI_TX_TIMESTAMPS));
}


/* This function will enable the given event queue with the requested
 * properties.
 */
static int
ef10_nic_event_queue_enable(struct efhw_nic *nic,
                            struct efhw_evq_params *params)
{
  int rc;
  int flags = params->flags;
  int enable_time_sync_events = ef10_nic_evq_requires_time_sync(nic, flags);
  int enable_cut_through = (flags & EFHW_VI_NO_EV_CUT_THROUGH) == 0;
  int enable_rx_merging = ((flags & EFHW_VI_RX_PACKED_STREAM) != 0) ||
                          ((flags & EFHW_VI_ENABLE_RX_MERGE) != 0);
  int enable_timer = (flags & EFHW_VI_ENABLE_EV_TIMER);

  /* See bug66017 - we'd like to sometimes be able to use
   * wakeups without an event timer, but that isn't currently
   * possible, so force the allocation of a timer
   */
  if( force_ev_timer )
    enable_timer = 1;

  rc = ef10_mcdi_cmd_event_queue_enable(nic, params, enable_cut_through,
                                        enable_rx_merging, enable_timer);

  EFHW_TRACE("%s: enable evq %u size %u rc %d", __FUNCTION__, params->evq,
             params->evq_size, rc);

  if( rc == 0 && enable_time_sync_events ) {
    rc = _ef10_mcdi_cmd_ptp_time_event_subscribe(nic, params->evq,
                                                 &params->flags_out,
                                                 __FUNCTION__);
  if( rc != 0 ) {
    ef10_mcdi_cmd_event_queue_disable(nic, params->evq);
    /* Firmware returns EPERM if you do not have the licence to subscribe to
     * time sync events.  We convert it to ENOKEY which in Onload means you are
     * lacking the appropriate licence.
     *
     * Firmware returns ENOSYS in case it does not support timestamping.  We
     * convert it to EOPNOTSUPP.
     */
    if( rc == -ENOSYS )
      return -EOPNOTSUPP;
    if( rc == -EPERM )
      return -ENOKEY;
    }
  }
  return rc;
}

static void
ef10_nic_event_queue_disable(struct efhw_nic *nic, uint evq,
                             int time_sync_events_enabled)
{
  if( time_sync_events_enabled )
    _ef10_mcdi_cmd_ptp_time_event_unsubscribe(nic, evq, __FUNCTION__);
  ef10_mcdi_cmd_event_queue_disable(nic, evq);
}

static void
ef10_nic_wakeup_request(struct efhw_nic *nic, volatile void __iomem* io_page,
                        int vi_id, int rptr)
{
  __DWCHCK(ERF_DZ_EVQ_RPTR);
  __RANGECHCK(rptr, ERF_DZ_EVQ_RPTR_WIDTH);

  if( nic->flags & NIC_FLAG_BUG35388_WORKAROUND ) {
    ef10_update_evq_rptr_bug35388_workaround(io_page, rptr);
  }
  else {
    /* When the NIC is under reset,
     * NIC_FLAG_BUG35388_WORKAROUND can disappear for some time.
     * wakeup_request() at such time can't do anything useful. */

    ef10_update_evq_rptr(io_page, rptr);
  }
}


static void ef10_nic_sw_event(struct efhw_nic *nic, int data, int evq)
{
  uint64_t ev_data = data;

  ev_data &= ~EF10_EVENT_CODE_MASK;
  ev_data |= EF10_EVENT_CODE_SW;

  /* No MCDI event code is set for a sw event so it is implicitly 0 */

  ef10_mcdi_cmd_driver_event(nic, ev_data, evq);
  EFHW_TRACE("%s: evq[%d]->%x", __FUNCTION__, evq, data);
}

bool ef10_accept_vi_constraints(int low, unsigned order, void* arg)
{
  struct ef10_ef100_alloc_vi_constraints *avc = arg;
  struct efhw_vi_constraints *vc = avc->evc;
  struct efhw_nic *nic = avc->nic;

  int high = low + vc->min_vis_in_set;
  int ok = 1;
  if ((vc->min_vis_in_set > 1) && (!vc->has_rss_context)) {
    /* We need to ensure that if an RSS-enabled filter is
     * pointed at this VI-set then the queue selected will be
     * within the default set.  The queue selected by RSS will be
     * in the range (low | (rss_channel_count - 1)).
     */
    ok &= ((low | (nic->rss_channel_count - 1)) < high);
  }
  return ok;
}


int ef10_vi_alloc(struct efhw_nic *nic, struct efhw_vi_constraints *evc,
                  unsigned n_vis) {
  struct efx_auxdev_client *cli;
  int rc;

  cli = efhw_nic_acquire_auxdev(nic);
  if(cli != NULL) {
    unsigned order = fls(n_vis - 1);
    struct ef10_aux_arch_extra *arch_extra = nic->arch_extra;
    struct efhw_buddy_allocator *vi_allocator = arch_extra->vi_allocator;
    struct ef10_ef100_alloc_vi_constraints avc = {
      .nic = nic,
      .evc = evc,
    };
    mutex_lock(&arch_extra->vi_alloc_lock);
    rc = efhw_buddy_alloc_special(vi_allocator, order,
                                  ef10_accept_vi_constraints, &avc);
    mutex_unlock(&arch_extra->vi_alloc_lock);
    efhw_nic_release_auxdev(nic, cli);
  }
  else
    rc = -ENETDOWN;
  return rc;
}


void ef10_vi_free(struct efhw_nic *nic, int instance, unsigned n_vis) {
  struct efx_auxdev_client *cli;

  cli = efhw_nic_acquire_auxdev(nic);
  if(cli != NULL) {
    unsigned order = fls(n_vis - 1);
    struct ef10_aux_arch_extra *arch_extra = nic->arch_extra;
    struct efhw_buddy_allocator *vi_allocator = arch_extra->vi_allocator;
    mutex_lock(&arch_extra->vi_alloc_lock);
    efhw_buddy_free(vi_allocator, instance, order);
    mutex_unlock(&arch_extra->vi_alloc_lock);
    efhw_nic_release_auxdev(nic, cli);
  }
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
ef10_handle_event(struct efhw_nic *nic, efhw_event_t *ev, int budget)
{
  unsigned evq;

  if (EF10_EVENT_CODE(ev) == EF10_EVENT_CODE_CHAR) {
    switch (EF10_EVENT_DRIVER_SUBCODE(ev)) {
    case ESE_DZ_DRV_WAKE_UP_EV:
      evq = (EF10_EVENT_WAKE_EVQ_ID(ev) - nic->vi_base) >> nic->vi_shift;
      if (evq < nic->vi_lim && evq >= nic->vi_min) {
        return efhw_handle_wakeup_event(nic, evq, budget);
      }
      else {
        EFHW_NOTICE("%s: wakeup evq out of range: %d %d %d %d", __FUNCTION__,
                    evq, nic->vi_base, nic->vi_min, nic->vi_lim);
        return -EINVAL;
      }
    case ESE_DZ_DRV_TIMER_EV:
      evq = (EF10_EVENT_WAKE_EVQ_ID(ev) - nic->vi_base) >> nic->vi_shift;
      if (evq < nic->vi_lim && evq >= nic->vi_min) {
        return efhw_handle_timeout_event(nic, evq, budget);
      }
      else {
        EFHW_NOTICE("%s: timer evq out of range: %d %d %d %d",
                    __FUNCTION__, evq, nic->vi_base, nic->vi_min, nic->vi_lim);
        return -EINVAL;
      }
    default:
      EFHW_TRACE("UNKNOWN DRIVER EVENT: " EF10_EVENT_FMT,
                 EF10_EVENT_PRI_ARG(*ev));
      return -EINVAL;
    }
  }

  if (EF10_EVENT_CODE(ev) == EF10_EVENT_CODE_SW) {
    int code = EF10_EVENT_SW_SUBCODE(ev);
    switch (code) {
    case MCDI_EVENT_CODE_TX_FLUSH:
      evq = EF10_EVENT_TX_FLUSH_Q_ID(ev);
      EFHW_TRACE("%s: tx flush done %d", __FUNCTION__, evq);
      return efhw_handle_txdmaq_flushed(nic, evq);
    case MCDI_EVENT_CODE_RX_FLUSH:
      evq = EF10_EVENT_RX_FLUSH_Q_ID(ev);
      EFHW_TRACE("%s: rx flush done %d", __FUNCTION__, evq);
      return efhw_handle_rxdmaq_flushed(nic, evq, false);
    case MCDI_EVENT_CODE_TX_ERR:
      EFHW_NOTICE("%s: unexpected MCDI TX error event (event code %d)",
                  __FUNCTION__, code);
      return -EINVAL;
    case MCDI_EVENT_CODE_RX_ERR:
      EFHW_NOTICE("%s: unexpected MCDI RX error event (event code %d)",
                  __FUNCTION__, code);
      return -EINVAL;
    case MCDI_EVENT_CODE_AOE:
      /* This event doesn't signify an error case, so just return 0 to avoid
       * logging
       */
      return -EINVAL;
    default:
      EFHW_NOTICE("%s: unexpected MCDI event code %d", __FUNCTION__, code);
      return -EINVAL;
    }
  }

  EFHW_TRACE("%s: unknown event type=%x", __FUNCTION__,
             (unsigned)EF10_EVENT_CODE(ev));

  return -EINVAL;
}


static int
ef10_inject_reset_ev(struct efhw_nic* nic, void* base, unsigned capacity,
                     const volatile uint32_t* evq_ptr)
{
  efhw_event_t* evq = base;
  efhw_event_t* endev;
  uint32_t mask = capacity - 1;
  ci_qword_t reset_ev;
  uint32_t ptrend;
  uint32_t i;
  int sanity = 10;

  EFHW_ASSERT((capacity & (capacity - 1)) == 0);

  while (--sanity) {
    uint32_t ptr1, ptr2;

    /* Scan for the next unused event, being careful because userspace may
     * be concurrently modifying evq_ptr (and hence wiping out past evs).
     * We assume that the NIC has stopped writing by this point. */
    ptr1 = READ_ONCE(*evq_ptr);
    rmb();

    ptrend = ptr1;
    for (i = 0; i < capacity; ++i) {
      endev = &evq[(ptrend / sizeof(evq[0])) & mask];
      if (!EFHW_IS_EVENT(endev))
        break;
      ptrend += sizeof(evq[0]);
    }
    if (i == capacity)
      return -EOVERFLOW;

    /* Deal with the race when we read evq_ptr (into ptr1) and then by the
     * time we test EFHW_IS_EVENT() userspace has already polled and
     * cleared that entry. This would make that event appear to be the
     * end, except that it's now in the past from userspace's perspective.
     * Here we're checking if there's been any poll between the
     * beginning and the end, and retrying everything if there has been. */
    rmb();
    ptr2 = READ_ONCE(*evq_ptr);
    if (ptr1 == ptr2)
      break;
  }
  /* In theory, userspace could meddle with evq_ptr constantly so that
   * the above loop goes around essentially forever in kernelspace. This
   * prevents that, with the assumption that the only way to go around so
   * many times is for userspace to be malicious, and malicious userspace
   * doesn't deserve to be told about reset */
  if (!sanity)
    return -EDEADLK;

  CI_POPULATE_QWORD_2(reset_ev, ESF_DZ_EV_CODE, ESE_DZ_EV_CODE_MCDI_EV,
                      MCDI_EVENT_CODE, MCDI_EVENT_CODE_MC_REBOOT);
  WRITE_ONCE(endev->u64, reset_ev.u64[0]);
  return 0;
}


/*----------------------------------------------------------------------------
 *
 * multicast loopback - MCDI cmds
 *
 *---------------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_enable_multicast_loopback(struct efhw_nic *nic,
                                         int instance, int enable)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_PARSER_DISP_CONFIG_IN_LEN(1));
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_TYPE,
                MC_CMD_SET_PARSER_DISP_CONFIG_IN_TXQ_MCAST_UDP_DST_LOOKUP_EN);
  EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_ENTITY, instance);
  EFHW_MCDI_SET_DWORD(in, SET_PARSER_DISP_CONFIG_IN_VALUE, enable ? 1 : 0);

  rc = ef10_mcdi_rpc(nic, MC_CMD_SET_PARSER_DISP_CONFIG, sizeof(in), 0,
                     &out_size, in, NULL);
  MCDI_CHECK(MC_CMD_SET_PARSER_DISP_CONFIG, rc, out_size, 0);
  return rc;
}

static int
_ef10_set_multicast_loopback_suppression(struct efhw_nic *nic,
                                         int suppress_self, uint32_t port_id,
                                         uint8_t stack_id)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->set_multicast_loopback_suppression(cli,
      suppress_self, port_id, stack_id);
  AUX_POST(dev, auxdev, cli, nic, rc);
  return rc;
}


/*----------------------------------------------------------------------------
 *
 * TX Alternatives
 *
 *---------------------------------------------------------------------------*/

static int
ef10_mcdi_common_pool_alloc(struct efhw_nic *nic, unsigned txq_id,
                            unsigned num_32b_words, unsigned num_alt,
                            unsigned *pool_id_out)
{
  size_t out_size;
  int rc;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOCATE_TX_VFIFO_CP_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOCATE_TX_VFIFO_CP_OUT_LEN);

  unsigned buf_size = nic->tx_alts_cp_buf_size;
  unsigned num_bufs = (num_32b_words * 32 + buf_size - 1) / buf_size;

  /* Up to two buffers get allocated per VFIFO by the hardware,
   * which in practice means we need extra buffers to ensure we
   * get the buffering the user expects.
   */
  num_bufs += 2 * num_alt;

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_CP_IN_INSTANCE, txq_id);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_CP_IN_MODE, 1);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_CP_IN_SIZE, num_bufs);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_CP_IN_INGRESS, -1);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_CP_IN_EGRESS, -1);

  rc = ef10_mcdi_rpc(nic, MC_CMD_ALLOCATE_TX_VFIFO_CP, sizeof(in), sizeof(out),
                     &out_size, in, out);

  MCDI_CHECK(MC_CMD_ALLOCATE_TX_VFIFO_CP, rc, out_size, 0);
  if (rc == 0)
    *pool_id_out = EFHW_MCDI_DWORD(out, ALLOCATE_TX_VFIFO_CP_OUT_CP_ID);
  return rc;
}


static int
ef10_mcdi_common_pool_free(struct efhw_nic *nic, unsigned pool_id)
{
  size_t out_size;
  int rc;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_DEALLOCATE_TX_VFIFO_CP_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, DEALLOCATE_TX_VFIFO_CP_IN_POOL_ID, pool_id);

  rc = ef10_mcdi_rpc(nic, MC_CMD_DEALLOCATE_TX_VFIFO_CP, sizeof(in), 0,
                     &out_size, in, NULL);

  MCDI_CHECK(MC_CMD_DEALLOCATE_TX_VFIFO_CP, rc, out_size, 0);
  return rc;
}


static int
ef10_mcdi_vfifo_alloc(struct efhw_nic *nic, unsigned pool_id,
                      unsigned *vfifo_id_out)
{
  size_t out_size;
  int rc;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOCATE_TX_VFIFO_VFIFO_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOCATE_TX_VFIFO_VFIFO_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_VFIFO_IN_CP, pool_id);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_VFIFO_IN_EGRESS, -1);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_VFIFO_IN_SIZE, 0);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_VFIFO_IN_MODE, 1);
  EFHW_MCDI_SET_DWORD(in, ALLOCATE_TX_VFIFO_VFIFO_IN_PRIORITY, -1);

  rc = ef10_mcdi_rpc(nic, MC_CMD_ALLOCATE_TX_VFIFO_VFIFO, sizeof(in),
                     sizeof(out), &out_size, in, out);

  MCDI_CHECK(MC_CMD_ALLOCATE_TX_VFIFO_VFIFO, rc, out_size, 0);
  if (rc == 0)
    *vfifo_id_out = EFHW_MCDI_DWORD(out, ALLOCATE_TX_VFIFO_VFIFO_OUT_VID);
  return rc;
}


static int
ef10_mcdi_vfifo_free(struct efhw_nic *nic, unsigned vfifo_id)
{
  size_t out_size;
  int rc;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_TEARDOWN_TX_VFIFO_VF_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, TEARDOWN_TX_VFIFO_VF_IN_VFIFO, vfifo_id);
  rc = ef10_mcdi_rpc(nic, MC_CMD_TEARDOWN_TX_VFIFO_VF, sizeof(in), 0,
                     &out_size, in, NULL);
  MCDI_CHECK(MC_CMD_TEARDOWN_TX_VFIFO_VF, rc, out_size, 0);
  return rc;
}


static int
ef10_tx_alt_alloc(struct efhw_nic *nic, int tx_q_id, int num_alt,
                  int num_32b_words, unsigned *cp_id_out,
                  unsigned *alt_ids_out)
{
  int i, rc;

  rc = ef10_mcdi_common_pool_alloc(nic, tx_q_id, num_32b_words, num_alt,
                                   cp_id_out);
  if (rc < 0)
    goto fail1;

  for (i = 0; i < num_alt; ++i) {
    rc = ef10_mcdi_vfifo_alloc(nic, *cp_id_out, &(alt_ids_out[i]));
    if (rc < 0)
      goto fail2;
  }
  return 0;

fail2:
  while (--i >= 0)
    ef10_mcdi_vfifo_free(nic, alt_ids_out[i]);
  ef10_mcdi_common_pool_free(nic, *cp_id_out);
fail1:
  return rc;
}


static int
ef10_tx_alt_free(struct efhw_nic *nic, int num_alt, unsigned cp_id,
                 const unsigned *alt_ids)
{
  int i;
  for (i = 0; i < num_alt; ++i)
    ef10_mcdi_vfifo_free(nic, alt_ids[i]);

  ef10_mcdi_common_pool_free(nic, cp_id);
  return 0;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface - MCDI cmds
 *
 *---------------------------------------------------------------------------*/
int
ef10_mcdi_cmd_init_txq(struct efhw_nic *nic, struct efhw_dmaq_params *params,
                       int flag_timestamp, int crc_mode, int flag_tcp_udp_only,
                       int flag_tcp_csum_dis, int flag_ip_csum_dis,
                       int flag_buff_mode, int flag_pacer_bypass,
                       int flag_ctpio, int flag_ctpio_uthresh)
{
  int i;
  int rc;
  size_t outlen;
  int inner_csum = nic->devtype.arch == EFHW_ARCH_EF10 &&
                   nic->devtype.variant == 'B';
  u32 mcdi_vport_id;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_TXQ_EXT_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  rc = ef10_mcdi_vport_id(nic, params->vport_id, &mcdi_vport_id);
  if( rc < 0 )
    return rc;
  mcdi_vport_id = EVB_STACK_ID(params->stack_id) | mcdi_vport_id;

  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_SIZE, params->dmaq_size);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_TARGET_EVQ, params->evq);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_LABEL, params->tag);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_INSTANCE, params->dmaq);
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_OWNER_ID,
                      REAL_OWNER_ID(params->owner));
  EFHW_MCDI_SET_DWORD(in, INIT_TXQ_EXT_IN_PORT_ID, mcdi_vport_id);

  EFHW_MCDI_POPULATE_DWORD_11(in, INIT_TXQ_EXT_IN_FLAGS,
              INIT_TXQ_EXT_IN_FLAG_BUFF_MODE, flag_buff_mode,
              INIT_TXQ_EXT_IN_FLAG_IP_CSUM_DIS, flag_ip_csum_dis,
              INIT_TXQ_EXT_IN_FLAG_TCP_CSUM_DIS, flag_tcp_csum_dis,
              INIT_TXQ_EXT_IN_FLAG_INNER_IP_CSUM_EN, inner_csum,
              INIT_TXQ_EXT_IN_FLAG_INNER_TCP_CSUM_EN, inner_csum,
              INIT_TXQ_EXT_IN_FLAG_TCP_UDP_ONLY, flag_tcp_udp_only,
              INIT_TXQ_EXT_IN_CRC_MODE, crc_mode,
              INIT_TXQ_EXT_IN_FLAG_TIMESTAMP, flag_timestamp,
              INIT_TXQ_EXT_IN_FLAG_CTPIO, flag_ctpio,
              INIT_TXQ_EXT_IN_FLAG_CTPIO_UTHRESH, flag_ctpio_uthresh,
              INIT_TXQ_EXT_IN_FLAG_PACER_BYPASS, flag_pacer_bypass);

  for( i = 0; i < params->n_dma_addrs; i++ )
    EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_TXQ_EXT_IN_DMA_ADDR, i,
                              params->dma_addrs[i]);

  rc = ef10_mcdi_rpc(nic, MC_CMD_INIT_TXQ, MC_CMD_INIT_TXQ_EXT_IN_LEN, 0,
                     &outlen, in, NULL);

  return rc;
}


static int ps_buf_size_to_mcdi_buf_size(int ps_buf_size)
{
  switch (ps_buf_size){
    case (1 << 20):
      return MC_CMD_INIT_RXQ_EXT_IN_PS_BUFF_1M;
    case (1 << 19):
      return MC_CMD_INIT_RXQ_EXT_IN_PS_BUFF_512K;
    case (1 << 18):
      return MC_CMD_INIT_RXQ_EXT_IN_PS_BUFF_256K;
    case (1 << 17):
      return MC_CMD_INIT_RXQ_EXT_IN_PS_BUFF_128K;
    case (1 << 16):
      return MC_CMD_INIT_RXQ_EXT_IN_PS_BUFF_64K;
    default:
      return -1;
  }
}

static int
_ef10_get_ps_buf_size_mcdi(uint32_t numentries, int ps_buf_size)
{
  int ps_buf_size_mcdi;
  /* Bug45759: This should really be checked in the fw or 2048
   * should be exposed via mcdi headers. */
  if (numentries > 2048) {
    EFHW_ERR("%s: ERROR: rxq_size=%d > 2048 in packed stream mode",
             __FUNCTION__, numentries);
    return -EINVAL;
  }
  ps_buf_size_mcdi = ps_buf_size_to_mcdi_buf_size(ps_buf_size);
  if (ps_buf_size_mcdi < 0) {
    EFHW_ERR("%s: ERROR: ps_buf_size=%d is invalid", __FUNCTION__, ps_buf_size);
    return -EINVAL;
  }
  return ps_buf_size_mcdi;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
ef10_dmaq_tx_q_init(struct efhw_nic *nic, struct efhw_dmaq_params *params)
{
  int rc;
  int flag_timestamp = (params->flags & EFHW_VI_TX_TIMESTAMPS) != 0;
  int flag_tcp_udp_only = (params->flags & EFHW_VI_TX_TCPUDP_ONLY) != 0;
  int flag_tcp_csum_dis = (params->flags & EFHW_VI_TX_TCPUDP_CSUM_DIS) != 0;
  int flag_ip_csum_dis = (params->flags & EFHW_VI_TX_IP_CSUM_DIS) != 0;
  int flag_buff_mode = (params->flags & EFHW_VI_TX_PHYS_ADDR_EN) == 0;
  int flag_loopback = (params->flags & EFHW_VI_TX_LOOPBACK) != 0;
  int flag_ctpio = (params->flags & EFHW_VI_TX_CTPIO) != 0;
  int flag_ctpio_uthresh = (params->flags & EFHW_VI_TX_CTPIO_NO_POISON) == 0;
  int flag_pacer_bypass;

  if (nic->flags & NIC_FLAG_MCAST_LOOP_HW) {
    rc = _ef10_mcdi_cmd_enable_multicast_loopback(nic, params->dmaq,
                                                  flag_loopback);
    if(rc != 0) {
      /* We are graceful in case there is firmware with incomplete support as
       * well as in case we have no permissions e.g. with VF.  We just
       * hope the current configuration is right. */
      if (flag_loopback || (rc != -ENOSYS && rc != -EPERM))
        return rc;
    }
  }

  /* Pre-Medford 2 NICs will ignore the CTPIO-request bit and the call to
   * MC_CMD_INIT_TXQ will succeed, so force failure here ourselves. */
  if (flag_ctpio && ~nic->flags & NIC_FLAG_TX_CTPIO)
    return -EOPNOTSUPP;

  if (flag_loopback) {
    if (nic->flags & NIC_FLAG_MCAST_LOOP_HW) {
      rc = _ef10_set_multicast_loopback_suppression(nic, 1, params->vport_id,
                                                    params->stack_id);
      if (rc == -EPERM) {
        /* Few notes:
         *
         * 1. This setting is not essential.  It might increase performance in
         *    some cases.
         * 2. We might have no permissions to enable or disable loopback
         *    suppression, typically true for VF.
         * 3. loopback suppression is a vadapter setting and might require
         *    differentpermissions than enable_multicast_loopback.
         * 4. In some modes (e.g. VF passthrough) the setting is enabled by
         *    default, however there is no way to verify that.
         */
        EFHW_WARN("%s: WARNING: failed to adjust loopback suppression, "
                  "continuing with default setting", __FUNCTION__);
      }
      else if( rc != 0 ) {
        return rc;
      }
    }
  }

  /* No option for pacer bypass yet, but we want it on as it cuts latency.
   * This might not work in some cases due to permissions (e.g. VF),
   * if so we retry without it. */
  for (flag_pacer_bypass = 1; 1; flag_pacer_bypass = 0) {
    rc = ef10_mcdi_cmd_init_txq(nic, params, flag_timestamp,
                                QUEUE_CRC_MODE_NONE, flag_tcp_udp_only,
                                flag_tcp_csum_dis, flag_ip_csum_dis,
                                flag_buff_mode, flag_pacer_bypass, flag_ctpio,
                                flag_ctpio_uthresh);
    if ((rc != -EPERM) || (!flag_pacer_bypass))
      break;
  }

  if ((rc == 0) && !flag_pacer_bypass) {
    EFHW_WARN("%s: WARNING: failed to enable pacer bypass, "
              "continuing without it", __FUNCTION__);
  }

  if (rc == -EOPNOTSUPP)
    rc = -ENOKEY;

  if (rc == 0)
    params->qid_out = params->dmaq;

  return rc;
}


static int 
ef10_dmaq_rx_q_init(struct efhw_nic *nic, struct efhw_dmaq_params *params)
{
  int i;
  int rc;
  int flag_rx_prefix = (params->flags & EFHW_VI_RX_PREFIX) ? 1 : 0;
  int flag_timestamp = (params->flags & EFHW_VI_RX_TIMESTAMPS) ? 1 : 0;
  int flag_hdr_split = (params->flags & EFHW_VI_RX_HDR_SPLIT) ? 1 : 0;
  int flag_buff_mode = (params->flags & EFHW_VI_RX_PHYS_ADDR_EN) ? 0 : 1;
  int flag_packed_stream = (params->flags & EFHW_VI_RX_PACKED_STREAM)  ? 1 : 0;
  int flag_force_rx_merge = (params->flags & EFHW_VI_NO_RX_CUT_THROUGH) &&
                       (nic->flags & NIC_FLAG_RX_FORCE_EVENT_MERGING) ? 1 : 0;
  int flag_enable_tph = (params->flags & EFHW_VI_ENABLE_TPH) != 0;
  int flag_tph_tag_mode = (params->flags & EFHW_VI_TPH_TAG_MODE) != 0;
  int ps_buf_size_mcdi = 0;
  int dma_mode = MC_CMD_INIT_RXQ_EXT_IN_SINGLE_PACKET;
  size_t outlen;
  u32 mcdi_vport_id;

  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_INIT_RXQ_V4_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  if (flag_packed_stream) {
    if (!(nic->flags & NIC_FLAG_PACKED_STREAM))
      return -EOPNOTSUPP;
    if ((params->rx.ps_buf_size != (1<<20)
        && !(nic->flags & NIC_FLAG_VAR_PACKED_STREAM)))
      return -EOPNOTSUPP;

    dma_mode = MC_CMD_INIT_RXQ_EXT_IN_PACKED_STREAM;
    rc = _ef10_get_ps_buf_size_mcdi(params->dmaq_size, params->rx.ps_buf_size);
    if( rc < 0 )
      return rc;
    ps_buf_size_mcdi = rc;
  }

  rc = ef10_mcdi_vport_id(nic, params->vport_id, &mcdi_vport_id);
  if( rc < 0 )
    return rc;
  mcdi_vport_id = EVB_STACK_ID(params->stack_id) | mcdi_vport_id;

  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V4_IN_SIZE, params->dmaq_size);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V4_IN_TARGET_EVQ, params->evq);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V4_IN_LABEL, params->tag);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V4_IN_INSTANCE, params->dmaq);
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V4_IN_OWNER_ID,
                      REAL_OWNER_ID(params->owner));
  EFHW_MCDI_SET_DWORD(in, INIT_RXQ_V4_IN_PORT_ID, mcdi_vport_id);

  EFHW_MCDI_POPULATE_DWORD_8(in, INIT_RXQ_V4_IN_FLAGS,
              INIT_RXQ_V4_IN_FLAG_BUFF_MODE, flag_buff_mode,
              INIT_RXQ_V4_IN_FLAG_HDR_SPLIT, flag_hdr_split,
              INIT_RXQ_V4_IN_FLAG_TIMESTAMP, flag_timestamp,
              INIT_RXQ_V4_IN_FLAG_PREFIX, flag_rx_prefix,
              INIT_RXQ_V4_IN_CRC_MODE, QUEUE_CRC_MODE_NONE,
              INIT_RXQ_V4_IN_DMA_MODE, dma_mode,
              INIT_RXQ_V4_IN_PACKED_STREAM_BUFF_SIZE, ps_buf_size_mcdi,
              INIT_RXQ_V4_IN_FLAG_FORCE_EV_MERGING, flag_force_rx_merge);

  for( i = 0; i < params->n_dma_addrs; i++ )
    EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_RXQ_V4_IN_DMA_ADDR, i,
                              params->dma_addrs[i]);

  rc = ef10_mcdi_rpc(nic, MC_CMD_INIT_RXQ, MC_CMD_INIT_RXQ_V4_IN_LEN,
                     MC_CMD_INIT_RXQ_V4_OUT_LEN, &outlen, in, NULL);

  /* Always set TPH steering even if flag_enable_tph == 0 to clear
   * previous state. */
  if( rc == 0 )
    efhw_set_tph_steering(nic, params->evq, flag_enable_tph, flag_tph_tag_mode);

  if( rc == 0 )
    params->qid_out = params->dmaq;

  return rc == 0 ? flag_rx_prefix ? nic->rx_prefix_len : 0 : rc;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_fini_rxq(struct efhw_nic *nic, uint32_t instance)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_RXQ_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FINI_RXQ_IN_INSTANCE, instance);

  rc = ef10_mcdi_rpc(nic, MC_CMD_FINI_RXQ, MC_CMD_FINI_RXQ_IN_LEN, 0,
                     &out_size, in, NULL);
  MCDI_CHECK(MC_CMD_FINI_RXQ, rc, out_size, 0);
  return rc;
}


static int
_ef10_mcdi_cmd_fini_txq(struct efhw_nic *nic, uint32_t instance)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_TXQ_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FINI_TXQ_IN_INSTANCE, instance);

  rc = ef10_mcdi_rpc(nic, MC_CMD_FINI_TXQ, MC_CMD_FINI_TXQ_IN_LEN, 0,
                     &out_size, in, NULL);
  MCDI_CHECK(MC_CMD_FINI_TXQ, rc, out_size, 0);
  return rc;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


int ef10_flush_tx_dma_channel(struct efhw_nic *nic, uint dmaq, uint evq)
{
  return _ef10_mcdi_cmd_fini_txq(nic, dmaq);
}


int ef10_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
  return _ef10_mcdi_cmd_fini_rxq(nic, dmaq);
}


/*--------------------------------------------------------------------
 *
 * Buffer table - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static int
_ef10_mcdi_cmd_buffer_table_alloc(struct efhw_nic *nic, int page_size,
                                  int owner_id, int *btb_index,
                                  int *numentries, efhw_btb_handle *handle)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOC_BUFTBL_CHUNK_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOC_BUFTBL_CHUNK_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, ALLOC_BUFTBL_CHUNK_IN_OWNER, owner_id);
  EFHW_MCDI_SET_DWORD(in, ALLOC_BUFTBL_CHUNK_IN_PAGE_SIZE, page_size);

  rc = ef10_mcdi_rpc(nic, MC_CMD_ALLOC_BUFTBL_CHUNK, sizeof(in), sizeof(out),
                     &out_size, in, out);
  MCDI_CHECK(MC_CMD_ALLOC_BUFTBL_CHUNK, rc, out_size, 1);
  if ( rc != 0 )
    return rc;

  *btb_index = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_ID);
  *numentries = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_NUMENTRIES);
  *handle = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_HANDLE);
  return rc;
}


static void
_ef10_mcdi_cmd_buffer_table_free(struct efhw_nic *nic, efhw_btb_handle handle)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FREE_BUFTBL_CHUNK_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_SET_DWORD(in, FREE_BUFTBL_CHUNK_IN_HANDLE, handle);

  rc = ef10_mcdi_rpc(nic, MC_CMD_FREE_BUFTBL_CHUNK, sizeof(in), 0, &out_size,
                     in, NULL);
  MCDI_CHECK(MC_CMD_FREE_BUFTBL_CHUNK, rc, out_size, 1);
}


static int
_ef10_mcdi_cmd_buffer_table_program(struct efhw_nic *nic,
                                    dma_addr_t *dma_addrs, int n_entries,
                                    int first_entry, efhw_btb_handle handle)
{
  /* chip_src uses eftest_func_dma_to_dma48_addr() to convert
  * the dma addresses.  Do I need to do something similar?
  */
  int i, rc;
  size_t out_size;
  size_t in_size = MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_LEN(n_entries);
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_LEN(
                              MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM));
  EFHW_MCDI_INITIALISE_BUF_SIZE(in, in_size);

  EFHW_ASSERT(n_entries <= MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM);

  EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_HANDLE, handle);
  EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_FIRSTID, first_entry);
  EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_NUMENTRIES, n_entries);

  if (n_entries > MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM) {
    EFHW_ERR("%s: n_entries (%d) cannot be greater than "
             "MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM (%d)",
             __FUNCTION__, n_entries,
             MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM);
    return -EINVAL;
  }

  for (i = 0; i < n_entries; ++i)
    EFHW_MCDI_SET_ARRAY_QWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_ENTRY, i,
                              dma_addrs[i]);

  rc = ef10_mcdi_rpc(nic, MC_CMD_PROGRAM_BUFTBL_ENTRIES, in_size, 0, &out_size,
                     in, NULL);
  MCDI_CHECK(MC_CMD_PROGRAM_BUFTBL_ENTRIES, rc, out_size, 1);
  return rc;
}


/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int ef10_nic_buffer_table_orders[] = {0,4,8,10};

static int __ef10_nic_buffer_table_alloc(struct efhw_nic *nic, int owner,
                                         int order,
                                         struct efhw_buffer_table_block *block)
{
  int numentries = 0, rc, btb_index = 0;

  rc = _ef10_mcdi_cmd_buffer_table_alloc(nic, EFHW_NIC_PAGE_SIZE << order,
                                         owner, &btb_index, &numentries,
                                         &block->btb_hw.ef10.handle);

  /* Initialise the software state even if MCDI failed, so that we can
   * retry the MCDI call at some point in the future. */
  if (rc != 0)
    return rc;
  if (numentries != 32) {
    EFHW_ERR("%s: _ef10_ef100_mcdi_cmd_buffer_table_alloc expected 32"
             " but allocated %d entries", __FUNCTION__, numentries);
    return -EINVAL;
  }

  block->btb_vaddr = EF10_BUF_ID_ORDER_2_VADDR(btb_index, order);

  return 0;
}


static int
ef10_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
                            struct efhw_buffer_table_block **block_out,
                            int reset_pending)
{
  int rc = 0;
  struct efhw_buffer_table_block *block;

  block = kmalloc(sizeof(*block), GFP_KERNEL);
  if (block == NULL)
  return -ENOMEM;

  memset(block, 0, sizeof(*block));

  /* [reset_pending] indicates that the caller's hardware state is going
  * to be reallocated.  In that case, we don't want to allocate from the
  * HW now as that state would be leaked when the reallocation happens.
  * Instead, we just return the software block to the caller as if the
  * allocation had actually happened, and then the reallocation will
  * take care of things in due course. */
  if (! reset_pending) {
    rc = __ef10_nic_buffer_table_alloc(nic, REAL_OWNER_ID(owner), order, block);
    /* ENETDOWN indicates absent hardware. In this case we should
     * keep the software state, although we propagate the failure
     * out of the efhw layer. */
    if (rc != 0 && rc != -ENETDOWN) {
      kfree(block);
      return rc;
    }
  }

  *block_out = block;
  return rc;
}


static int
ef10_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
                              struct efhw_buffer_table_block *block)
{
  return __ef10_nic_buffer_table_alloc(nic, REAL_OWNER_ID(owner), order,
                                       block);
}


static void
ef10_nic_buffer_table_free(struct efhw_nic *nic,
                           struct efhw_buffer_table_block *block,
                           int reset_pending)
{
  if (! reset_pending) {
    _ef10_mcdi_cmd_buffer_table_free(nic, block->btb_hw.ef10.handle);
  }
  kfree(block);
}


static int
__ef10_nic_buffer_table_set(struct efhw_nic *nic,
                            struct efhw_buffer_table_block *block,
                            int first_entry, int n_entries,
                            dma_addr_t *dma_addrs)
{
  int i, rc, batch;
  i = 0;
  while (i < n_entries) {
    batch = n_entries - i < MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM ?
            n_entries - i : MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM;
    rc = _ef10_mcdi_cmd_buffer_table_program(nic, dma_addrs + i, batch,
                                             first_entry + i,
                                             block->btb_hw.ef10.handle);
    if (rc != 0)
      /* XXX: unprogram entries already made.  Not
       * bothering for now as all current callers do
       * not handle error anyways. */
      return rc;

    i += batch;
  }
  return 0;
}


static int
ef10_nic_buffer_table_set(struct efhw_nic *nic,
                          struct efhw_buffer_table_block *block,
                          int first_entry, int n_entries,
                          dma_addr_t *dma_addrs)
{
  int rc;
  int buffer_id = EF10_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;

  rc = __ef10_nic_buffer_table_set(nic, block, buffer_id, n_entries,
                                   dma_addrs);
  EFHW_DO_DEBUG(
  if (rc == 0)
    efhw_buffer_table_set_debug(block, first_entry, n_entries)
  );
  return rc;
}


static void
ef10_nic_buffer_table_clear(struct efhw_nic *nic,
                            struct efhw_buffer_table_block *block,
                            int first_entry, int n_entries)
{
  int rc;
  int buffer_id = EF10_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;
  dma_addr_t null_addrs[MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM];

  memset(null_addrs, 0, sizeof(null_addrs));
  rc = __ef10_nic_buffer_table_set(nic, block, buffer_id, n_entries,
                                   null_addrs);
  EFHW_DO_DEBUG(efhw_buffer_table_clear_debug(block, first_entry, n_entries));
}


/*--------------------------------------------------------------------
 *
 * PIO mgmt
 *
 *--------------------------------------------------------------------*/

static int ef10_nic_piobuf_alloc(struct efhw_nic *nic, unsigned *handle_out)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOC_PIOBUF_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOC_PIOBUF_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  rc = ef10_mcdi_rpc(nic, MC_CMD_ALLOC_PIOBUF,
  sizeof(in), sizeof(out), &out_size, in, out);
  if ( rc != 0 )
  return rc;

  *handle_out = EFHW_MCDI_DWORD(out, ALLOC_PIOBUF_OUT_PIOBUF_HANDLE);
  return rc;
}


static int ef10_nic_piobuf_free(struct efhw_nic *nic, unsigned handle)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FREE_PIOBUF_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_FREE_PIOBUF_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, FREE_PIOBUF_IN_PIOBUF_HANDLE, handle);

  rc = ef10_mcdi_rpc(nic, MC_CMD_FREE_PIOBUF, sizeof(in), sizeof(out),
                     &out_size, in, out);
  return rc;
}


static int ef10_nic_piobuf_link(struct efhw_nic *nic, unsigned txq, unsigned handle)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_LINK_PIOBUF_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_LINK_PIOBUF_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, LINK_PIOBUF_IN_PIOBUF_HANDLE, handle);
  EFHW_MCDI_SET_DWORD(in, LINK_PIOBUF_IN_TXQ_INSTANCE, txq);

  rc = ef10_mcdi_rpc(nic, MC_CMD_LINK_PIOBUF, sizeof(in), sizeof(out),
                     &out_size, in, out);
  return rc;
}


static int ef10_nic_piobuf_unlink(struct efhw_nic *nic, unsigned txq)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_UNLINK_PIOBUF_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_UNLINK_PIOBUF_OUT_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  EFHW_MCDI_SET_DWORD(in, UNLINK_PIOBUF_IN_TXQ_INSTANCE, txq);

  rc = ef10_mcdi_rpc(nic, MC_CMD_UNLINK_PIOBUF, sizeof(in), sizeof(out),
                     &out_size, in, out);
  return rc;
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

static int
ef10_nic_set_tx_port_sniff(struct efhw_nic *nic, int instance, int enable,
                           int rss_context)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_CONTEXT, rss_context);
  EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE,
                      rss_context == -1 ?
                      MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE_SIMPLE :
                      MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE_RSS);
  EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_QUEUE, instance);
  EFHW_MCDI_POPULATE_DWORD_1(in, SET_TX_PORT_SNIFF_CONFIG_IN_FLAGS,
                      SET_TX_PORT_SNIFF_CONFIG_IN_ENABLE, enable ? 1 : 0);

  rc = ef10_mcdi_rpc(nic, MC_CMD_SET_TX_PORT_SNIFF_CONFIG, sizeof(in), 0,
                     &out_size, in, NULL);
  return rc;
}


static int
ef10_nic_set_port_sniff(struct efhw_nic *nic, int instance, int enable,
			int promiscuous, int rss_context)
{
  int rc;
  size_t out_size;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_SET_PORT_SNIFF_CONFIG_IN_LEN);
  EFHW_MCDI_INITIALISE_BUF(in);

  EFHW_MCDI_POPULATE_DWORD_2(in, SET_PORT_SNIFF_CONFIG_IN_FLAGS,
                   SET_PORT_SNIFF_CONFIG_IN_ENABLE, enable ? 1 : 0,
                   SET_PORT_SNIFF_CONFIG_IN_PROMISCUOUS, promiscuous ? 1 : 0);
  EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_QUEUE, instance);
  EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_MODE, rss_context == -1 ?
                               MC_CMD_SET_PORT_SNIFF_CONFIG_IN_RX_MODE_SIMPLE :
                               MC_CMD_SET_PORT_SNIFF_CONFIG_IN_RX_MODE_RSS);
  EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_CONTEXT, rss_context);

  rc = ef10_mcdi_rpc(nic, MC_CMD_SET_PORT_SNIFF_CONFIG, sizeof(in), 0,
                     &out_size, in, NULL);
  return rc;
}


/*--------------------------------------------------------------------
 *
 * Port Sniff
 *
 *--------------------------------------------------------------------*/

static int
ef10_get_rx_error_stats(struct efhw_nic *nic, int instance,
                        void *data, int data_len, int do_reset)
{
  int rc;
  int flags = 0;
  EFHW_MCDI_DECLARE_BUF(in, MC_CMD_RMON_STATS_RX_ERRORS_IN_LEN);
  EFHW_MCDI_DECLARE_BUF(out, MC_CMD_RMON_STATS_RX_ERRORS_OUT_LEN);
  size_t out_size = sizeof(out);
  uint32_t* data_out = data;

  EFHW_MCDI_INITIALISE_BUF(in);
  EFHW_MCDI_INITIALISE_BUF(out);

  if (data_len != sizeof(*data_out) * 4)
    return -EINVAL;

  EFHW_MCDI_SET_DWORD(in, RMON_STATS_RX_ERRORS_IN_RX_QUEUE, instance);
  if (do_reset)
    flags = 1 << MC_CMD_RMON_STATS_RX_ERRORS_IN_RST_LBN;
  EFHW_MCDI_SET_DWORD(in, RMON_STATS_RX_ERRORS_IN_FLAGS, flags);

  rc = ef10_mcdi_rpc(nic, MC_CMD_RMON_STATS_RX_ERRORS, sizeof(in),
                     out_size, &out_size, in, out);

  if (rc != 0)
    return rc;

  /* the following layout is used in lib/ciul/vi_stats.c */
  data_out[0] = EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_CRC_ERRORS);
  data_out[1] = EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_TRUNC_ERRORS);
  data_out[2] = EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_RX_NO_DESC_DROPS);
  data_out[3] = EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_RX_ABORT);
  return rc;
}


/*--------------------------------------------------------------------
 *
 * Filtering
 *
 *--------------------------------------------------------------------*/


static int
ef10_rss_flags(struct efhw_nic *nic, u32 *flags_out)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  union efx_auxiliary_param_value val;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->base_ops->get_param(cli, EFX_RXFH_DEFAULT_FLAGS,
                                               &val);
  AUX_POST(dev, auxdev, cli, nic, rc);

  if( rc == 0 )
    *flags_out = val.value;

  return rc;
}


static int
ef10_rss_mode_to_nic_flags(struct efhw_nic *efhw_nic, u32 rss_mode,
                           u32 *flags_out)
{
  int rc;
  u32 rss_flags = 0;
  u32 nic_tcp_mode;
  u32 nic_src_mode = (1 << RSS_MODE_HASH_SRC_ADDR_LBN) |
                     (1 << RSS_MODE_HASH_SRC_PORT_LBN);
  u32 nic_dst_mode = (1 << RSS_MODE_HASH_DST_ADDR_LBN) |
                     (1 << RSS_MODE_HASH_DST_PORT_LBN);
  u32 nic_all_mode = nic_src_mode | nic_dst_mode;
  ci_dword_t nic_flags_new;
  ci_dword_t nic_flags_mask;

  rc = ef10_rss_flags(efhw_nic, &rss_flags);
  if( rc < 0 )
    return rc;

   /* we need to use default flags in packed stream mode,
    * note in that case TCP hashing will surely be enabled,
    * so nothing to do there anyway */
  if( efhw_nic->flags & NIC_FLAG_RX_RSS_LIMITED ) {
    *flags_out = rss_flags;
    return 0;
  }

  switch(rss_mode) {
    case EFHW_RSS_MODE_SRC:
      nic_tcp_mode = nic_src_mode;
      break;
    case EFHW_RSS_MODE_DST:
      nic_tcp_mode = nic_dst_mode;
      break;
    case EFHW_RSS_MODE_DEFAULT:
      nic_tcp_mode = nic_all_mode;
      break;
    default:
      EFHW_ASSERT(!"Unknown rss mode");
      return -EINVAL;
  };

  CI_POPULATE_DWORD_2(nic_flags_mask,
       MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_TCPV4_EN,
       (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_IPV4_EN_WIDTH) - 1,
       MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE,
       ( efhw_nic->flags & NIC_FLAG_ADDITIONAL_RSS_MODES ) ?
       (1 << MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE_WIDTH) - 1 : 0);
  CI_POPULATE_DWORD_2(nic_flags_new,
       MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TOEPLITZ_TCPV4_EN, 1,
       MC_CMD_RSS_CONTEXT_SET_FLAGS_IN_TCP_IPV4_RSS_MODE, nic_tcp_mode);
   EFHW_ASSERT((nic_flags_new.u32[0] & nic_flags_mask.u32[0]) ==
               nic_flags_new.u32[0]);
  *flags_out = (rss_flags & ~nic_flags_mask.u32[0]) | nic_flags_new.u32[0];
  return 0;
}


static int
ef10_set_rss_mode(struct efhw_nic *nic, u32 context, u32 mode)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  u32 nic_rss_flags;

  rc = ef10_rss_mode_to_nic_flags(nic, mode, &nic_rss_flags);
  if (rc < 0)
    return rc;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->set_rxfh_flags(cli, context, nic_rss_flags);
  AUX_POST(dev, auxdev, cli, nic, rc);

  return rc;
}

static int
ef10_rss_alloc(struct efhw_nic *nic, const u32 *indir, const u8 *key,
               u32 efhw_rss_mode, int num_qs, u32 *rss_context_out)
{
  int rc;
  int fail_rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  struct ethtool_rxfh_param params = { 0 };

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->create_rxfh_context(cli, &params, num_qs);
  AUX_POST(dev, auxdev, cli, nic, rc);
  if( rc < 0 ) {
    fail_rc = rc;
    goto fail;
  }

  params.key = (u8*)key;
  params.key_size = nic->rss_key_size;
  params.indir = (u32*)indir;
  params.indir_size = nic->rss_indir_size;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->modify_rxfh_context(cli, &params);
  AUX_POST(dev, auxdev, cli, nic, rc);
  if( rc < 0 ) {
    fail_rc = rc;
    goto fail_free_context;
  }

  rc = ef10_set_rss_mode(nic, params.rss_context, efhw_rss_mode);
  if( rc < 0 ) {
    fail_rc = rc;
    goto fail_free_context;
  }

  *rss_context_out = params.rss_context;
  return rc;

 fail_free_context:
  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->remove_rxfh_context(cli, &params);
  AUX_POST(dev, auxdev, cli, nic, rc);
 fail:

  return fail_rc;
}


static int
ef10_rss_free(struct efhw_nic *nic, u32 rss_context)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  struct ethtool_rxfh_param params = { .rss_context = rss_context };

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->remove_rxfh_context(cli, &params);
  AUX_POST(dev, auxdev, cli, nic, rc);

  return rc;
}


static int
ef10_filter_insert(struct efhw_nic *nic, struct efx_filter_spec *spec,
                   int *rxq, unsigned pd_excl_token,
                   const struct cpumask *mask, unsigned flags)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->filter_insert(cli, spec,
                                  (flags & EFHW_FILTER_F_REPLACE) != 0);
  AUX_POST(dev, auxdev, cli, nic, rc);

  return rc;
}

static void
ef10_filter_remove(struct efhw_nic *nic, int filter_id)
{
  int rc;
  struct device *dev = efhw_nic_get_dev(nic);
  struct efx_auxdev *auxdev = to_efx_auxdev(to_auxiliary_dev(dev));
  struct efx_auxdev_client *cli = efhw_nic_acquire_auxdev(nic);

  /* Note: We do not use AUX_PRE/AUX_POST here as we do with other filter
   * operations. The filter_remove operation in the net driver has some
   * additional logic to handle removing a filter during a reset which we rely
   * on. */
  if( auxdev != NULL ) {
    rc = auxdev->onload_ops->filter_remove(cli, filter_id);

    efhw_nic_release_auxdev(nic, cli);
  }
  /* If [auxdev] is NULL, the hardware is morally absent and so there's
   * nothing to do. */
  put_device(dev);
}

static int
ef10_filter_redirect(struct efhw_nic *nic, int filter_id,
                     struct efx_filter_spec *spec)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  int stack_id = spec->flags & EFX_FILTER_FLAG_STACK_ID ?  spec->stack_id : 0;
  /* If the RSS flag is not set we can pass NULL to indicate that we don't
   * want a context, otherwise use the value from the spec. */
  unsigned *rss_context = (spec->flags & EFX_FILTER_FLAG_RX_RSS ) ?
                           &spec->rss_context : NULL;


  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->filter_redirect(cli, filter_id, spec->dmaq_id,
                                    rss_context, stack_id);
  AUX_POST(dev, auxdev, cli, nic, rc);

  return rc;
}

static int
ef10_filter_query(struct efhw_nic *nic, int filter_id,
                  struct efhw_filter_info *info)
{
  return -EOPNOTSUPP;
}

static int ef10_multicast_block(struct efhw_nic *nic, bool block)
{
  int rc = 0;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  union efx_auxiliary_param_value val = { .b = block };

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->base_ops->set_param(cli,
      EFX_PARAM_FILTER_BLOCK_KERNEL_MCAST, &val);
  AUX_POST(dev, auxdev, cli, nic, rc);
  return rc;
}

static int ef10_unicast_block(struct efhw_nic *nic, bool block)
{
  int rc = 0;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;
  union efx_auxiliary_param_value val = { .b = block };

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->base_ops->set_param(cli,
      EFX_PARAM_FILTER_BLOCK_KERNEL_UCAST, &val);
  AUX_POST(dev, auxdev, cli, nic, rc);
  return rc;
}

/*--------------------------------------------------------------------
 *
 * vports
 *
 *--------------------------------------------------------------------*/
static int ef10_vport_alloc(struct efhw_nic *nic, u16 vlan_id,
		            u16 *vport_handle_out)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->vport_new(cli, vlan_id, 0);
  AUX_POST(dev, auxdev, cli, nic, rc);

  if( rc >= 0 ) {
    *vport_handle_out = rc;
    rc = 0;
  }

  return rc;
}

static int ef10_vport_free(struct efhw_nic *nic, u16 vport_handle)
{
  int rc;
  struct device *dev;
  struct efx_auxdev *auxdev;
  struct efx_auxdev_client *cli;

  AUX_PRE(dev, auxdev, cli, nic, rc);
  rc = auxdev->onload_ops->vport_free(cli, vport_handle);
  AUX_POST(dev, auxdev, cli, nic, rc);

  return rc;
}
 

/*--------------------------------------------------------------------
 *
 * Device
 *
 *--------------------------------------------------------------------*/
struct pci_dev* ef10_get_pci_dev(struct efhw_nic* nic)
{
  struct pci_dev* dev = NULL;
  spin_lock_bh(&nic->pci_dev_lock);
  if( nic->dev && nic->pci_dev ) {
    dev = nic->pci_dev;
    pci_dev_get(dev);
  }
  spin_unlock_bh(&nic->pci_dev_lock);
  return dev;
}

static int ef10_vi_io_region(struct efhw_nic* nic, int instance,
                             size_t* size_out, resource_size_t* addr_out)
{
  unsigned vi_stride = nic->vi_stride;

  /* If the page size was bigger than the VI window we'd have to map
   * multiple VI windows at a time, meaning that the window for a
   * specific VI would be at an offset within the mapping, needing
   * special handling. That handling doesn't exist, so grumble if we're
   * building on an arch where this would be a problem. */
  CI_BUILD_ASSERT(PAGE_SIZE <= ER_DZ_EVQ_TMR_REG_STEP);

  /* We are claiming that only one page needs to be mapped. This is less
   * than the full window, but it contains everything we're interested
   * in. */
  *size_out = CI_PAGE_SIZE;

  /* We say that we only needed one page for the IO mapping so check
   * that the registers we're interested in fall within a page. */
  EFHW_ASSERT(ef10_tx_dma_page_offset(vi_stride, instance) < CI_PAGE_SIZE);
  EFHW_ASSERT(ef10_rx_dma_page_offset(vi_stride, instance) < CI_PAGE_SIZE);
  EFHW_ASSERT(ef10_tx_dma_page_base(vi_stride, instance) ==
              ef10_rx_dma_page_base(vi_stride, instance));

  *addr_out = nic->ctr_ap_addr + ef10_tx_dma_page_base(vi_stride, instance);

  return 0;
}

/*--------------------------------------------------------------------
 *
 * CTPIO
 *
 *--------------------------------------------------------------------*/
static int ef10_ctpio_addr(struct efhw_nic* nic, int instance,
                           resource_size_t* addr)
{
  const size_t VI_WINDOW_CTPIO_OFFSET = 12*1024;
  resource_size_t bar_off;
  bar_off = ef10_tx_dma_page_base(nic->vi_stride, instance);
  bar_off += VI_WINDOW_CTPIO_OFFSET;
  *addr = nic->ctr_ap_addr + bar_off;
  return 0;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops ef10aux_char_functional_units = {
	.sw_ctor = ef10_nic_sw_ctor,
	.sw_dtor = ef10_nic_sw_dtor,
	.init_hardware = ef10_nic_init_hardware,
	.post_reset = ef10_nic_tweak_hardware,
	.release_hardware = ef10_nic_release_hardware,
	.event_queue_enable = ef10_nic_event_queue_enable,
	.event_queue_disable = ef10_nic_event_queue_disable,
	.evq_requires_time_sync = ef10_nic_evq_requires_time_sync,
	.wakeup_request = ef10_nic_wakeup_request,
	.sw_event = ef10_nic_sw_event,
	.handle_event = ef10_handle_event,
	.vi_alloc = ef10_vi_alloc,
	.vi_free = ef10_vi_free,
	.dmaq_tx_q_init = ef10_dmaq_tx_q_init,
	.dmaq_rx_q_init = ef10_dmaq_rx_q_init,
	.flush_tx_dma_channel = ef10_flush_tx_dma_channel,
	.flush_rx_dma_channel = ef10_flush_rx_dma_channel,
	.buffer_table_orders = ef10_nic_buffer_table_orders,
	.buffer_table_orders_num = CI_ARRAY_SIZE(ef10_nic_buffer_table_orders),
	.buffer_table_alloc = ef10_nic_buffer_table_alloc,
	.buffer_table_realloc = ef10_nic_buffer_table_realloc,
	.buffer_table_free = ef10_nic_buffer_table_free,
	.buffer_table_set = ef10_nic_buffer_table_set,
	.buffer_table_clear = ef10_nic_buffer_table_clear,
	.set_port_sniff = ef10_nic_set_port_sniff,
	.set_tx_port_sniff = ef10_nic_set_tx_port_sniff,
	.get_rx_error_stats = ef10_get_rx_error_stats,
	.tx_alt_alloc = ef10_tx_alt_alloc,
	.tx_alt_free = ef10_tx_alt_free,
	.rss_alloc = ef10_rss_alloc,
	.rss_free = ef10_rss_free,
	.filter_insert = ef10_filter_insert,
	.filter_remove = ef10_filter_remove,
	.filter_redirect = ef10_filter_redirect,
	.filter_query = ef10_filter_query,
	.multicast_block = ef10_multicast_block,
	.unicast_block = ef10_unicast_block,
	.vport_alloc = ef10_vport_alloc,
	.vport_free = ef10_vport_free,
	.get_pci_dev = ef10_get_pci_dev,
	.vi_io_region = ef10_vi_io_region,
	.inject_reset_ev = ef10_inject_reset_ev,
	.ctpio_addr = ef10_ctpio_addr,
	.piobuf_alloc = ef10_nic_piobuf_alloc,
	.piobuf_free = ef10_nic_piobuf_free,
	.piobuf_link = ef10_nic_piobuf_link,
	.piobuf_unlink = ef10_nic_piobuf_unlink,
	.set_vi_tlp_processing = ef10_mcdi_cmd_set_vi_tlp_processing,
};
