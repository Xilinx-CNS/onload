/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2012-2020 Xilinx, Inc. */
/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains EF10 hardware support.
 *
 * Copyright 2005-2008: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
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

#include <ci/driver/efab/hardware.h>
#include <ci/efhw/debug.h>
#include <ci/efhw/iopage.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>
#include <ci/efhw/checks.h>
#include <ci/efhw/efhw_buftable.h>

#include <ci/driver/driverlink_api.h>

#include <ci/efhw/ef10.h>
#include <ci/efhw/mc_driver_pcol.h>
#include "ef10_mcdi.h"


int force_ev_timer = 1;
module_param(force_ev_timer, int, S_IRUGO);
MODULE_PARM_DESC(force_ev_timer,
                 "Set to 0 to avoid forcing allocation of event timer with wakeup queue");


/*----------------------------------------------------------------------------
 *
 * Helper for MCDI operations
 *
 *---------------------------------------------------------------------------*/

int ef10_ef100_mcdi_rpc(struct efhw_nic *nic, unsigned int cmd,
			size_t inlen, size_t outlen, size_t *outlen_actual,
			const void *inbuf, void *outbuf)
{
	int rc;
	struct efx_dl_device *efx_dev = efhw_nic_acquire_dl_device(nic);

	EFHW_ASSERT(!in_atomic());

	/* [nic->resetting] means we have detected that we are in a reset.
	 * There is potentially a period after [nic->resetting] is cleared
	 * but before driverlink is re-enabled, during which time [efx_dev]
	 * will be NULL. */
	if (nic->resetting || efx_dev == NULL) {
		if (outlen == 0) {
			/* user should not handle any errors */
			*outlen_actual = 0;
			rc = 0;
		}
		else {
			rc = -ENETDOWN;
		}
	}
	else {
		/* Driverlink handle is valid and we're not resetting, so issue
		 * the MCDI call. */

		rc = efx_dl_mcdi_rpc(efx_dev, cmd, inlen, outlen,
				     outlen_actual, (const u8*) inbuf,
				     (u8*) outbuf);

		/* If we see ENETDOWN here, we must be in the window between
		 * hardware being removed and being informed about this fact by
		 * the kernel. */
		if (rc == -ENETDOWN)
			ci_atomic32_or(&nic->resetting,
				       NIC_RESETTING_FLAG_VANISHED);
	}

	/* This is safe even if [efx_dev] is NULL. */
	efhw_nic_release_dl_device(nic, efx_dev);

	return rc;
}


void
ef10_ef100_mcdi_check_response(const char* caller, const char* failed_cmd,
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
			EFHW_ERR_LIMITED("%s: %s failed rc=%d",
					 caller, failed_cmd, rc);
		else
			EFHW_ERR("%s: %s failed rc=%d",
				 caller, failed_cmd, rc);
	}
	else if (actual_len < expected_len) {
		EFHW_ERR("%s: ERROR: '%s' expected response len %d, got %d",
			 caller, failed_cmd, expected_len, actual_len);
	}
}


#define EFX_DL_PRE(efx_dev, nic, rc) \
{ \
	(efx_dev) = efhw_nic_acquire_dl_device((nic)); \
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


/*----------------------------------------------------------------------------
 *
 * Initialisation and configuration discovery
 *
 *---------------------------------------------------------------------------*/

static int _ef10_nic_get_35388_workaround(struct efhw_nic *nic)
{
	int rc, enabled;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_WORKAROUNDS_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(out);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_WORKAROUNDS,
				 0, sizeof(out), &out_size, NULL, out);
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
	EFHW_MCDI_SET_DWORD(in, WORKAROUND_IN_TYPE,
			    MC_CMD_WORKAROUND_BUG35388);

	/* For this workaround, the MC_CMD_WORKAROUND does nothing
	 * other than report if the workaround is known by the
	 * firmware.  If it is known then it is enabled.  The value of
	 * "enabled" is ignored.
	 *
	 * Try this first rather than just calling
	 * MC_CMD_GET_WORKAROUNDS as I think there are some older
	 * firmware versions that don't have both
	 */
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_WORKAROUND, sizeof(in), 0,
				 &out_size, in, NULL);

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


#define IP_LOCAL	(1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define IP_FULL 	(1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_SRC_IP_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_SRC_PORT_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define VLAN_IP_WILD	(1 << MC_CMD_FILTER_OP_IN_MATCH_DST_IP_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_DST_PORT_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_OUTER_VLAN_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define ETH_LOCAL	(1 << MC_CMD_FILTER_OP_IN_MATCH_DST_MAC_LBN)
#define ETH_LOCAL_VLAN	(1 << MC_CMD_FILTER_OP_IN_MATCH_DST_MAC_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_OUTER_VLAN_LBN)
#define UCAST_MISMATCH	(1<<MC_CMD_FILTER_OP_IN_MATCH_UNKNOWN_UCAST_DST_LBN)
#define MCAST_MISMATCH	(1<<MC_CMD_FILTER_OP_IN_MATCH_UNKNOWN_MCAST_DST_LBN)
#define IP_PROTOCOL	(1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN |\
			 1 << MC_CMD_FILTER_OP_IN_MATCH_IP_PROTO_LBN)
#define ETHERTYPE	(1 << MC_CMD_FILTER_OP_IN_MATCH_ETHER_TYPE_LBN)


static int
_ef10_ef100_nic_check_supported_filter(ci_dword_t* matches, int len, unsigned filter)
{
	int i;
	for(i = 0; i < len; i++)
		if ( EFHW_MCDI_ARRAY_DWORD(matches,
		     GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES, i) == filter )
			return 1;

	return 0;
}


void
ef10_ef100_nic_check_supported_filters(struct efhw_nic *nic) {
	int rc, num_matches;
	size_t out_size;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_PARSER_DISP_INFO_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMAX);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, GET_PARSER_DISP_INFO_IN_OP,
		MC_CMD_GET_PARSER_DISP_INFO_IN_OP_GET_SUPPORTED_RX_MATCHES);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_PARSER_DISP_INFO,
				 sizeof(in), sizeof(out), &out_size, in, out);
	if( rc != 0 )
		EFHW_ERR("%s: failed rc=%d", __FUNCTION__, rc);
	else if ( out_size < MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN )
		EFHW_ERR("%s: failed, expected response min len %d, got %d",
			__FUNCTION__, MC_CMD_GET_PARSER_DISP_INFO_OUT_LENMIN,
			(int)out_size);

	num_matches = EFHW_MCDI_VAR_ARRAY_LEN(out_size,
		GET_PARSER_DISP_INFO_OUT_SUPPORTED_MATCHES);

	/* We check types of filters that may be used by onload, or ef_vi
	 * users.  This information will be exposed by the capabilities API.
	 */
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, IP_LOCAL) )
		nic->flags |= NIC_FLAG_RX_FILTER_TYPE_IP_LOCAL;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, IP_FULL) )
		nic->flags |= NIC_FLAG_RX_FILTER_TYPE_IP_FULL;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, VLAN_IP_WILD) )
		nic->flags |= NIC_FLAG_VLAN_FILTERS;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, ETH_LOCAL) )
		nic->flags |= NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, ETH_LOCAL_VLAN) )
		nic->flags |= NIC_FLAG_RX_FILTER_TYPE_ETH_LOCAL_VLAN;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, IP_PROTOCOL) )
		nic->flags |= NIC_FLAG_RX_FILTER_IP4_PROTO;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, ETHERTYPE) )
		nic->flags |= NIC_FLAG_RX_FILTER_ETHERTYPE;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, UCAST_MISMATCH) )
		nic->flags |= NIC_FLAG_RX_FILTER_TYPE_UCAST_MISMATCH;
	if( _ef10_ef100_nic_check_supported_filter(out, num_matches, MCAST_MISMATCH) )
		nic->flags |= NIC_FLAG_RX_FILTER_TYPE_MCAST_MISMATCH;

	/* All fw variants support IPv6 filters */
	nic->flags |= NIC_FLAG_RX_FILTER_TYPE_IP6;
}


static int
ef10_nic_license_check(struct efhw_nic *nic, const uint32_t feature,
		       int* licensed) {
	size_t out_size;
	int rc;
	uint32_t license_state;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_LICENSED_APP_STATE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_LICENSED_APP_STATE_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, GET_LICENSED_APP_STATE_IN_APP_ID, feature);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_LICENSED_APP_STATE,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_GET_LICENSED_APP_STATE, rc, out_size, 0);
	if (rc != 0)
		return rc;
	license_state = EFHW_MCDI_DWORD(out, GET_LICENSED_APP_STATE_OUT_STATE);
	*licensed = license_state == MC_CMD_GET_LICENSED_APP_STATE_OUT_LICENSED;
	return 0;
}


static int
ef10_nic_v3_license_check(struct efhw_nic *nic, const uint64_t app_id,
		       int* licensed) {
	size_t out_size;
	int rc;
	uint32_t license_state;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_LICENSED_V3_APP_STATE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_LICENSED_V3_APP_STATE_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_QWORD(in, GET_LICENSED_V3_APP_STATE_IN_APP_ID, app_id);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_LICENSED_V3_APP_STATE,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_GET_LICENSED_V3_APP_STATE, rc, out_size, 0);
	if (rc != 0)
		return rc;
	license_state = EFHW_MCDI_DWORD(out, GET_LICENSED_V3_APP_STATE_OUT_STATE);
	*licensed = license_state == MC_CMD_GET_LICENSED_V3_APP_STATE_OUT_LICENSED;

	return 0;
}


static int
ef10_nic_license_challenge(struct efhw_nic *nic, 
			   const uint32_t feature, 
			   const uint8_t* challenge, 
			   uint32_t* expiry,
			   uint8_t* signature) {
	size_t out_size;
	int rc;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_LICENSED_APP_OP_VALIDATE_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_LICENSED_APP_OP_VALIDATE_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_TRACE("%s:", __FUNCTION__);

	EFHW_ASSERT(challenge);
	EFHW_ASSERT(expiry);
	EFHW_ASSERT(signature);

	EFHW_MCDI_SET_DWORD(in, LICENSED_APP_OP_VALIDATE_IN_APP_ID, feature);
	EFHW_MCDI_SET_DWORD(in, LICENSED_APP_OP_VALIDATE_IN_OP, 
			    MC_CMD_LICENSED_APP_OP_IN_OP_VALIDATE);

	memcpy(_EFHW_MCDI_ARRAY_PTR(in, LICENSED_APP_OP_VALIDATE_IN_CHALLENGE, 0, 4),
	       challenge, MC_CMD_LICENSED_APP_OP_VALIDATE_IN_CHALLENGE_LEN);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_LICENSED_APP_OP,
				 sizeof(in), sizeof(out), &out_size, in, out);
	if (rc != 0)
	  return rc;
	MCDI_CHECK(MC_CMD_LICENSED_APP_OP_VALIDATE, rc, out_size, 0);
	*expiry = EFHW_MCDI_DWORD(out, LICENSED_APP_OP_VALIDATE_OUT_EXPIRY);
	memcpy(signature, 
	       _EFHW_MCDI_ARRAY_PTR(out, LICENSED_APP_OP_VALIDATE_OUT_RESPONSE,
				    0, 4), 
	       MC_CMD_LICENSED_APP_OP_VALIDATE_OUT_RESPONSE_LEN);
	return 0;
}

static int
ef10_nic_v3_license_challenge(struct efhw_nic *nic,
			   const uint64_t app_id,
			   const uint8_t* challenge,
			   uint32_t* expiry,
			   uint32_t* days,
			   uint8_t* signature,
                           uint8_t* base_mac,
                           uint8_t* vadaptor_mac) {
	size_t out_size;
	int rc;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_LICENSED_V3_VALIDATE_APP_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_LICENSED_V3_VALIDATE_APP_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_TRACE("%s:", __FUNCTION__);

	EFHW_ASSERT(challenge);
	EFHW_ASSERT(expiry);
	EFHW_ASSERT(days);
	EFHW_ASSERT(signature);
	EFHW_ASSERT(base_mac);
	EFHW_ASSERT(vadaptor_mac);

	EFHW_MCDI_SET_QWORD(in, LICENSED_V3_VALIDATE_APP_IN_APP_ID, app_id);
	EFHW_MCDI_SET_DWORD(in, LICENSED_APP_OP_VALIDATE_IN_OP,
			    MC_CMD_LICENSED_APP_OP_IN_OP_VALIDATE);

	memcpy(_EFHW_MCDI_ARRAY_PTR(in, LICENSED_V3_VALIDATE_APP_IN_CHALLENGE, 0, 2),
	       challenge, MC_CMD_LICENSED_V3_VALIDATE_APP_IN_CHALLENGE_LEN);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_LICENSED_V3_VALIDATE_APP,
				 sizeof(in), sizeof(out), &out_size, in, out);
	if (rc != 0)
	  return rc;
	MCDI_CHECK(MC_CMD_LICENSED_V3_VALIDATE_APP, rc, out_size, 0);
	*expiry = EFHW_MCDI_DWORD(out, LICENSED_V3_VALIDATE_APP_OUT_EXPIRY_TIME);
	*days = (EFHW_MCDI_DWORD(out, LICENSED_V3_VALIDATE_APP_OUT_EXPIRY_UNITS) ==
					  MC_CMD_LICENSED_V3_VALIDATE_APP_OUT_EXPIRY_UNIT_DAYS) ? 1 : 0;
	memcpy(signature,
	       _EFHW_MCDI_ARRAY_PTR(out, LICENSED_V3_VALIDATE_APP_OUT_RESPONSE,
				    0, 4),
	       MC_CMD_LICENSED_V3_VALIDATE_APP_OUT_RESPONSE_LEN);
	memcpy(base_mac,
	       _EFHW_MCDI_ARRAY_PTR(out, LICENSED_V3_VALIDATE_APP_OUT_BASE_MACADDR,
				    0, 1),
	       MC_CMD_LICENSED_V3_VALIDATE_APP_OUT_VADAPTOR_MACADDR_LEN);
	memcpy(vadaptor_mac,
	       _EFHW_MCDI_ARRAY_PTR(out, LICENSED_V3_VALIDATE_APP_OUT_VADAPTOR_MACADDR,
				    0, 1),
	       MC_CMD_LICENSED_V3_VALIDATE_APP_OUT_VADAPTOR_MACADDR_LEN);
	return 0;
}

int ef10_ef100_nic_mac_spoofing_privilege(struct efhw_nic *nic)
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
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_FUNCTION_INFO, 0, sizeof(fi_outbuf),
				 &outlen, NULL, fi_outbuf);
	MCDI_CHECK(MC_CMD_GET_FUNCTION_INFO, rc, outlen, 0);
	if (rc != 0)
		return rc;

	pf = EFHW_MCDI_DWORD(fi_outbuf, GET_FUNCTION_INFO_OUT_PF);
	vf = EFHW_MCDI_DWORD(fi_outbuf, GET_FUNCTION_INFO_OUT_VF);

	EFHW_MCDI_POPULATE_DWORD_2(pm_inbuf, PRIVILEGE_MASK_IN_FUNCTION,
				   PRIVILEGE_MASK_IN_FUNCTION_PF, pf,
				   PRIVILEGE_MASK_IN_FUNCTION_VF, vf);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PRIVILEGE_MASK, sizeof(pm_inbuf),
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
					uint64_t* capability_flags,
					const char* caller)
{
	size_t out_size = 0;
	size_t ver_out_size;
	unsigned flags;
	char ver_buf[32];
	const __le16 *ver_words;
	int rc;

	EFHW_MCDI_DECLARE_BUF(ver_out, MC_CMD_GET_VERSION_OUT_LEN);
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_GET_CAPABILITIES_V2_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_GET_CAPABILITIES_V3_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(ver_out);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_CAPABILITIES,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_GET_CAPABILITIES, rc, out_size, 0);
	if (rc != 0)
		return rc;
	flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS1);
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PREFIX_LEN_14_LBN))
		*capability_flags |= NIC_FLAG_14BYTE_PREFIX;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_TX_MCAST_UDP_LOOPBACK_LBN))
		*capability_flags |= NIC_FLAG_MCAST_LOOP_HW;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PACKED_STREAM_LBN)) {
		rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_GET_VERSION, 0, sizeof(ver_out),
					 &ver_out_size, NULL, ver_out);
		if (rc == 0 && ver_out_size == MC_CMD_GET_VERSION_OUT_LEN) {
			ver_words = (__le16*)EFHW_MCDI_PTR(
				ver_out, GET_VERSION_OUT_VERSION);
			snprintf(ver_buf, 32, "%u.%u.%u.%u",
				 le16_to_cpu(ver_words[0]),
				 le16_to_cpu(ver_words[1]),
				 le16_to_cpu(ver_words[2]),
				 le16_to_cpu(ver_words[3]));
			if (!strcmp(ver_buf, "4.1.1.1022"))
				EFHW_ERR("%s: Error: Due to a known firmware "
					 "bug, packed stream mode is disabled "
					 "on version %s.  Please upgrade "
					 "firmware to use packed stream.",
					 __FUNCTION__, ver_buf);
			else
				*capability_flags |= NIC_FLAG_PACKED_STREAM;
		}
		else {
			*capability_flags |= NIC_FLAG_PACKED_STREAM;
		}
	}
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_RSS_LIMITED_LBN))
		*capability_flags |= NIC_FLAG_RX_RSS_LIMITED;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PACKED_STREAM_VAR_BUFFERS_LBN))
		*capability_flags |= NIC_FLAG_VAR_PACKED_STREAM;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_ADDITIONAL_RSS_MODES_LBN))
		*capability_flags |= NIC_FLAG_ADDITIONAL_RSS_MODES;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_TIMESTAMP_LBN))
		*capability_flags |= NIC_FLAG_HW_RX_TIMESTAMPING;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_MCAST_FILTER_CHAINING_LBN))
		*capability_flags |= NIC_FLAG_MULTICAST_FILTER_CHAINING;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_PREFIX_LEN_0_LBN))
		*capability_flags |= NIC_FLAG_ZERO_RX_PREFIX;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_BATCHING_LBN))
		*capability_flags |= NIC_FLAG_RX_MERGE;
	if (flags & (1u <<
		     MC_CMD_GET_CAPABILITIES_V3_OUT_RX_FORCE_EVENT_MERGING_LBN)) {
		*capability_flags |= NIC_FLAG_RX_FORCE_EVENT_MERGING;
	}

	/* If MAC filters are policed then check we've got the right privileges
	 * before saying we can do MAC spoofing.
	 */
	if (flags & (1u <<
		MC_CMD_GET_CAPABILITIES_V3_OUT_TX_MAC_SECURITY_FILTERING_LBN)) {
		if( ef10_ef100_nic_mac_spoofing_privilege(nic) == 1 )
			*capability_flags |= NIC_FLAG_MAC_SPOOFING;
	}
	else {
		*capability_flags |= NIC_FLAG_MAC_SPOOFING;
	}


        if (out_size >= MC_CMD_GET_CAPABILITIES_V2_OUT_LEN) {
		nic->pio_num = EFHW_MCDI_WORD(out,
					GET_CAPABILITIES_V3_OUT_NUM_PIO_BUFFS);
		nic->pio_size = EFHW_MCDI_WORD(out,
					GET_CAPABILITIES_V3_OUT_SIZE_PIO_BUFF);
		flags = EFHW_MCDI_DWORD(out, GET_CAPABILITIES_V3_OUT_FLAGS2);
		if (flags & (1u <<
			MC_CMD_GET_CAPABILITIES_V3_OUT_TX_VFIFO_ULL_MODE_LBN))
			*capability_flags |= NIC_FLAG_TX_ALTERNATIVES;
		if (flags & (1u <<
			     MC_CMD_GET_CAPABILITIES_V3_OUT_INIT_EVQ_V2_LBN))
			*capability_flags |= NIC_FLAG_EVQ_V2;
		if (flags & (1u << MC_CMD_GET_CAPABILITIES_V2_OUT_CTPIO_LBN))
			*capability_flags |= NIC_FLAG_TX_CTPIO;
		if (flags & (1u <<
			MC_CMD_GET_CAPABILITIES_V3_OUT_EVENT_CUT_THROUGH_LBN)) {
			*capability_flags |= NIC_FLAG_EVENT_CUT_THROUGH;
		}
		/* Huntington NICs with some firmware versions incorrectly
		 * report that they do not support RX cut-through. */
		if (flags & (1u <<
			MC_CMD_GET_CAPABILITIES_V3_OUT_RX_CUT_THROUGH_LBN) ||
		    nic->devtype.variant == 'A' ) {
			*capability_flags |= NIC_FLAG_RX_CUT_THROUGH;
		}
        }
	else {
		/* We hard code these values, as lack of support for get caps
		 * V2 implies we're on Torino.
		 */
		EFHW_ASSERT( nic->devtype.variant == 'A' );
		nic->pio_num = 16;
		nic->pio_size = 2048;
		*capability_flags |= NIC_FLAG_RX_CUT_THROUGH;
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
	EFHW_MCDI_DECLARE_BUF(out,
			      MC_CMD_PTP_OUT_GET_TIMESTAMP_CORRECTIONS_V2_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PTP_IN_OP,
			    MC_CMD_PTP_OP_GET_TIMESTAMP_CORRECTIONS);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), sizeof(out), &out_size,
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
				*tx_ts_correction =
					((uint64_t) *tx_ts_correction * 1000000000) >> 27;
		} else {
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
                                       uint32_t* ts_format,
                                       const char* caller)
{
	int rc;
	size_t out_size;

	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_GET_ATTRIBUTES_LEN);
	EFHW_MCDI_DECLARE_BUF(out,
			      MC_CMD_PTP_OUT_GET_ATTRIBUTES_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, PTP_IN_OP,
			    MC_CMD_PTP_OP_GET_ATTRIBUTES);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), sizeof(out), &out_size,
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
	/* No need to set RX_USR_BUF_SIZE for ef10, it's done
	 * per-descriptor
	 */

	/* The ONLOAD_UNSUPPORTED flag is managed by the resource manager, so
	 * we don't reset the value here.
	 */
	nic->flags &= ~NIC_FLAG_ONLOAD_UNSUPPORTED;

	/* Some capabilities are always present on ef10 */
	nic->flags |= NIC_FLAG_PIO | NIC_FLAG_HW_MULTICAST_REPLICATION |
		      NIC_FLAG_PHYS_MODE | NIC_FLAG_BUFFER_MODE |
		      NIC_FLAG_VPORTS;

	/* Determine what the filtering capabilies are */
	ef10_ef100_nic_check_supported_filters(nic);

	if( _ef10_nic_check_35388_workaround(nic) == 1 )
		nic->flags |= NIC_FLAG_BUG35388_WORKAROUND;

	/* Determine capabilities reported by firmware */
	_ef10_nic_check_capabilities(nic, &nic->flags, __FUNCTION__);

	nic->rx_prefix_len = (nic->flags & NIC_FLAG_14BYTE_PREFIX) ?
			      14 :
			      0;
}


static int
ef10_nic_init_hardware(struct efhw_nic *nic,
		       struct efhw_ev_handler *ev_handlers,
		       const uint8_t *mac_addr)
{
	int rc;
	EFHW_TRACE("%s:", __FUNCTION__);

	memcpy(nic->mac_addr, mac_addr, ETH_ALEN);

	ef10_nic_tweak_hardware(nic);

	rc = ef10_nic_get_timestamp_correction(nic, &(nic->rx_ts_correction),
					       &(nic->tx_ts_correction),
					       __FUNCTION__);
	if( rc < 0 ) {
		if( rc == -EPERM || rc == -ENOSYS ) 
			EFHW_TRACE("%s: WARNING: failed to get HW timestamp "
				   "corrections rc=%d", __FUNCTION__, rc);
		else
			EFHW_ERR("%s: ERROR: failed to get HW timestamp "
				 "corrections rc=%d", __FUNCTION__, rc);
		/* This will happen if the NIC does not have a PTP
		 * licence.  Without that licence the user is unlikely
		 * to be doing such accurate timestamping, but try to
		 * do something sensible... these values are correct
		 * for Huntington.
		 */
		nic->rx_ts_correction = -12;
		nic->tx_ts_correction = 178;
	}

	rc = ef10_nic_get_ptp_attributes(nic, &(nic->ts_format),
                                         __FUNCTION__);
	if( rc < 0 ) {
		if( rc == -EPERM || rc == -ENOSYS )
			EFHW_TRACE("%s: WARNING: failed to get PTP "
				   "attributes rc=%d", __FUNCTION__, rc);
		else
			EFHW_ERR("%s: ERROR: failed to get PTP "
				 "attributes rc=%d", __FUNCTION__, rc);

                /* As above. */
                nic->ts_format = TS_FORMAT_SECONDS_27FRACTION;
        }

	/* No buffer_table_ctor() on EF10 */
	/* No non_irq_evq on EF10 */

	return 0;
}


static void
ef10_nic_release_hardware(struct efhw_nic *nic)
{
	EFHW_TRACE("%s:", __FUNCTION__);
}


/*--------------------------------------------------------------------
 *
 * Events - MCDI cmds and register interface
 *
 *--------------------------------------------------------------------*/


int
ef10_ef100_mcdi_cmd_event_queue_enable(struct efhw_nic *nic,
				       uint evq, /* evq id */
				       uint evq_size, /* Number of events */
				       dma_addr_t *dma_addrs,
				       uint n_pages,
				       uint interrupting,
				       uint enable_dos_p,
				       uint enable_cut_through,
				       uint enable_rx_merging,
				       int wakeup_evq,
				       uint enable_timer)
{
	int rc, i;
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_INIT_EVQ_V2_OUT_LEN);
	size_t out_size;
	size_t in_size = MC_CMD_INIT_EVQ_V2_IN_LEN(n_pages);
	EFHW_MCDI_DECLARE_BUF(in,
		MC_CMD_INIT_EVQ_V2_IN_LEN(MC_CMD_INIT_EVQ_V2_IN_DMA_ADDR_MAXNUM));
	EFHW_MCDI_INITIALISE_BUF_SIZE(in, in_size);

	EFHW_ASSERT(n_pages <= MC_CMD_INIT_EVQ_V2_IN_DMA_ADDR_MAXNUM);

	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_SIZE, evq_size);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_INSTANCE, evq);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_LOAD, 0);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_RELOAD, 0);

	if( nic->devtype.arch == EFHW_ARCH_EF10 &&
	    nic->devtype.variant == 'A' ) {
		/* TX merging is needed for good throughput with small
		 * packets.  TX and RX event merging must be requested
		 * together (or not at all). Event cut through reduces latency,
		 * but is incompatible with RX event merging.  Enabling event
		 * cut through causes firmware to disables RX event merging. So
		 * by requesting all three we get what we want: Event cut
		 * through and tx event merging. 
		 */
		EFHW_MCDI_POPULATE_DWORD_5(in, INIT_EVQ_IN_FLAGS,
			INIT_EVQ_IN_FLAG_INTERRUPTING, interrupting ? 1 : 0,
			INIT_EVQ_IN_FLAG_RPTR_DOS, enable_dos_p ? 1 : 0,
			INIT_EVQ_IN_FLAG_CUT_THRU, enable_cut_through ? 1 : 0,
			INIT_EVQ_IN_FLAG_RX_MERGE, 1,
			INIT_EVQ_IN_FLAG_TX_MERGE, 1);
	}
	else {
		/* No such restrictions on Medford, we can ask for
		 * what we actually want.
		 *
		 * On Medford we must explicitly request a timer if we are
		 * not interrupting (we'll get one anyway if we are).
		 */
		EFHW_MCDI_POPULATE_DWORD_6(in, INIT_EVQ_IN_FLAGS,
			INIT_EVQ_IN_FLAG_INTERRUPTING, interrupting ? 1 : 0,
			INIT_EVQ_IN_FLAG_USE_TIMER, enable_timer ? 1 : 0,
			INIT_EVQ_IN_FLAG_RPTR_DOS, enable_dos_p ? 1 : 0,
			INIT_EVQ_IN_FLAG_CUT_THRU, enable_cut_through ? 1 : 0,
			INIT_EVQ_IN_FLAG_RX_MERGE, enable_rx_merging ? 1 : 0,
			INIT_EVQ_IN_FLAG_TX_MERGE, 1);
	}

	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TMR_MODE, 
			    MC_CMD_INIT_EVQ_IN_TMR_MODE_DIS);

	/* EF10 TODO We may want to direct the wakeups to another EVQ,
	 * but by default do old-style spreading
	 */
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_TARGET_EVQ, wakeup_evq);

	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_COUNT_MODE,
			    MC_CMD_INIT_EVQ_IN_COUNT_MODE_DIS);
	EFHW_MCDI_SET_DWORD(in, INIT_EVQ_IN_COUNT_THRSHLD, 0);

	for( i = 0; i < n_pages; ++i ) {
		EFHW_MCDI_SET_ARRAY_QWORD(in, INIT_EVQ_IN_DMA_ADDR, i, 
					  dma_addrs[i]);
	}

	EFHW_ASSERT(evq >= 0);
	EFHW_ASSERT(evq < nic->num_evqs);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_INIT_EVQ, in_size, sizeof(out),
				 &out_size, in, &out);
	if( nic->flags & NIC_FLAG_EVQ_V2 )
		MCDI_CHECK(MC_CMD_INIT_EVQ_V2, rc, out_size, 0);
	else
		MCDI_CHECK(MC_CMD_INIT_EVQ, rc, out_size, 0);
        return rc;
}


void
ef10_ef100_mcdi_cmd_event_queue_disable(struct efhw_nic *nic, uint evq)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_EVQ_IN_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_SET_DWORD(in, FINI_EVQ_IN_INSTANCE, evq);

	EFHW_ASSERT(evq >= 0);
	EFHW_ASSERT(evq < nic->num_evqs);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_FINI_EVQ, sizeof(in), 0,
				 &out_size, in, NULL);
	MCDI_CHECK(MC_CMD_FINI_EVQ, rc, out_size, 0);
}


/*--------------------------------------------------------------------
 *
 * Event Management - and SW event posting
 *
 *--------------------------------------------------------------------*/


void
ef10_ef100_mcdi_cmd_driver_event(struct efhw_nic *nic, uint64_t data, uint32_t evq)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_DRIVER_EVENT_IN_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_SET_DWORD(in, DRIVER_EVENT_IN_EVQ, evq);
	EFHW_MCDI_SET_QWORD(in, DRIVER_EVENT_IN_DATA, data);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_DRIVER_EVENT, sizeof(in), 0, &out_size,
				 in, NULL);
	MCDI_CHECK(MC_CMD_DRIVER_EVENT, rc, out_size, 0);
}


static int
_ef10_mcdi_cmd_ptp_time_event_subscribe(struct efhw_nic *nic, uint32_t evq,
					unsigned* out_flags, const char* caller)
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

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size, in, NULL);
	if (rc == -ERANGE) {
		sync_flag = 0;
		EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_SUBSCRIBE_QUEUE, evq);
		rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size,
					 in, NULL);
	}

#ifndef MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_OUT_LEN
#define MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_OUT_LEN	\
	MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE_LEN
#endif
	MCDI_CHECK(MC_CMD_PTP_OUT_TIME_EVENT_SUBSCRIBE, rc, out_size, 0);
	if (rc == 0 && out_flags != NULL)
		*out_flags |= sync_flag;
	return rc;
}

static int _ef10_mcdi_cmd_ptp_time_event_unsubscribe(struct efhw_nic *nic,
						     uint32_t evq,
						     const char* caller)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);

	EFHW_MCDI_SET_DWORD(in, PTP_IN_OP,
			    MC_CMD_PTP_OP_TIME_EVENT_UNSUBSCRIBE);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_PERIPH_ID, 0);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_UNSUBSCRIBE_CONTROL,
			    MC_CMD_PTP_IN_TIME_EVENT_UNSUBSCRIBE_SINGLE);
	EFHW_MCDI_SET_DWORD(in, PTP_IN_TIME_EVENT_UNSUBSCRIBE_QUEUE, evq);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PTP, sizeof(in), 0, &out_size,
				 in, NULL);

#ifndef MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_OUT_LEN
#define MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_OUT_LEN	\
	MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE_LEN
#endif
	MCDI_CHECK(MC_CMD_PTP_OUT_TIME_EVENT_UNSUBSCRIBE, rc, out_size, 0);
	return rc;
}


/* This function will enable the given event queue with the requested
 * properties.
 */
static int
ef10_nic_event_queue_enable(struct efhw_nic *nic, uint evq, uint evq_size,
			    dma_addr_t *dma_addrs,
			    uint n_pages, int interrupting, int enable_dos_p,
			    int wakeup_evq, int flags, int* flags_out)
{
	int rc;
	int enable_time_sync_events = (flags & (EFHW_VI_RX_TIMESTAMPS |
						EFHW_VI_TX_TIMESTAMPS)) != 0;
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

	rc = ef10_ef100_mcdi_cmd_event_queue_enable(nic, evq, evq_size, dma_addrs,
						    n_pages, interrupting,
						    enable_dos_p, enable_cut_through,
						    enable_rx_merging,
						    wakeup_evq, enable_timer);

	EFHW_TRACE("%s: enable evq %u size %u rc %d", __FUNCTION__, evq,
		   evq_size, rc);

	if( rc == 0 && enable_time_sync_events ) {
		rc = _ef10_mcdi_cmd_ptp_time_event_subscribe
			(nic, evq, flags_out, __FUNCTION__);
		if( rc != 0 ) {
			ef10_ef100_mcdi_cmd_event_queue_disable(nic, evq);
			/* Firmware returns EPERM if you do not have
			 * the licence to subscribe to time sync
			 * events.  We convert it to ENOKEY which in
			 * Onload means you are lacking the
			 * appropriate licence.
			 *
			 * Firmware returns ENOSYS in case it does not
			 * support timestamping.  We convert it to
			 * EOPNOTSUPP.
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
		_ef10_mcdi_cmd_ptp_time_event_unsubscribe
			(nic, evq, __FUNCTION__);
	ef10_ef100_mcdi_cmd_event_queue_disable(nic, evq);
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

	ef10_ef100_mcdi_cmd_driver_event(nic, ev_data, evq);
	EFHW_TRACE("%s: evq[%d]->%x", __FUNCTION__, evq, data);
}

/*--------------------------------------------------------------------
 *
 * EF10 specific event callbacks
 *
 *--------------------------------------------------------------------*/

static int
ef10_handle_event(struct efhw_nic *nic, struct efhw_ev_handler *h,
		  efhw_event_t *ev, int budget)
{
	unsigned evq;

	if (EF10_EVENT_CODE(ev) == EF10_EVENT_CODE_CHAR) {
		switch (EF10_EVENT_DRIVER_SUBCODE(ev)) {
		case ESE_DZ_DRV_WAKE_UP_EV:
			evq = (EF10_EVENT_WAKE_EVQ_ID(ev) - nic->vi_base) >> nic->vi_shift;
			if (evq < nic->vi_lim && evq >= nic->vi_min) {
				return efhw_handle_wakeup_event(nic, h, evq,
								budget);
			}
			else {
				EFHW_NOTICE("%s: wakeup evq out of range: "
					    "%d %d %d %d",
					    __FUNCTION__, evq, nic->vi_base,
					    nic->vi_min, nic->vi_lim);
				return -EINVAL;
			}
		case ESE_DZ_DRV_TIMER_EV:
			evq = (EF10_EVENT_WAKE_EVQ_ID(ev) - nic->vi_base) >> nic->vi_shift;
			if (evq < nic->vi_lim && evq >= nic->vi_min) {
				return efhw_handle_timeout_event(nic, h, evq,
								 budget);
			}
			else {
				EFHW_NOTICE("%s: timer evq out of range: "
					    "%d %d %d %d",
					    __FUNCTION__, evq, nic->vi_base,
					    nic->vi_min, nic->vi_lim);
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
			return efhw_handle_txdmaq_flushed(nic, h, evq);
		case MCDI_EVENT_CODE_RX_FLUSH:
			evq = EF10_EVENT_RX_FLUSH_Q_ID(ev);
			EFHW_TRACE("%s: rx flush done %d", __FUNCTION__, evq);
			return efhw_handle_rxdmaq_flushed(nic, h, evq, false);
		case MCDI_EVENT_CODE_TX_ERR:
			EFHW_NOTICE("%s: unexpected MCDI TX error event "
				    "(event code %d)",__FUNCTION__, code);
			return -EINVAL;
		case MCDI_EVENT_CODE_RX_ERR:
			EFHW_NOTICE("%s: unexpected MCDI RX error event "
				    "(event code %d)",__FUNCTION__, code);
			return -EINVAL;
		case MCDI_EVENT_CODE_AOE:
			/* This event doesn't signify an error case,
			 * so just return 0 to avoid logging 
			 */
			return -EINVAL;
		default:
			EFHW_NOTICE("%s: unexpected MCDI event code %d",
				    __FUNCTION__, code);
			return -EINVAL;
		}
	}

	EFHW_TRACE("%s: unknown event type=%x", __FUNCTION__,
		   (unsigned)EF10_EVENT_CODE(ev));

	return -EINVAL;
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

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_SET_PARSER_DISP_CONFIG, sizeof(in), 0,
				 &out_size, in, NULL);
	MCDI_CHECK(MC_CMD_SET_PARSER_DISP_CONFIG, rc, out_size, 0);
	return rc;
}

static int
_ef10_mcdi_cmd_set_multicast_loopback_suppression
		(struct efhw_nic *nic,
		 int suppress_self_transmission,
		 uint32_t port_id, uint8_t stack_id )
{
	int rc;
	struct efx_dl_device *efx_dev;
	EFX_DL_PRE(efx_dev, nic, rc)
		rc = efx_dl_set_multicast_loopback_suppression(
			efx_dev, suppress_self_transmission,
			port_id, stack_id);
	EFX_DL_POST(efx_dev, nic, rc)
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
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_ALLOCATE_TX_VFIFO_CP,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_ALLOCATE_TX_VFIFO_CP, rc, out_size, 0);
	if (rc == 0) {
		*pool_id_out =
			EFHW_MCDI_DWORD(out, ALLOCATE_TX_VFIFO_CP_OUT_CP_ID);
	}
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
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_DEALLOCATE_TX_VFIFO_CP,
				 sizeof(in), 0, &out_size, in, NULL);
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
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_ALLOCATE_TX_VFIFO_VFIFO,
				 sizeof(in), sizeof(out), &out_size, in, out);
        MCDI_CHECK(MC_CMD_ALLOCATE_TX_VFIFO_VFIFO, rc, out_size, 0);
	if (rc == 0) {
		*vfifo_id_out =
			EFHW_MCDI_DWORD(out, ALLOCATE_TX_VFIFO_VFIFO_OUT_VID);
	}
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
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_TEARDOWN_TX_VFIFO_VF,
				 sizeof(in), 0, &out_size, in, NULL);
        MCDI_CHECK(MC_CMD_TEARDOWN_TX_VFIFO_VF, rc, out_size, 0);
        return rc;
}


static int
ef10_tx_alt_alloc(struct efhw_nic *nic, int tx_q_id, int num_alt,
		  int num_32b_words, unsigned *cp_id_out, unsigned *alt_ids_out)
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
ef10_ef100_mcdi_cmd_init_txq(struct efhw_nic *nic, dma_addr_t *dma_addrs,
			     int n_dma_addrs, uint32_t port_id, uint8_t stack_id,
			     uint32_t owner_id,
			     int flag_timestamp, int crc_mode, int flag_tcp_udp_only,
			     int flag_tcp_csum_dis, int flag_ip_csum_dis,
			     int flag_buff_mode, int flag_pacer_bypass,
			     int flag_ctpio, int flag_ctpio_uthresh,
			     uint32_t instance, uint32_t label,
			     uint32_t target_evq, uint32_t numentries)
{
	int rc;
	struct efx_dl_device *efx_dev;
	int inner = nic->devtype.arch == EFHW_ARCH_EF10 &&
		nic->devtype.variant == 'B';
	EFX_DL_PRE(efx_dev, nic, rc)
		rc = efx_dl_init_txq(
			efx_dev, dma_addrs, n_dma_addrs, port_id, stack_id, owner_id,
			!!flag_timestamp, crc_mode, !!flag_tcp_udp_only, !!flag_tcp_csum_dis,
			!!flag_ip_csum_dis, inner, inner, !!flag_buff_mode, !!flag_pacer_bypass,
			!!flag_ctpio, !!flag_ctpio_uthresh, instance, label, target_evq,
			numentries);
	EFX_DL_POST(efx_dev, nic, rc)
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
		EFHW_ERR("%s: ERROR: ps_buf_size=%d is invalid",
			 __FUNCTION__, ps_buf_size);
		return -EINVAL;
	}
	return ps_buf_size_mcdi;
}

int
ef10_ef100_mcdi_cmd_init_rxq(struct efhw_nic *nic, dma_addr_t *dma_addrs,
			     int n_dma_addrs, uint32_t port_id, uint8_t stack_id,
			     uint32_t owner_id,
			     int crc_mode, int flag_timestamp, int flag_hdr_split,
			     int flag_buff_mode, int flag_rx_prefix,
			     int flag_packed_stream, uint32_t instance,
			     uint32_t label, uint32_t target_evq,
			     uint32_t numentries, int ps_buf_size,
			     int flag_force_rx_merge, int ef100_rx_buffer_size)
{
	int rc;
	struct efx_dl_device *efx_dev;
	int ps_buf_size_mcdi = 0;
	int dma_mode = MC_CMD_INIT_RXQ_EXT_IN_SINGLE_PACKET;
	if( flag_packed_stream ) {
		dma_mode = MC_CMD_INIT_RXQ_EXT_IN_PACKED_STREAM;
		rc = _ef10_get_ps_buf_size_mcdi(numentries, ps_buf_size);
		if( rc < 0 )
			return rc;
		ps_buf_size_mcdi = rc;
	}
	EFX_DL_PRE(efx_dev, nic, rc)
		rc = efx_dl_init_rxq(
			efx_dev, dma_addrs, n_dma_addrs, port_id, stack_id, owner_id,
			crc_mode, !!flag_timestamp, !!flag_hdr_split, !!flag_buff_mode,
			!!flag_rx_prefix, dma_mode, instance, label, target_evq,
			numentries, ps_buf_size_mcdi, !!flag_force_rx_merge,
			ef100_rx_buffer_size);
	EFX_DL_POST(efx_dev, nic, rc)
	return rc;
}


/*----------------------------------------------------------------------------
 *
 * DMAQ low-level register interface
 *
 *---------------------------------------------------------------------------*/


static int
ef10_dmaq_tx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint flags)
{
	int rc;
	int flag_timestamp = (flags & EFHW_VI_TX_TIMESTAMPS) != 0;
	int flag_tcp_udp_only = (flags & EFHW_VI_TX_TCPUDP_ONLY) != 0;
	int flag_tcp_csum_dis = (flags & EFHW_VI_TX_TCPUDP_CSUM_DIS) != 0;
	int flag_ip_csum_dis = (flags & EFHW_VI_TX_IP_CSUM_DIS) != 0;
	int flag_buff_mode = (flags & EFHW_VI_TX_PHYS_ADDR_EN) == 0;
	int flag_loopback = (flags & EFHW_VI_TX_LOOPBACK) != 0;
	int flag_ctpio = (flags & EFHW_VI_TX_CTPIO) != 0;
	int flag_ctpio_uthresh = (flags & EFHW_VI_TX_CTPIO_NO_POISON) == 0;
	int flag_pacer_bypass;

	if (nic->flags & NIC_FLAG_MCAST_LOOP_HW) {
		rc = _ef10_mcdi_cmd_enable_multicast_loopback
			(nic, dmaq, flag_loopback);
		if(rc != 0) {
			/* We are greaceful in case there is firmware
			 * with incomplete support as well as in case we
			 * have no permissions e.g. with VF.  We just
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
			rc = _ef10_mcdi_cmd_set_multicast_loopback_suppression
				(nic, 1, vport_id, stack_id);
			if (rc == -EPERM) {
				/* Few notes:
				 *
				 * 1. This setting is not essential.  It might
				 * increase performance in some cases.
				 * 2. We might have no permissions to enable
				 * or disable loopback suppression,
				 * typically true for VF.
				 * 3. loopback suppression is a vadapter
				 * setting and might require different
				 * permissions than enable_multicast_loopback.
				 * 4. In some modes (e.g. VF passthrough)
				 * the setting is enabled by default,
				 * however there is no way to verify that.
				 */
				EFHW_WARN("%s: WARNING: failed to adjust "
				          "loopback suppression, continuing "
					  "with default setting", __FUNCTION__);
			}
			else if( rc != 0 )
				return rc;
		}
	}

	/* No option for pacer bypass yet, but we want it on as it cuts latency.
	 * This might not work in some cases due to permissions (e.g. VF),
	 * if so we retry without it. */
	for (flag_pacer_bypass = 1; 1; flag_pacer_bypass = 0) {
		rc = ef10_ef100_mcdi_cmd_init_txq
			(nic, dma_addrs, n_dma_addrs, vport_id, stack_id,
			 REAL_OWNER_ID(own_id), flag_timestamp,
			 QUEUE_CRC_MODE_NONE, flag_tcp_udp_only,
			 flag_tcp_csum_dis, flag_ip_csum_dis,
			 flag_buff_mode, flag_pacer_bypass, flag_ctpio,
			 flag_ctpio_uthresh, dmaq, tag, evq_id, dmaq_size);
		if ((rc != -EPERM) || (!flag_pacer_bypass))
			break;
	}

	if ((rc == 0) && !flag_pacer_bypass) {
		EFHW_WARN("%s: WARNING: failed to enable pacer bypass, "
			 "continuing without it", __FUNCTION__);
	}

	if (rc == -EOPNOTSUPP)
		rc = -ENOKEY;

	return rc;
}


static int 
ef10_dmaq_rx_q_init(struct efhw_nic *nic, uint dmaq, uint evq_id, uint own_id,
		    uint tag, uint dmaq_size,
		    dma_addr_t *dma_addrs, int n_dma_addrs,
		    uint vport_id, uint stack_id, uint ps_buf_size, uint flags)
{
	int rc;
	int flag_rx_prefix = (flags & EFHW_VI_RX_PREFIX) != 0;
	int flag_timestamp = (flags & EFHW_VI_RX_TIMESTAMPS) != 0;
	int flag_hdr_split = (flags & EFHW_VI_RX_HDR_SPLIT) != 0;
	int flag_buff_mode = (flags & EFHW_VI_RX_PHYS_ADDR_EN) == 0;
	int flag_packed_stream = (flags & EFHW_VI_RX_PACKED_STREAM) != 0;
	int flag_force_rx_merge = ((flags & EFHW_VI_NO_RX_CUT_THROUGH) != 0) &&
				(nic->flags & NIC_FLAG_RX_FORCE_EVENT_MERGING);
	if (flag_packed_stream) {
		if (!(nic->flags & NIC_FLAG_PACKED_STREAM))
			return -EOPNOTSUPP;
		if ((ps_buf_size != (1<<20)
		     && !(nic->flags & NIC_FLAG_VAR_PACKED_STREAM)))
			return -EOPNOTSUPP;
	}

	rc = ef10_ef100_mcdi_cmd_init_rxq
		(nic, dma_addrs, n_dma_addrs, vport_id, stack_id,
		 REAL_OWNER_ID(own_id), QUEUE_CRC_MODE_NONE, flag_timestamp,
		 flag_hdr_split, flag_buff_mode, flag_rx_prefix,
		 flag_packed_stream, dmaq, tag, evq_id, dmaq_size, ps_buf_size,
		 flag_force_rx_merge, 0);
	return rc == 0 ?
		flag_rx_prefix ? nic->rx_prefix_len : 0 :
		rc;
}

void ef10_ef100_dmaq_tx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}

void ef10_ef100_dmaq_rx_q_disable(struct efhw_nic *nic, uint dmaq)
{
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static int
_ef10_ef100_mcdi_cmd_fini_rxq(struct efhw_nic *nic, uint32_t instance)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_RXQ_IN_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_SET_DWORD(in, FINI_RXQ_IN_INSTANCE, instance);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_FINI_RXQ, sizeof(in), 0, &out_size,
				 in, NULL);
	MCDI_CHECK(MC_CMD_FINI_RXQ, rc, out_size, 0);
	return rc;
}


static int
_ef10_ef100_mcdi_cmd_fini_txq(struct efhw_nic *nic, uint32_t instance)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FINI_TXQ_IN_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_SET_DWORD(in, FINI_TXQ_IN_INSTANCE, instance);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_FINI_TXQ, sizeof(in), 0, &out_size,
				 in, NULL);
	MCDI_CHECK(MC_CMD_FINI_TXQ, rc, out_size, 0);
	return rc;
}


/*--------------------------------------------------------------------
 *
 * DMA Queues - mid level API
 *
 *--------------------------------------------------------------------*/


int ef10_ef100_flush_tx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	return _ef10_ef100_mcdi_cmd_fini_txq(nic, dmaq);
}


int ef10_ef100_flush_rx_dma_channel(struct efhw_nic *nic, uint dmaq)
{
	return _ef10_ef100_mcdi_cmd_fini_rxq(nic, dmaq);
}


/*--------------------------------------------------------------------
 *
 * Buffer table - MCDI cmds
 *
 *--------------------------------------------------------------------*/

static int
_ef10_ef100_mcdi_cmd_buffer_table_alloc(struct efhw_nic *nic, int page_size,
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

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_ALLOC_BUFTBL_CHUNK,
				 sizeof(in), sizeof(out), &out_size, in, out);
	MCDI_CHECK(MC_CMD_ALLOC_BUFTBL_CHUNK, rc, out_size, 1);
	if ( rc != 0 )
		return rc;

	*btb_index = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_ID);
	*numentries = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_NUMENTRIES);
	*handle = EFHW_MCDI_DWORD(out, ALLOC_BUFTBL_CHUNK_OUT_HANDLE);
	return rc;
}


static void
_ef10_ef100_mcdi_cmd_buffer_table_free(struct efhw_nic *nic,
				       efhw_btb_handle handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FREE_BUFTBL_CHUNK_IN_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_SET_DWORD(in, FREE_BUFTBL_CHUNK_IN_HANDLE, handle);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_FREE_BUFTBL_CHUNK, sizeof(in), 0,
				 &out_size, in, NULL);
	MCDI_CHECK(MC_CMD_FREE_BUFTBL_CHUNK, rc, out_size, 1);
}


static int
_ef10_ef100_mcdi_cmd_buffer_table_program(struct efhw_nic *nic, dma_addr_t *dma_addrs,
					  int n_entries, int first_entry,
					  efhw_btb_handle handle)
{

	/* chip_src uses eftest_func_dma_to_dma48_addr() to convert
	 * the dma addresses.  Do I need to do something similar?
	 */
	int i, rc;
	size_t out_size;
	size_t in_size = MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_LEN(n_entries);
	EFHW_MCDI_DECLARE_BUF(in, 
		MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_LEN(
			MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM));
	EFHW_MCDI_INITIALISE_BUF_SIZE(in, in_size);

	EFHW_ASSERT(n_entries <=
		    MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM);

	EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_HANDLE, handle);
	EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_FIRSTID, first_entry);
	EFHW_MCDI_SET_DWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_NUMENTRIES, 
			    n_entries);

	if (n_entries > MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM) {
		EFHW_ERR("%s: n_entries (%d) cannot be greater than "
			 "MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM (%d)",
			 __FUNCTION__, n_entries,
			 MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM);
		return -EINVAL;
	}

	for (i = 0; i < n_entries; ++i)
		EFHW_MCDI_SET_ARRAY_QWORD(in, PROGRAM_BUFTBL_ENTRIES_IN_ENTRY,
					  i, dma_addrs[i]);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_PROGRAM_BUFTBL_ENTRIES, in_size, 0,
				 &out_size, in, NULL);
	MCDI_CHECK(MC_CMD_PROGRAM_BUFTBL_ENTRIES, rc, out_size, 1);
	return rc;
}


/*--------------------------------------------------------------------
 *
 * Buffer table - API
 *
 *--------------------------------------------------------------------*/

static const int __ef10_nic_buffer_table_get_orders[] = {0,4,8,10};

static int __ef10_ef100_nic_buffer_table_alloc(struct efhw_nic *nic, int owner,
					       int order,
					       struct efhw_buffer_table_block *block)
{
	int numentries = 0, rc, btb_index = 0;

	rc = _ef10_ef100_mcdi_cmd_buffer_table_alloc
		(nic, EFHW_NIC_PAGE_SIZE << order, owner, &btb_index,
		 &numentries, &block->btb_hw.ef10.handle);

	/* Initialise the software state even if MCDI failed, so that we can
	 * retry the MCDI call at some point in the future. */
	if (rc != 0)
		return rc;
	if (numentries != 32) {
		EFHW_ERR("%s: _ef10_ef100_mcdi_cmd_buffer_table_alloc expected 32"
			 " but allocated %d entries", __FUNCTION__, numentries);
		return -EINVAL;
	}

	if (nic->devtype.arch == EFHW_ARCH_EF10)
		block->btb_vaddr = EF10_BUF_ID_ORDER_2_VADDR(btb_index, order);
	else
		block->btb_vaddr = EF100_BUF_ID_ORDER_2_VADDR(btb_index, order);

	return 0;
}


int
ef10_ef100_nic_buffer_table_alloc(struct efhw_nic *nic, int owner, int order,
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
		rc = __ef10_ef100_nic_buffer_table_alloc(nic, REAL_OWNER_ID(owner),
							 order, block);
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


int
ef10_ef100_nic_buffer_table_realloc(struct efhw_nic *nic, int owner, int order,
				    struct efhw_buffer_table_block *block)
{
	return __ef10_ef100_nic_buffer_table_alloc(nic, REAL_OWNER_ID(owner),
						   order, block);
}


void
ef10_ef100_nic_buffer_table_free(struct efhw_nic *nic,
				 struct efhw_buffer_table_block *block,
				 int reset_pending)
{
	if (! reset_pending) {
		_ef10_ef100_mcdi_cmd_buffer_table_free(nic,
						       block->btb_hw.ef10.handle);
	}
	kfree(block);
}


static int
__ef10_ef100_nic_buffer_table_set(struct efhw_nic *nic,
				  struct efhw_buffer_table_block *block,
				  int first_entry, int n_entries,
				  dma_addr_t *dma_addrs)
{
	int i, rc, batch;
	i = 0;
	while (i < n_entries) {
		batch = n_entries - i <
			        MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM ?
			n_entries - i :
			MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM;
		rc = _ef10_ef100_mcdi_cmd_buffer_table_program
			(nic, dma_addrs + i, batch, first_entry + i,
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


int
ef10_ef100_nic_buffer_table_set(struct efhw_nic *nic,
				struct efhw_buffer_table_block *block,
				int first_entry, int n_entries,
				dma_addr_t *dma_addrs)
{
	int rc;
	int buffer_id;

	if (nic->devtype.arch == EFHW_ARCH_EF10)
		buffer_id = EF10_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;
	else
		buffer_id = EF100_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;

	rc = __ef10_ef100_nic_buffer_table_set(nic, block, buffer_id, n_entries,
					       dma_addrs);
	EFHW_DO_DEBUG(
		if (rc == 0)
			efhw_buffer_table_set_debug(block, first_entry,
						    n_entries)
	);
	return rc;
}


void
ef10_ef100_nic_buffer_table_clear(struct efhw_nic *nic,
				  struct efhw_buffer_table_block *block,
				  int first_entry, int n_entries)
{
	int rc;
	int buffer_id;
	dma_addr_t null_addrs[MC_CMD_PROGRAM_BUFTBL_ENTRIES_IN_ENTRY_MAXNUM];

	if (nic->devtype.arch == EFHW_ARCH_EF10)
		buffer_id = EF10_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;
	else
		buffer_id = EF100_BUF_VADDR_2_ID(block->btb_vaddr) + first_entry;

	memset(null_addrs, 0, sizeof(null_addrs));
	rc = __ef10_ef100_nic_buffer_table_set(nic, block, buffer_id, n_entries,
					       null_addrs);
	EFHW_DO_DEBUG(efhw_buffer_table_clear_debug(block, first_entry,
						    n_entries));
}


/*--------------------------------------------------------------------
 *
 * PIO mgmt
 *
 *--------------------------------------------------------------------*/

int ef10_nic_piobuf_alloc(struct efhw_nic *nic, unsigned *handle_out)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_ALLOC_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_ALLOC_PIOBUF_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_ALLOC_PIOBUF,
				 sizeof(in), sizeof(out), &out_size, in, out);
	if ( rc != 0 )
		return rc;

	*handle_out = EFHW_MCDI_DWORD(out, ALLOC_PIOBUF_OUT_PIOBUF_HANDLE);
	return rc;
}


int ef10_nic_piobuf_free(struct efhw_nic *nic, unsigned handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_FREE_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_FREE_PIOBUF_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, FREE_PIOBUF_IN_PIOBUF_HANDLE, handle);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_FREE_PIOBUF,
				 sizeof(in), sizeof(out), &out_size, in, out);
	return rc;
}


int ef10_nic_piobuf_link(struct efhw_nic *nic, unsigned txq, unsigned handle)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_LINK_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_LINK_PIOBUF_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, LINK_PIOBUF_IN_PIOBUF_HANDLE, handle);
	EFHW_MCDI_SET_DWORD(in, LINK_PIOBUF_IN_TXQ_INSTANCE, txq);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_LINK_PIOBUF,
				 sizeof(in), sizeof(out), &out_size, in, out);
	return rc;
}


int ef10_nic_piobuf_unlink(struct efhw_nic *nic, unsigned txq)
{
	int rc;
	size_t out_size;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_UNLINK_PIOBUF_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_UNLINK_PIOBUF_OUT_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	EFHW_MCDI_SET_DWORD(in, UNLINK_PIOBUF_IN_TXQ_INSTANCE, txq);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_UNLINK_PIOBUF,
				 sizeof(in), sizeof(out), &out_size, in, out);
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

	EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_CONTEXT,
			    rss_context);
	EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE,
		rss_context == -1 ?
		MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE_SIMPLE :
		MC_CMD_SET_TX_PORT_SNIFF_CONFIG_IN_RX_MODE_RSS);
	EFHW_MCDI_SET_DWORD(in, SET_TX_PORT_SNIFF_CONFIG_IN_RX_QUEUE, instance);
	EFHW_MCDI_POPULATE_DWORD_1(in, SET_TX_PORT_SNIFF_CONFIG_IN_FLAGS,
		SET_TX_PORT_SNIFF_CONFIG_IN_ENABLE, enable ? 1 : 0);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_SET_TX_PORT_SNIFF_CONFIG,
				 sizeof(in), 0, &out_size, in, NULL);
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
	EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_MODE,
		rss_context == -1 ?
		MC_CMD_SET_PORT_SNIFF_CONFIG_IN_RX_MODE_SIMPLE :
		MC_CMD_SET_PORT_SNIFF_CONFIG_IN_RX_MODE_RSS);
	EFHW_MCDI_SET_DWORD(in, SET_PORT_SNIFF_CONFIG_IN_RX_CONTEXT,
		rss_context);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_SET_PORT_SNIFF_CONFIG,
				 sizeof(in), 0, &out_size, in, NULL);
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
	if (do_reset) {
		flags = 1 << MC_CMD_RMON_STATS_RX_ERRORS_IN_RST_LBN;
	}
	EFHW_MCDI_SET_DWORD(in, RMON_STATS_RX_ERRORS_IN_FLAGS, flags);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_RMON_STATS_RX_ERRORS, sizeof(in),
				 out_size, &out_size, in, out);

	if (rc != 0)
		return rc;

	/* the following layout is used in lib/ciul/vi_stats.c */
	data_out[0] =
		EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_CRC_ERRORS);
	data_out[1] =
		EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_TRUNC_ERRORS);
	data_out[2] =
		EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_RX_NO_DESC_DROPS);
	data_out[3] =
		EFHW_MCDI_DWORD(out, RMON_STATS_RX_ERRORS_OUT_RX_ABORT);
	return rc;
}


int
ef10_vport_alloc(struct efhw_nic *nic, int vlan_id, unsigned *vport_id_out)
{
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_VPORT_ALLOC_IN_LEN);
	EFHW_MCDI_DECLARE_BUF(out, MC_CMD_VPORT_ALLOC_OUT_LEN);
	size_t out_size;
	int rc;

	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_INITIALISE_BUF(out);

	if (vlan_id > 4095)
		return -EINVAL;

	EFHW_MCDI_SET_DWORD(in, VPORT_ALLOC_IN_UPSTREAM_PORT_ID,
			    EVB_PORT_ID_ASSIGNED);
	EFHW_MCDI_SET_DWORD(in, VPORT_ALLOC_IN_TYPE,
			    MC_CMD_VPORT_ALLOC_IN_VPORT_TYPE_NORMAL);
	if (vlan_id >= 0) {
		EFHW_MCDI_SET_DWORD(in, VPORT_ALLOC_IN_NUM_VLAN_TAGS, 1);
		EFHW_MCDI_POPULATE_DWORD_1(in, VPORT_ALLOC_IN_VLAN_TAGS,
					   VPORT_ALLOC_IN_VLAN_TAG_0, vlan_id);
	} else {
		EFHW_MCDI_SET_DWORD(in, VPORT_ALLOC_IN_NUM_VLAN_TAGS, 0);
	}
	EFHW_MCDI_POPULATE_DWORD_1(in, VPORT_ALLOC_IN_FLAGS,
				   VPORT_ALLOC_IN_FLAG_AUTO_PORT, 0);

	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_VPORT_ALLOC, sizeof(in), sizeof(out),
				 &out_size, in, out);
	MCDI_CHECK(MC_CMD_VPORT_ALLOC, rc, out_size, 0);
	if (rc)
		return rc;
	if (out_size < MC_CMD_VPORT_ALLOC_OUT_LEN)
		return -EIO;

	*vport_id_out = EFHW_MCDI_DWORD(out, VPORT_ALLOC_OUT_VPORT_ID);
	return 0;
}


void
ef10_vport_free(struct efhw_nic *nic, unsigned vport_id)
{
	size_t out_size;
	int rc;
	EFHW_MCDI_DECLARE_BUF(in, MC_CMD_VPORT_FREE_IN_LEN);
	EFHW_MCDI_INITIALISE_BUF(in);
	EFHW_MCDI_SET_DWORD(in, VPORT_FREE_IN_VPORT_ID, vport_id);
	rc = ef10_ef100_mcdi_rpc(nic, MC_CMD_VPORT_FREE, sizeof(in), 0,
				 &out_size, in, NULL);
	MCDI_CHECK(MC_CMD_VPORT_FREE, rc, out_size, 0);
}


/*--------------------------------------------------------------------
 *
 * AF_XDP
 *
 *--------------------------------------------------------------------*/

static void* ef10_af_xdp_mem(struct efhw_nic* nic, int instance)
{
  return NULL;
}

static int ef10_af_xdp_init(struct efhw_nic* nic, int instance,
                            int chunk_size, int headroom,
                            struct socket** sock_out,
                            struct efhw_page_map* pages_out)
{
  return 0;
}


/*--------------------------------------------------------------------
 *
 * Abstraction Layer Hooks
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops ef10_char_functional_units = {
	ef10_nic_init_hardware,
	ef10_nic_tweak_hardware,
	ef10_nic_release_hardware,
	ef10_nic_event_queue_enable,
	ef10_nic_event_queue_disable,
	ef10_nic_wakeup_request,
	ef10_nic_sw_event,
	ef10_handle_event,
	ef10_dmaq_tx_q_init,
	ef10_dmaq_rx_q_init,
	ef10_ef100_dmaq_tx_q_disable,
	ef10_ef100_dmaq_rx_q_disable,
	ef10_ef100_flush_tx_dma_channel,
	ef10_ef100_flush_rx_dma_channel,
	__ef10_nic_buffer_table_get_orders,
	sizeof(__ef10_nic_buffer_table_get_orders) /
		sizeof(__ef10_nic_buffer_table_get_orders[0]),
	ef10_ef100_nic_buffer_table_alloc,
	ef10_ef100_nic_buffer_table_realloc,
	ef10_ef100_nic_buffer_table_free,
	ef10_ef100_nic_buffer_table_set,
	ef10_ef100_nic_buffer_table_clear,
	ef10_nic_set_port_sniff,
	ef10_nic_set_tx_port_sniff,
	ef10_nic_license_challenge,
	ef10_nic_license_check,
	ef10_nic_v3_license_challenge,
	ef10_nic_v3_license_check,
	ef10_get_rx_error_stats,
	ef10_tx_alt_alloc,
	ef10_tx_alt_free,
	ef10_af_xdp_mem,
	ef10_af_xdp_init,
};
