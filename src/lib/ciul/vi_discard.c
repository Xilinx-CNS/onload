/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2016-2020 Xilinx, Inc. */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_SOURCE>
** \author  Paul Emberson <pemberson@solarflare.com>
**  \brief  Configure which errors cause rx discard
**   \date  2016/01
**    \cop  (c) Solarflare Communications, Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/
#include <etherfabric/vi.h>
#include "ef_vi_internal.h"
#include <ci/tools/byteorder.h>

static int
ef10_ef_vi_receive_set_discards(ef_vi* vi, unsigned discard_err_flags)
{
  uint64_t mask = 0;

  if( discard_err_flags & EF_VI_DISCARD_RX_ETH_LEN_ERR )
    mask |= 1LL << ESF_DZ_RX_ECC_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_L4_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_TCPUDP_CKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_L3_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_IPCKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_INNER_L4_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_INNER_TCPUDP_CKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_INNER_L3_CSUM_ERR )
    mask |= 1LL << ESF_DZ_RX_INNER_IPCKSUM_ERR_LBN;
  if( discard_err_flags & EF_VI_DISCARD_RX_ETH_FCS_ERR )
    mask |= 1LL << ESF_DZ_RX_ECRC_ERR_LBN;

  vi->rx_discard_mask = CI_BSWAPC_LE64(mask);
  return 0;
}


int
ef_vi_receive_set_discards(ef_vi* vi, unsigned discard_err_flags)
{
  switch( vi->nic_type.arch ) {
  case EF_VI_ARCH_EF10:
    return ef10_ef_vi_receive_set_discards(vi, discard_err_flags);
  case EF_VI_ARCH_EF100:
    /* FIXME: copy from ef10 */
    return ef10_ef_vi_receive_set_discards(vi, discard_err_flags);
  default:
    EF_VI_BUG_ON(1);
    return -EINVAL;
  }
}

