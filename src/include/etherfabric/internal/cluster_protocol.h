/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __EFAB_CLUSTER_PROTOCOL_H__
#define __EFAB_CLUSTER_PROTOCOL_H__

/* Internal interfaces, so exclude from doxygen documentation */
/*! \cond internal */

/* WARNING!!! This file is not part of the public ef_vi API and should
 * not be included by any applications. */

/* src/tool/solar_clusterd will need updating if you update any of the
 * definitions below
 */

/*
 *  \brief  Cluster Daemon Protocol
 *   \date  2013/11/28
 */


#define CLUSTERD_PROTOCOL_VERSION 1

/*
 * Default file names and location.
 * For example, /tmp/solar_clusterd-root/solar_clusterd.log
 */
#define DEFAULT_CLUSTERD_DIR       "/tmp/solar_clusterd-"
#define DEFAULT_CLUSTERD_SOCK_NAME "solar_clusterd"

#define MSGLEN_MAX 255

enum cluster_req {
  CLUSTERD_VERSION_REQ,
  CLUSTERD_VERSION_RESP,
  CLUSTERD_ALLOC_CLUSTER_REQ,
  CLUSTERD_ALLOC_CLUSTER_RESP,
};

enum cluster_result_code {
  CLUSTERD_ERR_SUCCESS,
  CLUSTERD_ERR_FAIL,
  CLUSTERD_ERR_BAD_REQUEST,
};

/*! \endcond internal */

#endif /* __EFAB_CLUSTER_PROTOCOL_H__ */
