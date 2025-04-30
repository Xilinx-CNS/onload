/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <ci/compat.h>
#include <ci/tools.h>
#include <onload/debug.h>
#include <onload/shrub_spawner.h>
#include <onload/fd_private.h>
#include <etherfabric/shrub_shared.h>

#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>

#include "onload_kernel_compat.h"

int shrub_spawn_server(char* controller_id)
{
  int rc = 0;
  char* argv_cmd = "/usr/bin/shrub_controller";
  char* argv[] = {
    argv_cmd,
    "-c",
    controller_id,
    NULL
  };
  char* envp_flags = "EF_VI_PD_FLAGS=llct";
  char* envp[] = {
    envp_flags,
    NULL
  };

  printk(KERN_INFO "controller_name: controller-%s\n", controller_id);

  rc = ci_call_usermodehelper(argv_cmd, argv, envp, UMH_WAIT_EXEC
    #ifdef UMH_KILLABLE
                                                    | UMH_KILLABLE
    #endif
                                  );
  return rc;
}

int oo_shrub_spawn_server(ci_private_t *priv, void *arg) {
  int rc;
  shrub_ioctl_data_t *shrub_data = (shrub_ioctl_data_t *) arg;
  char controller_id[EF_SHRUB_MAX_DIGITS];

  if ( shrub_data->controller_id > EF_SHRUB_MAX_CONTROLLER ) {
    printk(KERN_ERR "controller_id out of range: %u\n", shrub_data->controller_id);
    return -EINVAL;
  }

  rc = snprintf(controller_id, sizeof(controller_id), "%u", shrub_data->controller_id);
  if ( rc < 0 || rc >= sizeof(controller_id) )
    return -EINVAL;
  return shrub_spawn_server(controller_id);
}

int oo_shrub_set_sockets(ci_private_t *priv, void* arg) {
  int rc;
  shrub_socket_ioctl_data_t *shrub_data = (shrub_socket_ioctl_data_t *) arg;
  tcp_helper_resource_t* trs;
  struct ef_vi* vi;
  if (priv->thr == NULL)
    return -EINVAL;
  trs = priv->thr;
  vi = ci_netif_vi(&trs->netif, shrub_data->intf_i);
  return efct_ubufs_set_shared(vi, shrub_data->controller_id, shrub_data->shrub_socket_id);
}
