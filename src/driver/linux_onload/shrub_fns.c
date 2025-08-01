/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2025 Advanced Micro Devices, Inc. */

#include <ci/compat.h>
#include <ci/tools.h>
#include <onload/debug.h>
#include <onload/shrub_fns.h>
#include <onload/fd_private.h>
#include <etherfabric/shrub_shared.h>

#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/moduleparam.h>
#include <linux/spinlock.h>

#include "onload_kernel_compat.h"

/*
 * Onload module parameters for shrub controller.
 */

#ifndef DEFAULT_SHRUB_CONTROLLER_PATH
#define DEFAULT_SHRUB_CONTROLLER_PATH "/sbin/shrub_controller"
#endif

static char* shrub_controller_path = NULL;

static DEFINE_SPINLOCK(shrub_lock);

static char* shrub_get_controller_path(void)
{
  return shrub_controller_path != NULL && *shrub_controller_path != '\0' ?
           shrub_controller_path :
           DEFAULT_SHRUB_CONTROLLER_PATH;
}

static int shrub_controller_path_set(const char* val,
                                     const struct kernel_param* kp)
{
  char* old_path;
  char* new_path = kstrdup(skip_spaces(val), GFP_KERNEL);

  if( new_path == NULL )
    return -ENOMEM;

  strim(new_path);

  spin_lock(&shrub_lock);
  old_path = shrub_controller_path;
  shrub_controller_path = new_path;
  spin_unlock(&shrub_lock);

  kfree(old_path);

  return 0;
}

static int shrub_controller_path_get(char* buffer,
                                     const struct kernel_param* kp)
{
  char* path;
  int len;

  spin_lock(&shrub_lock);
  path = shrub_get_controller_path();
  /* The magic 4096 is documented in linux/moduleparam.h. */
  strncpy(buffer, path, 4096);
  buffer[4095] = '\0';
  len = strnlen(buffer, 4096);
  spin_unlock(&shrub_lock);

  return len;
}

static const struct kernel_param_ops shrub_controller_path_ops = {
  .set = shrub_controller_path_set,
  .get = shrub_controller_path_get,
};
module_param_cb(shrub_controller_path, &shrub_controller_path_ops,
                NULL, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(shrub_controller_path,
                 "Sets the path to the shrub_controller binary. Defaults to "
                 DEFAULT_SHRUB_CONTROLLER_PATH" if empty.");

int shrub_spawn_server(char* controller_id)
{
  int rc = 0;
  char* path;
  char* argv[] = {
    NULL,
    "-c",
    controller_id,
    NULL
  };
  char* envp_flags = "";
  char* envp[] = {
    envp_flags,
    NULL
  };

  spin_lock(&shrub_lock);
  path = kstrdup(shrub_get_controller_path(), GFP_KERNEL);
  spin_unlock(&shrub_lock);

  if ( !path )
    return -ENOMEM;

  argv[0] = path;
  OO_DEBUG_TCPH(ci_log("%s: pid=%d path=%s controller_id=%s", __FUNCTION__,
                       task_tgid_nr(current), path, controller_id));

  rc = ci_call_usermodehelper(path, argv, envp, UMH_WAIT_EXEC
    #ifdef UMH_KILLABLE
                                                    | UMH_KILLABLE
    #endif
                                  );
  if ( rc == -ENOENT )
    LOG_E(ci_log("%s: No such file %s. Is onload installed properly?",
                 __FUNCTION__, path));
  kfree(path);
  return rc;
}

int oo_shrub_spawn_server(ci_private_t *priv, void *arg) {
  int rc;
  shrub_ioctl_data_t *shrub_data;
  char controller_id[EF_SHRUB_MAX_DIGITS];
  
  if ( !priv || !arg ) 
    return -EINVAL;
  
  shrub_data = (shrub_ioctl_data_t *) arg;

  if ( shrub_data->controller_id > EF_SHRUB_MAX_CONTROLLER ) {
    LOG_E(ci_log("%s: ERROR: controller_id out of range: %d\n",
          __FUNCTION__, shrub_data->controller_id));
    return -EINVAL;
  }

  rc = snprintf(controller_id, sizeof(controller_id), "%u", shrub_data->controller_id);
  if ( rc < 0 || rc >= sizeof(controller_id) )
    return -EINVAL;
  return shrub_spawn_server(controller_id);
}

int oo_shrub_set_sockets(ci_private_t *priv, void* arg) {
  shrub_socket_ioctl_data_t *shrub_data = (shrub_socket_ioctl_data_t *) arg;
  tcp_helper_resource_t* trs;
  struct ef_vi* vi;

  if ( !priv || !arg ) 
    return -EINVAL;

  if ( priv->thr == NULL )
    return -EINVAL;

  if ( shrub_data->controller_id > EF_SHRUB_MAX_CONTROLLER ) {
    LOG_E(ci_log("%s: ERROR: controller_id out of range: %d\n",
      __FUNCTION__, shrub_data->controller_id));
    return -EINVAL;
  }

  if ( shrub_data->shrub_socket_id > EF_SHRUB_MAX_SHRUB ) {
    LOG_E(ci_log("%s: ERROR: shrub_socket_id out of range: %d\n",
      __FUNCTION__, shrub_data->shrub_socket_id));
    return -EINVAL;
  }

  trs = priv->thr;
  vi = ci_netif_vi(&trs->netif, shrub_data->intf_i);
  return efct_ubufs_set_shared(vi, shrub_data->controller_id, shrub_data->shrub_socket_id);
}

int
oo_shrub_driver_ctor(void)
{
  return 0;
}

int
oo_shrub_driver_dtor(void)
{
  if( shrub_controller_path != NULL )
    kfree(shrub_controller_path);
  return 0;
}
