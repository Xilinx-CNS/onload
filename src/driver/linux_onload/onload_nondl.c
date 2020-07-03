/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/* This file contains the resource driver management for non driverlink
 * devices. */

#include <ci/internal/transport_config_opt.h>

#include <linux/netdevice.h>
#include <onload/debug.h>
#include <onload/nic.h>
#include <ci/efrm/nondl.h>
#include "onload_internal.h"

static int oo_nondl_register_device(struct efrm_nondl_handle *handle)
{
        ASSERT_RTNL();
        ci_log("%s: register %s", __func__, handle->device->netdev->name);

        return 0;
}

static void oo_nondl_unregister_device(struct efrm_nondl_handle *handle)
{
        ASSERT_RTNL();
        ci_log("%s: unregister %s", __func__, handle->device->netdev->name);
}

static void oo_nondl_start_device(struct efrm_nondl_handle *handle)
{
        struct oo_nic* onic;
        ASSERT_RTNL();
        ci_log("%s: start %s", __func__, handle->device->netdev->name);


        onic = oo_nic_find_dev(handle->device->netdev);
        if( onic != NULL ) {
                ci_log("%s: device %s came back",
                       __func__, handle->device->netdev->name);
        } else {
                onic = oo_netdev_may_add(handle->device->netdev);
        }

        if(onic == NULL) {
                ci_log("%s: couldn't add device %s",
                       __func__, handle->device->netdev->name);

        } else if( netif_running(handle->device->netdev) ) {
                oo_netdev_up(handle->device->netdev);

        }
}

static void oo_nondl_stop_device(struct efrm_nondl_handle *handle)
{
        ASSERT_RTNL();
        ci_log("%s: stop %s", __func__, handle->device->netdev->name);
        oo_common_remove(handle->device->netdev);
}

static struct efrm_nondl_driver oo_nondl_driver = {
        .register_device = oo_nondl_register_device,
        .unregister_device = oo_nondl_unregister_device,
        .start_device = oo_nondl_start_device,
        .stop_device = oo_nondl_stop_device,
};

extern void oo_nondl_register(void)
{
        int rc;

        rc = efrm_nondl_register_driver(&oo_nondl_driver);
        if(rc < 0) {
                ci_log("Couldn't register driver: %d\n", rc);
        }
}

extern void oo_nondl_unregister(void)
{
        efrm_nondl_unregister_driver(&oo_nondl_driver);
}
