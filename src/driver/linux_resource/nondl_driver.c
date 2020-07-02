/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* This file contains the resource driver management for non driverlink
 * devices. */

#include "linux_resource_internal.h"
#include "kernel_compat.h"
#include <ci/efrm/efrm_client.h>
#include <ci/efrm/nondl.h>
#include <linux/rtnetlink.h>

static int efrm_nondl_register_device(struct efrm_nondl_handle *handle)
{
        int rc;

        ASSERT_RTNL();
        EFRM_ERR("%s: register %s", __func__, handle->device->netdev->name);
        rc = efrm_nic_add_device(handle->device->netdev, handle->device->n_vis);

        return rc;
}

static void efrm_nondl_unregister_device(struct efrm_nondl_handle *handle)
{
        ASSERT_RTNL();
        EFRM_ERR("%s: unregister %s", __func__, handle->device->netdev->name);
        efrm_nic_del_device(handle->device->netdev);
}

static void efrm_nondl_start_device(struct efrm_nondl_handle *handle)
{
        ASSERT_RTNL();
        EFRM_ERR("%s: start %s", __func__, handle->device->netdev->name);
}

static void efrm_nondl_stop_device(struct efrm_nondl_handle *handle)
{
        ASSERT_RTNL();
        EFRM_ERR("%s: stop %s", __func__, handle->device->netdev->name);
}

static struct efrm_nondl_driver efrm_nondl_driver = {
        .register_device = efrm_nondl_register_device,
        .unregister_device = efrm_nondl_unregister_device,
        .start_device = efrm_nondl_start_device,
        .stop_device = efrm_nondl_stop_device,
};

extern void efrm_nondl_register(void)
{
        int rc;

        rc = efrm_nondl_register_driver(&efrm_nondl_driver);
        if(rc < 0) {
                EFRM_ERR("Couldn't register driver: %d\n", rc);
        }
}

extern void efrm_nondl_unregister(void)
{
        efrm_nondl_unregister_driver(&efrm_nondl_driver);
}
