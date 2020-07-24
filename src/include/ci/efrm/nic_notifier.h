/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef CI_EFRM_NIC_NOTIFIER_H
#define CI_EFRM_NIC_NOTIFIER_H


struct net_device;


struct efrm_nic_notifier {
        int (*probe)(const struct net_device *net_dev);
        void (*remove)(const struct net_device *net_dev);
};


extern void efrm_register_nic_notifier(struct efrm_nic_notifier* notifier);
extern void efrm_unregister_nic_notifier(struct efrm_nic_notifier* notifier);


#endif /* CI_EFRM_NIC_NOTIFIER_H */
