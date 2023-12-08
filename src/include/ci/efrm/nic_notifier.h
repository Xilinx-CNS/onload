/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */

#ifndef CI_EFRM_NIC_NOTIFIER_H
#define CI_EFRM_NIC_NOTIFIER_H


struct efhw_nic;


struct efrm_nic_notifier {
        int (*probe)(const struct efhw_nic *nic, const struct net_device *dev);
        void (*remove)(const struct efhw_nic *nic);
};


extern void efrm_register_nic_notifier(struct efrm_nic_notifier* notifier);
extern void efrm_unregister_nic_notifier(struct efrm_nic_notifier* notifier);


#endif /* CI_EFRM_NIC_NOTIFIER_H */
