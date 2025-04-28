/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2008-2020 Xilinx, Inc. */
#ifndef __ONLOAD_NIC_H__
#define __ONLOAD_NIC_H__


#define OO_NIC_BLACKLIST 0x1
#define OO_NIC_WHITELIST 0x2 


struct oo_nic {
  struct efrm_client* efrm_client;
#define OO_NIC_UP         0x00000001u  /* Interface is currently IFF_UP. */
#define OO_NIC_UNPLUGGED  0x00000002u  /* Interface has been hot-unplugged. */
#define OO_NIC_LL         0x00000004u  /* Interface is preferred LL port */
#define OO_NIC_FALLBACK   0x00000008u  /* Interface is fallback for LL port */
  unsigned            oo_nic_flags;
#ifdef __KERNEL__
#if CI_CFG_WANT_BPF_NATIVE && CI_HAVE_BPF_NATIVE
  struct bpf_prog*    prog;
#endif
#endif
  /* Set with OO_NIC_LL to indicate alternate fallback port for same net_dev.
   * Set with OO_NIC_FALLBACK to indicate alternate primary port for same
   * net_dev. */
  int alternate_hwport;
};


extern struct oo_nic oo_nics[];

extern void oo_nic_failover_from_hwport(int hwport);

struct efhw_nic;
extern struct oo_nic* oo_nic_add(const struct efhw_nic* nic);

extern struct oo_nic* oo_nic_find(const struct efhw_nic* nic);
extern struct oo_nic* oo_nic_find_by_net_dev(const struct net_device* dev,
                                             uint64_t require_flags,
                                             uint64_t reject_flags);

extern int oo_nic_hwport(struct oo_nic*);

extern int oo_check_nic_suitable_for_onload(struct oo_nic* onic);

extern int oo_check_nic_llct(struct oo_nic* onic);

extern void oo_nic_shutdown(void);

extern struct oo_nic *oo_netdev_may_add(const struct net_device *net_dev);

extern void oo_common_remove(const struct net_device* dev);

extern void oo_netdev_up(const struct net_device* netdev);

#endif  /* __ONLOAD_NIC_H__ */
