/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#define EFX_IN_KCOMPAT_C 1

#include "efx.h"
#include "kernel_compat.h"
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/random.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/rtnetlink.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#ifdef EFX_HAVE_STRUCT_SIZE
#include <linux/overflow.h>
#endif
#include <linux/cpumask.h>
#include <asm/uaccess.h>
#ifdef EFX_HAVE_LINUX_EXPORT_H
#include <linux/export.h>
#endif
#if defined(EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO)
#include <linux/hwmon.h>
#endif
#ifdef EFX_TC_OFFLOAD
#ifndef EFX_HAVE_TC_FLOW_OFFLOAD
#include <net/tc_act/tc_pedit.h>
#include <net/tc_act/tc_mirred.h>
#include <net/tc_act/tc_vlan.h>
#include <net/tc_act/tc_tunnel_key.h>
#include <net/tc_act/tc_csum.h>
#include <net/tc_act/tc_gact.h>
#include <net/tc_act/tc_skbedit.h>
#endif
#endif

/*
 * Kernel backwards compatibility
 *
 * This file provides functionality missing from earlier kernels.
 */

#ifdef EFX_NEED_USLEEP_RANGE

void usleep_range(unsigned long min, unsigned long max)
{
	unsigned long delay = DIV_ROUND_UP(min, 1000) ? : 1;
	msleep(delay);
}

#endif

#ifdef EFX_NEED_NS_TO_TIMESPEC
#ifndef EFX_HAVE_TIMESPEC64

#include <linux/math64.h>

struct timespec ns_to_timespec(const s64 nsec)
{
	struct timespec ts;
	s32 rem;

	if (!nsec)
		return (struct timespec) {0, 0};

	ts.tv_sec = div_s64_rem(nsec, NSEC_PER_SEC, &rem);
	if (unlikely(rem < 0)) {
		ts.tv_sec--;
		rem += NSEC_PER_SEC;
	}
	ts.tv_nsec = rem;

	return ts;
}

#endif /* EFX_HAVE_TIMESPEC64 */
#endif /* EFX_NEED_NS_TO_TIMESPEC */

#ifdef EFX_HAVE_PARAM_BOOL_INT

int efx_param_set_bool(const char *val, struct kernel_param *kp)
{
	bool v;

	if (!val) {
		/* No equals means "set"... */
		v = true;
	} else {
		/* One of =[yYnN01] */
		switch (val[0]) {
		case 'y':
		case 'Y':
		case '1':
			v = true;
			break;
		case 'n':
		case 'N':
		case '0':
			v = false;
			break;
		default:
			return -EINVAL;
		}
	}

	*(bool *)kp->arg = v;
	return 0;
}

int efx_param_get_bool(char *buffer, struct kernel_param *kp)
{
	/* Y and N chosen as being relatively non-coder friendly */
	return sprintf(buffer, "%c", *(bool *)kp->arg ? 'Y' : 'N');
}

#endif /* EFX_HAVE_PARAM_BOOL_INT */

#ifndef EFX_HAVE_PCI_VFS_ASSIGNED
int pci_vfs_assigned(struct pci_dev *dev)
{
#if defined(CONFIG_PCI_ATS) && defined(EFX_HAVE_PCI_DEV_FLAGS_ASSIGNED)
	struct pci_dev *vfdev;
	int pos;
	unsigned int vfs_assigned = 0;
	unsigned short dev_id;

	/* only search if we are a PF */
	if (!dev->is_physfn)
		return 0;

	pos = pci_find_ext_capability(dev, PCI_EXT_CAP_ID_SRIOV);
	if (!pos)
		return 0;

	/*
	 * determine the device ID for the VFs, the vendor ID will be the
	 * same as the PF so there is no need to check for that one
	 */
	pci_read_config_word(dev, pos + PCI_SRIOV_VF_DID, &dev_id);

	/* loop through all the VFs to see if we own any that are assigned */
	vfdev = pci_get_device(dev->vendor, dev_id, NULL);
	while (vfdev) {
		/*
		 * It is considered assigned if it is a virtual function with
		 * our dev as the physical function and the assigned bit is set
		 */
		if (vfdev->is_virtfn && (vfdev->physfn == dev) &&
		    (vfdev->dev_flags & PCI_DEV_FLAGS_ASSIGNED))
			vfs_assigned++;

		vfdev = pci_get_device(dev->vendor, dev_id, vfdev);
	}

	return vfs_assigned;
#else
	return 0;
#endif
}
#endif
#ifdef EFX_HAVE_MSIX_CAP
#ifdef EFX_NEED_PCI_MSIX_VEC_COUNT
#ifndef msix_table_size
#define msix_table_size(flags)	((flags & PCI_MSIX_FLAGS_QSIZE) + 1)
#endif

/**
 * pci_msix_vec_count - return the number of device's MSI-X table entries
 * @dev: pointer to the pci_dev data structure of MSI-X device function
 * This function returns the number of device's MSI-X table entries and
 * therefore the number of MSI-X vectors device is capable of sending.
 * It returns a negative errno if the device is not capable of sending MSI-X
 * interrupts.
 **/
int pci_msix_vec_count(struct pci_dev *dev)
{
	u16 control;

	if (!dev->msix_cap)
		return -EINVAL;

	pci_read_config_word(dev, dev->msix_cap + PCI_MSIX_FLAGS, &control);
	return msix_table_size(control);
}
#endif
#endif

#if defined(EFX_NEED_CPUMASK_LOCAL_SPREAD) && (NR_CPUS != 1)
unsigned int cpumask_local_spread(unsigned int i, int node)
{
	int cpu;

	/* Wrap: we always want a cpu. */
	i %= num_online_cpus();

	if (node == -1) {
		for_each_cpu(cpu, cpu_online_mask)
			if (i-- == 0)
				return cpu;
	} else {
		/* NUMA first. */
		for_each_cpu(cpu, cpu_online_mask) {
			if (!cpumask_test_cpu(cpu, cpumask_of_node(node)))
				continue;
			if (i-- == 0)
				return cpu;
		}

		for_each_cpu(cpu, cpu_online_mask) {
			/* Skip NUMA nodes, done above. */
			if (cpumask_test_cpu(cpu, cpumask_of_node(node)))
				continue;

			if (i-- == 0)
				return cpu;
		}
	}
	BUG();
	/* silence compiler warning */
	return -EIO;
}
#endif

#ifdef EFX_NEED_D_HASH_AND_LOOKUP
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	/* The real in-kernel function checks for an FS specific hash.
	 * We only use this in debugfs handling, where there is no such
	 * hash.
	 */
	name->hash = full_name_hash(name->name, name->len);
	return d_lookup(dir, name);
}
#endif

#if defined(EFX_NEED_HWMON_DEVICE_REGISTER_WITH_INFO) && defined(CONFIG_SFC_MCDI_MON)
struct device *hwmon_device_register_with_info(
	struct device *dev,
	const char *name __always_unused,
	void *drvdata __always_unused,
	const struct hwmon_chip_info *info __always_unused,
	const struct attribute_group **extra_groups __always_unused)
{
	return hwmon_device_register(dev);
}
#endif

#ifdef EFX_TC_OFFLOAD
#ifndef EFX_HAVE_TC_FLOW_OFFLOAD
struct flow_rule *flow_rule_alloc(unsigned int num_actions)
{
	struct flow_rule *rule;

	rule = kzalloc(struct_size(rule, action.entries, num_actions),
		       GFP_KERNEL);
	if (!rule)
		return NULL;

	rule->action.num_entries = num_actions;

	return rule;
}

#define FLOW_DISSECTOR_MATCH(__rule, __type, __out)				\
	const struct flow_match *__m = &(__rule)->match;			\
	struct flow_dissector *__d = (__m)->dissector;				\
										\
	(__out)->key = skb_flow_dissector_target(__d, __type, (__m)->key);	\
	(__out)->mask = skb_flow_dissector_target(__d, __type, (__m)->mask);	\

void flow_rule_match_basic(const struct flow_rule *rule,
			   struct flow_match_basic *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_BASIC, out);
}

void flow_rule_match_control(const struct flow_rule *rule,
			     struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CONTROL, out);
}

void flow_rule_match_eth_addrs(const struct flow_rule *rule,
			       struct flow_match_eth_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ETH_ADDRS, out);
}

void flow_rule_match_vlan(const struct flow_rule *rule,
			  struct flow_match_vlan *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_VLAN, out);
}

#ifdef EFX_HAVE_FLOW_DISSECTOR_KEY_CVLAN
void flow_rule_match_cvlan(const struct flow_rule *rule,
			   struct flow_match_vlan *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_CVLAN, out);
}
#endif

void flow_rule_match_ipv4_addrs(const struct flow_rule *rule,
				struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV4_ADDRS, out);
}

void flow_rule_match_ipv6_addrs(const struct flow_rule *rule,
				struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IPV6_ADDRS, out);
}

void flow_rule_match_ip(const struct flow_rule *rule,
			struct flow_match_ip *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_IP, out);
}

void flow_rule_match_ports(const struct flow_rule *rule,
			   struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_PORTS, out);
}

void flow_rule_match_tcp(const struct flow_rule *rule,
			 struct flow_match_tcp *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_TCP, out);
}

void flow_rule_match_icmp(const struct flow_rule *rule,
			  struct flow_match_icmp *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ICMP, out);
}

void flow_rule_match_mpls(const struct flow_rule *rule,
			  struct flow_match_mpls *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_MPLS, out);
}

void flow_rule_match_enc_control(const struct flow_rule *rule,
				 struct flow_match_control *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_CONTROL, out);
}

void flow_rule_match_enc_ipv4_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv4_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV4_ADDRS, out);
}

void flow_rule_match_enc_ipv6_addrs(const struct flow_rule *rule,
				    struct flow_match_ipv6_addrs *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IPV6_ADDRS, out);
}

#ifdef EFX_HAVE_FLOW_DISSECTOR_KEY_ENC_IP
void flow_rule_match_enc_ip(const struct flow_rule *rule,
			    struct flow_match_ip *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_IP, out);
}
#endif

void flow_rule_match_enc_ports(const struct flow_rule *rule,
			       struct flow_match_ports *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_PORTS, out);
}

void flow_rule_match_enc_keyid(const struct flow_rule *rule,
			       struct flow_match_enc_keyid *out)
{
	FLOW_DISSECTOR_MATCH(rule, FLOW_DISSECTOR_KEY_ENC_KEYID, out);
}

#ifndef tcf_exts_for_each_action
#ifdef CONFIG_NET_CLS_ACT
#define tcf_exts_for_each_action(i, a, exts) \
	for (i = 0; i < TCA_ACT_MAX_PRIO && ((a) = (exts)->actions[i]); i++)
#else
#define tcf_exts_for_each_action(i, a, exts) \
	for (; 0; (void)(i), (void)(a), (void)(exts))
#endif
#endif

#ifdef EFX_NEED_TCF_MIRRED_DEV
static inline struct net_device *tcf_mirred_dev(const struct tc_action *a)
{
	return rtnl_dereference(to_mirred(a)->tcfm_dev);
}
#endif

unsigned int tcf_exts_num_actions(struct tcf_exts *exts)
{
	unsigned int num_acts = 0;
	struct tc_action *act;
	int i;

	tcf_exts_for_each_action(i, act, exts) {
		if (is_tcf_pedit(act))
			num_acts += tcf_pedit_nkeys(act);
		else
			num_acts++;
	}
	return num_acts;
}

int tc_setup_flow_action(struct flow_action *flow_action,
			 const struct tcf_exts *exts)
{
	const struct tc_action *act;
	int i, j, k;

	if (!exts)
		return 0;

	j = 0;
	tcf_exts_for_each_action(i, act, exts) {
		struct flow_action_entry *entry;

		entry = &flow_action->entries[j];
		if (is_tcf_gact_ok(act)) {
			entry->id = FLOW_ACTION_ACCEPT;
		} else if (is_tcf_gact_shot(act)) {
			entry->id = FLOW_ACTION_DROP;
		} else if (is_tcf_gact_trap(act)) {
			entry->id = FLOW_ACTION_TRAP;
		} else if (is_tcf_gact_goto_chain(act)) {
			entry->id = FLOW_ACTION_GOTO;
			entry->chain_index = tcf_gact_goto_chain_index(act);
		} else if (is_tcf_mirred_egress_redirect(act)) {
			entry->id = FLOW_ACTION_REDIRECT;
			entry->dev = tcf_mirred_dev(act);
		} else if (is_tcf_mirred_egress_mirror(act)) {
			entry->id = FLOW_ACTION_MIRRED;
			entry->dev = tcf_mirred_dev(act);
		} else if (is_tcf_vlan(act)) {
			switch (tcf_vlan_action(act)) {
			case TCA_VLAN_ACT_PUSH:
				entry->id = FLOW_ACTION_VLAN_PUSH;
				entry->vlan.vid = tcf_vlan_push_vid(act);
				entry->vlan.proto = tcf_vlan_push_proto(act);
				entry->vlan.prio = tcf_vlan_push_prio(act);
				break;
			case TCA_VLAN_ACT_POP:
				entry->id = FLOW_ACTION_VLAN_POP;
				break;
			case TCA_VLAN_ACT_MODIFY:
				entry->id = FLOW_ACTION_VLAN_MANGLE;
				entry->vlan.vid = tcf_vlan_push_vid(act);
				entry->vlan.proto = tcf_vlan_push_proto(act);
				entry->vlan.prio = tcf_vlan_push_prio(act);
				break;
			default:
				goto err_out;
			}
		} else if (is_tcf_tunnel_set(act)) {
			entry->id = FLOW_ACTION_TUNNEL_ENCAP;
			entry->tunnel = tcf_tunnel_info(act);
		} else if (is_tcf_tunnel_release(act)) {
			entry->id = FLOW_ACTION_TUNNEL_DECAP;
		} else if (is_tcf_pedit(act)) {
			for (k = 0; k < tcf_pedit_nkeys(act); k++) {
				switch (tcf_pedit_cmd(act, k)) {
				case TCA_PEDIT_KEY_EX_CMD_SET:
					entry->id = FLOW_ACTION_MANGLE;
					break;
				case TCA_PEDIT_KEY_EX_CMD_ADD:
					entry->id = FLOW_ACTION_ADD;
					break;
				default:
					goto err_out;
				}
				entry->mangle.htype = tcf_pedit_htype(act, k);
				entry->mangle.mask = tcf_pedit_mask(act, k);
				entry->mangle.val = tcf_pedit_val(act, k);
				entry->mangle.offset = tcf_pedit_offset(act, k);
				entry = &flow_action->entries[++j];
			}
		} else if (is_tcf_csum(act)) {
			entry->id = FLOW_ACTION_CSUM;
			entry->csum_flags = tcf_csum_update_flags(act);
		} else if (is_tcf_skbedit_mark(act)) {
			entry->id = FLOW_ACTION_MARK;
			entry->mark = tcf_skbedit_mark(act);
		} else {
			goto err_out;
		}

		if (!is_tcf_pedit(act))
			j++;
	}
	return 0;
err_out:
	return -EOPNOTSUPP;
}

struct flow_rule *efx_compat_flow_rule_build(struct tc_cls_flower_offload *tc)
{
	struct flow_rule *rule = flow_rule_alloc(tcf_exts_num_actions(tc->exts));
	int err;

	if (!rule)
		return ERR_PTR(-ENOMEM);
	rule->match.dissector = tc->dissector;
	rule->match.mask = tc->mask;
	rule->match.key = tc->key;
	err = tc_setup_flow_action(&rule->action, tc->exts);
	if (err) {
		kfree(rule);
		return ERR_PTR(err);
	}
	return rule;
}
#endif /* EFX_HAVE_TC_FLOW_OFFLOAD */
#endif /* EFX_TC_OFFLOAD */

#if !defined(EFX_HAVE_PCI_FIND_NEXT_EXT_CAPABILITY)

#define PCI_CFG_SPACE_SIZE    256
#define PCI_CFG_SPACE_EXP_SIZE        4096

int pci_find_next_ext_capability(struct pci_dev *dev, int start, int cap)
{
	u32 header;
	int ttl;
	int pos = PCI_CFG_SPACE_SIZE;

	/* minimum 8 bytes per capability */
	ttl = (PCI_CFG_SPACE_EXP_SIZE - PCI_CFG_SPACE_SIZE) / 8;

	if (dev->cfg_size <= PCI_CFG_SPACE_SIZE)
		return 0;

	if (start)
		pos = start;

	if (pci_read_config_dword(dev, pos, &header) != PCIBIOS_SUCCESSFUL)
		return 0;

	/*
	 * If we have no capabilities, this is indicated by cap ID,
	 * cap version and next pointer all being 0.
	 */
	if (header == 0)
		return 0;

	while (ttl-- > 0) {
		if (PCI_EXT_CAP_ID(header) == cap && pos != start)
			return pos;

		pos = PCI_EXT_CAP_NEXT(header);
		if (pos < PCI_CFG_SPACE_SIZE)
			break;

		if (pci_read_config_dword(dev, pos, &header) != PCIBIOS_SUCCESSFUL)
			break;
	}

	return 0;
}

#endif

#ifdef EFX_USE_DEVLINK

#ifdef EFX_NEED_DEVLINK_FLASH_UPDATE_TIMEOUT_NOTIFY
void devlink_flash_update_timeout_notify(struct devlink *devlink,
					 const char *status_msg,
					 const char *component,
					 unsigned long timeout)
{
	/* Treat as a status notifcation with no timeout indicated */
	devlink_flash_update_status_notify(devlink, status_msg, component, 0, 0);
}
#endif

#else

static int efx_devlink_info_add(struct devlink_info_req *req,
				const char *prefix, const char *name,
				const char *value)
{
	int offset = strlen(req->buf);

	scnprintf(&req->buf[offset], req->bufsize - offset, "%s%s: %s\n",
		  prefix, name, value);
	return 0;
}

int devlink_info_serial_number_put(struct devlink_info_req *req, const char *sn)
{
	return efx_devlink_info_add(req, "", "serial_number", sn);
}

int devlink_info_driver_name_put(struct devlink_info_req *req, const char *name)
{
	return efx_devlink_info_add(req, "", "driver", name);
}

int devlink_info_board_serial_number_put(struct devlink_info_req *req,
					 const char *bsn)
{
	return efx_devlink_info_add(req, "board.", "serial_number", bsn);
}

int devlink_info_version_fixed_put(struct devlink_info_req *req,
				   const char *version_name,
				   const char *version_value)
{
	return efx_devlink_info_add(req, "fixed.", version_name, version_value);
}

int devlink_info_version_stored_put(struct devlink_info_req *req,
				    const char *version_name,
				    const char *version_value)
{
	return efx_devlink_info_add(req, "stored.", version_name,
				    version_value);
}

int devlink_info_version_running_put(struct devlink_info_req *req,
				     const char *version_name,
				     const char *version_value)
{
	return efx_devlink_info_add(req, "running.", version_name,
				    version_value);
}

#endif	/* !EFX_USE_DEVLINK */

#ifdef CONFIG_DEBUG_FS
void debugfs_lookup_and_remove(const char *name, struct dentry *dir)
{
	struct qstr child_name = QSTR_INIT(name, strlen(name));
	struct dentry *child;

	child = d_hash_and_lookup(dir, &child_name);
	if (!IS_ERR_OR_NULL(child)) {
		/* If it's a "regular" file, free its parameter binding */
		if (S_ISREG(child->d_inode->i_mode))
			kfree(child->d_inode->i_private);
		debugfs_remove(child);
		dput(child);
	}
}
#endif	/* CONFIG_DEBUGFS */
