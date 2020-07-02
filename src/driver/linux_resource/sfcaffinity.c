/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <ci/compat/sysdep.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/driverlink_api.h>
#include <ci/driver/chrdev.h>
#include <ci/driver/resource/linux_efhw_nic.h>
#include <ci/efhw/nic.h>
#include <ci/efrm/debug.h>
#include <ci/efrm/kernel_proc.h>
#include <linux/nsproxy.h>

#include "kernel_compat.h"
#include "sfcaffinity.h"


#define T(x)  x
#define E(x)  x


struct aff_interface {
	struct list_head all_interfaces_link;
	struct linux_efhw_nic* nic;
	int* cpu_to_q;
	efrm_pd_handle cpu_to_q_file;
};


static LIST_HEAD(all_interfaces);
static DEFINE_MUTEX(lock);
static efrm_pd_handle new_interface;


/* simple_strtol() does not strip leading whitespace. */
static long strtol(const char *s, char **p_end, unsigned int base)
{
	while (isspace(*s))
		++s;
	return simple_strtol(s, p_end, base);
}


static int aff_proc_read_cpu2rxq(struct seq_file *seq, void *s)
{
	/* ?? fixme: this really needs to grab [lock] */
	struct aff_interface *intf = seq->private;
	int n_cpus = num_online_cpus();
	int i;
	mutex_lock(&lock);
	for (i = 0; i < n_cpus; ++i)
		seq_printf(seq, "%s%d", i == 0 ? "":" ", intf->cpu_to_q[i]);
	mutex_unlock(&lock);
	seq_printf(seq, "\n");
	return 0;
}
static int aff_proc_open_cpu2rxq(struct inode *inode, struct file *file)
{
	return single_open(file, aff_proc_read_cpu2rxq, PDE_DATA(inode));
}
static const struct proc_ops aff_proc_fops_cpu2rxq = {
	PROC_OPS_SET_OWNER
	.proc_open	= aff_proc_open_cpu2rxq,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};


static struct aff_interface *interface_find(const struct linux_efhw_nic* nic)
{
	/* Caller must hold [lock]. */
	struct aff_interface *intf;
	list_for_each_entry(intf, &all_interfaces, all_interfaces_link)
		if (intf->nic == nic)
			return intf;
	return NULL;
}


static struct aff_interface *interface_find_by_dev(const struct net_device* dev)
{
	/* Caller must hold [lock]. */
	struct aff_interface *intf;
	struct net_device* nic_dev;

	EFRM_ASSERT(dev);

	list_for_each_entry(intf, &all_interfaces, all_interfaces_link) {
	        nic_dev = efhw_nic_get_net_dev(&intf->nic->efrm_nic.efhw_nic);
		if (nic_dev == dev) {
			dev_put(nic_dev);
			return intf;
		}
		dev_put(nic_dev);
	}

	return NULL;
}


void efrm_affinity_interface_up(struct linux_efhw_nic* nic)
{
	int i, add_proc = 0, n_cpus = num_possible_cpus();
	struct aff_interface *new_intf;
	struct aff_interface *intf;
	int *new_cpu_to_q;

	new_intf = kmalloc(sizeof(*new_intf), GFP_KERNEL);
	new_cpu_to_q = kmalloc(n_cpus * sizeof(int), GFP_KERNEL);

	mutex_lock(&lock);
	if ((intf = interface_find(nic)) == NULL) {
		intf = new_intf;
		new_intf = NULL;
		intf->cpu_to_q = NULL;
	}
	if (intf->cpu_to_q == NULL) {
		intf->cpu_to_q = new_cpu_to_q;
		new_cpu_to_q = NULL;
		for (i = 0; i < n_cpus; ++i)
			intf->cpu_to_q[i] = -1;
	}
	intf->nic = nic;
	if (! new_intf) {
		list_add(&intf->all_interfaces_link, &all_interfaces);
		add_proc = 1;
	}
	mutex_unlock(&lock);

	/* This must be after dropping mutex as proc_mkdir() can block */
	if (add_proc) {
		intf->cpu_to_q_file = efrm_proc_create_file("cpu2rxq", 0444,
						nic->proc_dir,
						&aff_proc_fops_cpu2rxq, intf);
	}

	kfree(new_cpu_to_q);
	kfree(new_intf);
}


static struct net_device* dev_get_in_current_netns(int ifindex)
{
	return dev_get_by_index(current->nsproxy->net_ns, ifindex);
}


static int interface_configure(struct net_device* dev, const int *cpu_to_q)
{
	int n_cpus = num_possible_cpus();
	struct aff_interface *intf;
	int rc;

	rc = -EINVAL;

	mutex_lock(&lock);
	if ((intf = interface_find_by_dev(dev)) == NULL) {
		EFRM_ERR("ERROR: unknown affiinity ifindex=%d", dev->ifindex);
		goto fail1;
	}
	memcpy(intf->cpu_to_q, cpu_to_q, n_cpus * sizeof(intf->cpu_to_q[0]));
	mutex_unlock(&lock);
	return 0;

fail1:
	mutex_unlock(&lock);
	return rc;
}


static ssize_t aff_proc_write_new_interface(struct file *file,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	int max_cpus = num_possible_cpus();
	int i, rc, ifindex;
	int *cpu_to_q;
	char *buf, *s;
	struct net_device* dev;

	rc = -E2BIG;
	if (count > max_cpus * 8 + 20)
		goto fail1;
	rc = -ENOMEM;
	cpu_to_q = kmalloc(max_cpus * sizeof(int), GFP_KERNEL);
	if (cpu_to_q == NULL)
		goto fail1;
	buf = kmalloc(count + 1, GFP_KERNEL);
	if (buf == NULL)
		goto fail2;
	rc = -EFAULT;
	if (copy_from_user(buf, buffer, count))
		goto fail3;
	buf[count] = '\0';
	s = buf;
	ifindex = strtol(s, &s, 0);
	/*n_rxqs =*/ strtol(s, &s, 0);  /* discarded field: not used on modern
	                                 * NICs */
	for (i = 0; i < max_cpus; ++i)
		cpu_to_q[i] = strtol(s, &s, 0);
	for (; i < max_cpus; ++i)
		cpu_to_q[i] = 0;
	while (isspace(*s))
		++s;
	rc = -EINVAL;
	if (*s)
		goto fail3;
	dev = dev_get_in_current_netns(ifindex);
	if (! dev)
		goto fail3;
	interface_configure(dev, cpu_to_q);
	dev_put(dev);
	rc = count;
fail3:
	kfree(buf);
fail2:
	kfree(cpu_to_q);
fail1:
	return rc;
}
static const struct proc_ops aff_proc_fops_new_interface = {
	PROC_OPS_SET_OWNER
	.proc_write		= aff_proc_write_new_interface,
};


static void interface_free(struct aff_interface *intf)
{
	efrm_proc_remove_file(intf->cpu_to_q_file);
        kfree(intf->cpu_to_q);
        kfree(intf);
}


void efrm_affinity_interface_down(struct linux_efhw_nic* nic)
{
	struct aff_interface *intf;

	mutex_lock(&lock);
	if ((intf = interface_find(nic)) != NULL) {
		list_del(&intf->all_interfaces_link);
	}
	mutex_unlock(&lock);

	interface_free(intf);
}


int efrm_affinity_install_proc_entries(void)
{
	new_interface = efrm_proc_create_file("new_interface", 0644, NULL,
					      &aff_proc_fops_new_interface,
					      NULL);
	return new_interface ? 0 : -1;
}


void efrm_affinity_remove_proc_entries(void)
{
	/* TODO shouldn't this take [lock]? */
	while (! list_empty(&all_interfaces)) {
		struct aff_interface *intf;
		intf = list_entry(all_interfaces.next, struct aff_interface,
				  all_interfaces_link);
		list_del(&intf->all_interfaces_link);
		interface_free(intf);
	}

	efrm_proc_remove_file(new_interface);
	new_interface = NULL;
}


int efrm_affinity_cpu_to_channel_dev(const struct net_device* dev, int cpu)
{
	struct aff_interface *intf;
	int rc = -1;
	mutex_lock(&lock);
	if (cpu >= 0 && cpu < num_possible_cpus() &&
	    (intf = interface_find_by_dev(dev)) != NULL)
		rc = intf->cpu_to_q[cpu];
	mutex_unlock(&lock);
	return rc;
}
