/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* TODO:
 *
 * - When reconfigure cpu_to_q map, redirect existing filters...?  (Only
 * those that specified cpu rather than rxq of course).
 */

#include <ci/affinity/k_drv_intf.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/ctype.h>
#include <ci/compat/sysdep.h>
#include <ci/driver/efab/hardware.h>
#include <ci/driver/driverlink_api.h>
#include <ci/driver/chrdev.h>
#include <linux/nsproxy.h>

#include "kernel_compat.h"


#define T(x)  x
#define E(x)  x


MODULE_AUTHOR("Solarflare Communications");
MODULE_LICENSE("GPL");


struct aff_interface {
	struct list_head all_interfaces_link;
	struct efx_dl_device *dl_device;
	int* cpu_to_q;
	char proc_name[12];
	struct proc_dir_entry *proc_dir;
};


static struct efx_dl_driver dl_driver;
static LIST_HEAD(all_interfaces);
static DEFINE_MUTEX(lock);
static struct proc_dir_entry *aff_proc_root;


/* simple_strtol() does not strip leading whitespace. */
static long strtol(const char *s, char **p_end, unsigned int base)
{
	while (isspace(*s))
		++s;
	return simple_strtol(s, p_end, base);
}


static int aff_proc_read_int(struct seq_file *seq, void *s)
{
	int *pint = seq->private;
	seq_printf(seq, "%d\n", *pint);
	return 0;
}
static int aff_proc_open_int(struct inode *inode, struct file *file)
{
	return single_open(file, aff_proc_read_int, PDE_DATA(inode));
}
static const struct proc_ops aff_proc_fops_int = {
	PROC_OPS_SET_OWNER
	.proc_open	= aff_proc_open_int,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};


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


static struct aff_interface *interface_find(const struct net_device* dev)
{
	/* Caller must hold [lock]. */
	struct aff_interface *intf;
	list_for_each_entry(intf, &all_interfaces, all_interfaces_link)
		if (intf->dl_device->priv == dev)
			return intf;
	return NULL;
}


static void interface_add_proc(struct aff_interface *intf,
			       const char *name, void *data,
			       const struct proc_ops *proc_fops)
{
	proc_create_data(name, 0444, intf->proc_dir, proc_fops, data);
}


static void interface_add_proc_int(struct aff_interface *intf,
				   const char *name, int *data)
{
	interface_add_proc(intf, name, data, &aff_proc_fops_int);
}


static void interface_add_proc_entries(struct aff_interface *intf)
{
	static int zero = 0;
	intf->proc_dir = proc_mkdir(intf->proc_name, aff_proc_root);
	if (intf->proc_dir != NULL) {
		struct net_device* dev = intf->dl_device->priv;
		interface_add_proc_int(intf, "ifindex", &dev->ifindex);
		/* n_rxqs is a legacy feature from old hardware: leave the file
		 * present for backward-compatibility, but always report zero */
		interface_add_proc_int(intf, "n_rxqs", &zero);
		interface_add_proc(intf, "cpu2rxq", intf,
				   &aff_proc_fops_cpu2rxq);
	}
}


static void interface_remove_proc_entries(struct aff_interface *intf)
{
	if (intf->proc_dir != NULL) {
		remove_proc_entry("ifindex", intf->proc_dir);
		remove_proc_entry("n_rxqs", intf->proc_dir);
		remove_proc_entry("cpu2rxq", intf->proc_dir);
		intf->proc_dir = NULL;
	}
	remove_proc_entry(intf->proc_name, aff_proc_root);
}


static struct aff_interface *interface_up(const struct net_device* dev,
										  struct efx_dl_device *dl_dev)
{
	int i, add_proc = 0, n_cpus = num_possible_cpus();
	struct aff_interface *new_intf;
	struct aff_interface *intf;
	int *new_cpu_to_q;

	new_intf = kmalloc(sizeof(*new_intf), GFP_KERNEL);
	new_cpu_to_q = kmalloc(n_cpus * sizeof(int), GFP_KERNEL);

	mutex_lock(&lock);
	if ((intf = interface_find(dev)) == NULL) {
		printk(KERN_NOTICE "[sfcaffinity] interface_up: %d NEW\n",
		       dev->ifindex);
		intf = new_intf;
		new_intf = NULL;
		sprintf(intf->proc_name, "%d", dev->ifindex);
		intf->cpu_to_q = NULL;
	} else {
		printk(KERN_NOTICE "[sfcaffinity] interface_up: %d RESURECT\n",
		       dev->ifindex);
	}
	if (intf->cpu_to_q == NULL) {
		intf->cpu_to_q = new_cpu_to_q;
		new_cpu_to_q = NULL;
		for (i = 0; i < n_cpus; ++i)
			intf->cpu_to_q[i] = -1;
	}
	intf->dl_device = dl_dev;
	dl_dev->priv = (void*)dev;
	if (! new_intf) {
		list_add(&intf->all_interfaces_link, &all_interfaces);
		add_proc = 1;
	}
	mutex_unlock(&lock);

	/* This must be after dropping mutex as proc_mkdir() can block */
	if (add_proc)
		interface_add_proc_entries(intf);

	kfree(new_cpu_to_q);
	kfree(new_intf);
	return intf;
}


static struct net_device* dev_get_in_current_netns(int ifindex)
{
	return dev_get_by_index(current->nsproxy->net_ns, ifindex);
}


static int interface_configure(struct net_device* dev,
                               const int *cpu_to_q)
{
	int n_cpus = num_possible_cpus();
	struct aff_interface *intf;
	int rc;

	rc = -EINVAL;

	mutex_lock(&lock);
	if ((intf = interface_find(dev)) == NULL) {
		printk(KERN_ERR "[sfcaffinity] ERROR: unknown ifindex=%d\n",
		       dev->ifindex);
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


static int aff_proc_init(void)
{
	struct proc_dir_entry *pde;
	int rc = -ENOMEM;

	aff_proc_root = proc_mkdir("driver/sfc_affinity", NULL);
	if (aff_proc_root == NULL)
		goto fail1;

	pde = proc_create("new_interface", 0644, aff_proc_root,
			&aff_proc_fops_new_interface);
	if (pde == NULL)
		goto fail1;
	return 0;

fail1:
	return rc;
}


static void aff_proc_fini(void)
{
	remove_proc_entry("new_interface", aff_proc_root);
	remove_proc_entry("driver/sfc_affinity", NULL);
}


static int fop_open(struct inode *inode, struct file *filp)
{
	return 0;
}


static int fop_close(struct inode *inode, struct file *filp) 
{
	return 0;
}


struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = fop_open,
	.release = fop_close,
};


static struct aff_interface* interface_down(struct net_device *dev)
{
	struct aff_interface *intf;

	mutex_lock(&lock);
	if ((intf = interface_find(dev)) != NULL) {
		list_del(&intf->all_interfaces_link);
	}
	mutex_unlock(&lock);
	return intf;
}


static void interface_free(struct aff_interface *intf)
{
	interface_remove_proc_entries(intf);
	kfree(intf->cpu_to_q);
	kfree(intf);
}


static int dl_probe(struct efx_dl_device* dl_dev,
		    const struct net_device* net_dev,
		    const struct efx_dl_device_info* dev_info,
		    const char* silicon_rev)
{
	printk(KERN_NOTICE "[sfcaffinity] probe ifindex=%d\n",
	       net_dev->ifindex);
	if (interface_up(net_dev, dl_dev) == NULL)
		return -1;
	return 0;
}


static void dl_remove(struct efx_dl_device* dl_dev)
{
	struct net_device *net_dev = dl_dev->priv;
	printk(KERN_NOTICE "[sfcaffinity] remove ifindex=%d\n",
	       net_dev->ifindex);
	interface_free(interface_down(net_dev));
}


static struct efx_dl_driver dl_driver = {
  .name   = "sfcaffinity",
  .priority = EFX_DL_EV_LOW,
  /* This flag is required to for the driver to register with the net
   * driver however this driver will never receive packets so it will
   * not be doing any actual checking. */
  .flags = EFX_DL_DRIVER_CHECKS_FALCON_RX_USR_BUF_SIZE |
	   EFX_DL_DRIVER_CHECKS_MEDFORD2_VI_STRIDE,
  .probe  = dl_probe,
  .remove = dl_remove,
};


static struct ci_chrdev_registration* sfc_affinity_chrdev;


static int __init init_sfc_affinity(void)
{
	int rc;

	T(printk("sfc_affinity: starting\n"));

	rc = aff_proc_init();
	if (rc < 0)
		goto fail1;

	rc = efx_dl_register_driver(&dl_driver);
	if (rc < 0)
		goto fail2;

	rc = create_one_chrdev_and_mknod(0, "sfc_affinity", &fops,
	                                 &sfc_affinity_chrdev);
	if (rc < 0)
		goto fail3;

	return 0;

fail3:
	efx_dl_unregister_driver(&dl_driver);
fail2:
	aff_proc_fini();
fail1:
	return rc;
}


static void cleanup_sfc_affinity(void)
{
	/* TODO shouldn't this take [lock]? */
	T(printk("sfc_affinity: cleaning up\n"));
	destroy_chrdev_and_mknod(sfc_affinity_chrdev);
	efx_dl_unregister_driver(&dl_driver);
	while (! list_empty(&all_interfaces)) {
		struct aff_interface *intf;
		intf = list_entry(all_interfaces.next, struct aff_interface,
				  all_interfaces_link);
		list_del(&intf->all_interfaces_link);
		interface_free(intf);
	}
	aff_proc_fini();
	T(printk("sfc_affinity: unloaded\n"));
}


module_init(init_sfc_affinity);
module_exit(cleanup_sfc_affinity);


int sfc_affinity_cpu_to_channel_dev(const struct net_device* dev, int cpu)
{
	struct aff_interface *intf;
	int rc = -1;
	mutex_lock(&lock);
	if (cpu >= 0 && cpu < num_possible_cpus() &&
	    (intf = interface_find(dev)) != NULL)
		rc = intf->cpu_to_q[cpu];
	mutex_unlock(&lock);
	return rc;
}
EXPORT_SYMBOL(sfc_affinity_cpu_to_channel_dev);
