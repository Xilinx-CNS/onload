/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Copyright 2009-2020 Xilinx, Inc. */

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

#include <ci/driver/kernel_compat.h>
#include "sfcaffinity.h"

static DEFINE_MUTEX(lock);

int efrm_affinity_show_cpu2rxq(struct linux_efhw_nic* nic, char* buf)
{
	int n_cpus = num_possible_cpus();
	int i, rc = 0;
	int written = 0;
	mutex_lock(&lock);
	for (i = 0; i < n_cpus; ++i) {
		char c = i == n_cpus - 1 ? '\n' : ' ';
		rc = scnprintf(buf + written, PAGE_SIZE - written, "%d%c", nic->cpu_to_q[i], c);
		if( rc < 0 )
			break;
		rc = written += rc;
	}
	mutex_unlock(&lock);
	return rc;
}


int efrm_affinity_interface_probe(struct linux_efhw_nic* nic)
{
	int n_cpus = num_possible_cpus();
	int *new_cpu_to_q;
	int i;

	new_cpu_to_q = kmalloc(n_cpus * sizeof(int), GFP_KERNEL);

	if (new_cpu_to_q == NULL)
		return -ENOMEM;

	for (i = 0; i < n_cpus; ++i)
		new_cpu_to_q[i] = -1;

	mutex_lock(&lock);
	nic->cpu_to_q = new_cpu_to_q;
	mutex_unlock(&lock);
	return 0;
}

void efrm_affinity_interface_remove(struct linux_efhw_nic* nic)
{
	int *new_cpu_to_q;
	mutex_lock(&lock);
	new_cpu_to_q = nic->cpu_to_q;
	nic->cpu_to_q = NULL;
	mutex_unlock(&lock);
	kfree(new_cpu_to_q);
}

static int interface_configure(struct linux_efhw_nic* nic, const int *cpu_to_q)
{
	int n_cpus = num_possible_cpus();

	mutex_lock(&lock);
	memcpy(nic->cpu_to_q, cpu_to_q, n_cpus * sizeof(nic->cpu_to_q[0]));
	mutex_unlock(&lock);
	return 0;
}


ssize_t efrm_affinity_store_cpu2rxq(struct linux_efhw_nic* nic,
				    const char* buf,
				    size_t count)
{
	int max_cpus = num_possible_cpus();
	int i;
	int *cpu_to_q;
	int rc = -EINVAL;
	const char* s = buf;

	if (count > max_cpus * 8 + 20)
		return -E2BIG;
	cpu_to_q = kmalloc(max_cpus * sizeof(int), GFP_KERNEL);
	if (cpu_to_q == NULL)
		return -ENOMEM;

	for (i = 0; i < max_cpus; ++i) {
		int v;
		int rc2;
		for(;;) {
			if (s >= buf + count)
				goto fail;
			if (!isspace(*s))
				break;
			++s;
		}
		rc2 = sscanf(s, "%d", &v);
		if (rc2 < 0 || v < -1 || v >= max_cpus)
			goto fail;
		cpu_to_q[i] = v;
		for(;;) {
			if (s >= buf + count)
				goto fail;
			if (isspace(*s))
				break;
			++s;
		}
	}
	while (s < buf + count && isspace(*s))
		++s;

	if (s == buf + count) {
		interface_configure(nic, cpu_to_q);
		rc = count;
	}
fail:
	kfree(cpu_to_q);
	return rc;
}

int efrm_affinity_cpu_to_channel_dev(const struct linux_efhw_nic* nic, int cpu)
{
	int rc = -1;
	mutex_lock(&lock);
	EFRM_ASSERT(nic->cpu_to_q);
	if (cpu >= 0 && cpu < num_possible_cpus())
		rc = nic->cpu_to_q[cpu];
	mutex_unlock(&lock);
	return rc;
}
