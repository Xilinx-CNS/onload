/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#include <linux/module.h>
#include <linux/debugfs.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "linux_resource_internal.h"
#include "debugfs.h"

#ifdef CONFIG_DEBUG_FS

/* Parameter definition bound to a structure - each file has one of these */
struct efrm_debugfs_bound_param {
  const struct efrm_debugfs_parameter *param;
  void *ref;
};


#ifdef EFRM_NEED_DEBUGFS_LOOKUP_AND_REMOVE
/* Compat for linux<5.19. */
void debugfs_lookup_and_remove(const char *name, struct dentry *dir)
{
  struct dentry *child = debugfs_lookup(name, dir);

  if (child) {
    debugfs_remove(child);
    dput(child);
  }
}
#endif


/* Top-level debug directory ([/sys/kernel]/debug/sfc_resource) */
static struct dentry *efrm_debug_root;

/* "nics" directory ([/sys/kernel]/debug/sfc_resource/nics) */
struct dentry *efrm_debug_nics;

/* Sequential file interface to bound parameters */

static int efrm_debugfs_seq_show(struct seq_file *file, void *v)
{
  struct efrm_debugfs_bound_param *binding = file->private;

  return binding->param->reader(file, binding->ref + binding->param->offset);
}

static int efrm_debugfs_open(struct inode *inode, struct file *file)
{
  return single_open(file, efrm_debugfs_seq_show, inode->i_private);
}


static struct file_operations efrm_debugfs_file_ops = {
  .owner   = THIS_MODULE,
  .open    = efrm_debugfs_open,
  .read    = seq_read,
  .llseek  = seq_lseek,
  .release = single_release
};

static int efrm_debugfs_params_len(const struct efrm_debugfs_parameter *params)
{
  int len = 0;

  while( params++->name )
    ++len;

  return len;
}

/* Functions for printing various types of parameter. */

#define EFRM_READ_PARAM(name, format, type) \
int efrm_debugfs_read_##name(struct seq_file *file, const void *data) { \
    seq_printf(file, format"\n", *(type *)data); \
    return 0; \
}

EFRM_READ_PARAM(u16, "%u", u16)
EFRM_READ_PARAM(x16, "0x%x", u16)
EFRM_READ_PARAM(s16, "%d", s16)
EFRM_READ_PARAM(u32, "%u", u32)
EFRM_READ_PARAM(x32, "0x%x", u32)
EFRM_READ_PARAM(s32, "%d", s32)
EFRM_READ_PARAM(u64, "%llu", u64)
EFRM_READ_PARAM(x64, "0x%llx", u64)
EFRM_READ_PARAM(bool, "%d", bool)
EFRM_READ_PARAM(string, "%s", const char*)

int efrm_debugfs_read_atomic(struct seq_file *file, const void *data)
{
  unsigned int value = atomic_read((atomic_t *) data);

  seq_printf(file, "%#x\n", value);
  return 0;
}

int efrm_debugfs_read_mac(struct seq_file *file, const void *data)
{
  const struct efhw_nic *nic = data;
  seq_printf(file, "%pM\n", &nic->mac_addr);
  return 0;
}

int efrm_debugfs_read_netdev_name(struct seq_file *file, const void *data)
{
  const struct efhw_nic *nic = data;
  seq_printf(file, "%s\n", nic->net_dev->name);
  return 0;
}

int efrm_debugfs_read_devname(struct seq_file *file, const void *data)
{
  const struct efhw_nic *nic = data;
  seq_printf(file, "%s\n", nic->dev ? dev_name(nic->dev) : "no dev");
  return 0;
}


/**
 * efrm_init_debugfs_files - create parameter-files in a debugfs directory
 * @debug_dir: Pointer to struct holding the containing directory
 * @params: Pointer to zero-terminated parameter definition array
 * @ref: Pointer passed to reader function
 *
 * Add parameter-files to the given debugfs directory.
 */
void efrm_init_debugfs_files(struct efrm_debugfs_dir *debug_dir,
                             const struct efrm_debugfs_parameter *params,
                             void *ref)
{
  struct efrm_debugfs_bound_param *bindings;
  unsigned int pos = 0;

  if (IS_ERR_OR_NULL(debug_dir->dir))
    return;

  bindings = kmalloc(sizeof(*bindings) * efrm_debugfs_params_len(params),
                     GFP_KERNEL);
  if (!bindings)
    goto err;

  for (pos = 0; params[pos].name; pos++) {
    struct dentry *entry;

    bindings[pos].param = &params[pos];
    bindings[pos].ref = ref;

    entry = debugfs_create_file(params[pos].name, S_IRUGO, debug_dir->dir,
                                &bindings[pos], &efrm_debugfs_file_ops);
    if (IS_ERR_OR_NULL(entry)) {
      kfree(bindings);
      EFRM_ERR("%s failed, rc=%ld.\n", __FUNCTION__, PTR_ERR(entry));
      goto err;
    }
  }

  debug_dir->bindings = bindings;
  return;

err:
  while (pos--)
    debugfs_lookup_and_remove(params[pos].name, debug_dir->dir);
}

void efrm_fini_debugfs_files(struct efrm_debugfs_dir *debug_dir)
{
  kfree(debug_dir->bindings);
  /* debugfs_remove is ok to pass ERR_OR_NULL here */
  debugfs_remove_recursive(debug_dir->dir);
  debug_dir->dir = NULL;
}

/**
 * efrm_init_debugfs - create debugfs directories for sfc_resource
 *
 * Create debugfs directories "sfc_resource" and "sfc_resource/nics".
 * This must be called before any of the other functions that create debugfs
 * directories.  The directories must be cleaned up using
 * efrm_fini_debugfs().
 */
void efrm_init_debugfs(void)
{
  int rc;

  /* Create top-level directory */
  efrm_debug_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
  if (IS_ERR_OR_NULL(efrm_debug_root)) {
    rc = PTR_ERR(efrm_debug_root);
    EFRM_ERR("debugfs_create_dir %s failed, rc=%d.\n", KBUILD_MODNAME, rc);
    return;
  }

  /* Create "nics" directory */
  efrm_debug_nics = debugfs_create_dir("nics", efrm_debug_root);
  if (IS_ERR_OR_NULL(efrm_debug_nics)) {
    rc = PTR_ERR(efrm_debug_nics);
    EFRM_ERR("debugfs_create_dir nics failed, rc=%d.\n", rc);
  }
}

/**
 * efrm_fini_debugfs - remove debugfs directories for sfc_resource
 *
 * Remove directories created by efrm_init_debugfs().
 */
void efrm_fini_debugfs(void)
{
  /* It's safe to do this even if the intial init failed, as debugfs functions
   * are explicitly written to handle being passed error values. */
  debugfs_remove_recursive(efrm_debug_root);
  efrm_debug_nics = NULL;
  efrm_debug_root = NULL;
}

#else /* !CONFIG_DEBUG_FS */

void efhw_init_debugfs(void)
{
  return 0;
}

void efhw_fini_debugfs(void) {}

#endif /* CONFIG_DEBUG_FS */
