/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: Copyright (C) 2023, Advanced Micro Devices, Inc. */

#ifndef EFRM_DEBUGFS_H
#define EFRM_DEBUGFS_H

extern void efrm_init_debugfs(void);
extern void efrm_fini_debugfs(void);

extern void efhw_init_debugfs_nic(struct efhw_nic *nic);
extern void efhw_fini_debugfs_nic(struct efhw_nic *nic);

extern void efhw_init_debugfs_efct(struct efhw_nic *nic);
extern void efhw_fini_debugfs_efct(struct efhw_nic *nic);

#ifdef CONFIG_DEBUG_FS
struct seq_file;

struct efrm_debugfs_parameter {
  const char *name;
  size_t offset;
  int (*reader)(struct seq_file *, const void *);
};

extern struct dentry* efrm_debug_nics;

/* Helpers for handling debugfs entry reads */
extern int efrm_debugfs_read_u16(struct seq_file *file, const void *data);
extern int efrm_debugfs_read_x16(struct seq_file *, const void *);
extern int efrm_debugfs_read_s16(struct seq_file *, const void *);
extern int efrm_debugfs_read_u32(struct seq_file *file, const void *data);
extern int efrm_debugfs_read_x32(struct seq_file *, const void *);
extern int efrm_debugfs_read_s32(struct seq_file *, const void *);
extern int efrm_debugfs_read_u64(struct seq_file *, const void *);
extern int efrm_debugfs_read_x64(struct seq_file *, const void *);
extern int efrm_debugfs_read_atomic(struct seq_file *, const void *);
extern int efrm_debugfs_read_bool(struct seq_file *, const void *);
extern int efrm_debugfs_read_string(struct seq_file *, const void *);


/* Handy macros for filling out parameters */
#define STRING_TABLE_LOOKUP(val, member) \
  (((val) < member ## _max) && member ## _names[val] ? member ## _names[val] : \
                                                       "(invalid)")

/* Initialiser for a struct efrm_debugfs_parameter without type-checking */
#define _EFRM_RAW_PARAMETER(_name, reader_function) { \
  .name = #_name, \
  .offset = 0, \
  .reader = reader_function, \
}

/* This has to be valid to use in the middle of struct definition, which
 * means we can't use something like typecheck() directly. */
#define TYPECHECK_OFFSET(field_type, container_type, parameter) \
  ((((field_type *) 0) == &((container_type *) 0)->parameter) ? \
                            offsetof(container_type, parameter) : \
                            offsetof(container_type, parameter))

/* Initialiser for a struct efrm_debugfs_parameter with type-checking */
#define EFRM_PARAMETER(container_type, parameter, field_type, \
                       reader_function) { \
  .name = #parameter, \
  .offset = TYPECHECK_OFFSET(field_type, container_type, parameter), \
  .reader = reader_function, \
}


#define EFRM_U16_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 u16, efrm_debugfs_read_u16)

#define EFRM_X16_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 u16, efrm_debugfs_read_x16)

#define EFRM_S16_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 s16, efrm_debugfs_read_s16)

#define EFRM_U32_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 u32, efrm_debugfs_read_u32)

#define EFRM_X32_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 u32, efrm_debugfs_read_x32)

#define EFRM_S32_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 s32, efrm_debugfs_read_s32)

#define EFRM_U64_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, u64, efrm_debugfs_read_u64)

#define EFRM_X64_PARAMETER(container_type, parameter)            \
  EFRM_PARAMETER(container_type, parameter, u64, efrm_debugfs_read_x64)

#define EFRM_ATOMIC_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, \
                 atomic_t, efrm_debugfs_read_atomic)

#define EFRM_BOOL_PARAMETER(container_type, parameter) \
  EFRM_PARAMETER(container_type, parameter, bool, efrm_debugfs_read_bool)

#define EFRM_STRING_PARAMETER(container_type, parameter) { \
  .name = #parameter, \
  .offset = TYPECHECK_OFFSET((char*), container_type, parameter), \
  .reader = efrm_debugfs_read_string, \
}


extern void efrm_init_debugfs_files(struct efrm_debugfs_dir *debug_dir,
                       const struct efrm_debugfs_parameter *params,
                       void *ref);
extern void efrm_fini_debugfs_files(struct efrm_debugfs_dir *debug_dir);

#endif /* CONFIG_DEBUG_FS */

#endif /* EFRM_DEBUGFS_H */
