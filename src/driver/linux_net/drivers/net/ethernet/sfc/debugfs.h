/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DEBUGFS_H
#define EFX_DEBUGFS_H
#ifdef CONFIG_SFC_VDPA
#include "ef100_vdpa.h"
#endif

struct seq_file;

struct efx_debugfs_parameter {
	const char *name;
	size_t offset;
	int (*reader)(struct seq_file *, void *);
};

#ifdef CONFIG_DEBUG_FS
void efx_fini_debugfs_child(struct dentry *dir, const char *name);
int efx_init_debugfs_netdev(struct net_device *net_dev);
void efx_fini_debugfs_netdev(struct net_device *net_dev);
void efx_update_debugfs_netdev(struct efx_nic *efx);
int efx_init_debugfs_nic(struct efx_nic *efx);
void efx_fini_debugfs_nic(struct efx_nic *efx);
int efx_init_debugfs_channels(struct efx_nic *efx);
void efx_fini_debugfs_channels(struct efx_nic *efx);
int efx_init_debugfs(const char *module);
void efx_fini_debugfs(void);
int efx_extend_debugfs_port(struct efx_nic *efx,
			    void *context, u64 ignore,
			    const struct efx_debugfs_parameter *params);
void efx_trim_debugfs_port(struct efx_nic *efx,
			   const struct efx_debugfs_parameter *params);
#ifdef CONFIG_SFC_VDPA
int efx_init_debugfs_vdpa(struct ef100_vdpa_nic *vdpa);
void efx_fini_debugfs_vdpa(struct ef100_vdpa_nic *vdpa);
int efx_init_debugfs_vdpa_vring(struct ef100_vdpa_nic *vdpa,
				struct ef100_vdpa_vring_info *vdpa_vring,
				u16 idx);
void efx_fini_debugfs_vdpa_vring(struct ef100_vdpa_vring_info *vdpa_vring);
#endif

/* Helpers for handling debugfs entry reads */
int efx_debugfs_read_ushort(struct seq_file *file, void *data);
int efx_debugfs_read_uint(struct seq_file *, void *);
int efx_debugfs_read_ulong(struct seq_file *, void *);
int efx_debugfs_read_string(struct seq_file *, void *);
int efx_debugfs_read_int(struct seq_file *, void *);
int efx_debugfs_read_atomic(struct seq_file *, void *);
int efx_debugfs_read_dword(struct seq_file *, void *);
int efx_debugfs_read_u64(struct seq_file *, void *);
int efx_debugfs_read_bool(struct seq_file *, void *);
#ifdef CONFIG_SFC_VDPA
int efx_debugfs_read_x64(struct seq_file *, void *);
#endif

/* Handy macros for filling out parameters */

/* Initialiser for a struct efx_debugfs_parameter without type-checking */
#define _EFX_RAW_PARAMETER(_name, reader_function) {			\
	.name = #_name,							\
	.offset = 0,							\
	.reader = reader_function,					\
}

/* Initialiser for a struct efx_debugfs_parameter without type-checking */
#define _EFX_PARAMETER(container_type, parameter, reader_function) {	\
	.name = #parameter,						\
	.offset = offsetof(container_type, parameter),			\
	.reader = reader_function,					\
}

/* Initialiser for a struct efx_debugfs_parameter with type-checking */
#define EFX_PARAMETER(container_type, parameter, field_type,		\
			reader_function) {				\
	.name = #parameter,						\
	.offset = ((((field_type *) 0) ==				\
		    &((container_type *) 0)->parameter) ?		\
		   offsetof(container_type, parameter) :		\
		   offsetof(container_type, parameter)),		\
	.reader = reader_function,					\
}

/* Likewise, but the file name is not taken from the field name */
#define EFX_NAMED_PARAMETER(_name, container_type, parameter, field_type, \
				reader_function) {			\
	.name = #_name,							\
	.offset = ((((field_type *) 0) ==				\
		    &((container_type *) 0)->parameter) ?		\
		   offsetof(container_type, parameter) :		\
		   offsetof(container_type, parameter)),		\
	.reader = reader_function,					\
}

/* Likewise, but with one file for each of 4 lanes */
#define EFX_PER_LANE_PARAMETER(prefix, suffix, container_type, parameter, \
				field_type, reader_function) {		\
	.name = prefix "0" suffix,					\
	.offset = ((((field_type *) 0) ==				\
		      ((container_type *) 0)->parameter) ?		\
		    offsetof(container_type, parameter[0]) :		\
		    offsetof(container_type, parameter[0])),		\
	.reader = reader_function,					\
},  {									\
	.name = prefix "1" suffix,					\
	.offset = offsetof(container_type, parameter[1]),		\
	.reader = reader_function,					\
}, {									\
	.name = prefix "2" suffix,					\
	.offset = offsetof(container_type, parameter[2]),		\
	.reader = reader_function,					\
}, {									\
	.name = prefix "3" suffix,					\
	.offset = offsetof(container_type, parameter[3]),		\
	.reader = reader_function,					\
}

/* A string parameter (string embedded in the structure) */
#define EFX_STRING_PARAMETER(container_type, parameter) {	\
	.name = #parameter,					\
	.offset = ((((char *) 0) ==				\
		    ((container_type *) 0)->parameter) ?	\
		   offsetof(container_type, parameter) :	\
		   offsetof(container_type, parameter)),	\
	.reader = efx_debugfs_read_string,			\
}

/* An unsigned short parameter */
#define EFX_USHORT_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      unsigned short, efx_debugfs_read_ushort)

/* An unsigned integer parameter */
#define EFX_UINT_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      unsigned int, efx_debugfs_read_uint)

/* An unsigned long integer parameter */
#define EFX_ULONG_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      unsigned long, efx_debugfs_read_ulong)

/* A dword parameter */
#define EFX_DWORD_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      efx_dword_t, efx_debugfs_read_dword)

/* A u64 parameter */
#define EFX_U64_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      u64, efx_debugfs_read_u64)

/* A u64 hex parameter */
#define EFX_X64_PARAMETER(container_type, parameter)            \
	EFX_PARAMETER(container_type, parameter,                \
			u64, efx_debugfs_read_x64)

/* An atomic_t parameter */
#define EFX_ATOMIC_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      atomic_t, efx_debugfs_read_atomic)

/* An integer parameter */
#define EFX_INT_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      int, efx_debugfs_read_int)

#define EFX_BOOL_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,		\
		      bool, efx_debugfs_read_bool)

/* utility functions common between farch and ef10 */
void efx_debugfs_print_filter(char *s, size_t l, struct efx_filter_spec *spec);
#ifdef EFX_NOT_UPSTREAM
int efx_debugfs_read_kernel_blocked(struct seq_file *file, void *data);
#endif

#else /* !CONFIG_DEBUG_FS */

static inline int efx_init_debugfs_netdev(struct net_device *net_dev)
{
	return 0;
}
static inline void efx_fini_debugfs_netdev(struct net_device *net_dev) {}

static inline void efx_update_debugfs_netdev(struct efx_nic *efx) {}

static inline int efx_init_debugfs_port(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_port(struct efx_nic *efx) {}
static inline int efx_init_debugfs_nic(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_nic(struct efx_nic *efx) {}
static inline int efx_init_debugfs_channels(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_channels(struct efx_nic *efx) {}
static inline int efx_init_debugfs(const char *module)
{
	return 0;
}
static inline void efx_fini_debugfs(void) {}

static inline
int efx_extend_debugfs_port(struct efx_nic *efx,
			    void *context, u64 ignore,
			    const struct efx_debugfs_parameter *params)
{
	return 0;
}

static inline
void efx_trim_debugfs_port(struct efx_nic *efx,
			   const struct efx_debugfs_parameter *params)
{
}

#ifdef CONFIG_SFC_VDPA
static inline int efx_init_debugfs_vdpa(struct ef100_vdpa_nic *vdpa)
{
	return 0;
}

static inline void efx_fini_debugfs_vdpa(struct ef100_vdpa_nic *vdpa)
{
}

static inline
int efx_init_debugfs_vdpa_vring(struct ef100_vdpa_nic *vdpa,
				struct ef100_vdpa_vring_info *vdpa_vring,
				u16 idx)
{
	return 0;
}

static inline
void efx_fini_debugfs_vdpa_vring(struct ef100_vdpa_vring_info *vdpa_vring)
{
}
#endif
#endif /* CONFIG_DEBUG_FS */

#endif /* EFX_DEBUGFS_H */
