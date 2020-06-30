/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __EFAB_SLICE_EXTS_H__
#define __EFAB_SLICE_EXTS_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

struct ef_pd;
/* A handle to an extension, as opened by ef_vi_open_extension() */
typedef struct ef_vi_extension_s ef_vi_extension;  /* opaque */
/* This type is identical to libuuid's uuid_t, but without forcing us to add
 * that as a dependency */
typedef unsigned char ef_vi_uuid_t[16];

struct ef_vi_extension_info {
  /* Identifier of the extension. This value is passed to
   * ef_vi_open_extension() to interface with the extension or just to
   * query further information. */
  ef_vi_uuid_t id;
  /* Extensions are grouped in to administrative buckets, where each
   * extension with the same admin_group is in the same bucket. Extensions
   * sharing an admin_group are loaded/unloaded/upgraded/etc. as a unit
   * at the hardware level. */
  unsigned admin_group;
  unsigned reserved[7];
};

/* Returns the list of facilities which are currently loaded in to the FPGA
 * dynamic region and which can be applied with ef_vi_open_extension().
 *
 * exts is an array of size num_exts which is populated with the list of
 * loaded extensions. The number of elements actually present is the
 * return value of this function. It is recommended that callers allocate
 * space for a minimum of 32 exts, and future hardware may allow
 * significantly more.
 *
 * Applications may obtain notification when the set of available
 * extensions changes by creating an event queue and watching for the
 * EF100_CTL_EV_PLUGIN_CHANGE control event.
 *
 * The flags parameter is currently unused and must be 0.
 *
 * Return values:
 *  >=0: success: the number of exts actually retrieved
 *  -E2BIG: there are more than num_exts extensions currently loaded
 *  -EINVAL: invalid parameter
 *  <0: any other error
 */
int ef_vi_query_extensions(struct ef_pd* pd, ef_driver_handle pd_dh,
                           struct ef_vi_extension_info* exts, size_t num_exts,
                           unsigned flags);


enum ef_ext_flags {
  /* Create a handle for metadata querying purposes only. The
   * ef_vi_extension_send_message() function will not be available.
   * Query-only handles require fewer privileges. */
  EF_EXT_QUERY_ONLY = 0x01,
};

/* Open a handle to an extension loaded in to the FPGA dynamic region. The
 * extension must have been pre-loaded by an administrator using the tools
 * available for that purpose.
 *
 * The 'id' parameter identifies the specific piece of functionality to
 * open. The flags parameter must be a bitwise OR of the ef_ext_flags
 * enumerators.
 *
 * Use ef_vi_close_extension() to close the returned handle.
 *
 * Return values:
 *  0: success
 *  -EINVAL: invalid parameter
 *  -ENOENT: id parameter is not found/not currently loaded on the FPGA.
 *  <0: any other error
 */
int ef_vi_open_extension(struct ef_pd* pd, ef_driver_handle dh,
                         const ef_vi_uuid_t id, enum ef_ext_flags flags,
                         ef_vi_extension** ext_out);


/* Closes a handle previously opened by ef_vi_open_extension().
 *
 * Return values:
 *  0: success
 *  -EINVAL: invalid parameter
 *  <0: any other error
 */
int ef_vi_close_extension(ef_vi_extension* ext);


struct ef_vi_key_value {
  const char* key;
  const char* value;
};

/* Information about the current extension. */
struct ef_vi_ext_metadata {
  /* Number of bytes in this struct. Callers should check this value before
   * reading fields which were added in later versions, to ensure that they
   * are accessing memory which has been correctly populated by the library
   * currently being used. */
  size_t size;
  /* The triple id.minor_version.patch_version forms a semver (Semantic
   * versioning) version number.
   *
   * -# When you make incompatible API changes, generate a new UUID.
   * -# When you add functionality in a backwards compatible manner, increment
   *    minor_version.
   * -# When you make backwards compatible bug fixes, increment patch_version.
   *
   * These rules mean that if a handle is successfully opened with a UUID with
   * ef_vi_open_extension() then it will have the basic functionality that the
   * application needs, without having to check the minor_version or
   * patch_version here. */
  ef_vi_uuid_t id;
  uint16_t minor_version;
  uint16_t patch_version;
  /* Array (of size num_about) of fields containing basic human-readable
   * information about this plugin. The key names are specified by RFC5013;
   * keys and values are nominally encoded with UTF-8. Duplicate keys are
   * permitted. Note that all this information is provided directly by the
   * plugin author so care must be taken when interpreting or displaying it;
   * in particular, the UTF-8 encoding cannot be assumed to be valid. */
  const struct ef_vi_key_value *about;
  size_t num_about;
};

/* Returns (in *metadata) basic information about this extension.
 *
 * The memory of *metadata is owned by the ef_vi_extension handle; it is
 * freed when ef_vi_close_extension() is called.
 *
 * The flags parameter is currently unused and must be 0.
 *
 * Return values:
 *  0: success
 *  <0: any other error
 */
int ef_vi_extension_get_metadata(ef_vi_extension* ext,
                                 const struct ef_vi_ext_metadata **metadata,
                                 unsigned flags);

/* Sends a request to a FPGA plugin.
 *
 * 'Messages' are a generalized concept for plugin authors to offer the
 * ability for ef_vi applications to communicate with them in a secure,
 * validated way. See the plugin author's guide for a fuller description of
 * how plugin messages are created. See the documentation for the specific
 * plugin being used to determine what messages are available and what payload
 * they take.
 *
 * The payload may be modified in arbitrary ways as part of the plugin's
 * processing; usually this is just to populate it with output parameters.
 * The payload is typically a struct in a form provided by the plugin author.
 * For future extensibility, users should memset these structs to zero before
 * populating them.
 *
 * The flags parameter is currently unused and must be 0.
 *
 * Return values:
 *  >=0: success, with the value being plugin-specified
 *  -EIO: error communicating with the plugin
 *  -EFAULT: bad payload pointer or size
 *  -E2BIG: payload_size is larger than the plugin understands
 *  -EPERM: the extension was opened with EF_EXT_QUERY_ONLY
 *  <0: any other plugin-specified error
 */
int ef_vi_extension_send_message(ef_vi_extension* ext, uint32_t message,
                                 void* payload, size_t payload_size,
                                 unsigned flags);


/*   ===== DEPRECATED =====
 *   This function is going to go away as soon as the mcfw has enough stuff
 *   to be able to implement normal messages which can destroy resources.
 *
 * Terminate the use of a resource by the plugin
 *
 * 'Resources' are a general concept provided to plugins to manage the
 * lifetime of FPGA entities. See the documentation for the specific plugin
 * being used to determine what values to use for resource_class. resource_id
 * will come from an output parameter of an earlier
 * ef_vi_extension_send_message().
 *
 * The flags parameter is currently unused and must be 0.
 *
 * Return values:
 *  0: success
 *  -EINVAL: unknown resource_class
 *  -ENOENT: unknown resource_id
 *  -EPERM: the extension was opened with EF_EXT_QUERY_ONLY
 *  <0: any other error
 */
int ef_vi_extension_destroy_resource(ef_vi_extension* ext,
                                     uint32_t resource_class,
                                     uint32_t resource_id, unsigned flags);

#ifdef __cplusplus
}
#endif

#endif
