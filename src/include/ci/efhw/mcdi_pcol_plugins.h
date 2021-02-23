/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2020 Xilinx, Inc. */
#ifndef MCDI_PCOL_PLUGINS_H
#define MCDI_PCOL_PLUGINS_H

/*
 * NB: This file is manually maintained by extracting the relevant bits from
 * mc_driver_pcol_private.h in the firmware tree (which is generated from
 * sfregistry). Once the plugin MCDI is stabilised (i.e. declared non-private)
 * then these definitions will appear in the normal mc_driver_pcol.h and this
 * file can be removed.
 */

/***********************************/
/* MC_CMD_PLUGIN_ALLOC
 * Create a handle to a datapath plugin's extension. This involves finding a
 * currently-loaded plugin offering the given functionality (as identified by
 * the UUID) and allocating a handle to track the usage of it. Plugin
 * functionality is identified by 'extension' rather than any other identifier
 * so that a single plugin bitfile may offer more than one piece of independent
 * functionality. If two bitfiles are loaded which both offer the same
 * extension, then the metadata is interrogated further to determine which is
 * the newest and that is the one opened. See SF-123625-SW for architectural
 * detail on datapath plugins.
 */
#define MC_CMD_PLUGIN_ALLOC 0x1ad
#define MC_CMD_PLUGIN_ALLOC_MSGSET 0x1ad
#undef MC_CMD_0x1ad_PRIVILEGE_CTG

#define MC_CMD_0x1ad_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_ALLOC_IN msgrequest */
#define    MC_CMD_PLUGIN_ALLOC_IN_LEN 24
/* The functionality requested of the plugin, as a UUID structure */
#define       MC_CMD_PLUGIN_ALLOC_IN_UUID_OFST 0
#define       MC_CMD_PLUGIN_ALLOC_IN_UUID_LEN 16
/* Additional options for opening the handle */
#define       MC_CMD_PLUGIN_ALLOC_IN_FLAGS_OFST 16
#define       MC_CMD_PLUGIN_ALLOC_IN_FLAGS_LEN 4
#define        MC_CMD_PLUGIN_ALLOC_IN_FLAG_INFO_ONLY_OFST 16
#define        MC_CMD_PLUGIN_ALLOC_IN_FLAG_INFO_ONLY_LBN 0
#define        MC_CMD_PLUGIN_ALLOC_IN_FLAG_INFO_ONLY_WIDTH 1
#define        MC_CMD_PLUGIN_ALLOC_IN_FLAG_ALLOW_DISABLED_OFST 16
#define        MC_CMD_PLUGIN_ALLOC_IN_FLAG_ALLOW_DISABLED_LBN 1
#define        MC_CMD_PLUGIN_ALLOC_IN_FLAG_ALLOW_DISABLED_WIDTH 1
/* Load the extension only if it is in the specified administrative group.
 * Specify ANY to load the extension wherever it is found (if there are
 * multiple choices then the extension with the highest MINOR_VER/PATCH_VER
 * will be loaded). See MC_CMD_PLUGIN_GET_META_GLOBAL for a description of
 * administrative groups.
 */
#define       MC_CMD_PLUGIN_ALLOC_IN_ADMIN_GROUP_OFST 20
#define       MC_CMD_PLUGIN_ALLOC_IN_ADMIN_GROUP_LEN 2
/* enum: Load the extension from any ADMIN_GROUP. */
#define          MC_CMD_PLUGIN_ALLOC_IN_ANY 0xffff
/* Reserved */
#define       MC_CMD_PLUGIN_ALLOC_IN_RESERVED_OFST 22
#define       MC_CMD_PLUGIN_ALLOC_IN_RESERVED_LEN 2

/* MC_CMD_PLUGIN_ALLOC_OUT msgresponse */
#define    MC_CMD_PLUGIN_ALLOC_OUT_LEN 4
/* Unique identifier of this usage */
#define       MC_CMD_PLUGIN_ALLOC_OUT_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_ALLOC_OUT_HANDLE_LEN 4


/***********************************/
/* MC_CMD_PLUGIN_FREE
 * Delete a handle to a plugin's extension.
 */
#define MC_CMD_PLUGIN_FREE 0x1ae
#define MC_CMD_PLUGIN_FREE_MSGSET 0x1ae
#undef MC_CMD_0x1ae_PRIVILEGE_CTG

#define MC_CMD_0x1ae_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_FREE_IN msgrequest */
#define    MC_CMD_PLUGIN_FREE_IN_LEN 4
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_FREE_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_FREE_IN_HANDLE_LEN 4

/* MC_CMD_PLUGIN_FREE_OUT msgresponse */
#define    MC_CMD_PLUGIN_FREE_OUT_LEN 0


/***********************************/
/* MC_CMD_PLUGIN_GET_META_GLOBAL
 * Returns the global metadata applying to the whole plugin extension. See the
 * other metadata calls for subtypes of data.
 */
#define MC_CMD_PLUGIN_GET_META_GLOBAL 0x1af
#define MC_CMD_PLUGIN_GET_META_GLOBAL_MSGSET 0x1af
#undef MC_CMD_0x1af_PRIVILEGE_CTG

#define MC_CMD_0x1af_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_META_GLOBAL_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_META_GLOBAL_IN_LEN 4
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_IN_HANDLE_LEN 4

/* MC_CMD_PLUGIN_GET_META_GLOBAL_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_LEN 36
/* Unique identifier of this plugin extension. This is identical to the value
 * which was requested when the handle was allocated.
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_UUID_OFST 0
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_UUID_LEN 16
/* semver sub-version of this plugin extension */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MINOR_VER_OFST 16
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MINOR_VER_LEN 2
/* semver micro-version of this plugin extension */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_PATCH_VER_OFST 18
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_PATCH_VER_LEN 2
/* Number of different messages which can be sent to this extension */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_NUM_MSGS_OFST 20
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_NUM_MSGS_LEN 4
/* Byte offset within the VI window of the plugin's mapped CSR window. */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_OFFSET_OFST 24
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_OFFSET_LEN 2
/* Number of bytes mapped through to the plugin's CSRs. 0 if that feature was
 * not requested by the plugin (in which case MAPPED_CSR_OFFSET and
 * MAPPED_CSR_FLAGS are ignored).
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_SIZE_OFST 26
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_SIZE_LEN 2
/* Flags indicating how to perform the CSR window mapping. */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAGS_OFST 28
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAGS_LEN 4
#define        MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAG_READ_OFST 28
#define        MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAG_READ_LBN 0
#define        MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAG_READ_WIDTH 1
#define        MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAG_WRITE_OFST 28
#define        MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAG_WRITE_LBN 1
#define        MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAG_WRITE_WIDTH 1
/* Identifier of the set of extensions which all change state together.
 * Extensions having the same ADMIN_GROUP will always load and unload at the
 * same time. ADMIN_GROUP values themselves are arbitrary (but they contain a
 * generation number as an implementation detail to ensure that they're not
 * reused rapidly).
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_ADMIN_GROUP_OFST 32
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_ADMIN_GROUP_LEN 1
/* Bitshift in MC_CMD_DEVEL_CLIENT_PRIVILEGE_MODIFY's MASK parameters
 * corresponding to this extension, i.e. set the bit 1<<PRIVILEGE_BIT to permit
 * access to this extension.
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_PRIVILEGE_BIT_OFST 33
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_PRIVILEGE_BIT_LEN 1
/* Reserved */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_RESERVED_OFST 34
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_RESERVED_LEN 2


/***********************************/
/* MC_CMD_PLUGIN_GET_META_PUBLISHER
 * Returns metadata supplied by the plugin author which describes this
 * extension in a human-readable way. Contrast with
 * MC_CMD_PLUGIN_GET_META_GLOBAL, which returns information needed for software
 * to operate.
 */
#define MC_CMD_PLUGIN_GET_META_PUBLISHER 0x1b0
#define MC_CMD_PLUGIN_GET_META_PUBLISHER_MSGSET 0x1b0
#undef MC_CMD_0x1b0_PRIVILEGE_CTG

#define MC_CMD_0x1b0_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_META_PUBLISHER_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_META_PUBLISHER_IN_LEN 8
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_IN_HANDLE_LEN 4
/* Category of data to return */
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_IN_SUBTYPE_OFST 4
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_IN_SUBTYPE_LEN 4
/* enum: Top-level information about the extension. The returned data is an
 * array of key/value pairs using the keys in RFC5013 (Dublin Core) to describe
 * the extension. The data is a back-to-back list of zero-terminated strings;
 * the even-numbered fields (0,2,4,...) are keys and their following odd-
 * numbered fields are the corresponding values. Both keys and values are
 * nominally UTF-8. Per RFC5013, the same key may be repeated any number of
 * times. Note that all information (including the key/value structure itself
 * and the UTF-8 encoding) may have been provided by the plugin author, so
 * callers must be cautious about parsing it. Callers should parse only the
 * top-level structure to separate out the keys and values; the contents of the
 * values is not expected to be machine-readable.
 */
#define          MC_CMD_PLUGIN_GET_META_PUBLISHER_IN_EXTENSION_KVS 0x0

/* MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_LENMIN 0
#define    MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_LENMAX 252
#define    MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_LENMAX_MCDI2 1020
#define    MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_LEN(num) (0+1*(num))
#define    MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_DATA_NUM(len) (((len)-0)/1)
/* The information requested by SUBTYPE. */
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_DATA_OFST 0
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_DATA_LEN 1
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_DATA_MINNUM 0
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_DATA_MAXNUM 252
#define       MC_CMD_PLUGIN_GET_META_PUBLISHER_OUT_DATA_MAXNUM_MCDI2 1020


/***********************************/
/* MC_CMD_PLUGIN_GET_META_MSG
 * Returns the simple metadata for a specific plugin request message. This
 * supplies information necessary for the host to know how to build an
 * MC_CMD_PLUGIN_REQ request.
 */
#define MC_CMD_PLUGIN_GET_META_MSG 0x1b1
#define MC_CMD_PLUGIN_GET_META_MSG_MSGSET 0x1b1
#undef MC_CMD_0x1b1_PRIVILEGE_CTG

#define MC_CMD_0x1b1_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_META_MSG_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_META_MSG_IN_LEN 8
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_GET_META_MSG_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_GET_META_MSG_IN_HANDLE_LEN 4
/* Unique message ID to obtain */
#define       MC_CMD_PLUGIN_GET_META_MSG_IN_ID_OFST 4
#define       MC_CMD_PLUGIN_GET_META_MSG_IN_ID_LEN 4

/* MC_CMD_PLUGIN_GET_META_MSG_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_META_MSG_OUT_LEN 44
/* Unique message ID. This is the same value as the input parameter; it exists
 * to allow future MCDI extensions which enumerate all messages.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_ID_OFST 0
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_ID_LEN 4
/* Packed index number of this message, assigned by the MC to give each message
 * a unique ID in an array to allow for more efficient storage/management.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_INDEX_OFST 4
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_INDEX_LEN 4
/* Short human-readable codename for this message. This is conventionally
 * formatted as a C identifier in the basic ASCII character set with any spare
 * bytes at the end set to 0, however this convention is not enforced by the MC
 * so consumers must check for all potential malformations before using it for
 * a trusted purpose.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_NAME_OFST 8
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_NAME_LEN 32
/* Number of bytes of data which must be passed from the host kernel to the MC
 * for this message's payload, and which are passed back again in the response.
 * The MC's plugin metadata loader will have validated that the number of bytes
 * specified here will fit in to MC_CMD_PLUGIN_REQ_IN_DATA in a single MCDI
 * message.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_DATA_SIZE_OFST 40
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_DATA_SIZE_LEN 4


/***********************************/
/* MC_CMD_PLUGIN_GET_ALL
 * Returns a list of all plugin extensions currently loaded and available. The
 * UUIDs returned can be passed to MC_CMD_PLUGIN_ALLOC in order to obtain more
 * detailed metadata via the MC_CMD_PLUGIN_GET_META_* family of requests. The
 * ADMIN_GROUP field collects how extensions are grouped in to units which are
 * loaded/unloaded together; extensions with the same value are in the same
 * group.
 */
#define MC_CMD_PLUGIN_GET_ALL 0x1b2
#define MC_CMD_PLUGIN_GET_ALL_MSGSET 0x1b2
#undef MC_CMD_0x1b2_PRIVILEGE_CTG

#define MC_CMD_0x1b2_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_ALL_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_ALL_IN_LEN 4
/* Additional options for querying. Note that if neither FLAG_INCLUDE_ENABLED
 * nor FLAG_INCLUDE_DISABLED are specified then the result set will be empty.
 */
#define       MC_CMD_PLUGIN_GET_ALL_IN_FLAGS_OFST 0
#define       MC_CMD_PLUGIN_GET_ALL_IN_FLAGS_LEN 4
#define        MC_CMD_PLUGIN_GET_ALL_IN_FLAG_INCLUDE_ENABLED_OFST 0
#define        MC_CMD_PLUGIN_GET_ALL_IN_FLAG_INCLUDE_ENABLED_LBN 0
#define        MC_CMD_PLUGIN_GET_ALL_IN_FLAG_INCLUDE_ENABLED_WIDTH 1
#define        MC_CMD_PLUGIN_GET_ALL_IN_FLAG_INCLUDE_DISABLED_OFST 0
#define        MC_CMD_PLUGIN_GET_ALL_IN_FLAG_INCLUDE_DISABLED_LBN 1
#define        MC_CMD_PLUGIN_GET_ALL_IN_FLAG_INCLUDE_DISABLED_WIDTH 1

/* MC_CMD_PLUGIN_GET_ALL_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_ALL_OUT_LENMIN 0
#define    MC_CMD_PLUGIN_GET_ALL_OUT_LENMAX 240
#define    MC_CMD_PLUGIN_GET_ALL_OUT_LENMAX_MCDI2 1020
#define    MC_CMD_PLUGIN_GET_ALL_OUT_LEN(num) (0+20*(num))
#define    MC_CMD_PLUGIN_GET_ALL_OUT_EXTENSIONS_NUM(len) (((len)-0)/20)
/* The list of available plugin extensions, as an array of PLUGIN_EXTENSION
 * structs.
 */
#define       MC_CMD_PLUGIN_GET_ALL_OUT_EXTENSIONS_OFST 0
#define       MC_CMD_PLUGIN_GET_ALL_OUT_EXTENSIONS_LEN 20
#define       MC_CMD_PLUGIN_GET_ALL_OUT_EXTENSIONS_MINNUM 0
#define       MC_CMD_PLUGIN_GET_ALL_OUT_EXTENSIONS_MAXNUM 12
#define       MC_CMD_PLUGIN_GET_ALL_OUT_EXTENSIONS_MAXNUM_MCDI2 51


/***********************************/
/* MC_CMD_PLUGIN_REQ
 * Send a command to a plugin. A plugin may define an arbitrary number of
 * 'messages' which it allows applications on the host system to send, each
 * identified by a 32-bit ID.
 */
#define MC_CMD_PLUGIN_REQ 0x1b3
#define MC_CMD_PLUGIN_REQ_MSGSET 0x1b3
#undef MC_CMD_0x1b3_PRIVILEGE_CTG

#define MC_CMD_0x1b3_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_REQ_IN msgrequest */
#define    MC_CMD_PLUGIN_REQ_IN_LENMIN 8
#define    MC_CMD_PLUGIN_REQ_IN_LENMAX 252
#define    MC_CMD_PLUGIN_REQ_IN_LENMAX_MCDI2 1020
#define    MC_CMD_PLUGIN_REQ_IN_LEN(num) (8+1*(num))
#define    MC_CMD_PLUGIN_REQ_IN_DATA_NUM(len) (((len)-8)/1)
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_REQ_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_REQ_IN_HANDLE_LEN 4
/* Message ID defined by the plugin author */
#define       MC_CMD_PLUGIN_REQ_IN_ID_OFST 4
#define       MC_CMD_PLUGIN_REQ_IN_ID_LEN 4
/* Data blob being the parameter to the message. This must be of the length
 * specified by MC_CMD_PLUGIN_GET_META_MSG_IN_MCDI_PARAM_SIZE.
 */
#define       MC_CMD_PLUGIN_REQ_IN_DATA_OFST 8
#define       MC_CMD_PLUGIN_REQ_IN_DATA_LEN 1
#define       MC_CMD_PLUGIN_REQ_IN_DATA_MINNUM 0
#define       MC_CMD_PLUGIN_REQ_IN_DATA_MAXNUM 244
#define       MC_CMD_PLUGIN_REQ_IN_DATA_MAXNUM_MCDI2 1012

/* MC_CMD_PLUGIN_REQ_OUT msgresponse */
#define    MC_CMD_PLUGIN_REQ_OUT_LENMIN 0
#define    MC_CMD_PLUGIN_REQ_OUT_LENMAX 252
#define    MC_CMD_PLUGIN_REQ_OUT_LENMAX_MCDI2 1020
#define    MC_CMD_PLUGIN_REQ_OUT_LEN(num) (0+1*(num))
#define    MC_CMD_PLUGIN_REQ_OUT_DATA_NUM(len) (((len)-0)/1)
/* The input data, as transformed and/or updated by the plugin's eBPF. Will be
 * the same size as the input DATA parameter.
 */
#define       MC_CMD_PLUGIN_REQ_OUT_DATA_OFST 0
#define       MC_CMD_PLUGIN_REQ_OUT_DATA_LEN 1
#define       MC_CMD_PLUGIN_REQ_OUT_DATA_MINNUM 0
#define       MC_CMD_PLUGIN_REQ_OUT_DATA_MAXNUM 252
#define       MC_CMD_PLUGIN_REQ_OUT_DATA_MAXNUM_MCDI2 1020

#endif
