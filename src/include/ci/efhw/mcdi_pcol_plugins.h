/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
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
 * Create a handle to a datapath plugin's service. This involves finding a currently-loaded plugin offering the given functionality (as identified by the UUID) and allocating a handle to track the usage of it. Plugin functionality is identified by 'service' rather than any other identifier so that a single plugin bitfile may offer more than one piece of independent functionality. If two bitfiles are loaded which both offer the same service, then the metadata is interrogated further to determine which is the newest and that is the one opened. See SF-123526-SW for architectural detail on datapath plugins.
 */
#define MC_CMD_PLUGIN_ALLOC 0x1ad
#undef MC_CMD_0x1ad_PRIVILEGE_CTG

#define MC_CMD_0x1ad_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_ALLOC_IN msgrequest */
#define    MC_CMD_PLUGIN_ALLOC_IN_LEN 16
/* The functionality requested of the plugin, as a UUID structure */
#define       MC_CMD_PLUGIN_ALLOC_IN_UUID_OFST 0
#define       MC_CMD_PLUGIN_ALLOC_IN_UUID_LEN 16

/* MC_CMD_PLUGIN_ALLOC_OUT msgresponse */
#define    MC_CMD_PLUGIN_ALLOC_OUT_LEN 4
/* Unique identifier of this usage */
#define       MC_CMD_PLUGIN_ALLOC_OUT_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_ALLOC_OUT_HANDLE_LEN 4


/***********************************/
/* MC_CMD_PLUGIN_FREE
 * Delete a handle to a plugin's service.
 */
#define MC_CMD_PLUGIN_FREE 0x1ae
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
 * Returns the global metadata applying to the whole plugin service. See the other metadata calls for subtypes of data.
 */
#define MC_CMD_PLUGIN_GET_META_GLOBAL 0x1af
#undef MC_CMD_0x1af_PRIVILEGE_CTG

#define MC_CMD_0x1af_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_META_GLOBAL_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_META_GLOBAL_IN_LEN 4
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_IN_HANDLE_LEN 4

/* MC_CMD_PLUGIN_GET_META_GLOBAL_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_LEN 33
/* Unique identifier of this plugin service. This is identical to the value
 * which was requested when the handle was allocated.
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_UUID_OFST 0
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_UUID_LEN 16
/* semver sub-version of this plugin service */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MINOR_VER_OFST 16
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MINOR_VER_LEN 2
/* semver micro-version of this plugin service */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_PATCH_VER_OFST 18
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_PATCH_VER_LEN 2
/* Number of different messages which can be sent to this service */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_NUM_MSGS_OFST 20
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_NUM_MSGS_LEN 4
/* One more than the maximum resource class number allowed for this service.
 * It's theoretically allowed (but unusual) for not all the resource classes to
 * be used.
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_NUM_RCS_OFST 24
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_NUM_RCS_LEN 4
/* Byte offset within the VI window of the plugin's mapped CSR window, as
 * provisioned by the MC into PCI routing on the NIC.
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_OFFSET_OFST 28
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_OFFSET_LEN 2
/* Number of bytes mapped through to the plugin's CSRs. 0 if that feature was
 * not requested by the plugin, or if it was optionally requested and found to
 * be unavailable.
 */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_SIZE_OFST 30
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_SIZE_LEN 2
/* Flags indicating how to perform the CSR window mapping. */
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAGS_OFST 32
#define       MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_MAPPED_CSR_FLAGS_LEN 1
/* enum: The CSR window is mapped to allow reads from the host */
#define          MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_CSR_READ 0x1
/* enum: The CSR window is mapped to allow writes by the host */
#define          MC_CMD_PLUGIN_GET_META_GLOBAL_OUT_CSR_WRITE 0x2


/***********************************/
/* MC_CMD_PLUGIN_GET_META_RC
 * Returns the simple metadata for a specific plugin resource class. Resource classes are a generic concept usable by plugin authors to offload state management from the FPGA to the MC.
 */
#define MC_CMD_PLUGIN_GET_META_RC 0x1b0
#undef MC_CMD_0x1b0_PRIVILEGE_CTG

#define MC_CMD_0x1b0_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_META_RC_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_META_RC_IN_LEN 8
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_GET_META_RC_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_GET_META_RC_IN_HANDLE_LEN 4
/* Resource class number for which to retrieve information. */
#define       MC_CMD_PLUGIN_GET_META_RC_IN_CLASS_OFST 4
#define       MC_CMD_PLUGIN_GET_META_RC_IN_CLASS_LEN 4

/* MC_CMD_PLUGIN_GET_META_RC_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_META_RC_OUT_LEN 8
/* Maximum number of resources of this class which may be allocated. */
#define       MC_CMD_PLUGIN_GET_META_RC_OUT_MAX_ALLOWED_OFST 0
#define       MC_CMD_PLUGIN_GET_META_RC_OUT_MAX_ALLOWED_LEN 4
/* Number of bytes of extra data which the plugin author has requested be
 * allocated per resource of this class for use by the message handling eBPF
 * programs which run in the kernel. This extra space may be used for whatever
 * purpose the plugin author needs.
 */
#define       MC_CMD_PLUGIN_GET_META_RC_OUT_KERN_EXTRA_OFST 4
#define       MC_CMD_PLUGIN_GET_META_RC_OUT_KERN_EXTRA_LEN 4


/***********************************/
/* MC_CMD_PLUGIN_GET_META_MSG
 * Returns the simple metadata for a specific plugin request message. See also MC_CMD_PLUGIN_GET_META_MSG_PROG which returns the eBPF program for validating each message in the kernel. Messages pass through two stages of processing/validation - an in-kernel eBPF program and an in-MC eBPF program. The in-kernel program takes message payload from a consuming application, validates it against kernel security boundaries and tracks the resource modifications made before passing it on to the MC using MC_CMD_PLUGIN_REQ. The in-MC program does similar validation, against PCI function security boundaries this time, and calls eBPF helper functions as necessary to perform whatever actions the datapath plugin requires for this message. Hosts without a userspace/kernel boundary still require the message reformatting functionality of the in-kernel eBPF program but may be run it with simplified eBPF helper functions.
 */
#define MC_CMD_PLUGIN_GET_META_MSG 0x1b1
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
#define    MC_CMD_PLUGIN_GET_META_MSG_OUT_LEN 52
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
 * formatted as a C identifier with any spare bytes at the end set to 0,
 * however this convention is not enforced by the MC so consumers must check
 * for all potential malformations before using it for a trusted purpose.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_NAME_OFST 8
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_NAME_LEN 32
/* Number of bytes of data which must be passed from the application using the
 * plugin to the in-kernel message validation/processing eBPF program for this
 * message's payload.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_USER_PARAM_SIZE_OFST 40
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_USER_PARAM_SIZE_LEN 4
/* Number of bytes of data which must be passed from the host kernel to the MC
 * for this message's payload. It is the job of the in-kernel message
 * validation/processing eBPF program to construct this payload. The MC's
 * plugin metadata loader will have validated that the number of bytes
 * specified here will fit in to MC_CMD_PLUGIN_REQ_IN_DATA in a single MCDI
 * message.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_MCDI_PARAM_SIZE_OFST 44
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_MCDI_PARAM_SIZE_LEN 4
/* Number of eBPF instructions in the in-kernel message validation/ processing
 * program. Each instruction is 8 bytes.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_PROG_NUM_INSNS_OFST 48
#define       MC_CMD_PLUGIN_GET_META_MSG_OUT_PROG_NUM_INSNS_LEN 4


/***********************************/
/* MC_CMD_PLUGIN_GET_META_MSG_PROG
 * Returns a chunk of the in-kernel validation/processing program for a specific message. The program may be larger than the maximum MCDI message size, hence the OFFSET parameter allowing a subset to be retrieved. The user of the message should use a loop to obtain the complete program, continuing until the returned DATA is shorter than the maximum allowed size.
 */
#define MC_CMD_PLUGIN_GET_META_MSG_PROG 0x1b2
#undef MC_CMD_0x1b2_PRIVILEGE_CTG

#define MC_CMD_0x1b2_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_GET_META_MSG_PROG_IN msgrequest */
#define    MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_LEN 12
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_HANDLE_LEN 4
/* Unique message ID */
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_ID_OFST 4
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_ID_LEN 4
/* Byte offset of the chunk requested */
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_OFFSET_OFST 8
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_IN_OFFSET_LEN 4

/* MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT msgresponse */
#define    MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_LENMIN 0
#define    MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_LENMAX 252
#define    MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_LENMAX_MCDI2 1020
#define    MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_LEN(num) (0+1*(num))
#define    MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_DATA_NUM(len) (((len)-0)/1)
/* Requested chunk of the in-kernel eBPF program's instructions for this
 * message. This will not be aligned to eBPF instruction boundaries if the
 * OFFSET input parameter was not aligned.
 */
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_DATA_OFST 0
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_DATA_LEN 1
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_DATA_MINNUM 0
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_DATA_MAXNUM 252
#define       MC_CMD_PLUGIN_GET_META_MSG_PROG_OUT_DATA_MAXNUM_MCDI2 1020


/***********************************/
/* MC_CMD_PLUGIN_REQ
 * Send a command to a plugin. A plugin may define an arbitrary number of 'messages' which it allows applications on the host system to send, each identified by a 32-bit ID.
 */
#define MC_CMD_PLUGIN_REQ 0x1b3
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


/***********************************/
/* MC_CMD_PLUGIN_DESTROY_RSRC
 * Destroy a specific resource allocated by an earlier message sent to the plugin. Plugins may own 'resources', each of which is an instance of a 'resource class'. They are allocated by eBPF helper functions called by plugin message handlers, however they are deallocated by this MCDI message in order to allow for automatic cleanup by the controlling kernel in the case where the user abortively exits.
 */
#define MC_CMD_PLUGIN_DESTROY_RSRC 0x1b4
#undef MC_CMD_0x1b4_PRIVILEGE_CTG

#define MC_CMD_0x1b4_PRIVILEGE_CTG SRIOV_CTG_GENERAL

/* MC_CMD_PLUGIN_DESTROY_RSRC_IN msgrequest */
#define    MC_CMD_PLUGIN_DESTROY_RSRC_IN_LEN 12
/* Handle returned by MC_CMD_PLUGIN_ALLOC_OUT */
#define       MC_CMD_PLUGIN_DESTROY_RSRC_IN_HANDLE_OFST 0
#define       MC_CMD_PLUGIN_DESTROY_RSRC_IN_HANDLE_LEN 4
/* Type of resource to be destroyed. */
#define       MC_CMD_PLUGIN_DESTROY_RSRC_IN_CLASS_OFST 4
#define       MC_CMD_PLUGIN_DESTROY_RSRC_IN_CLASS_LEN 4
/* Specific instance of the resource to be destroyed. */
#define       MC_CMD_PLUGIN_DESTROY_RSRC_IN_ID_OFST 8
#define       MC_CMD_PLUGIN_DESTROY_RSRC_IN_ID_LEN 4

/* MC_CMD_PLUGIN_DESTROY_RSRC_OUT msgresponse */
#define    MC_CMD_PLUGIN_DESTROY_RSRC_OUT_LEN 0

#endif
