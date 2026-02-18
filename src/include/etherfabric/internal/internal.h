/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2013-2020 Xilinx, Inc. */

#ifndef __EFAB_INTERNAL_H__
#define __EFAB_INTERNAL_H__

/* Internal interfaces, so exclude from doxygen documentation */
/*! \cond internal */

/* This must die. It is used where we don't yet know how to find the 
 * right NIC to use in a multiple NIC system. */
#define CI_DEFAULT_NIC 0

typedef union {
  uint64_t  u64[1];
  uint32_t  u32[2];
  uint16_t  u16[4];
} ef_vi_qword;


typedef struct ef_vi ef_vi;
typedef struct ef_pd ef_pd;
typedef struct ef_memreg ef_memreg;


/*! Return size of state buffer of an initialised VI. */
extern int ef_vi_state_bytes(ef_vi*);

/*! Return size of buffer needed for VI state given sizes of RX and TX
** DMA queues.  Queue sizes must be legal sizes (power of 2), or 0 (no
** queue).
*/
extern int ef_vi_calc_state_bytes(int rxq_size, int txq_size);

/*! Convert an efhw device arch to ef_vi_arch, or returns -1 if not
** recognised.
*/
extern int  ef_vi_arch_from_efhw_arch(int efhw_arch);

/* Add a VI into the set managed by a VI with an event queue.  Only needed
 * when a VI is constructed manually.
 *
 * Returns the Q label (>= 0) on success, or -EBUSY if [evq_vi] already has
 * a full complement of slaved VIs.
 */
extern int ef_vi_add_queue(ef_vi* evq_vi, ef_vi* add_vi);

/* Place statistics relating to errors in the nominated buffer.
 *
 * This call does not populate [s] immediately; stats are updated by other
 * calls, so the lifetime of [s] must be as long as the vi.
 */
extern void ef_vi_set_stats_buf(ef_vi* vi, ef_vi_stats* s);


/**********************************************************************
 * Re-Initialisation **************************************************
 **********************************************************************/

/* This set of functions will reinitialise the software rings and deal
 * with any buffers that they contain by calling the supplied callback
 * for each one to allow it to be freed.
 */

typedef void (*ef_vi_reinit_callback)(ef_request_id id, void* arg);

extern int ef_vi_rxq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg);
extern int ef_vi_txq_reinit(ef_vi* vi, ef_vi_reinit_callback cb, void* cb_arg);
extern int ef_vi_evq_reinit(ef_vi* vi);

/**********************************************************************
 * Misc ***************************************************************
 **********************************************************************/

extern int  ef_vi_rx_ring_bytes(struct ef_vi*);
extern int  ef_vi_tx_ring_bytes(struct ef_vi*);

extern int  ef_vi_init(struct ef_vi*, int arch, int variant, int revision,
		       enum ef_vi_flags ef_vi_flags, unsigned char nic_flags,
		       ef_vi_state*);

extern void ef_vi_init_io(struct ef_vi*, void* io_area);

extern char* ef_vi_init_qs(struct ef_vi*, char* q_mem, uint32_t* ids,
                           int evq_size, int rxq_size, int rx_prefix_len,
                           int txq_size);

extern void ef_vi_init_rxq(struct ef_vi*, int ring_size, void* descriptors,
			   void* ids, int prefix_len);

extern void ef_vi_init_txq(struct ef_vi*, int ring_size, void* descriptors,
			   void* ids);

extern void ef_vi_init_evq(struct ef_vi*, int ring_size, void* event_ring);

extern void ef_vi_init_timer(struct ef_vi* vi, int timer_quantum_ns);

extern void ef_vi_init_rx_timestamping(struct ef_vi* vi, int rx_ts_correction);
extern void ef_vi_init_tx_timestamping(struct ef_vi* vi, int tx_ts_correction);
extern void ef_vi_set_ts_format(struct ef_vi* vi, enum ef_timestamp_format ts_format);

extern void ef_vi_init_out_flags(struct ef_vi* vi, unsigned flags);

extern void ef_vi_init_state(struct ef_vi*);

extern void ef_vi_reset_rxq(struct ef_vi*);

extern void ef_vi_reset_txq(struct ef_vi*);

extern void ef_vi_reset_evq(struct ef_vi*, int clear_ring);

extern int efct_kbufs_init_internal(ef_vi* vi,
                                    struct efab_efct_rxq_uk_shm_base *shm,
                                    void* buffer_space);
extern int efct_ubufs_init_internal(ef_vi* vi);
extern void efct_ubufs_local_attach_internal(ef_vi* vi, int ix, int qid, unsigned bufs);
extern int efct_ubufs_shared_attach_internal(ef_vi* vi, int ix, int qid,
                                             void* bufs, bool use_interrupts);
extern int efct_ubufs_set_shared(ef_vi* vi, int shrub_controller_id, int shrub_server_id);
volatile uint64_t* efct_ubufs_get_rxq_io_window(ef_vi* vi, int ix);
void efct_ubufs_set_rxq_io_window(ef_vi* vi, int ix, volatile uint64_t* p);
int efct_vi_find_free_rxq(ef_vi* vi, int qid);
void efct_vi_start_rxq(ef_vi* vi, int ix, int qid);
int efct_vi_sync_rxq(ef_vi* vi, int ix, int qid);
int efct_poll_tx(ef_vi* vi, ef_event* evs, int evs_len);
int efct_vi_get_wakeup_params(ef_vi* vi, int qid, unsigned* sbseq,
                              unsigned* pktix);

/* This returns the ID of the next RX buffer in the RXQ.  In the absence of
 * event merging and errors, this will be the same packet that will be returned
 * in the next RX event. */
ef_vi_inline unsigned ef_vi_next_rx_rq_id(ef_vi* vi)
{
  return vi->vi_rxq.ids[vi->ep_state->rxq.removed & vi->vi_rxq.mask];
}

unsigned efct_vi_next_rx_rq_id(ef_vi* vi, int qid);

/* efct tx packet descriptor, stored in the ring until completion */
struct efct_tx_descriptor
{
  /* total length including header and padding, in bytes */
  uint16_t len;
};

/* efct rx packet descriptor, one for each buffer assigned to a queue */
struct efct_rx_descriptor
{
  uint16_t refcnt;
  uint16_t superbuf_pkts;
  int16_t  sbid_next; /* id of next buffer in a linked list, or -1 */
  uint8_t  sentinel;  /* sentinel we expect to see in incoming packets */
  uint8_t  poison;    /* we are responsible for re-poisoning after use */

  /* This union assumes that mis-located metadata and user-space buffer
   * management are mutually exclusive. If that's ever not the case, we'll
   * need to squeeze another sbid into the unused bits of the fields above,
   * or accept an increase of the structure size.
   *
   * (It should be possible to do that by combining superbuf_pkts (10 bits)
   * with sentinel (1 bit) leaving 16 bits. We don't need to store the
   * whole packet id, though it's convenient to do so if we can.)
   */
  union {
    uint32_t final_meta_pkt; /* metadata for final packet, if meta_offset == 1 */
    ef_addr  dma_addr;       /* dma address of buffer, if meta_offset == 0 */
  };
};

#define EFCT_TX_DESCRIPTOR_BYTES sizeof(struct efct_tx_descriptor)
#define EFCT_RX_DESCRIPTOR_BYTES sizeof(struct efct_rx_descriptor)

#ifndef __KERNEL__
#include <sys/uio.h>
extern int ef10_ef_vi_transmitv_copy_pio(ef_vi* vi, int offset,
					 const struct iovec* iov, int iovcnt,
					 ef_request_id dma_id);

/* Exported for use by TCPDirect */
extern int ef10_receive_get_precise_timestamp_internal
	(ef_vi* vi, const void* pkt, ef_precisetime* ts_out,
	 uint32_t t_minor, uint32_t t_major);

#endif

/* Exported directly for onload to use in the kernel due to limitations with
 * calculating the pkt_id from the packer pointer in kernel space. */
extern int efct_vi_rxpkt_get_precise_timestamp(ef_vi* vi, uint32_t pkt_id,
                                               ef_precisetime* ts_out);

/*! Size of the CTPIO aperture in bytes (if present) */
#define EF_VI_CTPIO_APERTURE_SIZE     4096

/*! Calibrate the CTPIO write timing loop */
extern int ef_vi_ctpio_init(ef_vi* vi);


/* Hardware design parameters for NICs, typically acquired in the driver and
 * provided to userspace. Not all parameters make sense for all architectures;
 * unused ones should be left as zero. The structure is tagged with its size to
 * allow new ones to be added without breaking ABI compatibility.
 *
 * If an older userspace library does not know about a new parameter, the driver
 * can detect this and check that the parameter's value is compatible with the
 * library's assumptions.
 *
 * If an older driver does not know about a new parameter, the library can
 * detect this and infer a value based on the hardware spec before it was
 * parametrised. (A special case is when the driver cannot provide parameters
 * at all).
 *
 * For correct behaviour when adding new parameters, we need the driver to be
 * up to date with the NIC, so there are no parameters unknown to the driver.
 *
 * If the new parameter could modify existing behaviour, such that the library
 * assumes a particular known value:
 *  - define a default value below, based on the assumption
 *  - the driver should check that EITHER the parameter is known to the library,
 *    OR the value matches the assumption
 *  - the library should use parameterised value if known to the driver,
 *    otherwise the default value.
 *
 * If the new parameter is for new behaviour, with no prior assumptions:
 *  - there should be no need for a default value, though it might be useful
 *    to provide one if it makes sense
 *  - the driver can provide the value unconditionally; values unknown to the
 *    library will be truncated when copied to userland
 *  - the library should check whether the parameter is known to the driver and
 *    otherwise assume the new behaviour does not exist on this NIC.
 *
 * NOTE: we don't currently have a good solution for the case where the user
 * library is too old to have a concept of design parameters, and therefore
 * does not request them. In that case, we do not check its assumptions, giving
 * undefined behaviour if they do not match the NIC's parameters.
 */
struct efab_nic_design_parameters {
  /* This must come first */
  uint64_t known_size;

  /* Do not change or remove any existing parameters */
  uint64_t rx_superbuf_bytes;
  uint64_t rx_frame_offset;
  uint64_t tx_aperture_bytes;
  uint64_t tx_fifo_bytes;
  uint64_t timestamp_subnano_bits;
  uint64_t unsol_credit_seq_mask;
  uint64_t md_location;
  uint64_t rx_stride;
  uint64_t rx_queues;
  uint64_t ct_thresh_min;

  /* New parameters must be added at the end */
};

/* Default value for a parameter */
#define EFAB_NIC_DP_DEFAULT(PARAM) EFAB_NIC_DP_DEFAULT_ ## PARAM
#define EFAB_NIC_DP_DEFAULT_rx_superbuf_bytes 1048576
#define EFAB_NIC_DP_DEFAULT_rx_frame_offset 64
#define EFAB_NIC_DP_DEFAULT_tx_aperture_bytes 4096
#define EFAB_NIC_DP_DEFAULT_tx_fifo_bytes 32768
#define EFAB_NIC_DP_DEFAULT_timestamp_subnano_bits 2
#define EFAB_NIC_DP_DEFAULT_unsol_credit_seq_mask 0x7f
#define EFAB_NIC_DP_DEFAULT_md_location 0
#define EFAB_NIC_DP_DEFAULT_rx_stride 4096
#define EFAB_NIC_DP_DEFAULT_rx_queues 8
#define EFAB_NIC_DP_DEFAULT_ct_thresh_min 0

/* Initializer to set the known size according to the current context.
 * This (or equivalent) must be done before passing it to another context. */
#define EFAB_NIC_DP_INITIALIZER \
  {.known_size = sizeof(struct efab_nic_design_parameters)}

/* Check whether a parameter is known in the context that created the structure.
 * This must be done before accessing that parameter. */
#define EFAB_NIC_DP_KNOWN(DP, PARAM) \
  (offsetof(struct efab_nic_design_parameters, PARAM) < (DP).known_size)

/* Get a parameter value, or the default if not known */
#define EFAB_NIC_DP_GET(DP, PARAM) \
  (EFAB_NIC_DP_KNOWN(DP, PARAM) ? (DP).PARAM : EFAB_NIC_DP_DEFAULT(PARAM))

/* Check whether the provided `vi` is running with a compatibility layer, and
 * is specifically trying to pretend to be `compat_arch`. */
ef_vi_inline bool ef_vi_is_compat_vi(ef_vi* vi, enum ef_vi_arch compat_arch)
{
  return vi->compat_data != NULL && vi->nic_type.arch == compat_arch;
}

/* Get the architecture used by the hardware for a given `vi`. Notably, this
 * will see through the architecture exposed by the compatibility layer. */
ef_vi_inline enum ef_vi_arch ef_vi_get_real_arch(const ef_vi* vi)
{
  /* `vi->nic_type.arch` is actually defined as `unsigned char`, but is always
   * assigned with values from `enum ef_vi_arch`, so we cast it here to
   * satisfy the compiler. */
  return vi->compat_data ? vi->compat_data->underlying_arch
                         : (enum ef_vi_arch)vi->nic_type.arch;
}


/* Register a memory region for use with ef_vi. The only difference from
 * `ef_memreg_alloc` is the presence of the `mr_flags` parameter. */
extern int ef_memreg_alloc_flags(ef_memreg* mr, ef_driver_handle mr_dh,
                                 struct ef_pd* pd, ef_driver_handle pd_dh,
                                 void* p_mem, size_t len_bytes,
                                 unsigned mr_flags);

/* Return the default `ef_memreg` flags. */
extern unsigned ef_pd_mr_flags(ef_pd* pd);

/* Internal interfaces, so exclude from doxygen documentation */
/*! \endcond internal */

#endif  /* __EFAB_INTERNAL_H__ */
