/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

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


struct ef_vi;


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
 * TX Warming *********************************************************
 **********************************************************************/

typedef struct {
  unsigned removed;
  char* vi_ctpio_mmap_ptr;
} ef_vi_tx_warm_state;

extern ef_vi_noinline ef_vi_cold void
  ef_vi_start_transmit_warm(ef_vi* vi, ef_vi_tx_warm_state* saved_state,
                            char* warm_ctpio_mmap_ptr);

extern ef_vi_noinline ef_vi_cold void
  ef_vi_stop_transmit_warm(ef_vi* vi, const ef_vi_tx_warm_state* state);


/**********************************************************************
 * Misc ***************************************************************
 **********************************************************************/

extern int  ef_vi_rx_ring_bytes(struct ef_vi*);
extern int  ef_vi_tx_ring_bytes(struct ef_vi*);

extern int  ef_vi_init(struct ef_vi*, int arch, int variant, int revision,
		       unsigned ef_vi_flags, unsigned char nic_flags,
		       ef_vi_state*);

extern void ef_vi_init_io(struct ef_vi*, void* io_area);

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


/* This returns the ID of the next RX buffer in the RXQ.  In the absence of
 * event merging and errors, this will be the same packet that will be returned
 * in the next RX event. */
ef_vi_inline unsigned ef_vi_next_rx_rq_id(ef_vi* vi)
{
  return vi->vi_rxq.ids[vi->ep_state->rxq.removed & vi->vi_rxq.mask];
}


#ifndef __KERNEL__
#include <sys/uio.h>
extern int ef10_ef_vi_transmitv_copy_pio(ef_vi* vi, int offset,
					 const struct iovec* iov, int iovcnt,
					 ef_request_id dma_id);

/* Exported for use by TCPDirect */
extern int ef10_receive_get_timestamp_with_sync_flags_internal
	(ef_vi* vi, const void* pkt, struct timespec* ts_out,
	 unsigned* flags, uint32_t t_minor, uint32_t t_major);

#endif

/*! Size of the CTPIO aperture in bytes (if present) */
#define EF_VI_CTPIO_APERTURE_SIZE     4096

/*! Calibrate the CTPIO write timing loop */
extern int ef_vi_ctpio_init(ef_vi* vi);

/* Internal interfaces, so exclude from doxygen documentation */
/*! \endcond internal */

#endif  /* __EFAB_INTERNAL_H__ */
