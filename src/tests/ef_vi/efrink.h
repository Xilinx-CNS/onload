/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019 Xilinx, Inc. */
/* efrink.h
 *
 * Library for shared memory ring
 *
 * This is an advanced technique which has the potential to provide a more
 * efficient way to receive data when multiple consumer processes want to
 * receive the same data stream(s) from the network.
 *
 * A single controller (e.g. efrink_controller) sets up a region of shared
 * memory and posts chunks of this to the RX ring of the NIC. As the NIC writes
 * packet data, it returns completion events. The controller receives these
 * events and marks each packet buffer as complete.
 *
 * One or more readers (e.g. efrink_consumer) can access the shared memory to
 * read the packets. The data is protected via a generation counter.
 *
 * Consumers must:
 * 1. call read_begin() to wait for packet data to arrive
 * 2. read data from the packet buffer. Note that the data could get
 *    overwritten during the read, so any action taken should be reversible
 * 3. use is_read_valid() to check that the generation counter is unchanged. If
 *    this returns true the read was valid and the action can be finalised
 *    (e.g. by sending a response). If this returns false, the consumer can
 *    retry the read to get new data.
 */
#include <etherfabric/ef_vi.h>
#include <ci/tools.h>

struct pkt_buf {
  /* Must only access from controller
   * I/O address corresponding to the start of this pkt_buf struct
   */
  ef_addr            ef_addr;


  /* Items below can also be read safely from consumer */
  uint64_t           gen_c;   /* generation count - assumes x86_64 */
  int                flags;   /* packet status */
  int                len;     /* payload length */

  /* offset to where received packets start
   * need to use offset as each process may map to different addresses
   */
  int                rx_offset;
};

#define FLAG_RX_GOOD 1
#define FLAG_RX_BAD  0

#define PKT_BUF_SIZE 2048
#define PKT_BUFS_N ( 4096 * 4 )
#define SHM_NAME "/solarflare_rink1"

#ifndef __x86_64__
  #error Current code for x86_64 only
#endif


static inline
struct pkt_buf* pkt_buf_from_id(void* pkt_bufs, unsigned pkt_buf_i)
{
  assert( pkt_buf_i < PKT_BUFS_N );
  return (void*) ((char*) pkt_bufs + (size_t) pkt_buf_i * PKT_BUF_SIZE);
}


static inline unsigned next_pkt_buf_id(unsigned pkt_buf_i)
{
  return (pkt_buf_i + 1) % PKT_BUFS_N;
}


static inline unsigned previous_pkt_buf_id(unsigned pkt_buf_i)
{
  return (pkt_buf_i + PKT_BUFS_N - 1) % PKT_BUFS_N;
}


static inline unsigned id_difference(unsigned a, unsigned b)
{
  return (a + PKT_BUFS_N - b) % PKT_BUFS_N;
}


/* controller calls mark_packet_pending() prior to updating a pkt_buf and
 * posting it to the RX ring */
static inline void mark_packet_pending(struct pkt_buf* pkt_buf)
{
  assert( ! (pkt_buf->gen_c & 1) );
  ++pkt_buf->gen_c;
  /* ensure gen_c is updated to an odd value, before any further changes to
   * pkt_buf occur */
  ci_wmb();
}

/* controller calls mark_packet_ready() once pkt_buf is ready for consumers to
 * read */
static inline void mark_packet_ready(struct pkt_buf* pkt_buf)
{
  assert(pkt_buf->gen_c & 1);
  /* ensure all updates to pkt_buf are completed before gen_c is updated */
  ci_wmb();
  ++pkt_buf->gen_c;
}


/* consumer calls read_begin() to wait for the packet buffer to become ready to
 * read */
static inline uint64_t read_begin(struct pkt_buf* pkt_buf)
{
  uint64_t initial_gen_c;
  while( 1 ) {
    initial_gen_c = *(volatile uint64_t*) &pkt_buf->gen_c;
    if( ! (initial_gen_c & 1))
      break;
    ci_spinloop_pause();
  }
  /* ensure that subsequent reads from the pkt_buf occur after gen_c changed */
  ci_rmb();
  return initial_gen_c;
}


/* consumer uses is_read_valid() to check whether read was successful
 * NB after this call, further reads from pkt_buf are unsafe */
static inline int is_read_valid(struct pkt_buf* pkt_buf, uint64_t initial_gen_c)
{
  /* ensure all data reads complete before the check */
  ci_rmb();
  return pkt_buf->gen_c == initial_gen_c;
}


/* return the packet buffer index which the NIC is expected to write to next
 * NB this does not guarantee that this packet buffer is ready to read, so will
 * still need to call read_begin()
 * This is useful at start of day to know where to read data
 * May also be useful to check whether the reader is keeping up with new data */
static inline unsigned nic_id(unsigned initial_id, void* pkt_bufs)
{
  unsigned i = previous_pkt_buf_id(initial_id);
  int before = 0;
  uint64_t gen_c;
  struct pkt_buf* pkt_buf;

  while( 1 ) {
    pkt_buf = pkt_buf_from_id(pkt_bufs, i);
    gen_c = *(volatile uint64_t*) &pkt_buf->gen_c;
    if( before && (gen_c & 1) )
      return i;

    if( !(gen_c & 1) )
      before = 1;

    i = next_pkt_buf_id(i);
  }
}
