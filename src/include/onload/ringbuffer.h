/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#ifndef __ONLOAD_RINGBUFFER_H__
#define __ONLOAD_RINGBUFFER_H__

#include <ci/internal/ip.h> /* for OO_DO_STACK_POLL */

/* This header implements a kernel-ul ringbuffer in shared memory.
 * Kernel writes, UL reads.  No UL<->kernel interlocking is required.
 * Both kernel and UL must interlock these function calls inside kernel and
 * UL respectively.
 *
 * This ringbuffer is designed to be safe for kernel, i.e. misbehaving UL
 * can't harm.  When all the instances behave, UL reads kernel-written data
 * in time and without corruption.
 *
 *
 * Overruns
 * --------
 * Kernel does not prevent overruns.  UL logs overrun once.
 *
 * Preventing overruns makes kernel-side complicated; it requires
 * kernel-side to sleep, relying on UL to tell kernel when some space is
 * available again.  Sleeping in kernel is very complicated: it is not
 * available in some context, and we must not rely on UL, etc, etc.
 *
 * So the resolution is: do not handle overruns in any way.
 *
 * Data structures
 * ----------------------
 * Data structures are defined in other headers; see
 * "struct oo_ringbuffer_state" & "struct oo_ringbuffer".
 */


#ifdef __KERNEL__
static inline void
oo_ringbuffer_state_init(struct oo_ringbuffer_state* ring,
                         ci_uint32 size, size_t stride)
{
  ci_assert(CI_IS_POW2(size));
  ring->mask = size - 1;
  ring->stride = stride;
  ring->read = ring->write = 0;
  ring->overflow_cnt = 0;
}
#endif


static inline void
oo_ringbuffer_init(struct oo_ringbuffer *ring,
                   struct oo_ringbuffer_state* state,
#if OO_DO_STACK_POLL
                   const char* name,
#endif
                   void* data)
{
#ifdef __KERNEL__
  /* This function MUST be called immediately after _init() above, before the
   * ring is mmaped to UL, while its data is trusted. */
  ci_assert(CI_IS_POW2(state->mask + 1));
  ring->mask = state->mask;
  ring->stride = state->stride;
#endif
#if OO_DO_STACK_POLL
  ring->name = name;
#endif
  ring->state = state;
  ring->data = data;
}

#ifdef __KERNEL__
static inline void
oo_ringbuffer_write(struct oo_ringbuffer* ring, const void* data)
{
  ci_uint32 idx = ring->state->write & ring->mask;
  memcpy(ring->data + idx * ring->stride, data, ring->stride);
  ci_wmb();
  ring->state->write++;
  ci_wmb();
}
#endif

#if OO_DO_STACK_POLL
#include <onload/drv/dump_to_user.h>

typedef void (*oo_ringbuffer_callback_t)(void* arg, void* data);
extern void
oo_ringbuffer_iterate(struct oo_ringbuffer* ring,
                      oo_ringbuffer_callback_t cb, void* arg);

static inline void
oo_ringbuffer_dump(struct oo_ringbuffer* ring, const char* name,
                   const char* pf, oo_dump_log_fn_t logger, void* log_arg)
{
  logger(log_arg, "%s  %s: "
         "size=%d stride=%d read=%u write=%u overflow=%u", pf, name,
         ring->state->mask + 1, ring->state->stride,
         ring->state->read, ring->state->write, ring->state->overflow_cnt);
#ifdef __KERNEL__
  logger(log_arg, "%s  %s trusted: size=%u stride=%u", pf, name,
         ring->mask + 1, ring->stride);
#endif
}
#endif

#endif
