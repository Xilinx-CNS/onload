/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/**************************************************************************\
*//*! \file
** <L5_PRIVATE L5_HEADER >
** \author  djr
**  \brief  System dependent support for ef vi lib
**   \date  2015/11/11
**    \cop  (c) Solarflare Communications Inc.
** </L5_PRIVATE>
*//*
\**************************************************************************/

/*! \cidoxg_include_ci_ul */
#ifndef __CIUL_MEMCPY_TO_IO_H__
#define __CIUL_MEMCPY_TO_IO_H__

#include <ci/tools.h>


/* memcpy_to_pio: Copy packet to PIO buffer on the adapter.  The PIO region
 * on NIC is write only, and to avoid silicon bugs must only be hit with
 * writes at are 64-bit aligned and a multiple of 64-bits in size.
 */
#if defined(__PPC64__) && ! defined(__KERNEL__)

#define MEMCPY_TO_PIO_ALIGN  16

static inline volatile uint64_t*
  __memcpy_to_pio(volatile void* dst, const void* src, size_t len, int aligned)
{
  const ci_oword_t* o_src = src;
  volatile ci_oword_t* o_dst = dst;
  volatile ci_oword_t* o_dst_end = o_dst + (len >> 4);
  ci_oword_t merge;

  while( o_dst < o_dst_end ) {
    __asm__ __volatile__("lxvw4x %%vs32, 0, %2\n\t"
                         "stxvw4x %%vs32, 0, %1"
                         : "=m" (*o_dst)
                         : "r" (o_dst),
                           "r" (o_src),
                           "m" (*o_src)
                         : "vs32");
    ++o_src;
    ++o_dst;
  }
  if( ! aligned && (len & 15) ) {
    memcpy(&merge, o_src, len & 15);
    __asm__ __volatile__("lxvw4x %%vs32, 0, %2\n\t"
                         "stxvw4x %%vs32, 0, %1"
                         : "=m" (*o_dst)
                         : "r" (o_dst),
                           "r" (&merge),
                           "m" (merge)
                         : "vs32");
    ++o_dst;
  }
  /* Pad to 64-byte boundary.  Reduces number of transactions
   * on the power bus.
   */
  o_dst_end = (void*) EF_VI_ALIGN_FWD((ci_uintptr_t) o_dst, (ci_uintptr_t) 64);
  while( o_dst < o_dst_end ) {
    __asm__ __volatile__("lxvw4x %%vs32, 0, %2\n\t"
                         "stxvw4x %%vs32, 0, %1"
                         : "=m" (*o_dst)
                         : "r" (o_dst),
                           "r" (&merge)
                         : "vs32");
    ++o_dst;
  }
  __asm__ __volatile__("eieio" : : : "memory");
  return &o_dst->u64[0];
}

# define memcpy_to_pio(dst, src, len)           \
       __memcpy_to_pio((dst), (src), (len), 0)

# define memcpy_to_pio_aligned(dst, src, len)   \
       __memcpy_to_pio((dst), (src), (len), 1)

#else

#define MEMCPY_TO_PIO_ALIGN  8

#define WB_ALIGNED(p)  (((uintptr_t) (p) & (EF_VI_WRITE_BUFFER_SIZE - 1)) == 0)

/* Copy data from host buffers into the PIO or CTPIO apertures.
 *
 * Both are mapped using write-combining memory, and we write to them
 * only in naturally aligned 64-bit chunks. The last chunk may be up
 * to 7 bytes longer than the total length of the described data.
 *
 * \param dst     Pointer to the destination in the aperture. Must be
 *                64-bit aligned.
 *
 * \param iov     Pointer to an array of iovecs describing the source
 *                data. These iovecs do not have any particular
 *                alignment requirements, however for best performance
 *                64-bit alignment is recommended.
 *
 * \param iovcnt  Number of iovec structures in the array.
 *
 * \param aligned Non-zero to permit this function to assume that the
 *                first iov is 64-bit aligned in both size and length.
 *                This is intended to be a compile-time constant to
 *                allow the compiler to optimise this function.
 *
 * \param end_pad Non-zero to fill the final write-combining buffer to
 *                the end with zeros. This is intended to be a
 *                compile-time constant to allow the compiler to
 *                optimise this function.
 */
static inline volatile uint64_t*
__memcpy_iov_to_pio(volatile uint64_t* dst,
                    const struct iovec* iov,
                    unsigned iovcnt,
                    int aligned,
                    int end_pad)
{
  uint32_t in_hand_count = 0;
  union {
    uint8_t bytes[MEMCPY_TO_PIO_ALIGN];
    uint64_t word;
  } in_hand = { .word = 0 };
  unsigned int i;

  for( i = 0; i < iovcnt; i++ ) {
    uint64_t* data = (uint64_t*) iov[i].iov_base;
    int len = iov[i].iov_len;
    int src_aligned = aligned || (((long)data) & 7) == 0;
    int overshoot_allowed = src_aligned && (i == iovcnt-1);
    volatile uint64_t* data_end;

    EF_VI_ASSERT( in_hand_count < MEMCPY_TO_PIO_ALIGN );

    /* First, do we have a misaligned 'tail' remaining from the
     * previous iovec? */
    if( !aligned && (in_hand_count > 0) ) {
      /* How many bytes do we need to create the next 64-bit aligned
       * write? */
      unsigned needed_bytes = MEMCPY_TO_PIO_ALIGN - in_hand_count;

      /* How many bytes are available to be taken from the start of
       * this iov? */
      unsigned avail_bytes = CI_MIN(needed_bytes, len);

      /* Add bytes to the in_hand buffer. */
      memcpy(in_hand.bytes + in_hand_count, data, avail_bytes);
      in_hand_count += avail_bytes;
      len -= avail_bytes;
      data = (uint64_t*)(((uint8_t*)data) + avail_bytes);

      /* Was the iovec too small to fill the in_hand buffer? If so,
       * continue to the next. */
      if( in_hand_count < MEMCPY_TO_PIO_ALIGN )
        continue;

      /* Emit the newly-aligned write. */
      *dst++ = in_hand.word;
      in_hand_count = 0;
    }

    /* Emit as many aligned writes as we can. For efficiency we may
     * read beyond our src buffer, but we do that only when src ptr is
     * qword aligned as this ensures we do not to trample on next
     * cache line (or page).
     *
     * We will read up to:
     * * the qword boundary past the end in overshoot_allowed case, or
     * * the qword boundary before the end in !overshoot_allowed case */
    data_end = data + ((len + (overshoot_allowed ? 7 : 0)) >> 3);
    len -= ((uint8_t *)data_end) - ((uint8_t *)data);

    while( data < data_end )
      *dst++ = *data++;

    /* Note that len can be negative here, in the case where we've
     * deliberately overshot the end of the last buffer. */

    /* If we have any unaligned bytes left over, store them in the
     * in_hand buffer. */
    if( !aligned && (len > 0) ) {
      EF_VI_ASSERT( len < MEMCPY_TO_PIO_ALIGN );
      memcpy(in_hand.bytes, data, len);
      in_hand_count = len;
    }

    /* The 'aligned' parameter only applies to the first iov in the
     * list. */
    aligned = 0;
  }

  if( !aligned && (in_hand_count > 0) ) {
    *dst++ = in_hand.word;
  }

  if( end_pad )
    while( ! WB_ALIGNED(dst) )
      *dst++ = 0;

  wmb_wc();
  return dst;
}

/* Note that all of the macros below pad their write to the end of a
 * WC buffer. This means they're not suitable for non-sequential
 * writes in general because they may touch bytes of the destination
 * after the end of the region being copied into. */

# define memcpy_iov_to_pio_aligned(dst, iov, iovcnt)    \
  __memcpy_iov_to_pio((dst), (iov), (iovcnt), 1, 1)

/* Copies from a host buffer into the PIO or CTPIO region.  @param aligned dst,
 * src and len are all qword aligned. */
static inline volatile uint64_t*
  __memcpy_to_pio(volatile void* dst, const void* src, size_t len, int aligned)
{
  struct iovec iov = { (void*) src, len };
  return __memcpy_iov_to_pio(dst, &iov, 1, aligned, 0);
}

# define memcpy_to_pio(dst, src, len)           \
       __memcpy_to_pio((dst), (src), (len), 0)

# define memcpy_to_pio_aligned(dst, src, len)   \
       __memcpy_to_pio((dst), (src), (len), 1)


#define CTPIO_COPY_FLUSH()                      \
  do {                                          \
    if( copy ) {                                \
      int len = copy_dst - copy_local;          \
      __builtin_memcpy(fallback, copy_local, len);\
      fallback += len;                          \
      copy_dst = copy_local;                    \
    }                                           \
  } while(0)                                    \

/* Emit a word, and do optional actions between each write buffer. */
#define CTPIO_EMIT_WORD(data)                   \
  do {                                          \
    uint64_t word = (data);                     \
    if( WB_ALIGNED(dst) )  {                    \
      CTPIO_COPY_FLUSH();                       \
      if( wb_flush )                            \
        wmb_wc();                               \
      if( wb_ticks ) {                          \
        do                                      \
          ci_frc32(&now);                       \
        while( now - start < wb_ticks );        \
        start = now;                            \
      }                                         \
    }                                           \
    *dst++ = word;                              \
    if( copy ) {                                \
      *(uint64_t*)copy_dst = word;              \
      copy_dst += sizeof(word);                 \
    }                                           \
  } while(0)

/* Emit the word in the "in_hand" buffer. This might be the first word,
 * which needs handling differently. */
#define CTPIO_EMIT_IN_HAND()                    \
  do {                                          \
    if( first ) {                               \
      *dst++ = in_hand.qword;                   \
      if( copy ) {                              \
        *(uint32_t*)copy_dst = in_hand.dwords[1];\
        copy_dst += sizeof(in_hand.dwords[1]);  \
      }                                         \
      first = 0;                                \
    }                                           \
    else {                                      \
      CTPIO_EMIT_WORD(in_hand.qword);           \
    }                                           \
  } while(0)

static inline __attribute__((always_inline)) void
  memcpy_iov_to_ctpio(volatile uint64_t*__restrict__ dst,
                      uint32_t ctpio_control,
                      const struct iovec* iov,
                      unsigned iovcnt,
                      int wb_flush,
                      uint32_t wb_ticks,
                      int copy,
                      char*__restrict__ fallback)
{
  union {
    uint8_t  bytes[MEMCPY_TO_PIO_ALIGN];
    uint32_t dwords[MEMCPY_TO_PIO_ALIGN / 4];
    uint64_t qword;
  } in_hand;
  size_t in_hand_len, src_iov_len = iov[0].iov_len;
  const uint64_t*__restrict__ src_iov_p = iov[0].iov_base;
  unsigned iov_next_i = 1;
  int first = 1;

  /* It seems measurably faster to write the fallback data to a local buffer
   * in the main loop, and then copy this to the fallback buffer when we wait
   * between write buffers. I'm not sure why. */
  char copy_local[EF_VI_WRITE_BUFFER_SIZE];
  char* copy_dst = copy_local;

  uint32_t now, start = 0;
  if( wb_ticks )
    /* ?? todo: Can we avoid this ci_frc32 at start?  (NB. Tricky as must
     * still ensure that there is a suitable gap between first and second
     * WBs).
     */
    ci_frc32(&start);

  in_hand.dwords[0] = ctpio_control;
  in_hand_len = 4;

  while( 1 ) {
    /* Merge from current iov into in_hand. */
    size_t in_hand_space = MEMCPY_TO_PIO_ALIGN - in_hand_len;
    size_t n = CI_MIN(in_hand_space, src_iov_len);
    EF_VI_ASSERT( in_hand_len > 0 );
    __builtin_memcpy(in_hand.bytes + in_hand_len, src_iov_p, n);
    in_hand_len += n;
    src_iov_len -= n;
    src_iov_p = (void*) ((char*) src_iov_p + n);

    if(unlikely( in_hand_len < MEMCPY_TO_PIO_ALIGN ))
      goto next_iov;

    /* Emit in_hand.  (We reset in_hand_len below). */
    CTPIO_EMIT_IN_HAND();

  nothing_in_hand:
    /* Copy whole qwords. */
    n = src_iov_len >> 3;
    src_iov_len -= n << 3;
    while( n-- )
      CTPIO_EMIT_WORD(*src_iov_p++);

    if( src_iov_len ) {
      EF_VI_ASSERT( src_iov_len < MEMCPY_TO_PIO_ALIGN );
      __builtin_memcpy(in_hand.bytes, src_iov_p, src_iov_len);
      in_hand_len = src_iov_len;
    }
    else {
      in_hand_len = 0;
    }

  next_iov:
    if( iov_next_i == iovcnt )
      break;
    src_iov_len = iov[iov_next_i].iov_len;
    src_iov_p = iov[iov_next_i].iov_base;
    ++iov_next_i;
    if( in_hand_len == 0 )
      goto nothing_in_hand;
  }

  if( in_hand_len )
    CTPIO_EMIT_IN_HAND();

  /* Pad to end of write buffer.  It isn't obvious this is desirable, but I
   * (djr) have observed cases where more writes are out-of-order when this
   * is removed.
   */
  while( ! WB_ALIGNED(dst) )
    *dst++ = 0;

  CTPIO_COPY_FLUSH();
}


#endif


#endif  /* __CIUL_MEMCPY_TO_IO_H__ */
