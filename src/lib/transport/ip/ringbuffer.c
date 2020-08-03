/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

#include <onload/ringbuffer.h>

#if OO_DO_STACK_POLL
/* Returns false if it failed to read any data because it was overwritten.
 * Otherwise returns true and sets start_p and end_p indexes.
 */
static bool
ringbuffer_read(struct oo_ringbuffer* ring, char* data, int data_len,
                int* start_p, int* end_p)
{
  struct oo_ringbuffer_state* state = ring->state;
  ci_uint32 writer;
  ci_uint32 new_writer;
  ci_uint32 reader;
#ifdef __KERNEL__
  ci_uint32 mask = ring->mask;
  ci_uint32 stride = ring->stride;
#else
  ci_uint32 mask = state->mask;
  ci_uint32 stride = state->stride;
#endif
  int ridx;

  *start_p = *end_p = 0;
  reader = state->read;
  writer = OO_ACCESS_ONCE(state->write);
  ci_assert_ge((int)(writer - reader), 0);
  if( reader == writer )
    return true;
  ci_rmb();

  /* If writer is a few loops ahead, then let's read the last loop only.
   * Keeping in mind that writer+1 can be already corrupted, the maximum
   * amount of data is size-1 = mask.
   */
  if( writer - reader > mask )
    reader = writer - mask;

  /* Find the right end of the data we are reading */
  if( data_len <= writer - reader )
    writer = reader + data_len;
  *end_p = writer - reader;

  ridx = reader & mask;
  /* Now we doing to memcpy() from the main ringbuffer to the user data
   * array.  Unfortunately it may require 2 memcpys.
   */
  if( ridx + (writer - reader) > mask ) {
    size_t first_chunk = stride * (mask + 1 - ridx);
    memcpy(data, ring->data + ridx * stride, first_chunk);
    memcpy(data + first_chunk, ring->data, stride * (writer & mask));
  }
  else {
    memcpy(data, ring->data + ridx * stride, stride * (*end_p));
  }
  state->read = writer;
  ci_rmb();
  new_writer = OO_ACCESS_ONCE(state->write);

  /* Has the write pointer moved?
   * Has it invalidated any data we've just copied?
   *
   * Math: data[new_writer] can be already corrupted.
   * So the "good" case is
   * reader < writer <= new_writer < reader + size
   */
  if(CI_LIKELY( new_writer - reader <= mask ))
    return true;

  if( state->overflow_cnt == 0 )
    ci_log("ERROR: Ring buffer %s overflowed.  "
           "Consider increasing its size %d.", ring->name,
           mask + 1);
  state->overflow_cnt++;

  /* Have we overflowed by the entire data_len?
   *
   * Math: new_writer >= writer - 1 + size
   * i.e. the largest corrupted index "new_writer" corrupts
   * the right end of the copied area "writer - 1".
   */
  if( new_writer - writer >= mask ) {
    return false;
  }

  /* We've overflowed part but not all of the ring, so chop off the part
   * that's been overwritten in the data that we return.
   *
   * Math: new_writer is possibly corrupted, so we can use new_writer+1
   * and larger.  new_writer+1 ~= new_writer-mask.
   */
  *start_p = new_writer - reader - mask;
  return true;
}

void
oo_ringbuffer_iterate(struct oo_ringbuffer* ring,
                      oo_ringbuffer_callback_t cb, void* arg)
{
  char data[512] CI_ALIGN(8);
  int data_len = sizeof(data) / ring->state->stride;
  int start = 0; /* appease gcc */
  int end;

  ci_assert_ge(data_len, 4);
  do {
    /* Loop until we read some data which have not been invalidated already.
     */
    while( ! ringbuffer_read(ring, data, data_len, &start, &end) )
      ;

    /* Have we managed to read any data? */
    if( start == end )
      return;
    for( ; start < end; start++ )
      cb(arg, (void*)(data + start * ring->state->stride));
  } while( true );
}
#endif /* OO_DO_STACK_POLL */
