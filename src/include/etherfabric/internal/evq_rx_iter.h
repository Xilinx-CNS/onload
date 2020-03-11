/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#ifndef __EFAB_INTERNAL_EVQ_RX_ITER_H__
#define __EFAB_INTERNAL_EVQ_RX_ITER_H__

#include <etherfabric/ef_vi.h>

struct ef_vi_rvq_rx_iter {
  const ef_event* ev;
  unsigned n_evs;

  const uint32_t* ids;
  unsigned mask;
  unsigned di;

  unsigned multi_desc_left;
};


ef_vi_inline void
ef_vi_evq_rx_iter_set(struct ef_vi_rvq_rx_iter* ri_out, const ef_vi* vi,
                      const ef_event* evs, unsigned n_evs)
{
  struct ef_vi_rvq_rx_iter ri = {
    evs, n_evs, vi->vi_rxq.ids, vi->vi_rxq.mask, vi->ep_state->rxq.removed};
  *ri_out = ri;
}


/* Gives next id associated with current descriptor and
 * advances to next rx descriptor if needed - returns 1 in this case.
 * Returns 0 if all descriptors/events have been processed */
ef_vi_inline int
ef_vi_evq_rx_iter_next(struct ef_vi_rvq_rx_iter* ri, int32_t* id_out, size_t* len_out)
{
 redo:
  if( ri->multi_desc_left )
    goto multi_desc;
  for(; ri->n_evs;) {
    const ef_event* ev = ri->ev;
    --ri->n_evs;
    ++ri->ev;

    if( EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_RX ) {
      if( (ev->rx.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
                                                     == EF_EVENT_FLAG_SOP ) {
        *len_out = EF_EVENT_RX_BYTES(*ev);// - evq->rx_prefix_len;
        return EF_EVENT_RX_RQ_ID(*ev);
      }
    }
    /* multi events need to call unbundle or skip to increase qs->removed */
    else if( EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_RX_MULTI ) {
      if( (ev->rx_multi.flags & (EF_EVENT_FLAG_SOP | EF_EVENT_FLAG_CONT))
                                                     != EF_EVENT_FLAG_SOP )
        ri->di += ev->rx_multi.n_descs; /* just skip as irrelevant */
      else {
        ri->multi_desc_left = ev->rx_multi.n_descs;
        goto multi_desc;
      }
    }
    else if( EF_EVENT_TYPE(*ev) == EF_EVENT_TYPE_RX_MULTI_DISCARD )
      ri->di += ev->rx_multi.n_descs; /* just skip */
  }
  return 0;

 multi_desc:
  {
    int id;
    --ri->multi_desc_left;
    id = ri->ids[ri->di++ & ri->mask];
    if( id == EF_REQUEST_ID_MASK )
      goto redo;
    *len_out = 0;
    return id;
  }
}


#endif
