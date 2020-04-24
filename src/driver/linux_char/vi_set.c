/* SPDX-License-Identifier: GPL-2.0 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include <ci/efrm/efrm_client.h>
#include "efch.h"
#include <ci/efrm/vi_set.h>
#include <ci/efrm/vi_allocation.h>
#include <ci/efrm/pd.h>
#include <ci/efrm/efrm_port_sniff.h>
#include <ci/efrm/efrm_filter.h>
#include <ci/efch/op_types.h>
#include "char_internal.h"
#include "filter_list.h"

#include <ci/driver/driverlink_api.h>


static int
vi_set_rm_alloc(ci_resource_alloc_t* alloc_,
                ci_resource_table_t* priv_opt,
                efch_resource_t* rs, int intf_ver_id)
{
  struct efch_vi_set_alloc* alloc = &alloc_->u.vi_set;
  struct efrm_client *client;
  struct efrm_vi_set* vi_set;
  struct efrm_pd* pd;
  int rc;

  if( intf_ver_id >= 1 && alloc->in_pd_fd >= 0 ) {
    struct efrm_resource* rs;
    rc = efch_lookup_rs(alloc->in_pd_fd, alloc->in_pd_rs_id,
                        EFRM_RESOURCE_PD, &rs);
    if( rc < 0 ) {
      EFCH_ERR("%s: ERROR: could not find PD fd=%d id="EFCH_RESOURCE_ID_FMT
               " rc=%d", __FUNCTION__, alloc->in_pd_fd,
               EFCH_RESOURCE_ID_PRI_ARG(alloc->in_pd_rs_id), rc);
      goto fail1;
    }
    pd = efrm_pd_from_resource(rs);
    client = rs->rs_client;
    efrm_client_add_ref(client);
  }
  else {
    rc = efrm_client_get(alloc->in_ifindex, NULL, NULL, &client);
    if( rc != 0 ) {
      EFCH_ERR("%s: ERROR: ifindex=%d not found rc=%d",
               __FUNCTION__, alloc->in_ifindex, rc);
      goto fail1;
    }
    rc = efrm_pd_alloc(&pd, client, 0/*phys_addr_mode*/);
    if( rc != 0 ) {
      EFCH_ERR("%s: ERROR: efrm_pd_alloc(ifindex=%d) failed (rc=%d)",
               __FUNCTION__, alloc->in_ifindex, rc);
      goto fail2;
    }
  }

  rc = efrm_vi_set_alloc(pd, alloc->in_n_vis,
                         EFRM_RSS_MODE_DEFAULT, &vi_set);
  if( rc != 0 )
    goto fail3;

  efrm_client_put(client);
  efrm_pd_release(pd);
  efch_filter_list_init(&rs->vi_set.fl);
  rs->vi_set.sniff_flags = 0;
  rs->rs_base = efrm_vi_set_to_resource(vi_set);
  return 0;


 fail3:
  efrm_pd_release(pd);
 fail2:
  efrm_client_put(client);
 fail1:
  return rc;
}


static void vi_set_rm_free(efch_resource_t *rs)
{
  struct efrm_vi_set *vi_set = efrm_vi_set_from_resource(rs->rs_base);

  efch_filter_list_free(rs->rs_base, efrm_vi_set_get_pd(vi_set),
                        &rs->vi_set.fl);
  /* Remove any sniff config we may have set up. */
  if( rs->vi_set.sniff_flags & EFCH_RX_SNIFF )
    efrm_port_sniff(rs->rs_base, 0, 0, efrm_vi_set_get_rss_context(vi_set,
        EFRM_RSS_MODE_ID_DEFAULT));
  if( rs->vi_set.sniff_flags & EFCH_TX_SNIFF )
    efrm_tx_port_sniff(rs->rs_base, 0, efrm_vi_set_get_rss_context(vi_set,
        EFRM_RSS_MODE_ID_DEFAULT));
}


static int
vi_set_mmap_not_supported(struct efrm_resource* ors, unsigned long* bytes,
                          struct vm_area_struct* vma, int index)
{
  return -EINVAL;
}


static void
vi_set_rm_dump(struct efrm_resource* ors, ci_resource_table_t *priv_opt,
               const char *line_prefix)
{
}


static int
vi_set_rm_rsops(efch_resource_t* rs, ci_resource_table_t* priv_opt,
                ci_resource_op_t* op, int* copy_out)
{
  struct efrm_vi_set *vi_set = efrm_vi_set_from_resource(rs->rs_base);
  int rss_context = efrm_vi_set_get_rss_context(vi_set,
                                                EFRM_RSS_MODE_ID_DEFAULT);
  unsigned flags;

  int rc;
  switch(op->op) {
    case CI_RSOP_PT_SNIFF:
      rc = efrm_port_sniff(rs->rs_base, op->u.pt_sniff.enable,
                           op->u.pt_sniff.promiscuous, rss_context);
      if( rc == 0 && op->u.pt_sniff.enable )
        rs->vi_set.sniff_flags |= EFCH_RX_SNIFF;
      else if( rc == 0 && !op->u.pt_sniff.enable )
        rs->vi_set.sniff_flags &= ~EFCH_RX_SNIFF;
      break;
    case CI_RSOP_TX_PT_SNIFF:
      {
        int enable = op->u.pt_sniff.enable & EFCH_TX_SNIFF_ENABLE;
        rc = efrm_tx_port_sniff(rs->rs_base, enable, rss_context);
        if( rc == 0 && enable )
          rs->vi_set.sniff_flags |= EFCH_TX_SNIFF;
        else if( rc == 0 && !enable )
          rs->vi_set.sniff_flags &= ~EFCH_TX_SNIFF;
      }
      break;
    case CI_RSOP_FILTER_DEL:
      rc = efch_filter_list_op_del(rs->rs_base, efrm_vi_set_get_pd(vi_set),
                                   &rs->vi_set.fl, op);
      break;
    case CI_RSOP_FILTER_BLOCK_KERNEL:
      rc = efch_filter_list_op_block(rs->rs_base, efrm_vi_set_get_pd(vi_set),
                                     &rs->vi_set.fl, op);
      break;
    default:
      flags = 0;
      if( efrm_vi_set_num_vis(vi_set) > 1 )
        flags |= (unsigned) EFX_FILTER_FLAG_RX_RSS;
      if( rss_context == -1 )
        rss_context = EFX_FILTER_RSS_CONTEXT_DEFAULT;
      rc = efch_filter_list_op_add(rs->rs_base, efrm_vi_set_get_pd(vi_set),
                                   &rs->vi_set.fl, op, copy_out,
                                   flags, rss_context);
  }

  return rc;
}


efch_resource_ops efch_vi_set_ops = {
  .rm_alloc  = vi_set_rm_alloc,
  .rm_free   = vi_set_rm_free,
  .rm_mmap   = vi_set_mmap_not_supported,
  .rm_nopage = NULL,
  .rm_dump   = vi_set_rm_dump,
  .rm_rsops  = vi_set_rm_rsops,
};


