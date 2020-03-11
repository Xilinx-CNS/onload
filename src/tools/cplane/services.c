/* SPDX-License-Identifier: Solarflare-Binary */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
/* Services DNAT
 * ============================
 *
 * The services DNAT tables provide a way for the cplane server to store details
 * of Kubernetes services.  A Kubernetes service maps a set of frontend ip
 * address:port pairs onto a set of backend ip port pairs.  Any connection to a
 * frontend is forwarded to one of the backends, via some selection mechanism.
 * Our current implementation only allows a single frontend address:port per
 * service.
 *
 * There are two tables in the onload implementation:
 *  - An endpoint hash table with a double linked list overlay
 *  - A set of backend endpoint arrays for quick selection
 *
 * The hash table contains both frontend and backend endpoints.  The backends
 * contain an ci_mib_dllist_link that links them together into a double link
 * list.  Frontends instead contain a  ci_mib_dllist_t that points to the head
 * of the list.  Unlike backends they also keep track of the number of backends
 * in the service and contain an index to the second table.
 *
 * The second table is an array of arrays.  The outer array indexes services and
 * each inner array indexes backend endpoints in that service.  The array
 * indices do not rely on hashes and are are stored in the service's frontend
 * element in the hash table.  It is envisaged that, for efficiency, the inner
 * arrays will at some point occupy and align with an entire page.
 */

#include "private.h"


/* Walks hash table, decrementing use count for each row before end.
 * note: start can equal end, in which case that element is decremented once as
 * start and the walk proceeds as normal.*/
static inline void
svc_hash_decrement_usage(struct cp_mibs* mib,
                         cicp_mac_rowid_t start, cicp_mac_rowid_t step,
                         cicp_mac_rowid_t end)
{
  unsigned svc_table_mask = mib->dim->svc_ep_max - 1;
  cicp_mac_rowid_t hash = start;
  int iter = 0;
  do {
    ci_assert_le(iter, (svc_table_mask >> 2));
    struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[hash];
    ci_assert_ge(svc->use, 1);
    svc->use--;
    hash = (hash + step) & svc_table_mask;
    iter++;
  } while( hash != end );
}


/* Helper function for adding frontend and backend endpoints to the services
 * hash table.  Caller must at a minimum set row_type on returned element. */
static cicp_mac_rowid_t
hash_add(struct cp_mibs* mib, const ci_addr_sh_t addr, ci_uint16 port,
         bool allow_duplicates)
{
  /* svc_ep_max is guaranteed to be 2^n, see cfg_svc_ep_max in server.c */
  unsigned svc_table_mask = mib->dim->svc_ep_max - 1;
  cicp_mac_rowid_t hash1, hash2, hash;
  int iter = 0;

  cp_calc_svc_hash(svc_table_mask, &addr, port, &hash1, NULL);
  hash = hash1;
  hash2 = 0;

  do {
    struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[hash];

    svc->use++;
    if( svc->row_type == CP_SVC_EMPTY )
      return hash;
    if( ! allow_duplicates && svc->ep.port == port &&
        CI_IPX_ADDR_EQ(svc->ep.addr, addr) )
      return CICP_MAC_ROWID_BAD;

    if( hash2 == 0 ) /* After initial zero hash2 is always odd. */
      cp_calc_svc_hash(svc_table_mask, &addr, port, NULL, &hash2);
    hash = (hash + hash2) & svc_table_mask;
  } while( ++iter < (svc_table_mask >> 2) );

  /* No space in table, failed to add, revert use increments */
  svc_hash_decrement_usage(mib, hash1, hash2, hash);

  return CICP_MAC_ROWID_BAD;
}


static cicp_mac_rowid_t
hash_add_service(struct cp_mibs* mib, const ci_addr_sh_t addr, ci_uint16 port)
{
  return hash_add(mib, addr, port, /*allow_duplicates*/ false);
}


static cicp_mac_rowid_t
hash_add_backend(struct cp_mibs* mib, const ci_addr_sh_t addr, ci_uint16 port)
{
  return hash_add(mib, addr, port, /*allow_duplicates*/ true);
}


/* Helper function for removing frontend and backend endpoints from the
 * services hash table.  Caller needs to deal with anything not explicitly
 * related to the hash table, i.e. the linked list and backend array */
static void
svc_hash_ep_del(struct cp_mibs* mib, const cicp_mac_rowid_t rowid)
{
  /* svc_ep_max is guaranteed to be 2^n, see cfg_svc_ep_max in server.c */
  unsigned svc_table_mask = mib->dim->svc_ep_max - 1;
  struct cp_svc_ep_dllist* ep = &mib->svc_ep_table[rowid];
  cicp_mac_rowid_t hash1, hash2;

  cp_calc_svc_hash(svc_table_mask, &ep->ep.addr, ep->ep.port, &hash1, &hash2);

  /* fixup use count on the probe path up to but without the actual row to
   * remove */
  if( rowid != hash1 )
    svc_hash_decrement_usage(mib, hash1, hash2, rowid);

  ep->use--;
  ep->row_type = CP_SVC_EMPTY;
}


/* Free all arrays in the backend array chain of a service.
 * Does not alter the arrays, just marks them as unused in the session. */
static inline void
svc_array_free(struct cp_session* s, struct cp_mibs* mib,
               struct cp_svc_ep_dllist* svc)
{
  cicp_rowid_t array_id = svc->u.service.head_array_id;
  while( CICP_ROWID_IS_VALID(array_id) ) {
    /* Note: Unsetting mask twice in mib loop is not an error. */
    cp_row_mask_unset(s->service_used, array_id);
    array_id = mib->svc_arrays[array_id].next;
  }
}


/* Append an endpoint to the backend array chain of a service.
 * Also sets fields in the service and endpoint */
static cicp_rowid_t
svc_array_append(struct cp_session* s, struct cp_mibs* mib,
                 struct cp_svc_ep_dllist* svc, struct cp_svc_endpoint* ep,
                 const cicp_rowid_t free_array_id)
{
  struct cp_svc_ep_array* arr;
  cicp_rowid_t element_id = svc->u.service.n_backends;
  cicp_rowid_t index;

  /* Need to add a new array to the chain */
  if( svc->u.service.n_backends % CP_SVC_BACKENDS_PER_ARRAY == 0 ) {
    ci_assert( CICP_ROWID_IS_VALID(free_array_id) );
    arr = &mib->svc_arrays[free_array_id];
    arr->next = CICP_ROWID_BAD;
    arr->prev = svc->u.service.tail_array_id;
    index = 0;  /* new element is at the start of new array */

    /* Note: Setting mask twice in mib loop is not an error. */
    cp_row_mask_set(s->service_used, free_array_id);

    if( !CICP_ROWID_IS_VALID(svc->u.service.head_array_id) ) {
      svc->u.service.head_array_id = free_array_id;
    }
    else {
      mib->svc_arrays[svc->u.service.tail_array_id].next = free_array_id;
    }
    svc->u.service.tail_array_id = free_array_id;
  }
  else {
    cp_svc_walk_array_chain(mib, svc->u.service.head_array_id,
                            element_id, &arr, &index);
  }

  /* Update the array element */
  ci_assert(cp_row_mask_get(s->service_used, arr - mib->svc_arrays));
  arr->eps[index] = *ep;

  return element_id;
}


static void
svc_array_remove(struct cp_session* s, struct cp_mibs* mib,
                 struct cp_svc_ep_dllist* svc, cicp_rowid_t element_id)
{
  /* Find the tail of the array chain */
  cicp_rowid_t tail_element_id = svc->u.service.n_backends - 1;
  cicp_rowid_t tail_index = tail_element_id % CP_SVC_BACKENDS_PER_ARRAY;

  /* Replace element to be removed with tail element, unless it is the tail */
  if( element_id != tail_element_id ) {
    struct cp_svc_ep_array* arr;
    cicp_rowid_t index;
    cp_svc_walk_array_chain(mib, svc->u.service.head_array_id,
                            element_id, &arr, &index);
    arr->eps[index] =
      mib->svc_arrays[svc->u.service.tail_array_id].eps[tail_index];
  }

  /* If tail was at the start of an array then we now need to remove
   * that array */
  if( tail_index == 0 ) {
    /* Note: Unsetting mask twice in mib loop is not an error. */
    cp_row_mask_unset(s->service_used, svc->u.service.tail_array_id);

    if( svc->u.service.head_array_id == svc->u.service.tail_array_id ) {
      ci_assert_equal(element_id, 0);
      ci_assert_equal(svc->u.service.n_backends, 1);
      svc->u.service.head_array_id = CICP_ROWID_BAD;
      svc->u.service.tail_array_id = CICP_ROWID_BAD;
    }
    else {
      svc->u.service.tail_array_id =
        mib->svc_arrays[svc->u.service.tail_array_id].prev;
      mib->svc_arrays[svc->u.service.tail_array_id].next = CICP_ROWID_BAD;
    }
  }
}


static void svc_oof_add(struct cp_session* s, struct cp_svc_ep_dllist* svc)
{
  int rc;
  ci_assert_equal(svc->row_type, CP_SVC_SERVICE);

  /* This being true is currently equivalent to svc_externally_acceleratable(),
   * but it's in the current function that we genuinely require this property,
   * so we assert it directly. */
  ci_assert_equal(svc->u.service.n_backends, 1);

  const struct cp_mibs* mib = cp_get_active_mib(s);
  ci_mib_dllist_link* lnk = ci_mib_dllist_start(mib->dim,
                                                &svc->u.service.backends);
  struct cp_svc_ep_dllist* backend = CP_SVC_BACKEND_FROM_LINK(lnk);
  ci_assert_equal(backend->row_type, CP_SVC_BACKEND);

  struct oo_op_cplane_dnat_add op = {
    .orig_addr = svc->ep.addr,
    .orig_port = svc->ep.port,
    .xlated_addr = backend->ep.addr,
    .xlated_port = backend->ep.port,
  };

#ifndef CP_ANYUNIT
  rc = cplane_ioctl(s->oo_fd, OO_IOC_OOF_CP_DNAT_ADD, &op);
  if( rc != 0 )
    ci_log("%s ERROR: Failed to add dnat filter with code %d", __func__, rc);
#else
  (void) op;
  (void) rc;
#endif
  s->stats.notify.svc_add++;
}


static void svc_oof_del(struct cp_session* s, struct cp_svc_ep_dllist* svc)
{
  ci_assert_equal(svc->row_type, CP_SVC_SERVICE);

  struct oo_op_cplane_dnat_del op = {
    .orig_addr = svc->ep.addr,
    .orig_port = svc->ep.port,
  };

#ifndef CP_ANYUNIT
  cplane_ioctl(s->oo_fd, OO_IOC_OOF_CP_DNAT_DEL, &op);
#else
  (void) op;
#endif
  s->stats.notify.svc_del++;
}


static void svc_oof_erase_all(struct cp_session* s)
{
#ifndef CP_ANYUNIT
  cplane_ioctl(s->oo_fd, OO_IOC_OOF_CP_DNAT_RESET);
#endif
  s->stats.notify.svc_erase_all++;
}


/* There are restrictions on which services we will attempt to accelerate on
 * ingress (i.e. by inserting filters for service IPs).  These arise from a
 * deficit in the flexibility of the hardware's filtering capabilities versus
 * that of Kubernetes's service spec: in particular, we can't do any load-
 * balancing.  This function encapsulates some sufficient conditions for a
 * service to be externally-acceleratable by our mechanism. */
static inline bool
svc_externally_acceleratable(struct cp_session* s, cicp_mac_rowid_t id)
{
  ci_assert_nflags(s->flags, CP_SESSION_FLAG_CHANGES_STARTED);
  struct cp_svc_ep_dllist* svc = &cp_get_active_mib(s)->svc_ep_table[id];

  ci_assert_equal(svc->row_type, CP_SVC_SERVICE);
  return svc->u.service.n_backends == 1;
}


/* Call this after updating a service's backends.  It will prod OOF if
 * necessary. */
static void svc_updated(struct cp_session* s, cicp_mac_rowid_t id,
                        bool was_externally_acceleratable)
{
  ci_assert_nflags(s->flags, CP_SESSION_FLAG_CHANGES_STARTED);
  struct cp_svc_ep_dllist* svc = &cp_get_active_mib(s)->svc_ep_table[id];

  bool now_externally_acceleratable = svc_externally_acceleratable(s, id);
  if( !! now_externally_acceleratable != !! was_externally_acceleratable ) {
    if( now_externally_acceleratable )
      svc_oof_add(s, svc);
    else
      svc_oof_del(s, svc);
  }
}


cicp_mac_rowid_t
cp_svc_add(struct cp_session* s,
           const ci_addr_sh_t addr, const ci_uint16 port)
{
  int mib_i;
  struct cp_mibs* mib;
  cicp_mac_rowid_t id;

  MIB_UPDATE_LOOP(mib, s, mib_i)

    cp_mibs_under_change(s);
    id = hash_add_service(mib, addr, port);
    if( CICP_MAC_ROWID_IS_VALID(id) ) {
      /* Construct service element */
      struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[id];
      svc->row_type = CP_SVC_SERVICE;
      svc->ep.addr = addr;
      svc->ep.port = port;

      svc->u.service.n_backends = 0;
      svc->u.service.head_array_id = CICP_ROWID_BAD;
      svc->u.service.tail_array_id = CICP_ROWID_BAD;
      ci_mib_dllist_init(mib->dim, &svc->u.service.backends, 0, "back");
    }

  MIB_UPDATE_LOOP_END(mib, s);
  return id;
}


cicp_mac_rowid_t
cp_svc_backend_add(struct cp_session* s, const cicp_mac_rowid_t svc_id,
                   const ci_addr_sh_t addr, const ci_uint16 port)
{
  int mib_i;
  struct cp_mibs* mib;
  cicp_mac_rowid_t id;
  cicp_rowid_t free_array_id = CICP_ROWID_BAD;
  bool was_externally_acceleratable = svc_externally_acceleratable(s, svc_id);

  MIB_UPDATE_LOOP(mib, s, mib_i)

    struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[svc_id];
    ci_assert_equal(svc->row_type, CP_SVC_SERVICE);
    if( svc->row_type != CP_SVC_SERVICE )
      MIB_UPDATE_LOOP_UNCHANGED(mib, s, return CICP_MAC_ROWID_ERROR);

    /* If currently allocated backend arrays are full and we haven't found a
     * free array already then attempt to find a free one. */
    if( svc->u.service.n_backends % CP_SVC_BACKENDS_PER_ARRAY == 0 &&
        !CICP_ROWID_IS_VALID(free_array_id) ) {
      free_array_id = cp_row_mask_iter_set(s->service_used,
                                           0, mib->dim->svc_arrays_max, false);
      if( !CICP_ROWID_IS_VALID(free_array_id) )
        MIB_UPDATE_LOOP_UNCHANGED(mib, s, return CICP_MAC_ROWID_BAD);
    }

    cp_mibs_under_change(s);
    id = hash_add_backend(mib, addr, port);
    if( CICP_MAC_ROWID_IS_VALID(id) ) {
      struct cp_svc_ep_dllist* ep = &mib->svc_ep_table[id];
      /* Construct backend element */
      ep->row_type = CP_SVC_BACKEND;
      ep->ep.addr = addr;
      ep->ep.port = port;
      ep->u.backend.svc_id = svc_id;
      ci_mib_dllist_link_init(mib->dim, &ep->u.backend.link, 0, "back");

      /* Add element to associated service list and array */
      /* note: the order of elements in the dll list and the array must match */
      ci_mib_dllist_push_tail(mib->dim, &svc->u.service.backends,
                              &ep->u.backend.link);

      ep->u.backend.element_id =
        svc_array_append(s, mib, svc, &ep->ep, free_array_id);

      svc->u.service.n_backends++;
    }

  MIB_UPDATE_LOOP_END(mib, s);

  svc_updated(s, svc_id, was_externally_acceleratable);

  return id;
}


int
cp_svc_del(struct cp_session* s, const cicp_mac_rowid_t rowid)
{
  int mib_i;
  struct cp_mibs* mib;
  bool was_externally_acceleratable = svc_externally_acceleratable(s, rowid);

  /* First, remove the backends. */
  MIB_UPDATE_LOOP(mib, s, mib_i)

    struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[rowid];
    ci_assert_equal(svc->row_type, CP_SVC_SERVICE);
    if( svc->row_type != CP_SVC_SERVICE )
      MIB_UPDATE_LOOP_UNCHANGED(mib, s, return -EINVAL);

    /* Remove all associated backends from hash table.
     * Don't do linked list and array deletion as these are all getting wiped. */
    cp_mibs_under_change(s);
    ci_mib_dllist_link *lnk;
    for( lnk = ci_mib_dllist_start(mib->dim, &svc->u.service.backends);
         lnk != ci_mib_dllist_end(mib->dim, &svc->u.service.backends);
         lnk = (ci_mib_dllist_link*) cp_mib_off_to_ptr(mib->dim, lnk->next) ) {
      struct cp_svc_ep_dllist* ep = CP_SVC_BACKEND_FROM_LINK(lnk);
      svc_hash_ep_del(mib, ep - mib->svc_ep_table);
    }
    svc->u.service.n_backends = 0;

    /* Free any backend arrays. */
    if( CICP_ROWID_IS_VALID(svc->u.service.head_array_id) )
      svc_array_free(s, mib, svc);

  MIB_UPDATE_LOOP_END(mib, s);

  /* Report that the service has been updated before we actually delete it. */
  svc_updated(s, rowid, was_externally_acceleratable);

  /* Now actually delete the service. */
  MIB_UPDATE_LOOP(mib, s, mib_i)

    cp_mibs_under_change(s);
    /* Remove this element from hash table */
    svc_hash_ep_del(mib, rowid);

  MIB_UPDATE_LOOP_END(mib, s);

  return 0;
}


/* Used as a callback to cp_svc_iterate_matches(), which will pass us all
 * entries in the table having a given IP and port.  We are interested in the
 * first such backend that belongs to our service. */
static int /* Morally bool, but callback signature specifies an int-return. */
backend_is_ours(const struct cp_mibs* mib, cicp_mac_rowid_t backend_id,
                void* opaque_service_id)
{
  cicp_mac_rowid_t service_id = *(cicp_mac_rowid_t*) opaque_service_id;
  struct cp_svc_ep_dllist* backend = &mib->svc_ep_table[backend_id];
  if( backend->row_type != CP_SVC_BACKEND )
    return false;
  return backend->u.backend.svc_id == service_id;
}


int
cp_svc_backend_del(struct cp_session* s, cicp_mac_rowid_t svc_id,
                   const ci_addr_sh_t ep_addr, ci_uint16 ep_port)
{
  int mib_i;
  struct cp_mibs* mib;
  cicp_mac_rowid_t rowid;

  rowid = cp_svc_iterate_matches(cp_get_active_mib(s), ep_addr, ep_port,
                                 backend_is_ours, &svc_id);
  ci_assert(CICP_MAC_ROWID_IS_VALID(rowid));
  /* Ignore failure to find backend in production */
  if( ! CICP_MAC_ROWID_IS_VALID(rowid) )
    return 0;

  bool was_externally_acceleratable = svc_externally_acceleratable(s, svc_id);

  MIB_UPDATE_LOOP(mib, s, mib_i)

    struct cp_svc_ep_dllist* ep = &mib->svc_ep_table[rowid];
    ci_assert_equal(ep->row_type, CP_SVC_BACKEND);
    if( ep->row_type != CP_SVC_BACKEND )
      MIB_UPDATE_LOOP_UNCHANGED(mib, s, return -EINVAL);

    struct cp_svc_ep_dllist* svc = &mib->svc_ep_table[ep->u.backend.svc_id];
    ci_assert_equal(svc->row_type, CP_SVC_SERVICE);
    ci_assert_gt(svc->u.service.n_backends, 0);
    ci_assert( !ci_mib_dllist_is_empty(mib->dim, &svc->u.service.backends) );
    if( svc->row_type != CP_SVC_SERVICE || svc->u.service.n_backends == 0 ||
        ci_mib_dllist_is_empty(mib->dim, &svc->u.service.backends) )
      MIB_UPDATE_LOOP_UNCHANGED(mib, s, return -EPROTO);

    cp_mibs_under_change(s);
    /* Remove element from associated service list and array */
    /* note: the order of elements in the dll list and the array must match */
    svc_array_remove(s, mib, svc, ep->u.backend.element_id);

    /* If the endpoint being removed is not the tail element then the element
     * removed from the array has been replaced by the tail.  Need to
     * replicate this change in the linked list. */
    ci_mib_dllist_t* list = &svc->u.service.backends;
    ci_mib_dllist_link* tail_link = ci_mib_dllist_tail(mib->dim, list);
    if( tail_link != &ep->u.backend.link ) {
      ci_mib_dllist_remove(mib->dim, tail_link);
      ci_mib_dllist_insert_before(mib->dim, &ep->u.backend.link, tail_link);
      CP_SVC_BACKEND_FROM_LINK(tail_link)->u.backend.element_id =
        ep->u.backend.element_id;
    }
    ci_mib_dllist_remove(mib->dim, &ep->u.backend.link);
    svc->u.service.n_backends--;

    svc_hash_ep_del(mib, rowid);

  MIB_UPDATE_LOOP_END(mib, s);

  svc_updated(s, svc_id, was_externally_acceleratable);

  return 0;
}


void cp_svc_erase_all(struct cp_session* s)
{
  int mib_i;
  struct cp_mibs* mib;
  size_t table_size = sizeof(struct cp_svc_ep_dllist) *
                      s->mib[0].dim->svc_ep_max;
  size_t mask_size = cp_row_mask_sizeof(s->mib[0].dim->svc_arrays_max);

  MIB_UPDATE_LOOP(mib, s, mib_i)

    cp_mibs_under_change(s);
    memset(mib->svc_ep_table, 0, table_size);

  MIB_UPDATE_LOOP_END(mib, s);

  cp_row_mask_init(s->service_used, mask_size);

  svc_oof_erase_all(s);
}
