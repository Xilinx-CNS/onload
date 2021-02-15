/* There is no standard
#ifndef __ONLOAD_OO_P_DLLIST_H__
#define __ONLOAD_OO_P_DLLIST_H__
 * guard, because this file can be included with OO_P_DLLIST_NO_CODE and
 * without it.  We rely on the guard of the includer.
 *
 * We really should remove this crazy data / code separation in the include
 * files...
 */


#ifdef OO_P_DLLIST_NO_CODE

/* Structure to use for list head and members.
 *
 * This structure is designed for double-linked lists in the Onload stack
 * shared state.
 *
 * The most of these double-linked lists share common semantics:
 * - Circular linked list, with the head/tail at the main stack state
 *   and members scattered in socket states.
 * - Empty/unused link is self-linked.
 */
struct oo_p_dllink {
 oo_p next;
 oo_p prev;
};

#undef OO_P_DLLIST_NO_CODE
#else /* OO_P_DLLIST_NO_CODE */

/* Structure to declare locally and use in the code. */
struct oo_p_dllink_state {
  struct oo_p_dllink* l;
  oo_p p;
};

static inline struct oo_p_dllink* oo_p_dllink_from_p(ci_netif* ni, oo_p p)
{
  return (void*)CI_NETIF_PTR(ni, p);
}


/* Create the state link structure from a pointer in the stack state.
 * For pointers in socket state please use _sb() version below.
 */
static inline struct oo_p_dllink_state
oo_p_dllink_ptr(ci_netif* ni, struct oo_p_dllink* l)
{
  struct oo_p_dllink_state ret = {
    .l = l,
    .p = oo_state_ptr_to_statep(ni, l),
  };
  return ret;
}

/* Create the link state structure from statep */
static inline struct oo_p_dllink_state
oo_p_dllink_statep(ci_netif* ni, oo_p p)
{
  struct oo_p_dllink_state ret = {
    .l = oo_p_dllink_from_p(ni, p),
    .p = p,
  };
  return ret;
}

/* Create the state link structure from a pointer in a socket state */
#ifdef __KERNEL__
static inline oo_p
oo_p_dllink_sb_to_p(ci_netif* ni, citp_waitable* sb, struct oo_p_dllink* l)
{
  oo_p p = oo_sockp_to_statep(ni, sb->bufid);
  OO_P_ADD(p, (uintptr_t)l - (uintptr_t)sb);
  return p;
}

static inline struct oo_p_dllink_state
oo_p_dllink_sb(ci_netif* ni, citp_waitable* sb, struct oo_p_dllink* l)
{
  struct oo_p_dllink_state ret = {
    .l = l,
    .p = oo_p_dllink_sb_to_p(ni, sb, l),
  };
  return ret;
}
#else /* __KERNEL__ */
static inline struct oo_p_dllink_state
oo_p_dllink_sb(ci_netif* ni, citp_waitable* sb, struct oo_p_dllink* l)
{
  return oo_p_dllink_ptr(ni, l);
}
#endif /* __KERNEL__ */


/* Initialise a link or a head of a list */
static inline void
oo_p_dllink_init(ci_netif* ni, struct oo_p_dllink_state state)
{
  state.l->next = state.l->prev = state.p;
}

/* Delete a link from any list it is linked in.
 * In the most cases the caller should call oo_p_dllink_init()
 * after removal, unless the link is immediately reused.
 */
static inline void
oo_p_dllink_del(ci_netif* ni, struct oo_p_dllink_state link)
{
  oo_p_dllink_from_p(ni, link.l->prev)->next = link.l->next;
  oo_p_dllink_from_p(ni, link.l->next)->prev = link.l->prev;
}

static inline void
oo_p_dllink_del_init(ci_netif* ni, struct oo_p_dllink_state link)
{
  oo_p_dllink_del(ni, link);
  oo_p_dllink_init(ni, link);
}

static inline void
__oo_p_dllink_add(ci_netif* ni, struct oo_p_dllink_state prev,
                  struct oo_p_dllink_state next,
                  struct oo_p_dllink_state new)
{
  next.l->prev = new.p;
  new.l->next = next.p;
  new.l->prev = prev.p;
  prev.l->next = new.p;
}

static inline void
oo_p_dllink_add(ci_netif* ni, struct oo_p_dllink_state list,
                struct oo_p_dllink_state link)
{
  __oo_p_dllink_add(ni, list, oo_p_dllink_statep(ni, list.l->next), link);
}

static inline void
oo_p_dllink_add_tail(ci_netif* ni, struct oo_p_dllink_state list,
                struct oo_p_dllink_state link)
{
  __oo_p_dllink_add(ni, oo_p_dllink_statep(ni, list.l->prev), list, link);
}

static inline bool
oo_p_dllink_is_empty(ci_netif* ni, struct oo_p_dllink_state list)
{
  return list.l->next == list.p;
}

static inline void
oo_p_dllink_assert_empty(ci_netif* ni, struct oo_p_dllink_state l,
                         const char* file, int line)
{
  _ci_assert_equal(l.l->next, l.p, file, line);
  _ci_assert_equal(l.l->prev, l.p, file, line);
}
#define OO_P_DLLINK_ASSERT_EMPTY(ni, l) \
  oo_p_dllink_assert_empty(ni, l, __FILE__, __LINE__)
#define OO_P_DLLINK_ASSERT_EMPTY_SB(ni, sb, l) \
  OO_P_DLLINK_ASSERT_EMPTY(ni, oo_p_dllink_sb(ni, sb, l))


/* Iterate through the list */
#define oo_p_dllink_for_each(ni, link, list) \
  for( link = oo_p_dllink_statep(ni, list.l->next);  \
       link.l != list.l;                            \
       link = oo_p_dllink_statep(ni, link.l->next) )

/* Iterate through the list, protecting against removal */
#define oo_p_dllink_for_each_safe(ni, link, n, list) \
  for( link = oo_p_dllink_statep(ni, list.l->next),  \
       n = oo_p_dllink_statep(ni, link.l->next);     \
       link.l != list.l;                            \
       link = n, n = oo_p_dllink_statep(ni, link.l->next) )

/* Insert the `list` between `prev` and `next` */
static inline void
__oo_p_dllink_splice(ci_netif* ni, struct oo_p_dllink_state list,
                     struct oo_p_dllink_state prev,
                     struct oo_p_dllink_state next)
{
  struct oo_p_dllink_state first = oo_p_dllink_statep(ni, list.l->next);
  struct oo_p_dllink_state last = oo_p_dllink_statep(ni, list.l->prev);

  first.l->prev = prev.p;
  prev.l->next = first.p;

  last.l->next = next.p;
  next.l->prev = last.p;
}

static inline void
oo_p_dllink_splice(ci_netif* ni, struct oo_p_dllink_state list,
                   struct oo_p_dllink_state into)
{
  if( ! oo_p_dllink_is_empty(ni, list) ) {
    __oo_p_dllink_splice(ni, list, into,
                         oo_p_dllink_statep(ni, into.l->next));
  }
}

static inline void
oo_p_dllink_splice_tail(ci_netif* ni, struct oo_p_dllink_state list,
                        struct oo_p_dllink_state into)
{
  if( ! oo_p_dllink_is_empty(ni, list) ) {
    __oo_p_dllink_splice(ni, list, oo_p_dllink_statep(ni, into.l->prev),
                         into);
  }
}


/* As _add(), except that it is safe with concurrent traversal of the list
 * obtained by ci_xchg32(). Multiple writers still require synchronisation.
 * Returns non-zero on success and zero on failure. In case of failure,
 * [list] will not be modified and [link] will be restored to its original
 * state. */
static inline bool
oo_p_dllink_concurrent_add(ci_netif* ni, struct oo_p_dllink_state list,
                           struct oo_p_dllink_state link)
{
  oo_p next = OO_ACCESS_ONCE(list.l->next);
  oo_p next_orig = link.l->next;
  oo_p prev_orig = link.l->prev;

  link.l->next = next;
  link.l->prev = list.p;
  ci_wmb();

  /* If the list changes underneath us, the final traversal is underway, so
   * don't change anything. */
  if( ci_cas32u_fail((ci_uint32*)&list.l->next, next, link.p) ) {
    link.l->next = next_orig;
    link.l->prev = prev_orig;
    return false;
  }

  oo_p_dllink_statep(ni, next).l->prev = list.l->next;
  return true;
}

#endif /* OO_P_DLLIST_NO_CODE */
