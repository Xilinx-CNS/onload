#ifndef INCLUDED_LIB_CPLANE_UAPI_PRIVATE_H_
#define INCLUDED_LIB_CPLANE_UAPI_PRIVATE_H_
#include <cplane/api.h>
#include <cplane/cplane.h>
#include <limits.h>

#define EF_CP_PUBLIC_API __attribute__((visibility("default")))

struct llap_extra {
  void *cookie;
  bool is_registered;
};

#define EF_CP_LLAP_TRIE_BITS  4
#define EF_CP_LLAP_TRIE_NUM   (1 << EF_CP_LLAP_TRIE_BITS)
#define EF_CP_LLAP_TRIE_MASK  (EF_CP_LLAP_TRIE_NUM-1)
#define EF_CP_LLAP_TRIE_DEPTH ((sizeof(int) * CHAR_BIT + EF_CP_LLAP_TRIE_BITS-1) / EF_CP_LLAP_TRIE_BITS)

struct ef_cp_handle {
  int drv_fd;
  struct oo_cplane_handle cp;

  /* Additional information that we need to store per interface, as a
   * dictionary mapping ifindex->llap_extra.
   *
   * This data structure is fundamentally a bitwise trie on the 32-bit ifindex,
   * but with a couple of optimisations:
   * - The bottommost level's entries are an inline array rather than having
   *   another level of indirection to get at the actual data
   * - The 0th entry of every level (i.e. the path to get to keys 0-15) is
   *   inline here rather than being malloced directly. This gives better
   *   locality, but the main reason is to allow skipping the full tree lookup
   *   when the ifindex is a small integer (as it will almost always be): we
   *   can use a CLZ opcode to figure out how many levels we can skip and go
   *   straight there with simple array arithmetic.
   */
  struct llap_extra* llap_levels[EF_CP_LLAP_TRIE_DEPTH-1][EF_CP_LLAP_TRIE_NUM];
  struct llap_extra llap_level0[EF_CP_LLAP_TRIE_NUM];
  pthread_mutex_t llap_update_mtx;
};

void cp_uapi_ifindex_table_init(struct ef_cp_handle *cp);
void cp_uapi_ifindex_table_destroy(struct ef_cp_handle *cp);
struct llap_extra* cp_uapi_lookup_ifindex(struct ef_cp_handle *cp, int ifindex);

#endif
