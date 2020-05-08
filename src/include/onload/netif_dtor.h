
#include <ci/internal/ip.h>

#if (CI_CFG_UL_INTERRUPT_HELPER && ! defined(__KERNEL__)) || ( ! CI_CFG_UL_INTERRUPT_HELPER && defined(__KERNEL__))

#define OO_DO_STACK_DTOR 1


/* Release all the deferred packets */
void oo_deferred_free(ci_netif *ni);

/* Get all RX and TX complete events and check for packet leaks. */
void oo_netif_dtor_pkts(ci_netif* ni);

void oo_netif_apps_gone(ci_netif* netif);

#else
#define OO_DO_STACK_DTOR 0
#endif
