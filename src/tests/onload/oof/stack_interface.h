#ifndef __OOF_TEST_STACK_INTERFACE_H__
#define __OOF_TEST_STACK_INTERFACE_H__

#include "efrm_interface.h"
#include "stack.h"

/* Return the instance number of the VI associated with the named hwport,
 * or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_rx_vi_id(tcp_helper_resource_t*, int hwport);
extern int tcp_helper_plugin_vi_id(tcp_helper_resource_t*, int hwport,
                                   int subvi);

/* Return the hw stack id of the VI associated with the named hwport,
 * or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport);

/* Return the hw stack id of the VI associated with the named hwport on
 * given cluster, or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_cluster_vi_hw_stack_id(tcp_helper_cluster_t* thc, int hwport);

/* Return VI base of the VI set instantiated on the given hwport for the
 * given cluster, or -1 if cluster does not have VI set for that hwport */
extern int tcp_helper_cluster_vi_base(tcp_helper_cluster_t* thc, int hwport);

/* Return whether receiving of looped back traffic is enabled on
 * the named hwport, or -1 if we don't have a VI for that hwport.
 */
extern int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                                  int hwport);

extern int tcp_helper_vi_hw_drop_filter_supported(tcp_helper_resource_t* trs,
                                                  int hwport);

#endif /* __OOF_TEST_STACK_INTERFACE_H__ */
