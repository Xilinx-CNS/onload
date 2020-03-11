#include "stack_interface.h"

int tcp_helper_rx_vi_id(tcp_helper_resource_t* trs, int hwport)
{
  return trs->stack_id;
}

int tcp_helper_vi_hw_stack_id(tcp_helper_resource_t* trs, int hwport)
{
  return trs->stack_id;
}

int tcp_helper_cluster_vi_hw_stack_id(tcp_helper_cluster_t* thc, int hwport)
{
  return 1;
}

int tcp_helper_cluster_vi_base(tcp_helper_cluster_t* thc, int hwport)
{
  return 1;
}

int tcp_helper_vi_hw_rx_loopback_supported(tcp_helper_resource_t* trs,
                                                  int hwport)
{
  return 0;
}

