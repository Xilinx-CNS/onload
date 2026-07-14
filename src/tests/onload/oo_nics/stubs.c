/* SPDX-License-Identifier: GPL-2.0 */
/* SPDX-FileCopyrightText: (c) Copyright 2026 Advanced Micro Devices, Inc. */

#include "stubs.h"
#include <string.h>
#include <stdio.h>

/* Global NIC array — same as the kernel's oo_nics */
struct oo_nic oo_nics[CI_CFG_MAX_HWPORTS];

/* Mock efhw_nic and efrm_client storage */
static struct efhw_nic mock_efhw_nics[CI_CFG_MAX_HWPORTS];
static struct efrm_client mock_efrm_clients[CI_CFG_MAX_HWPORTS];

/* Cplane mock state */
static cicp_hwport_mask_t mock_cplane_hwports;

/* Interface name table for dev_get_by_name */
#define MAX_MOCK_INTERFACES 16
static struct {
  char name[16];
  int ifindex;
  cicp_hwport_mask_t rx_hwports;
} mock_interfaces[MAX_MOCK_INTERFACES];
static int mock_interface_count;

/* Mock net_device storage for dev_get_by_name */
static struct net_device mock_net_devices[MAX_MOCK_INTERFACES];

void test_set_cplane_hwports(cicp_hwport_mask_t mask)
{
  mock_cplane_hwports = mask;
}

void test_add_interface(const char* name, int ifindex,
                        cicp_hwport_mask_t rx_hwports)
{
  int i = mock_interface_count;
  ci_assert_lt(i, MAX_MOCK_INTERFACES);
  ++mock_interface_count;
  strncpy(mock_interfaces[i].name, name, sizeof(mock_interfaces[i].name) - 1);
  mock_interfaces[i].name[sizeof(mock_interfaces[i].name) - 1] = '\0';
  mock_interfaces[i].ifindex = ifindex;
  mock_interfaces[i].rx_hwports = rx_hwports;

  strncpy(mock_net_devices[i].name, name, sizeof(mock_net_devices[i].name) - 1);
  mock_net_devices[i].name[sizeof(mock_net_devices[i].name) - 1] = '\0';
  mock_net_devices[i].ifindex = ifindex;
}

void test_add_hwport(int hwport, int is_llct, struct net_device* net_dev)
{
  ci_assert_ge(hwport, 0);
  ci_assert_lt(hwport, CI_CFG_MAX_HWPORTS);
  mock_efhw_nics[hwport].index = hwport;
  mock_efhw_nics[hwport].net_dev = net_dev;
  mock_efhw_nics[hwport].flags = is_llct ? NIC_FLAG_LLCT : 0;
  mock_efhw_nics[hwport].devtype.function = EFHW_FUNCTION_PF;

  mock_efrm_clients[hwport].nic = &mock_efhw_nics[hwport];

  oo_nics[hwport].efrm_client = &mock_efrm_clients[hwport];
  oo_nics[hwport].oo_nic_flags = OO_NIC_UP;
}

void test_cleanup(void)
{
  memset(oo_nics, 0, sizeof(oo_nics));
  memset(mock_efhw_nics, 0, sizeof(mock_efhw_nics));
  memset(mock_efrm_clients, 0, sizeof(mock_efrm_clients));
  memset(mock_interfaces, 0, sizeof(mock_interfaces));
  memset(mock_net_devices, 0, sizeof(mock_net_devices));
  mock_cplane_hwports = 0;
  mock_interface_count = 0;
}


/* Mock implementations of kernel/driver functions */

cicp_hwport_mask_t oo_cp_get_hwports(struct oo_cplane_handle* cp)
{
  (void)cp;
  return mock_cplane_hwports;
}

int oo_cp_find_llap(struct oo_cplane_handle* cp, ci_ifid_t ifindex,
                    ci_mtu_t *out_mtu, cicp_hwport_mask_t *out_hwports,
                    cicp_hwport_mask_t *out_rx_hwports,
                    ci_mac_addr_t *out_mac, cicp_encap_t *out_encap)
{
  int i;
  (void)cp;

  for( i = 0; i < mock_interface_count; ++i ) {
    if( mock_interfaces[i].ifindex == ifindex ) {
      if( out_rx_hwports )
        *out_rx_hwports = mock_interfaces[i].rx_hwports;
      if( out_hwports )
        *out_hwports = mock_interfaces[i].rx_hwports;
      return 0;
    }
  }
  return -1;
}

struct efhw_nic *efrm_client_get_nic(struct efrm_client *client)
{
  return client->nic;
}

int efrm_client_accel_allowed(struct efrm_client *client)
{
  (void)client;
  return 1;
}

struct efhw_nic* efhw_nic_find_by_foo(nic_match_func match,
                                      const void *match_data)
{
  int i;
  for( i = 0; i < CI_CFG_MAX_HWPORTS; ++i ) {
    if( oo_nics[i].efrm_client &&
        match(&mock_efhw_nics[i], match_data) )
      return &mock_efhw_nics[i];
  }
  return NULL;
}

struct oo_nic* oo_nic_find(const struct efhw_nic* nic)
{
  if( nic->index >= 0 && nic->index < CI_CFG_MAX_HWPORTS &&
      oo_nics[nic->index].efrm_client )
    return &oo_nics[nic->index];
  return NULL;
}

int oo_check_nic_suitable_for_onload(struct oo_nic* onic)
{
  struct efhw_nic *nic = efrm_client_get_nic(onic->efrm_client);

  if( ! efrm_client_accel_allowed(onic->efrm_client) )
    return 0;
  return !(nic->flags & NIC_FLAG_PACKED_STREAM);
}

int oo_check_nic_llct(struct oo_nic* onic)
{
  struct efhw_nic *nic;

  if( ! onic->efrm_client )
    return 0;

  nic = efrm_client_get_nic(onic->efrm_client);
  return !!(nic->flags & NIC_FLAG_LLCT);
}

struct net_device* dev_get_by_name(struct net* ns, const char* name)
{
  int i;
  (void)ns;

  for( i = 0; i < mock_interface_count; ++i ) {
    if( strcmp(mock_net_devices[i].name, name) == 0 )
      return &mock_net_devices[i];
  }
  return NULL;
}

