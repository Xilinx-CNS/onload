/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Protection Domains for EtherFabric Virtual Interface HAL.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_PD_H__
#define __EFAB_PD_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/* src/tool/solar_clusterd will need updating if you change this
 * enum */
/*! \brief Flags for a protection domain */
enum ef_pd_flags {
  /** Default flags */
  EF_PD_DEFAULT          = 0x0,
  /** Protection domain uses a virtual function and the system
   * IOMMU instead of NIC buffer table.
   */
  EF_PD_VF               = 0x1,
  /** Protection domain uses physical addressing mode */
  EF_PD_PHYS_MODE        = 0x2,
  /** Protection domain supports packed stream mode */
  EF_PD_RX_PACKED_STREAM = 0x4,  /* ef10 only */
  /** Protection domain supports virtual ports */
  EF_PD_VPORT            = 0x8,  /* ef10 only */
  /** Protection domain supports HW multicast loopback */
  EF_PD_MCAST_LOOP       = 0x10,  /* ef10 only */
  /** Protection domain uses >= 64KB registered memory mappings */
  EF_PD_MEMREG_64KiB     = 0x20,  /* ef10 only */
  /** Bypass the /proc/driver/sfc_resource/.../enable blacklist feature.
   * Required CAP_NET_ADMIN */
  EF_PD_IGNORE_BLACKLIST = 0x40,
};


/*! \brief May be passed to ef_pd_alloc_with_vport() to indicate that the PD
 * is not associated with a particular VLAN.
 */
#define EF_PD_VLAN_NONE  -1


/*! \brief A protection domain */
typedef struct ef_pd {
  /** Flags for the protection domain */
  enum ef_pd_flags pd_flags;
  /** Resource ID of the protection domain */
  unsigned         pd_resource_id;
  /** Name of the interface associated with the protection domain */
  char*            pd_intf_name;

  /* Support for application clusters */
  /** Name of the application cluster associated with the protection domain */
  char*            pd_cluster_name;
  /** Socket for the application cluster associated with the protection
  **  domain */
  int              pd_cluster_sock;
  /** Driver handle for the application cluster associated with the protection
  **  domain */
  ef_driver_handle pd_cluster_dh;
  /** Resource ID of the virtual interface set for the application cluster
  **  associated with the protection domain */
  unsigned         pd_cluster_viset_resource_id;
  /** Index of VI wanted within a cluster. */
  int              pd_cluster_viset_index;
} ef_pd;


/*! \brief Allocate a protection domain
**
** \param pd      Memory to use for the allocated protection domain.
** \param pd_dh   The ef_driver_handle to associate with the protection
**                domain.
** \param ifindex Index of the interface to use for the protection domain.
** \param flags   Flags to specify protection domain properties.
**
** \return 0 on success, or a negative error code.
**
** Allocate a protection domain.
**
** Allocates a 'protection domain' which specifies how memory should be
** protected for your VIs. For supported modes - see \ref pb_addressing
**
** \note If you are using a 'hardened' kernel (e.g. Gentoo-hardened) then
**       this is the first call which will probably fail. Currently, the
**       only workaround to this is to run as root.
**
** Use "if_nametoindex" to find the index of an interface, which needs to
** be the physical interface (i.e. eth2, not eth2.6 or bond0 or similar.)
*/
extern int ef_pd_alloc(ef_pd* pd, ef_driver_handle pd_dh, int ifindex,
                       enum ef_pd_flags flags);


/*! \brief Allocate a protection domain for a named interface or cluster
**
** \param pd                   Memory to use for the allocated protection
**                             domain.
** \param pd_dh                An ef_driver_handle.
** \param cluster_or_intf_name Name of cluster, or name of interface.
** \param flags                Flags to specify protection domain
**                             properties.
**
** \return 0 on success, or a negative error code.
**
** Allocate a protection domain, trying first from a cluster of the given
** name, or if no cluster of that name exists assume that @p
** cluster_or_intf_name is the name of an interface.
**
** When @p cluster_or_intf_name gives the name of a cluster it may
** optionally be prefixed with a channel number.  For example: "0@cluster".
** In this case the specified channel instance within the cluster is
** allocated.
*/
extern int ef_pd_alloc_by_name(ef_pd* pd, ef_driver_handle pd_dh,
                               const char* cluster_or_intf_name,
                               enum ef_pd_flags flags);


/*! \brief Allocate a protection domain with vport support
**
** \param pd        Memory to use for the allocated protection domain.
** \param pd_dh     The ef_driver_handle to associate with the protection
**                  domain.
** \param intf_name Name of interface to use for the protection domain.
** \param flags     Flags to specify protection domain properties.
** \param vlan_id   The vlan id to associate with the protection domain.
**
** \return 0 on success, or a negative error code.
**
** Allocate a protection domain with vport support.
**
** Solarflare adapters have an internal switch to connect virtual ports
** (vports) to functions. This call is used to add an extra vport to a
** function, typically so that the function can then pass traffic to itself
** between an existing vport and the extra vport.
**
** The @p vlan_id can be either EF_PD_VLAN_NONE, or the id of a vlan to
** associate a vlan with the vport.
**
** This call requires full-featured firmware.
*/
extern int ef_pd_alloc_with_vport(ef_pd* pd, ef_driver_handle pd_dh,
                                  const char* intf_name,
                                  enum ef_pd_flags flags, int vlan_id);

/*! \brief Look up the interface being used by the protection domain
**
** \param pd Memory used by the protection domain.
**
** \return The interface being used by the protection domain.
**         NULL when interface was not accessible for user context.
**
** Look up the interface being used by the protection domain.
*/
extern const char* ef_pd_interface_name(ef_pd* pd);

/*! \brief Free a protection domain
**
** \param pd    Memory used by the protection domain.
** \param pd_dh The ef_driver_handle associated with the protection domain.
**
** \return 0 on success, or a negative error code.
**
** Free a protection domain.
**
** To free up all resources, you must also close the associated driver
** handle.
**
** You should call this when you're finished; although they will be cleaned
** up when the application exits, if you don't.
**
** Be very sure that you don't try and re-use the vi/pd/driver structure
** after it has been freed.
*/
extern int ef_pd_free(ef_pd* pd, ef_driver_handle pd_dh);

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PD_H__ */
