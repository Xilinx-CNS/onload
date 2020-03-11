/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Base definitions for EtherFabric Virtual Interface HAL.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_BASE_H__
#define __EFAB_BASE_H__

#include <etherfabric/ef_vi.h>

#ifdef __cplusplus
extern "C" {
#endif


/*! \brief How much to shift an address to get the page number */
#define EF_VI_NIC_PAGE_SHIFT 12
/*! \brief The size of a page of memory on the NIC, in bytes */
#define EF_VI_NIC_PAGE_SIZE  (1<<EF_VI_NIC_PAGE_SHIFT)


/*! \brief An ef_driver_handle is needed to allocate resources. */
#ifdef __KERNEL__
typedef struct efhw_nic*   ef_driver_handle;
#else
typedef int                ef_driver_handle;
#endif

struct timeval;

/*! \brief Format for outputting an ef_addr. */
#define EF_ADDR_FMT             "%" CI_PRIx64
/*! \brief An address that is always invalid. */
#define EF_INVALID_ADDR         ((ef_addr) -1)


/**********************************************************************
 * ef_vi **************************************************************
 **********************************************************************/

/*! \brief Block, waiting until the event queue is non-empty.
**
** \param vi          The virtual interface on which to wait.
** \param vi_dh       Driver handle associated with the virtual interface.
** \param current_ptr Must come from ef_eventq_current().
** \param timeout     Maximum time to wait for, or 0 to wait forever.
**
** \return 0 on success, or a negative error code:\n
**         -ETIMEDOUT on time-out).
**
** Block, waiting until the event queue is non-empty. This enables interrupts.
**
** Note that when this function returns it is not guaranteed that an event
** will be present in the event queue, but in most cases there will be.
*/
extern int ef_eventq_wait(ef_vi* vi, ef_driver_handle vi_dh,
                          unsigned current_ptr,
                          const struct timeval* timeout);


/**********************************************************************
 * ef_driver **********************************************************
 **********************************************************************/

/*! \brief Obtain a driver handle
**
** \param dh_out Pointer to an ef_driver_handle, that is updated on return
**               with the new driver handle.
**
** \return 0 on success, or a negative error code.
**
** Obtain a driver handle.
*/
extern int ef_driver_open(ef_driver_handle* dh_out);

/*! \brief Close a driver handle.
**
** \param dh The handle to the driver to close.
**
** \return 0 on success, or a negative error code.
**
** Close a driver handle.
**
** This should be called to free up resources when the driver handle is no
** longer needed, but the application is to contimue running.
**
** Any associated virtual interface, protection domain, or driver
** structures must not be used after this call has been made.
**
** \note Resources are also freed when the application exits, and so this
** function does not need to be called on exit.
*/
extern int ef_driver_close(ef_driver_handle dh);

#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_BASE_H__ */
