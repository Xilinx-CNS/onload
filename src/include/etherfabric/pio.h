/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Programmed Input/Output for EtherFabric Virtual Interface HAL.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_PIO_H__
#define __EFAB_PIO_H__

#include <etherfabric/base.h>

#ifdef __cplusplus
extern "C" {
#endif


#if defined(__x86_64__) || defined(__PPC64__) || defined(__aarch64__)
/*! \brief True if Programmed I/O regions can be configured */
# define EF_VI_CONFIG_PIO  1
#else
# define EF_VI_CONFIG_PIO  0
#endif


/*! \brief A Programmed I/O region */
typedef struct ef_pio {
  /** The buffer for the Programmed I/O region */
  uint8_t*         pio_buffer;
  /** The I/O region of the virtual interface that is linked with the
  ** Programmed I/O region */
  uint8_t*         pio_io;
  /** The resource ID for the Programmed I/O region */
  unsigned         pio_resource_id;
  /** The length of the Programmed I/O region */
  unsigned         pio_len;
} ef_pio;


struct ef_pd;
struct ef_vi;


#if EF_VI_CONFIG_PIO
/*! \brief Allocate a Programmed I/O region
**
** \param pio      Memory to use for the allocated Programmed I/O region.
** \param pio_dh   The ef_driver_handle to associate with the Programmed
**                 I/O region.
** \param pd       The protection domain to associate with the Programmed
**                 I/O region.
** \param len_hint Hint for the requested length of the Programmed I/O
**                 region.
** \param pd_dh    The ef_driver_handle for the protection domain.
**
** \return 0 on success, or a negative error code.
**
** Allocate a Programmed I/O region.
**
** This function is available only on 64-bit x86 processors.
*/
extern int ef_pio_alloc(ef_pio* pio, ef_driver_handle pio_dh, struct ef_pd* pd,
                        unsigned len_hint, ef_driver_handle pd_dh);
#endif


/*! \brief Get the size of the Programmed I/O region
**
** \param vi The virtual interface to query.
**
** \return The size of the Programmed I/O region.
**
** Get the size of the Programmed I/O region.
*/
extern int ef_vi_get_pio_size(ef_vi* vi);


/*! \brief Free a Programmed I/O region
**
** \param pio    The Programmed I/O region.
** \param pio_dh The ef_driver_handle for the Programmed I/O region.
**
** \return 0 on success, or a negative error code.
**
** Free a Programmed I/O region.
**
** The Programmed I/O region must not be linked when this function is
** called. See ef_pio_unlink_vi().
**
** To free up all resources, the associated driver handle must then be
** closed by calling ef_driver_close()).
*/
extern int ef_pio_free(ef_pio* pio, ef_driver_handle pio_dh);


/*! \brief Link a Programmed I/O region with a virtual interface
**
** \param pio    The Programmed I/O region.
** \param pio_dh The ef_driver_handle for the Programmed I/O region.
** \param vi     The virtual interface to link with the Programmed I/O
**               region.
** \param vi_dh  The ef_driver_handle for the virtual interface.
**
** \return 0 on success, or a negative error code.
**
** Link a Programmed I/O region with a virtual interface. Only one region can 
** be linked to a virtual interface.
*/
extern int ef_pio_link_vi(ef_pio* pio, ef_driver_handle pio_dh,
                          struct ef_vi* vi, ef_driver_handle vi_dh);

/*! \brief Unlink a Programmed I/O region from a virtual interface
**
** \param pio    The Programmed I/O region.
** \param pio_dh The ef_driver_handle for the Programmed I/O region.
** \param vi     The virtual interface to unlink from the Programmed I/O
**               region.
** \param vi_dh  The ef_driver_handle for the virtual interface.
**
** \return 0 on success, or a negative error code.
**
** Unlink a Programmed I/O region from a virtual interface.
*/
extern int ef_pio_unlink_vi(ef_pio* pio, ef_driver_handle pio_dh,
                            struct ef_vi* vi, ef_driver_handle vi_dh);


/*! \brief Copy data from memory into a Programmed I/O region
**
** \param vi     The virtual interface for the Programmed I/O region.
** \param base   The base address of the memory to copy.
** \param offset The offset into the Programmed I/O region at which to copy
**               the data to.  You shouldn't try to copy memory to part of the
**               PIO region that is already in use for an ongoing send as this
**               may result in corruption.
** \param len    The number of bytes to copy.
**
** \return 0 on success, or a negative error code.
**
** This function copies data from the user buffer to the adapter's PIO
** buffer.  It goes via an intermediate buffer to meet any alignment
** requirements that the adapter may have.
**
** Please refer to the PIO transmit functions (e.g.:
** ef_vi_transmit_pio() and ef_vi_transmit_copy_pio()) for alignment
** requirements of packets.
**
** The Programmed I/O region can hold multiple smaller packets, referenced
** by different offset parameters. All other constraints must still be
** observed, including:
** - alignment
** - minimum size
** - maximum size
** - avoiding reuse until transmission is complete.
*/
extern int ef_pio_memcpy(ef_vi* vi, const void* base, int offset, int len);


#ifdef __cplusplus
}
#endif

#endif  /* __EFAB_PIO_H__ */
