/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc. */

/**************************************************************************\
*//*! \file
** \author    Solarflare Communications, Inc.
** \brief     Checksum utility functions.
** \date      2018/11/06
** \copyright Copyright &copy; 2018 Solarflare Communications, Inc. All
**            rights reserved. Solarflare, OpenOnload and EnterpriseOnload
**            are trademarks of Solarflare Communications, Inc.
*//*
\**************************************************************************/

#ifndef __EFAB_CHECKSUM_H__
#define __EFAB_CHECKSUM_H__

#include <etherfabric/base.h>

#ifdef __KERNEL__
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#else
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct ipv6hdr;

/*! \brief Calculate the checksum for an IP header
**
** \param ip The IP header to use.
**
** \return The checksum of the IP header.
**
** Calculate the checksum for an IP header.  The IP header must be populated
** (with the exception of the checksum field itself, which is ignored) before
** calling this function.
*/
extern uint32_t ef_ip_checksum(const struct iphdr* ip);

/*! \brief Calculate the checksum for a non-IPv6 UDP packet
**
** \param ip     The IP header for the packet.
** \param udp    The UDP header for the packet.
** \param iov    Start of the iovec array describing the UDP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the UDP packet.
**
** Calculate the checksum for a non-IPv6 UDP packet.  The UDP header must be
** populated (with the exception of the checksum field itself, which is
** ignored) before calling this function.
*/
extern uint32_t
ef_udp_checksum(const struct iphdr* ip, const struct udphdr* udp,
                const struct iovec* iov, int iovlen);

/*! \brief Calculate the checksum for an IPv6 UDP packet
**
** \param ip6    The IPv6 header for the packet.
** \param udp    The UDP header for the packet.
** \param iov    Start of the iovec array describing the UDP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the UDP packet.
**
** Calculate the checksum for an IPv6 UDP packet.  The UDP header must be
** populated (with the exception of the checksum field itself, which is
** ignored) before calling this function.
*/
extern uint32_t
ef_udp_checksum_ip6(const struct ipv6hdr* ip6, const struct udphdr* udp,
                    const struct iovec* iov, int iovlen);

/*! \brief Calculate the checksum for a UDP packet
**
** \param af     The address family of the IP header for the packet.
** \param ipx    The IP header for the packet.
** \param udp    The UDP header for the packet.
** \param iov    Start of the iovec array describing the UDP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the UDP packet.
**
** Calculate the checksum for a UDP packet.  The UDP header must be populated
** (with the exception of the checksum field itself, which is ignored) before
** calling this function.
*/
extern uint32_t
ef_udp_checksum_ipx(int af, const void* ipx, const struct udphdr* udp,
                    const struct iovec* iov, int iovlen);

/*! \brief Calculate the checksum for a UDP packet
**
** \param af            The address family of the IP header for the packet.
** \param ipx           The IP header for the packet (struct iphdr or ipv6hdr).
** \param udp           The UDP header for the packet.
** \param payload       UDP payload.
** \param payload_len   Length of the payload.
**
** \return The checksum of the UDP packet in big endian order.
**
** Calculate the checksum for a UDP packet.  The UDP header must be populated
** (with the exception of the checksum field itself, which is ignored) before
** calling this function.
*/
ef_vi_inline uint32_t
ef_udp_checksum_ipx_buf(int af, const void* ipx, const struct udphdr* udp,
                        const void* payload, size_t payload_len)
{
  const struct iovec iov = {
    .iov_base = (void*)payload,
    .iov_len = payload_len
  };

  return ef_udp_checksum_ipx(af, ipx, udp, &iov, 1);
}

/*! \brief Calculate the checksum for a non-IPv6 TCP packet
**
** \param ip     The IP header for the packet.
** \param tcp    The TCP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the TCP packet.
**
** Calculate the checksum for a non-IPv6 TCP packet.  The TCP header must be
** populated (with the exception of the checksum field itself, which is
** ignored) before calling this function.
*/
extern uint32_t
ef_tcp_checksum(const struct iphdr* ip, const struct tcphdr* tcp,
                const struct iovec* iov, int iovlen);

/*! \brief Calculate the checksum for an IPv6 TCP packet
**
** \param ip6    The IPv6 header for the packet.
** \param tcp    The TCP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the TCP packet.
**
** Calculate the checksum for an IPv6 TCP packet.  The TCP header must be
** populated (with the exception of the checksum field itself, which is
** ignored) before calling this function.
*/
extern uint32_t
ef_tcp_checksum_ip6(const struct ipv6hdr* ip6, const struct tcphdr* tcp,
                    const struct iovec* iov, int iovlen);

/*! \brief Calculate the checksum for a TCP packet
**
** \param af     The address family of the IP header for the packet.
** \param ipx    The IP header for the packet.
** \param tcp    The TCP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the TCP packet.
**
** Calculate the checksum for a TCP packet.  The TCP header must be populated
** (with the exception of the checksum field itself, which is ignored) before
** calling this function.
*/
extern uint32_t
ef_tcp_checksum_ipx(int af, const void* ipx, const struct tcphdr* tcp,
                    const struct iovec* iov, int iovlen);

/*! \brief Calculate the checksum for a TCP packet
**
** \param af            The address family of the IP header for the packet.
** \param ipx           The IP header for the packet (struct iphdr or ipv6hdr).
** \param tcp           The TCP header for the packet.
** \param payload       TCP payload.
** \param payload_len   Length of the payload.
**
** \return The checksum of the TCP packet in big endian order.
**
** Calculate the checksum for a TCP packet.  The TCP header must be populated
** (with the exception of the checksum field itself, which is ignored) before
** calling this function.
*/
ef_vi_inline uint32_t
ef_tcp_checksum_ipx_buf(int af, const void* ipx, const struct tcphdr* tcp,
                        const void* payload, size_t payload_len)
{
  const struct iovec iov = {
    .iov_base = (void*)payload,
    .iov_len = payload_len
  };

  return ef_tcp_checksum_ipx(af, ipx, tcp, &iov, 1);
}

/*! \brief Check IPv4 UDP checksum correctness
**
** \param ip     The IPv4 header for the packet.
** \param udp    The UDP header for the packet.
** \param iov    Start of the iovec array describing the UDP payload.
** \param iovlen Length of the iovec array.
**
** \return Non-zero code if the checksum is correct, zero otherwise.
**
** IPv4 UDP packets are allowed to omit their checksum. Caller needs to check
** whether the checksum field is zero before calling the function.
*/
extern int
ef_udp_checksum_is_correct(const struct iphdr* ip, const struct udphdr* udp,
                           const struct iovec* iov, int iovlen);

/*! \brief Check IPv6 UDP checksum correctness
**
** \param ip     The IPv6 header for the packet.
** \param udp    The UDP header for the packet.
** \param iov    Start of the iovec array describing the UDP payload.
** \param iovlen Length of the iovec array.
**
** \return Non-zero code if the checksum is correct, zero otherwise.
*/
extern int
ef_udp_checksum_ip6_is_correct(const struct ipv6hdr* ip6,
                               const struct udphdr* udp,
                               const struct iovec* iov, int iovlen);

/*! \brief Check UDP checksum correctness
**
** \param ip            The IP header for the packet (struct iphdr or ipv6hdr).
** \param udp           The UDP header for the packet.
** \param payload       UDP payload.
** \param payload_len   Length of the payload.
**
** \return Non-zero code if the checksum is correct, zero otherwise.
**
** IPv4 UDP packets are allowed to omit their checksum. Caller needs to check
** whether the checksum field is zero before calling the function.
*/
ef_vi_inline int
ef_udp_checksum_ipx_is_correct(int af, const void* ipx, const struct udphdr* udp,
                               const void* payload, size_t payload_len)
{
  const struct iovec iov = {
    .iov_base = (void*)payload,
    .iov_len = payload_len
  };

  return af == AF_INET6 ?
    ef_udp_checksum_ip6_is_correct((const struct ipv6hdr*)ipx, udp, &iov, 1) :
    ef_udp_checksum_is_correct((const struct iphdr*)ipx, udp, &iov, 1);
}

/*! \brief Check IPv4 TCP checksum correctness
**
** \param ip     The IPv4 header for the packet.
** \param tcp    The TCP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return Non-zero code if the checksum is correct, zero otherwise.
*/
extern int
ef_tcp_checksum_is_correct(const struct iphdr* ip, const struct tcphdr* tcp,
                           const struct iovec* iov, int iovlen);

/*! \brief Check IPv6 TCP checksum correctness
**
** \param ip     The IPv6 header for the packet.
** \param tcp    The TCP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return Non-zero code if the checksum is correct, zero otherwise.
*/
extern int
ef_tcp_checksum_ip6_is_correct(const struct ipv6hdr* ip6,
                               const struct tcphdr* tcp,
                               const struct iovec* iov, int iovlen);

/*! \brief Check TCP checksum correctness
**
** \param ip            The IP header for the packet (struct iphdr or ipv6hdr).
** \param tcp           The TCP header for the packet.
** \param payload       TCP payload.
** \param payload_len   Length of the payload.
**
** \return Non-zero code if the checksum is correct, zero otherwise.
*/
ef_vi_inline int
ef_tcp_checksum_ipx_is_correct(int af, const void* ipx, const struct tcphdr* tcp,
                               const void* payload, size_t payload_len)
{
  const struct iovec iov = {
    .iov_base = (void*)payload,
    .iov_len = payload_len
  };

  return af == AF_INET6 ?
    ef_tcp_checksum_ip6_is_correct((const struct ipv6hdr*)ipx, tcp, &iov, 1) :
    ef_tcp_checksum_is_correct((const struct iphdr*)ipx, tcp, &iov, 1);
}

/*! \brief Calculate the checksum for an IPv6 ICMP packet
**
** \param ip6    The IPv6 header for the packet.
** \param icmp   The ICMP header for the packet.
** \param iov    Start of the iovec array describing the TCP payload.
** \param iovlen Length of the iovec array.
**
** \return The checksum of the ICMP packet.
**
** Calculate the checksum for an IPv6 ICMP packet.  The ICMP header must be
** populated (with the exception of the checksum field itself, which is
** ignored) before calling this function.
*/
extern uint32_t
ef_icmpv6_checksum(const struct ipv6hdr* ip6, const void* icmp,
                   const struct iovec* iov, int iovlen);

#ifdef __cplusplus
}
#endif

#endif /* __EFAB_CHECKSUM_H__ */
