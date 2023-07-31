#ifndef INCLUDED_ONLOAD_CPLANE_API_H_
#define INCLUDED_ONLOAD_CPLANE_API_H_
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <net/if.h>
#include <endian.h>

struct ef_cp_handle;

/* Onload control plane API introduction
 *
 * This API is intended for the use of ef_vi applications, to allow them to
 * perform lookups of the Linux routing tables efficiently and with support for
 * many of the advanced features of the Linux networking stack. It uses the
 * same infrastructure which supports Onload and TCPDirect, but presents an
 * API optimised for usage outside of those products.
 *
 * This API has the same ABI stability guarantees as ef_vi: applications linked
 * with a past version of the API will operate with any future installation of
 * Onload without recompiling. To achieve that compatibility, the library is
 * offered only as a shared object; that shared object must match the current
 * Onload install precisely, since the Onload cplane achieves its performance
 * by sharing a large, complex memory mapped data structure between the
 * onload_cp_server and its clients.
 *
 * There are 3 broad classes of functions in this API:
 * - Initialisation: ef_cp_init(), ef_cp_register_intf()
 * - System information query: ef_cp_get_all_intfs(), ef_cp_get_intf(),
 *   ef_cp_get_intf_addrs()
 * - Route lookup: ef_cp_resolve()
 *
 * The high-level flow of a simple application would look like:
 * -# ef_cp_init()
 * -# Get the application's config, including IP addresses (and possibly
 *    specific network interfaces) to use 
 * -# Use the system information functions to validate and/or populate the
 *    remaining config that's needed
 * -# Start up ef_vi on all the desired physical interfaces: ef_pd_alloc(),
 *    ef_vi_alloc_from_pd(), etc.
 * -# Call ef_cp_register_intf() on those interfaces
 * -# Enter the main application loop
 *   -# Construct a packet to transmit, omitting the fields which are not yet
 *      known (the layer 2 (Ethernet) header, source IP address, TTL)
 *   -# Call ef_cp_resolve()
 *   -# Send the packet
 */

/* Loads and initialises the connection to the control plane
 *
 * The (opaque) handle to the control plane is return in *cp. It must be freed
 * using ef_cp_fini(). Flags is currently unused and must be zero.
 *
 * Returns 0 on success or a negative error code on failure. Some common errors
 * are:
 *  - -ELIBACC Version mismatch between client libef_cp.so and current
 *    onload_cp_server
 *  - -ENOENT Onload driver is not currently loaded */
int ef_cp_init(struct ef_cp_handle **cp, unsigned flags);

/* Uninitialises the control plane access library and frees all memory */
void ef_cp_fini(struct ef_cp_handle *cp);

/* An IP address as represented by the control plane.
 *
 * The control plane always deals with IPv6 addresses. IPv4 routes are
 * represented in the standard IPv4-mapped form. See ef_cp_ipaddr_is_ipv4() and
 * ef_cp_ipaddr_is_ipv6().
 */
typedef struct {uint32_t addr[4];} ef_cp_ipaddr;

/* Flags for ef_cp_intf::flags */
/* Interface is up. */
#define EF_CP_INTF_F_UP                     0x00000001u
/* Interface is not acceleratable. */
#define EF_CP_INTF_F_ALIEN                  0x00000002u

/* Flags for ef_cp_intf::encap */
/* Uses VLAN (802.1q) encapsulation. Use ef_cp_get_lower_intfs() to get the
 * underlying interface */
#define EF_CP_ENCAP_F_VLAN                0x00000001
/* This is a bond (master). Use ef_cp_get_lower_intfs() to get the list of bond
 * ports */
#define EF_CP_ENCAP_F_BOND                0x00000002
/* This is bond port (slave). Use ef_cp_get_upper_intfs() to get the bond */
#define EF_CP_ENCAP_F_BOND_PORT           0x00000004
/* This is a loopback device */
#define EF_CP_ENCAP_F_LOOP                0x00000040
/* This is a Linux macvlan layered interface. Use ef_cp_get_lower_intfs() to
 * get the underlying interface */
#define EF_CP_ENCAP_F_MACVLAN             0x00000080
/* This is one end of a veth virtual adapter */
#define EF_CP_ENCAP_F_VETH                0x00000100
/* This is a Linux ipvlan layered interface. Use ef_cp_get_lower_intfs() to
 * get the underlying interface */
#define EF_CP_ENCAP_F_IPVLAN              0x00000400

/* Details about a network interface. Returned by ef_cp_get_intf() and
 * ef_cp_get_intf_by_name()
 */
struct ef_cp_intf {
  /* Linux ID of this network interface, as shown by ip-link(8) */
  int ifindex;
  /* Encapsulation type and other fundamental properties of this interface. A
   * bitmask of the EF_CP_ENCAP_F_* flags */
  uint32_t encap;
  /* Additional data describing the encapsulation. 
   * - If EF_CP_ENCAP_F_VLAN then encap_data[0] is the VLAN tag */
  uint32_t encap_data[4];
  /* Attributes of this interface. See EF_CP_INTF_F_* */
  uint64_t flags;
  /* The value passed to ef_cp_register_intf() for this interface.
   *
   * NULL if this interface has not been registered. */
  void *registered_cookie;
  /* Maximum transmission unit size of this interface, in bytes */
  int mtu;
  /* MAC address of this interface */
  uint8_t mac[6];
  /* Name assigned to this interface by Linux, like "eth0" */
  char name[IFNAMSIZ+1];
};

/* Details about an IP address currently attached to an interface */
struct ef_cp_ifaddr {
  /* Linux ID of the interface having this IP address */
  int ifindex;
  /* Scope qualifier of the address */
  int scope;
  /* No flags are currently defined */
  uint64_t flags;
  /* Length in bits of the local routing prefix, i.e. 24 represents a netmask
   * of 255.255.255.0 */
  int prefix_len;
  /* The IP address itself */
  ef_cp_ipaddr ip;
  /* Address to use for broadcasts to the local network */
  ef_cp_ipaddr bcast;
};

/* Returns true if the given IP address is an IPv4-mapped address */
static inline bool ef_cp_ipaddr_is_ipv4(ef_cp_ipaddr ip)
{
  if (ip.addr[0] | ip.addr[1])
    return false;
  if (ip.addr[2] == htobe32(0xffff))
    return true;
  if ((ip.addr[2] | ip.addr[3]) == 0)
    return true;
  return false;
}

/* Returns true if the given IP address is a full IPv6 address */
static inline bool ef_cp_ipaddr_is_ipv6(ef_cp_ipaddr ip)
{
  return !ef_cp_ipaddr_is_ipv4(ip);
}

/* Flags for ef_cp_get_all_intfs(), ef_cp_get_lower_intfs() and
 * ef_cp_get_upper_intfs() */
/* Returns interfaces which have full, native ef_vi acceleration support */
#define EF_CP_GET_INTFS_F_NATIVE    0x0001
/* Returns interfaces which have ef_vi acceleration support, but where that
 * support employs an abstraction layer (which could limit performance). */
#define EF_CP_GET_INTFS_F_GENERIC   0x0002
/* Returns interfaces which are neither native nor generic */
#define EF_CP_GET_INTFS_F_OTHER     0x0004
/* Return only interfaces which are currently active */
#define EF_CP_GET_INTFS_F_UP_ONLY   0x0100
/* When passed to ef_cp_get_lower_intfs(), returns the most networkwards
 * interfaces, rather than the immediate neighbors. */
#define EF_CP_GET_INTFS_F_MOST_DERIVED 0x10000

/* Returns the list of all network interfaces usable by the calling application
 *
 * The list is returned in the array \p ifindices, which has \p n elements. If
 * \p n is too small then only a partial list is returned. In all cases (except
 * errors) the total size of the full list of interfaces (which match the
 * flags) is returned, i.e. the caller should retry calling this function with
 * larger sized arrays until the return value is <= the value \p n passed in.
 * The order of items in the returned list is unspecified.
 *
 * \p flags is used to filter the returned list by broad category, using one or
 * more of the EF_CP_GET_INTF_F_* bits. Note that the definition is such that
 * flags=0 will guarantee that no interfaces are returned.
 *
 * Returns the total number of interfaces matching \p flags on success, or a
 * negative error code on failure.
 *
 * Thread safety: can be called concurrently with any other function, but it
 * returns a moment-in-time snapshot of the current system configuration, which
 * can be changed at any time.
 *
 * Performance: O(n) in the total number of interfaces in the current network
 * namespace.
 */
int ef_cp_get_all_intfs(struct ef_cp_handle *cp, int *ifindices, size_t n,
                        unsigned flags);

/* Returns a list of subordinate (more networkwards) interfaces of the given
 * child.
 *
 * This function behaves identically to ef_cp_get_all_intfs(), but returns only
 * a subset of interfaces.
 *
 * When \p flags does not include EF_CP_GET_INTF_F_MOST_DERIVED, the interfaces
 * returned are the immediate neighbors towards the network of the given
 * \p child ifindex. This can be used, for example, to list all the ports of a
 * bond. There may be lower interfaces which are in a different network
 * namespace and hence invisible to the current process; they will not be
 * listed.
 *
 * When \p flags does include EF_CP_GET_INTF_F_MOST_DERIVED, this function will
 * walk all the way down the heirarchy of interfaces until it reaches the
 * physical interfaces at the bottom. This mode is typically used to retrieve
 * the interfaces to which ef_vi should actually be attached, when given a
 * (potentially complex) tree of bonds and VLANs. If the \p child is already
 * a most-derived interface then it will be matched against the other \p flags
 * and returned as-is. This mode will return physical interfaces only; if any
 * of those physical interfaces are unreachable from the current network
 * namespace then they will not be included.
 *
 * Performance: O(n) in the total number of interfaces in the current network
 * namespace.
 */
int ef_cp_get_lower_intfs(struct ef_cp_handle *cp, int child,
                          int *ifindices, size_t n, unsigned flags);

/* Returns the list of immediate user (more abstractwards) interfaces of
 * the given parent.
 *
 * This function behaves identically to ef_cp_get_all_intfs(), but returns only
 * interfaces which are the immediate neighbors away from the network of the
 * given \p parent ifindex. This function can be used, for example, to list all
 * the VLANs of a given physical interface. There may be upper interfaces which
 * are in a different network namespace and hence invisible from the current
 * context; they will not be listed.
 *
 * Performance: O(n) in the total number of interfaces in the current network
 * namespace.
 */
int ef_cp_get_upper_intfs(struct ef_cp_handle *cp, int parent,
                          int *ifindices, size_t n, unsigned flags);

/* Retrieves detailed information about a single network interface
 *
 * Populates \p intf with details of the given interface. \p flags is currently
 * unused and must be zero.
 *
 * Returns 0 on success or a negative errno on failure. Most commonly -ENOENT,
 * when the given ifindex does not exist.
 *
 * Thread safety: can be called concurrently with any other function, but it
 * returns a moment-in-time snapshot of the current system configuration, which
 * can be changed at any time.
 *
 * Performance: O(n) in the total number of interfaces in the current network
 * namespace.
 */
int ef_cp_get_intf(struct ef_cp_handle *cp, int ifindex,
                   struct ef_cp_intf *intf, unsigned flags);

/* Retrieves detailed information about a single network interface
 *
 * Behaves identically to ef_cp_get_intf(), except that it does the lookup by
 * name (e.g. "eth0") rather than ID.
 *
 * Performance: O(n) in the total number of interfaces in the current network
 * namespace, plus the cost of string comparisons on them all.
 */
int ef_cp_get_intf_by_name(struct ef_cp_handle *cp, const char* name,
                           struct ef_cp_intf *intf, unsigned flags);

/* The contents of this structure are opaque. See ef_cp_intf_version_get(). */
struct ef_cp_intf_verinfo {
  unsigned generation;
  unsigned version;
};
#define EF_CP_INTF_VERINFO_INIT (struct ef_cp_intf_verinfo){0,0}

/* Return the current revision number of the interface table.
 *
 * This function is used in conjunction with ef_cp_intf_version_verify() to
 * detect changes to the system's interface table, i.e. any changes which may
 * cause the data returned by ef_cp_get_all_intfs(), ef_cp_get_intf() and
 * related functions to change. This includes:
 * - Adding/removing an interface
 * - Link up/down
 * - Bond failover
 * It does not include adding/removing IP addresses to an interface.
 *
 * Returns an opaque verinfo object, which can only be used by passing it to
 * ef_cp_intf_version_verify().
 *
 * Performance: O(1)
 */
struct ef_cp_intf_verinfo ef_cp_intf_version_get(struct ef_cp_handle *cp);

/* Checks whether the system's interface table has changed.
 *
 * See ef_cp_intf_version_get() for an introduction. This function may return
 * false positives, i.e. it may return \p false even when nothing observable
 * has changed. Typically code will look like:
 * \code
 * struct ef_cp_intf_verinfo ver = ef_cp_intf_version_get(cp);
 * initialize_application();
 * // Main application runtime loop:
 * for ( ; ; ) {
 *   if (!ef_cp_intf_version_verify(cp, &ver)) {
 *     ver = ef_cp_intf_version_get(cp);
 *     reinitialize_application();   // e.g. includes calls to ef_cp_get_intf()
 *   }
 *   do_packet_handling();
 * }
 * \endcode
 *
 * Returns true if information cached by the application since the last call to
 * ef_cp_intf_version_get() will have remained correct, false if the
 * application must re-check the system configuration.
 *
 * Thread safety: can be called concurrently with any other function, however
 * note that when reloading application caches it's vital that
 * ef_cp_intf_version_get() be called before the caches are reinitialized, so
 * that no configuration changes are lost.
 *
 * Performance: O(1)
 */
bool ef_cp_intf_version_verify(struct ef_cp_handle *cp,
                               const struct ef_cp_intf_verinfo *ver);

/* Retrieves the list of all IP addresses currently added to the given interface
 *
 * \p addrs is a caller-allocated array with \p n elements, in which the list
 * of addresses is stored. If \p n is too small then only a partial list is
 * returned. In all cases (except errors) the total size of the full list of
 * interfaces (which match the flags) is returned, i.e. the caller should retry
 * calling this function with larger sized arrays until the return value is <=
 * the value \p n passed in. The order of items in the returned list is
 * unspecified.
 *
 * If the control plane is currently running in IPv4-only mode then this
 * function will not return IPv6 addresses.
 *
 * \p flags is currently unused and must be zero.
 *
 * Returns the total number of IP addresses on the interface on success, or a
 * negative error code on failure. For performance reasons, an invalid ifindex
 * will return 0 addresses rather than an error.
 *
 * Thread safety: can be called concurrently with any other function, but it
 * returns a moment-in-time snapshot of the current system configuration, which
 * can be changed at any time.
 *
 * Performance: O(n) in the total number of IP addresses on all network
 * interfaces in the current network namespace.
 */
int ef_cp_get_intf_addrs(struct ef_cp_handle *cp, int ifindex,
                         struct ef_cp_ifaddr* addrs, size_t n, unsigned flags);

/* Marks a specific network interface as being of interest to the calling
 * application.
 *
 * Registering an interfaces allows the caller to associate an arbitrary
 * pointer with that interface (which is returned by ef_cp_resolve() and
 * ef_cp_get_intf()) and modifies the behaviour of ef_cp_resolve() to treat
 * this interface as 'more preferable' than others. For example, registering
 * the interface underneath a VLAN but not the VLAN itself will cause a routing
 * lookup to return the underlying (registered) interface and add a VLAN tag to
 * the packet header, whereas if the VLAN were registered then the resolution
 * would target the VLAN and not add the tag. Likewise when routing over a
 * bond, only registered bond ports will be used by default. See also
 * EF_CP_RESOLVE_F_UNREGISTERED.
 *
 * \p flags is currently unused and must be zero.
 *
 * There are two intended usage models:
 * 1. An application knows at startup time which interface(s) it plans to use,
 *    and allocates VIs on those interfaces (see ef_vi_alloc_from_pd()). It
 *    then calls this function to register those interfaces with the cplane
 *    API. When a route is resolved, the application can readily get access to
 *    its ef_vi* pointer needed to send the packet by using the
 *    previously-registered user_cookie.
 * 2. An application would like to be able to route potentially over any
 *    network interface (in the current network namespace), even those not yet
 *    added at the time the application starts. It doesn't allocate VIs or
 *    register interfaces at startup, but passes EF_CP_RESOLVE_F_UNREGISTERED
 *    to all calls to ef_cp_resolve(). If that function returns
 *    EF_CP_RESOLVE_S_UNREGISTERED then the application allocates a VI on the
 *    returned interface (or uses a different API for non-acceleratable NICs)
 *    and calls ef_cp_register_intf() to advertise that this interface is now
 *    usable.
 *
 * Re-registering an interface which is already registered is permitted, and
 * may be used to modify an interface's associated user_cookie.
 *
 * Returns 0 on success, or a negative errno on failure. Returns -ENOENT if
 * ifindex is invalid.
 *
 * Concurrency: this function is safe to call concurrently with
 * ef_cp_resolve(), however doing so inherently involves a potentially
 * indeterminite routing result. Note that registering an interface with the
 * cplane API will not prevent the removal of that Linux interface, however
 * allocating a VI on that interface with ef_vi will; applications for which
 * this is a risk should therefore create the VI first and then call this
 * function.
 *
 * Performance: Takes a mutex and may allocate memory
 */
int ef_cp_register_intf(struct ef_cp_handle *cp, int ifindex, void *user_cookie,
                        unsigned flags);

/* Unregisters an interface previously registered with ef_cp_register_intf()
 *
 * \p flags is currently unused and must be zero.
 *
 * Returns 0 on success, or a negative errno on failure. Returns -ENOENT if
 * ifindex is invalid.
 *
 * Performance: Takes a mutex
 */
int ef_cp_unregister_intf(struct ef_cp_handle *cp, int ifindex, unsigned flags);

/* Additional routing input/output parameters to ef_cp_resolve() */
struct ef_cp_fwd_meta {
  /* Input/output. On input, the network interface to use for sending the
   * packet, or -1 to indicate that no network interface is being forced and
   * hence that routing should resolve it in the normal manner. On output, the
   * actual network interface to use for sending.
   *
   * Note that even if this value is not -1 on input, it may still change on
   * output, for example in the case where the input interface is a VLAN
   * adapter and the output is the actual underlying hardware port. */
  int ifindex;
  /* Input. The origin interface for when the routing requested is simulating
   * forwarding of packets. -1 if this packet is not being 'forwarded'. */
  int iif_ifindex;
  /* Output. If ifindex is a registered interface (i.e. if ef_cp_resolve()'s
   * return value does not include EF_CP_RESOLVE_S_UNREGISTERED) then this is
   * the value provided to ef_cp_register_intf() when the interface was
   * registered. Otherwise NULL. */
  void *intf_cookie;
  /* Output. The maximum transmission unit (in bytes) of ifindex. */
  int mtu;
};

/* The contents of this structure are opaque. See ef_cp_route_verify(). */
struct ef_cp_route_verinfo {
  unsigned row;
  unsigned version;
  unsigned generation;
};
#define EF_CP_ROUTE_VERINFO_INIT (struct ef_cp_route_verinfo){0,0,0}

/* Flags for ef_cp_resolve() */
/* When set, the route lookup should constrain the source IP address to that
 * given (e.g. as if the caller used bind() or equivalent). When unset, the
 * source IP given in the input packet is ignored, and is populated on output
 * with the correct source IP to be used in the sent packet. */
#define EF_CP_RESOLVE_F_BIND_SRC      0x0001
/* Route as if the IP_TRANSPARENT option had been set on the socket. See
 * ip(7). */
#define EF_CP_RESOLVE_F_TRANSPARENT   0x0002
/* Allow routing to any interface. Without this flag, ef_cp_resolve() will
 * return an error if the routing decision was to an interface not previously
 * registered with ef_cp_register_intf(). With this flag, such routing requests
 * will succeed (and include the EF_CP_RESOLVE_S_UNREGISTERED) return flag). The
 * intended use-case is for applications which initialise and register
 * interfaces on-demand. */
#define EF_CP_RESOLVE_F_UNREGISTERED  0x0004
/* Return -EAGAIN rather than performing any context switches. If the route is
 * not already cached then it will not be possible to request that it be
 * resolved, so retrying the call is not likely to be successful. */
#define EF_CP_RESOLVE_F_NO_CTXT_SW    0x0008
/* Do not fail if the destination host is unreachable. This mode can be used to
 * obtain the destination interface (and related properties). If
 * EF_CP_RESOURCE_S_ARP_INVALID is included in the return code then the
 * destination MAC address is a garbage value. */
#define EF_CP_RESOLVE_F_NO_ARP        0x0010

/* Determines the network route to use for a given packet
 *
 * The input ip_hdr must point to a network packet's layer 3 (IPv4 or IPv6)
 * header which must have the following fields populated:
 * - IP version
 * - Destination IP address
 *
 * The following fields should also be populated:
 * - IP header length
 * - IP protocol (including the full next_hdr chain for IPv6 packets)
 * - TOS/DSCP/ECN byte
 * - Source IP address
 * - Layer 4 source port
 * - Layer 4 destination port
 *
 * The source IP address is used only if the EF_CP_RESOLVE_F_BIND_SRC flag is
 * passed. The rest of these optional header fields are used in some more
 * complex routing cases (e.g. LACP bonding, multipath). If they are needed but
 * are not populated correctly then routing may be suboptimal but will work
 * (however the memory must still be readable).
 *
 * On return the memory at ip_hdr and the few bytes before it will be modified
 * to:
 * - Prepend any necessary encapsulations (VLAN, GRE, etc.)
 * - Prepend the necessary Ethernet header
 * - Populate the source IP address
 * - Populate the ttl / max-hops information
 *
 * To allow for the prepending, *prefix_space must be at least 14, and
 * (unless external system knowledge ensures that encapsulations are impossible)
 * should be larger. Upon return, *prefix_space will contain the number of bytes
 * actually prepended, i.e. the packet to transmit on the wire begins at
 * (char*)ip_hdr - *prefix_space.
 *
 * \p meta is an input/output parameter with additional routing information
 * (which is not encoded in to the network packet itself).
 *
 * \p ver is an input/output opaque object which caches the routing information.
 * The application must initialise it with EF_CP_ROUTE_VERINFO_INIT and it may
 * later be used with ef_cp_route_verify() as a fast check to determine when a
 * full re-resolve is necessary.
 *
 * \p flags are zero or more of EF_CP_RESOLVE_F_*
 *
 * Returns a negative errno on failure. On success the return value is a
 * bitmask of the EF_CP_RESOLVE_S_* flags. Some common errors are:
 * - -ENOENT: No route to host
 * - -EAGAIN: A route exists, but the ARP is still in-flight so a destination
 *   MAC address is unavailable; the application may block, drop, enqueue or
 *   use a kernel path to send the packet being routed. If
 *   EF_CP_RESOLVE_F_NO_CTXT_SW is used then EAGAIN may be returned at any time.
 * - -EHOSTUNREACH: A route exists, but the ARP timed out; most likely the
 *   destination host (or gateway) is down
 * - -E2BIG: \p prefix_space is too small for the number of network headers
 *   which are needed for this route
 * - -EADDRNOTAVAIL: The route required use of an interface which was not
 *   registered, and EF_CP_RESOLVE_F_UNREGISTERED was not used
 *
 * Thread-safety: Safe to call concurrently with itself or any other function;
 * the returned routing information may become stale at any time.
 *
 * Performance: May enter the kernel and wait for a Linux route resolution to
 * occur (unless EF_CP_RESOLVE_F_NO_CTXT_SW is used). Otherwise, largely O(1)
 * but with a fair amount of computation.
 * 
 * An outline of how this function may be used:
 * \code
 *   char pkt_buf[2048];
 *   size_t prefix_space = 32;
 *   char *pkt_ip = pkt_buf + prefix_space;
 *   int payload_len = rand() % 1024;
 *
 *   build_my_ip_hdr(pkt_ip, payload_len);
 *   build_my_udp_hdr(pkt_ip + sizeof(struct iphdr), payload_len);
 *   gen_random(pkt_ip + sizeof(struct iphdr) + sizeof(udphdr), payload_len);
 *   struct ef_cp_fwd_meta meta = {.ifindex = -1, .iif_ifindex = -1};
 *   struct ef_cp_route_verinfo ver = EF_CP_ROUTE_VERINFO_INIT;
 *   int64_t rc = ef_cp_resolve(cp, pkt_ip, &prefix_space, &meta, &ver, 0);
 *   if (rc < 0)
 *     goto fail;
 *   if (!using_hardware_checksumming)
 *     recalc_ip_csum(pkt_ip);
 *   ef_vi_transmit((ef_vi*)meta.intf_cookie, pkt_ip - prefix_space,
 *                  prefix_space + sizeof(struct iphdr) + sizeof(udphdr) + payload_len, 0);
 * \endcode
 */
int64_t ef_cp_resolve(struct ef_cp_handle *cp, void *ip_hdr,
                      size_t *prefix_space, struct ef_cp_fwd_meta *meta,
                      struct ef_cp_route_verinfo *ver, uint64_t flags);

/* Returned flags from ef_cp_resolve() */
/* This route was via a loopback adapter */
#define EF_CP_RESOLVE_S_LOOPBACK   0x0001
/* This route used an unregistered interface. See EF_CP_RESOLVE_F_UNREGISTERED
 * and ef_cp_register_intf() */
#define EF_CP_RESOLVE_S_UNREGISTERED      0x0002
/* The destination MAC address in the returned packet is not correct. Returned
 * only if EF_CP_RESOLVE_F_NO_ARP was used. */
#define EF_CP_RESOLVE_S_ARP_INVALID       0x0004

/* Checks whether the information returned by a previous ef_cp_resolve() has
 * become out of date.
 *
 * It is correct (and moderately fast) to call ef_cp_resolve() for every network
 * packet to be sent. It is even faster to cache the result of that function
 * and re-use it for every packet to the same destination. When caching the
 * result, this function must be called prior to every transmit to determine
 * whether the route has changed or whether the last-used timestamp must be
 * refreshed (to allow for re-ARPs).
 *
 * Returns true if the prior cached information remains correct, or false if
 * the caller must call ef_cp_resolve() again to receive an update.
 *
 * Thread-safety: Safe to call concurrently with itself or any other function;
 * the returned routing information may become stale at any time.
 *
 * Performance: O(1) and trivial.
 */
bool ef_cp_route_verify(struct ef_cp_handle *cp,
                        const struct ef_cp_route_verinfo *ver);

#endif

