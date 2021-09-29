# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.

import pytest
import sys, os, time, struct, socket, copy, platform
import random
import math
import functools
from collections import deque
from datetime import datetime
from random import randint
from pyroute2 import NetNS, netlink, IPRoute, NetlinkError
from pyroute2.netlink.rtnl.ifaddrmsg import IFA_F_NODAD
from cplane import *


def ip2v4(ip):
    if CI_CFG_IPV6:
        assert len(ip) == 4
        assert ip[:3] == [0, 0, socket.htonl(0xffff)]
        return ip[3]
    return ip

def ipv4toapi(ip):
    if CI_CFG_IPV6:
        return (c_uint * 4)(0, 0, socket.htonl(0xffff), ip)
    return ip

def ipv42str(ip):
    return socket.inet_ntoa(struct.pack('=I', ip))

# ip comes from cplane, where is stored in a 128-bit value, which may be an
# IPv4-mapped address. It needs to be converted to bytes in current order.

def ip2str(ip):
    if ip[:3] == _ipv4_mapped_prefix:
        return ipv42str(ip2v4(ip))
    else:
        return socket.inet_ntop(socket.AF_INET6, struct.pack('=IIII', *ip))

def str2ipv4(ip_str):
    return struct.unpack('=I', socket.inet_aton(ip_str))[0]

def str2ip(ip_str):
    if ':' in ip_str:
        return (c_uint * 4)(*struct.unpack('=IIII',
                                   socket.inet_pton(socket.AF_INET6, ip_str)))
    return ipv4toapi(str2ipv4(ip_str))

_ipv4_mapped_prefix = str2ip('::ffff:0.0.0.0')[:3]
IP=str2ip
any_ip4 = str2ip('0.0.0.0')
any_ip6 = str2ip('::')

def any_ip(v6):
    return any_ip6 if v6 else any_ip4

def ip_is_any(ip):
    return ip[0] == 0 and ip[1] == 0 and ip[3] == 0 and \
           (ip[2] == any_ip4[2] or ip[2] == 0)

def mac_to_str(mac):
    return ':'.join([struct.pack('=B', s).encode('hex') for s in mac])


_is_netlink_capable = None
def is_kernel_netlink_capable(netns, any_bond_name):
    global _is_netlink_capable
    if _is_netlink_capable is None:
        attrs = dict(netns.link('get', ifname=any_bond_name)[0]['attrs'])
        linkinfo = attrs.get('IFLA_LINKINFO')
        # IFLA_LINK_SLAVE_KIND is what cplane's netlink.c looks for to disable
        # the periodic bond dump
        _is_netlink_capable = linkinfo and \
                              'IFLA_INFO_SLAVE_KIND' in dict(linkinfo['attrs'])
    return _is_netlink_capable


_has_ipv6_subtrees = None
def kernel_has_ipv6_subtrees():
    global _has_ipv6_subtrees
    if _has_ipv6_subtrees is None:
        _has_ipv6_subtrees = False
        with IPRoute() as ip:
            for r in ip.get_routes(family=socket.AF_INET6):
                if 'RTA_SRC' in dict(r['attrs']):
                    _has_ipv6_subtrees = True
                    break
    return _has_ipv6_subtrees


def cpserver_extra_opts():
    return '' if kernel_has_ipv6_subtrees() else '--ipv6-no-source'


def sleep_if_netlink_incapable(netns, any_bond_name):
    if not is_kernel_netlink_capable(netns, any_bond_name):
        # This is the default value of cfg_bond_base_msec plus a bit
        time.sleep(.11)


# Needed to overcome limitations of pyroute2
# FIXME figure out how to do these with pyroute2
def bond_set_active(cpserver, bond_name, nic_name):
    cpsystem(cpserver,
             '''bash -c 'echo "%s" > /sys/class/net/%s/bonding/active_slave' '''%(
             nic_name, bond_name))

def bond_set_mode(cpserver, bond_name, bond_mode):
    cpsystem(cpserver,
             '''bash -c 'echo "%s" > /sys/class/net/%s/bonding/mode' '''%(
             bond_mode, bond_name))


def cpsystem(cpserver, cmd, ignore_status=False):
    cmd = ' '.join([cpserver.getCmdPrefix(),cmd])
    print >> sys.stderr, datetime.now().strftime('%H:%M:%S.%f'), cmd
    status = os.system(cmd)
    if not ignore_status and status != 0:
        raise Exception('Execution of %s failed with code %d'%(cmd, status))


def cpresolve(cp, v, k, attempts=10, af=None):
    if af is None:
        if k.dst[:3] == _ipv4_mapped_prefix:
            af = socket.AF_INET
        else:
            af = socket.AF_INET6
    data = None
    for attempt in range(attempts):
        data = cp.routeResolve(af, v, k)
        if data:
            break
        if attempt != (attempts - 1):
          time.sleep(0.2)
    return data

def cpmakenic(netns, cp, ifname, hwport, ifindex=None):
    netns.link('add', kind='dummy', ifname=ifname, index=ifindex or 0)
    ix = netns.link_lookup(ifname=ifname)[0]
    cp.newHwport(ix, hwport)
    return ix



''' creates instances of cpserver, cpclient and netns
    and ensures cleanup.
    In case of problems dumps ip addr and ip route and mibdump

    Providing tag gives makes the instances wrapped in an object of the name
    before passing it to the decorated functions. This also allows the decorator
    to be stacked.
'''
def cpdecorate(tag=None, parent_tag=None):
    def real_cpdecorate(func):
        def wrapper(*args, **kwargs):
            main_shim_file = None
            if parent_tag:
                main_shim_file = kwargs[parent_tag].cpserver.shim_file.name
            cpserver = CPServer(main_shim_file=main_shim_file,
                                extra_opts=cpserver_extra_opts())
            cp = cpserver.getClient()
            d = None
            try:
                with NetNS(cpserver.getNetNsPath()) as netns:
                    d = dict(cpserver=cpserver, netns=netns, cp=cp)
                    if tag:
                        d = { tag: type('onload_cp_server', (object,), d) }
                    kwargs.update(d)
                    func(*args, **kwargs)
            except:
                if tag and d:
                    # in case class restarted cpserver get new object
                    cpserver = d[tag].cpserver
                cpsystem(cpserver, 'ip -d addr show', ignore_status=True)
                cpsystem(cpserver, 'ip -d route show table all', ignore_status=True)
                cpserver.mibdump('all')
                raise
            finally:
                # make sure cp server goes away
                if tag and d:
                    # in case class restarted cpserver get new object
                    cpserver = d[tag].cpserver
                d, cp = None, None
                cpserver.cleanup()
        return wrapper
    return real_cpdecorate


def v4andv6(func):
    @pytest.mark.parametrize("v6", [False, True])
    @functools.wraps(func)
    def wrapper(v6):
        func(v6=v6)
    return wrapper


# needs kernel >= 3.19 but 4 is good approximation
want_macandipvlan = int(platform.release().split('.')[0]) < 4

def macandipvlan(func):
    @pytest.mark.parametrize(
        "encap", [
          'macvlan',
          pytest.param('ipvlan',marks=pytest.mark.skipif(
              want_macandipvlan,
              reason="needs kernel >= 3.19")), # 4 is good approximation though
        ])
    @functools.wraps(func)
    def wrapper(encap):
        func(encap=encap)
    return wrapper


def wait_for_hwports(cp, v, k, attempts=10, expected_hwports=None, netns=None):
    ''' Calls cpresolve until the expected hwports value is seen.
        Times out after 5 seconds.
    '''
    t0 = time.time()
    t_end = t0 + 5 # If they've not updated in 5s, there's a bigger problem

    # Loop whilst the cplanes notice the changes and update themselves
    delayed = False
    while time.time() < t_end:
        data = cpresolve(cp, v, k, attempts)
        assert data

        d = getdict(data)

        if d['hwports'] == expected_hwports:
            break
        delayed = True
        time.sleep(0.1)

    if d['hwports'] != expected_hwports:
        print "hwports = %d, expected %d" % (d['hwports'], expected_hwports)

    if delayed:
        elapsed = time.time() - t0
        print "Spun for %fs while waiting for hwports update" % elapsed
        assert elapsed < 1

    return d


def check_route(d, rtype, mac, hwports):
    assert rtype != CICP_ROUTE_TYPE.LOCAL
    if rtype == CICP_ROUTE_TYPE.NORMAL:
        assert d['hwports'] == hwports
        assert mac_to_str(d['src_mac']) == mac, "route src mac matches"
        assert d['base']['ifindex'] != CI_IFID.BAD
        assert d['base']['ifindex'] != CI_IFID.LOOP
    else:
        assert d['hwports'] == 0
        assert d['base']['ifindex'] == CI_IFID.BAD


def addr_add(netns, address, **kwargs):
    if ':' in address:
        kwargs.setdefault('flags', IFA_F_NODAD)
    netns.addr('add', address=address, **kwargs)


def build_intf(netns, ifname, address,
               cp=None, hwport=None,
               kind='dummy', state='up', **kwargs):
    # NB: pyroute2's IPDB interface has a race inside commit() which causes
    # exceptions (which are caught and then mis-handled in a most confusing
    # way - typically "TypeError: unsupported operand type(s) for &:
    # 'NoneType' and 'int'"). The race is between commit() and the netlink
    # updates thread, being undecided about how many IP addresses a
    # newly-created interface has because the autoconfigured IPv6 link-local
    # address appears and disappears rapidly. Search for "dirtiest hack ever"
    # in interfaces.py in pyroute2 - the first 'for' loop tries to call
    # set.remove() on a non-existant item because it's gone by the time the
    # thread gets there. I also saw "set size changed during iteration" a few
    # times. My understanding of the pyroute2 code is that it can only be
    # encountered when there is more than one batch required in a single
    # commit and one of those batches (not the last) brings a link up.
    # We work around it by avoiding IPDB, which isn't painful at all because
    # we know the exact configuration changes we want to make.
    for i in range(10):
        try:
            netns.link('add', kind=kind, ifname=ifname, **kwargs)
        except NetlinkError as e:
            # creating some types of interfaces e.g. bridge uses
            # apparently some global resources and cannot be performed
            # in parallel even in separate namespaces.
            # So we try few times in case this is transient.
            if e.code == errno.EEXIST:
                continue
            raise
        break

    ix = netns.link_lookup(ifname=ifname)[0]
    if hwport is not None:
        cp.newHwport(ix, hwport)
    if address is not None:
        addrmask = address.split('/')
        if len(addrmask) == 1:
            addrmask = [address, 32]
        addr_add(netns, index=ix, address=addrmask[0], mask=int(addrmask[1]))
    if state is not None:
        netns.link('set', index=ix, state=state)

    return ix


def wait_for_route_update(netns, cp, v6):
    ''' Ensures that previous route changes have been picked up by the cplane
        by the time this function returns.
        This is only really useful for multipath tests.

        Requires at least one active interface
    '''
    # Add a route over any active interface and wait for it to be picked up
    # by the cplane.
    # It's assumed that all previous route changes have been picked up once
    # the cplane returns the new route.
    link_scope = 253
    active_interfaces = [x for x in netns.get_links()
                      if dict(x['attrs']).get('IFLA_OPERSTATE', '') != 'DOWN']
    assert len(active_interfaces) > 0, 'wait_for_route_update needs at least one active interface'
    scratch_ip = 'fcfe:fefe:fefe:fefe:fefe:fefe:fefe:fefe' \
                 if v6 else '254.254.254.254'
    scratch_subnet = scratch_ip + ('/128' if v6 else '/32')
    interface = active_interfaces[0]
    netns.route('add', dst=scratch_subnet, oif=interface['index'],
                       scope=link_scope)

    # Wait until the route appears
    v = cicp_verinfo(0, 0)
    k = cp_fwd_key(any_ip(v6), IP(scratch_ip))
    if_mac = dict(interface['attrs'])['IFLA_ADDRESS']
    t0 = time.time()
    while time.time() - t0 < 1:
        data = cpresolve(cp, v, k, 7)
        assert data

        d = getdict(data)

        if (d['hwports'] != 0 and
            mac_to_str(d['src_mac']) == if_mac):
            break

    assert (d['hwports'] != 0 and
            mac_to_str(d['src_mac']) == if_mac), 'wait_for_route_update failed'

    # Clean up after ourselves
    netns.route('del', dst=scratch_subnet, oif=interface['index'],
                       scope=link_scope)


def mac_addr(netns, index=None, ifname=None):
    if index is not None:
        link = netns.get_links(index)[0]
        attrs = dict(link['attrs'])
        return attrs['IFLA_ADDRESS']

    assert ifname
    for link in netns.get_links():
        attrs = dict(link['attrs'])
        if attrs['IFLA_IFNAME'] == ifname:
            return attrs.get('IFLA_ADDRESS', None)
    raise Exception('Missing interface ' + ifname)


def fake_ip_str(v6, part1, part2=1):
    if hasattr(part1, '__iter__'):
        parts = list(part1)
        if len(parts) < 4:
            parts.append(part2)
        if len(parts) < 4:
            parts = ([0,0,0] + parts)[-4:]
        if v6:
            return 'fc00:7e57:7e57:7e57:%x:%x:%x:%x' % tuple(parts)
        else:
            return '%d.%d.%d.%d' % tuple(parts)
    if v6:
        return 'fc00:7e57:7e57:7e57::%x:%x' % (part1, part2)
    else:
        return '192.168.%d.%d' % (part1, part2)


def fake_ip(v6, part1, part2=1):
    return IP(fake_ip_str(v6, part1, part2))


def fake_ip_subnet(v6, part1, part2=1, suffix=8):
    ip = fake_ip_str(v6, part1, part2)
    bits = 128 if v6 else 32
    return ip + '/' + str(bits - suffix)


# tests

# The tests are run on both an older kernel that does not provide bond info via
# netlink and on a newer one that does.  But we've been misled by the older
# machine having been uprgaded.  Ensure we're not passing the tests by
# inadvertantly running in the wrong environment.
@cpdecorate()
def test_ensure_running_in_expected_environment(cpserver,cp,netns):
    hwports = range(2)
    bond_name, _ = prep_bond(cpserver,cp,netns,hwports,mode=1)

    envvar = 'CPLANE_SYS_ASSERT_NETLINK_BOND'
    if envvar in os.environ:
        if os.environ[envvar] == 'Included':
            expectation = True
        elif os.environ[envvar] == 'Excluded':
            expectation = False
        else:
            raise RuntimeError("If defined, %s must have value 'Included' or 'Excluded'" % envvar)
        actual = is_kernel_netlink_capable(netns, bond_name)
        desc = 'This kernel ' + ('is' if expectation else 'is not') + ' expected to provide bond information via netlink, but it ' + ('does' if actual else 'doesn\'t')

        # We don't get IFLA_INFO_SLAVE_KIND back through pyroute2, even on newer
        # (3.10.0-957) kernels.  Don't know why, yet.  Hence this assertion lies
        # currently.
        #assert actual == expectation, desc


@v4andv6
@cpdecorate()
def test_singleroute(cpserver,cp,netns,v6):
    hwport = 1
    ix = build_intf(netns, 'O%d'%hwport, fake_ip_subnet(v6, hwport, 2),
                    cp=cp, hwport=hwport)

    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip(v6), fake_ip(v6, hwport))
    data = cpresolve(cp, v, k, 7)

    assert data

    d = getdict(data)

    mac = mac_addr(netns, ix)
    check_route(d, CICP_ROUTE_TYPE.NORMAL, mac, 1 << hwport)


# Not yet converted to IPv6 because it looks at route src - need
# CONFIG_IPV6_SUBTREES
@cpdecorate()
def test_singleroute_transparent(cpserver,cp,netns):
    hwport = 1
    ifname = 'O%d'%hwport
    ifindex = build_intf(netns, ifname, '192.168.%d.2/24'%hwport,
                         cp=cp, hwport=hwport)
    cpsystem(cpserver, 'ifconfig lo up');
    cpsystem(cpserver, 'bash -c "echo 0 | tee '
                                     '/proc/sys/net/ipv4/conf/{lo,all}/rp_filter"')
    cpsystem(cpserver, 'bash -c "echo 1 | tee '
                                     '/proc/sys/net/ipv4/conf/lo/forwarding"')
    v = cicp_verinfo(0,0)
    transparent_IP = '10.1.1.1'
    remote_IP = '192.168.%d.1'%hwport
    k = cp_fwd_key(IP(transparent_IP), IP(remote_IP),
                   ifindex, 0, 0, CP_FWD_KEY.TRANSPARENT)
    data = cpresolve(cp, v, k, 7)

    assert data

    d = getdict(data)

    mac = mac_addr(netns, ifindex)
    check_route(d, CICP_ROUTE_TYPE.NORMAL, mac, 1 << hwport)
    assert ip2str(d['base']['src']) == transparent_IP
    assert ip2str(d['base']['next_hop']) == remote_IP

def create_bond(cpserver, netns, ifname, ifnames, mode):
    netns.link('add', kind='bond', ifname=ifname)
    bond_set_mode(cpserver, ifname, str(mode))
    ifix = netns.link_lookup(ifname=ifname)[0]

    for slifname in ifnames:
        netns.link('set', ifname=slifname, master=ifix)
        netns.link('set', ifname=slifname, state='up')

    return ifix

def prep_bond(cpserver,cp,netns,hwports,v6=False,mode=1,
              include_non_sf_intf=False, ifname='bond2', address=None, mask=None):
    if address is None:
        address = fake_ip_str(v6, 0, 2)
    if mask is None:
        mask = 112 if v6 else 24
    ifnames = []
    for hwport in hwports:
        if include_non_sf_intf and hwport == 0:
            slifname = 'x0'
            netns.link('add', kind='dummy', ifname=slifname)
        else:
            slifname = 'O%d'%hwport
            cpmakenic(netns, cp, slifname, hwport)
        ifnames.append(slifname)

    ifix = create_bond(cpserver, netns, ifname, ifnames, mode)
    if address:
        addr_add(netns, index=ifix, address=address, mask=mask)
    netns.link('set', index=ifix, state='up')

    return (ifname, ifnames)


@v4andv6
@cpdecorate()
def test_bond(cpserver,cp,netns,v6):
    hwports = range(2)
    bond_name, slavenames = prep_bond(cpserver,cp,netns,hwports,v6,mode=1)
    mac = mac_addr(netns, ifname=bond_name)

    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip(v6), fake_ip(v6, 0))


    for active in hwports + list(reversed(hwports)):
        bond_set_active(cpserver, bond_name, slavenames[active])

        sleep_if_netlink_incapable(netns, bond_name)

        expected_hwports = 1 << active
        d = wait_for_hwports(cp, v, k, 3, expected_hwports, netns)

        check_route(d, CICP_ROUTE_TYPE.NORMAL, mac, expected_hwports)


@cpdecorate()
def do_test_accelerated_bond(cpserver,cp,netns,mode,v6):
    hwports = range(2)
    bond_name, slavenames = prep_bond(cpserver, cp, netns, hwports,
                                      v6, mode=mode)

    sleep_if_netlink_incapable(netns, bond_name)

    expected_hwports = sum(1 << hwport for hwport in hwports) if mode == 4 \
                       else 1 << hwports[0]
    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip(v6), fake_ip(v6, 0))
    d = wait_for_hwports(cp, v, k, 3, expected_hwports)

    # for ab bonds first hwport is assumed to be the active one
    mac = mac_addr(netns, ifname=bond_name)
    check_route(d, CICP_ROUTE_TYPE.NORMAL, mac, expected_hwports)


@pytest.mark.parametrize("v6", [False, True])
@pytest.mark.parametrize("mode", [ (1), (4) ])
def test_accelerated_bond(mode, v6):
    do_test_accelerated_bond(mode=mode, v6=v6)


@cpdecorate()
def do_test_alien_bond(cpserver,cp,netns,mode,v6,include_non_sf_intf=False):
    hwports = range(2)
    bond_name, slavenames = prep_bond(cpserver, cp, netns, hwports, v6,
                                      mode=mode,
                                      include_non_sf_intf=include_non_sf_intf)
    mac = mac_addr(netns, ifname=bond_name)

    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip(v6), fake_ip(v6, 0))

    for active in hwports + list(reversed(hwports)):
        if mode not in [0, 2, 3]: # some modes do not allow setting active inteface
            bond_set_active(cpserver, bond_name, slavenames[active])
        # FIMXE: for some reason the system call to check bond is needed
        #        without it cpresolve might produce out of date result
        #        see bug72877
        cpsystem(cpserver, 'cat /sys/class/net/%s/bonding/active_slave'%bond_name);
        data = cpresolve(cp, v, k, 3)
        assert data

        d = getdict(data)

        check_route(d, CICP_ROUTE_TYPE.ALIEN, mac, 0)


@pytest.mark.parametrize("mode", [ (0), (2), (3), (5), (6), ])
def test_alien_bond(mode):
    # no value in running this test again for IPv6 - it's all link-layer
    do_test_alien_bond(mode=mode, v6=False)


def test_unacceleratable_bond():
    # no value in running this test again for IPv6 - it's all link-layer
    do_test_alien_bond(mode=1, v6=False, include_non_sf_intf=True)


def compare_routing_tables(cp, netns, v6, applied_routes, requery_always,
                           gen_ips2query, os_dst, allow_bad_ifindex):
    '''Gets data for applied_routes from both cplane and OS and checks that
    the two are equal.'''
    oodata_collection = []

    # Firstly, we issue all requests asynchronously
    # for each route 3 requests are issued
    for r, attribs in applied_routes.iteritems():
        gw, vers = attribs
        ips = gen_ips2query(r)
        # issue those requests, store version information
        for ip, ver in zip(ips, list(vers)):
            if ip_is_any(ip):
                continue
            if requery_always:
                ver = cicp_verinfo()
            k = cp_fwd_key(any_ip(v6), ip)
            oodata = cpresolve(cp, ver, k, 1)
            # possibly we have managed to resolve the route, store the
            # result to not to do that again as not necessary
            oodata_collection.append(oodata)

    # Secondly, we issue all requests synchronously, most of them should
    # be ready by now or will get ready while other requests are being synced
    t_end = time.time() + 1
    while True:
        disparities = []
        oo_index = 0
        for r, attribs in applied_routes.iteritems():
            gw, vers = attribs
            ips = gen_ips2query(r)
            for ip, ver in zip(ips, list(vers)):
                if ip_is_any(ip):
                    continue
                k = cp_fwd_key(any_ip(v6), ip)
                try:
                    osdata = netns.route('get', dst=ip2str(ip))
                except netlink.exceptions.NetlinkError as e:
                    osdata = None
                # we use previously stored result if any
                oodata = oodata_collection[oo_index]
                if not oodata:
                    oodata = cpresolve(cp, ver, k)
                    oodata_collection[oo_index] = oodata
                osv, oov = None, None
                if oodata:
                    oodata = getdict(oodata)
                    od = oodata
                    oov = [ip2str(od['base']['next_hop']), od['base']['ifindex']]
                if osdata:
                    od = dict(osdata[0]['attrs'])
                    osv = [od[_] for _ in [os_dst,'RTA_OIF']]
                if allow_bad_ifindex and oodata['base']['ifindex'] == CI_IFID.BAD:
                    oov[1] = osv[1]
                assert osv and oov, "we should always get a route"
                if not all(a == b for a,b in zip(osv,oov)):
                    disparities.append(
                        'Disparity: route get %s: got %s vs %s'%(
                        ip2str(ip), str(oov), str(osv)))
                    oodata_collection[oo_index] = None
                oo_index += 1
        if not disparities:
            break
        if time.time() > t_end:
            assert False, disparities
        time.sleep(0.05)


@cpdecorate()
def do_test_route(v6, requery_always=False, iteration_count=64,
                  address_span=10,
                  cpserver=None, cp=None, netns=None):
    ''' The test keeps adding new routes and verifies responses to route queries
        change accordingly.  Responses of cplane are tested against os.
    '''

    def rand(i):
        return randint(0,i-1)

    def gen_gw(i):
        return fake_ip(v6, (99, 99, 99, i % 256))

    def gen_route():
        net = [0] * 4
        depth = rand(3) + 1
        for i in range(depth):
          net[i] = rand(address_span) + (1 if i == 0 else 0)
        if v6:
          depth += 12
        return (fake_ip_str(v6, net), depth * 8)

    # Give ip addresses to query in relation to given route. These are:
    # the route address; the one next to it (outside of the route) and
    # an extra one
    def gen_ips2query(r):
      d = 1 << r[1]
      ip = str2ip(r[0])
      base = ip[-1]
      return [(c_uint*4)(*(list(ip[:3]) + [base + d * mul]))
              for mul in range(3)]

    ifname = 'O0'
    oif = build_intf(netns, ifname, fake_ip_subnet(v6, 0, 1, suffix=16),
                     cp=cp, hwport=0)

    link_scope = 253
    netns.route('add', dst=fake_ip_subnet(v6, (99,99,99,0), suffix=8),
                       oif=oif, scope=link_scope)
    netns.route('add', dst='default', gateway=fake_ip_str(v6, 0, 2), oif=oif)

    applied_routes = {}
    ips2query = set()

    applied_routes[(ip2str(any_ip(v6)),0)] = [ fake_ip(v6, 0, 2),
                                               (cicp_verinfo * 3)() ]

    for it in range(iteration_count):
        # invent a new route
        while True:
          r = gen_route()
          if r not in applied_routes:
            break
        # give it some gateway
        gw = gen_gw(rand(255))
        # give it some gateway
        spec = dict(dst='%s/%d'%r, gateway=ip2str(gw))
        print 'route add %s'%spec
        netns.route('add', **spec)

        # give reasonable timeout to cp_server
        time.sleep(0.01)

        # for each route added, we'd be resolving 3 IP destinations,
        # for which we keep versions across changes
        applied_routes[r] = [ gw, (cicp_verinfo * 3)() ]

        compare_routing_tables(cp, netns, v6, applied_routes, requery_always,
                               gen_ips2query, 'RTA_GATEWAY', False)


def init_seed():
    try:
        seed = int(os.environ["UNIT_TEST_SEED"])
    except KeyError:
        seed = randint(0,1000000000)
    print 'SEED: ', seed
    random.seed(seed)


@pytest.mark.parametrize("v6", [False, True])
def test_route_requery(v6):
    ''' On each route query issue a request to get fresh route resolution,
        as if estabilishing new connection each time
    '''
    init_seed()
    do_test_route(v6, True)


@pytest.mark.parametrize("v6", [False, True])
def test_route_norequery(v6):
    ''' Only requery route if version changed as if keeping connections alive
        through route changes
    '''
    init_seed()
    do_test_route(v6, False)


@cpdecorate(tag='myns')
def do_test_nic_order(myns, encap):
    ''' tests creates a complicated macvlan/ipvlan over vlan over bond over
        macvlan over SFC interface and verifies hwport verification is correct.
        To make it more complicated bond is created before slaves, which makes
        cp_server require at least two passes to resolve hwports.
        And to make it 3 passes SFC nics are created at high ifindexes.
        Finally, the tests verfies whether change of active hwport is propagated
        to macvlan over vlan over bond.  This is done twice:
         * for cp_server instance that saw all the changes gradually,
         * for fresh cp_server instance
    '''

    slave_hwports=range(3)

    cpserver,cp,netns = myns.cpserver, myns.cp, myns.netns

    bond2ix = create_bond(cpserver, netns, 'bond2', [], mode=1)
    netns.link('add', kind='vlan', ifname='bond2_1', vlan_id=1, link=bond2ix)
    bond2_1ix = netns.link_lookup(ifname='bond2_1')[0]
    netns.link('add', kind=encap, ifname='bond2_1mv', link=bond2_1ix)

    # the 'physical' NICs, note they get fixed indexes far ahead
    for i in slave_hwports:
        cpmakenic(netns, cp, 'O%d'%i, i, ifindex=30+i);

    for i in slave_hwports:
        netns.link('add', kind='macvlan', ifname = 's%dmv'%i,
                   link=30+i)

    netns.link('set', index=bond2ix, state='up')
    for i in slave_hwports:
        netns.link('set', index=netns.link_lookup(ifname='s%dmv'%i)[0],
                   master=bond2ix)

    for link in netns.get_links():
        netns.link('set', index=link['index'], state='up')

    addr_add(netns, '192.168.0.2', mask=24, index=bond2ix)

    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip4, IP('192.168.0.1'))

    for i in range(2):
        print "i=%d"%i
        for active in slave_hwports + list(reversed(slave_hwports)):
            print"active=%d"%active
            ifname='bond2'
            bond_set_active(cpserver, ifname, 's%dmv'%active)
            expected_hwports = 1 << active
            d = wait_for_hwports(cp, v, k, 3, expected_hwports)

            check_route(d, CICP_ROUTE_TYPE.NORMAL, mac_addr(netns, bond2ix),
                        expected_hwports)

        if i == 0:
            ''' switch to another CPServer instance where interfaces are freshly scanned '''
            cpserver2 = CPServer(netns_pid=cpserver.pid,
                                 extra_opts=cpserver_extra_opts())
            time.sleep(1)
            cpserver.cleanup()
            # also update myns.cpserver for diagnostics in cpdecorate
            myns.cpserver = cpserver = cpserver2
            cp = cpserver.getClient()
            # We do not implement OO_IOC_CP_DUMP_HWPORTS in the shim, so we
            # should tell this new cp_server about already-established
            # hwports now:
            for j in slave_hwports:
                cp.newHwport(30+j, j)


@macandipvlan
def test_nic_order(encap):
    do_test_nic_order(encap=encap)


@cpdecorate(tag='main_ns')
@cpdecorate(tag='myns', parent_tag='main_ns')
def do_test_multi_ns(main_ns, myns, encap):
    ''' The test verifies hwport and license resolution of higher order intefaces
        based on lower order interfaces in different namespace.

        Creates two namespaces of which one is the main the other subordinate.
        MACVLAN interface in the subordinate namespace are based on the ifaces
        in the lower one.
    '''

    main_ix = cpmakenic(main_ns.netns, main_ns.cp, 'P0', 0);

    vifname= 'p0dmv'
    main_ns.netns.link('add', kind=encap, ifname=vifname,
                       link=main_ix)

    ix = main_ns.netns.link_lookup(ifname=vifname)[0]
    main_ns.netns.link('set', index=ix,
                       net_ns_fd=myns.cpserver.getNetNsPath())

    print 'ix=',ix,'iface=',vifname
    for l in myns.netns.get_links():
        print l
    addr_add(myns.netns, '192.168.0.2', index=ix, mask=24)
    myns.netns.link('set', index=ix, state='up')

    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip4, IP('192.168.0.1'))
    data = cpresolve(myns.cp, v, k, 7)
    assert data
    d = getdict(data)
    result = CICP_ROUTE_TYPE.NORMAL
    print '192.168.0.1', d
    check_route(d, result, mac_addr(myns.netns, index=ix), 1)


@macandipvlan
def test_multi_ns(encap):
    do_test_multi_ns(encap=encap)


@cpdecorate(tag='main_ns')
@cpdecorate(tag='myns', parent_tag='main_ns')
def do_test_multi_ns_bond(main_ns, myns, encap):
    hwports = range(3)
    prep_bond(main_ns.cpserver, main_ns.cp, main_ns.netns,
              hwports=hwports, address=None)

    main_ns.netns.link('add', kind=encap, ifname='bond2mv',
                       link=main_ns.netns.link_lookup(ifname='bond2')[0])
    main_ns.netns.link('set',
                       index=main_ns.netns.link_lookup(ifname='bond2mv')[0],
                       net_ns_fd=myns.cpserver.getNetNsPath())

    addr_add(myns.netns, index=myns.netns.link_lookup(ifname='bond2mv')[0],
             address='192.168.0.2', mask=24)
    myns.netns.link('set', index=myns.netns.link_lookup(ifname='bond2mv')[0],
                    state='up')

    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip4, IP('192.168.0.1'))

    for active in hwports + list(reversed(hwports)):
        bond_set_active(main_ns.cpserver, 'bond2', 'O%d'%active)
        expected_hwports = 1 << active

        d = wait_for_hwports(myns.cp, v, k, 3, expected_hwports)

        mac = mac_addr(myns.netns, ifname='bond2mv')
        check_route(d, CICP_ROUTE_TYPE.NORMAL, mac, expected_hwports)


@macandipvlan
def test_multi_ns_bond(encap):
    do_test_multi_ns_bond(encap=encap)


@cpdecorate()
def do_test_link_route(v6, requery_always=False, iteration_count=8,
                       address_span=10,
                       cpserver=None, cp=None, netns=None):
    ''' The test creates number of local interfaces in different often
        overlaping networks.  Interfaces are initially down, and
        then set up one-by-one to enable their link scope routes.
        In between each step route resolution is tested against the one of os.
    '''

    def rand(i):
        return randint(0,i-1)

    def gen_route():
        net = [0] * 4
        depth = rand(3) + 1
        for i in range(depth):
          net[i] = rand(address_span) + (1 if i == 0 else 0)
        if v6:
          depth += 12
        return (fake_ip_str(v6, net), depth * 8)

    def ip_add(ip, offset):
      return (c_uint*4)(*(list(ip[:3]) + [ip[3] + offset]))

    # Give ip addresses to query in relation to given route. These are:
    # the route address; the one next to it (outside of the route) and
    # an extra one
    def gen_ips2query(r):
      d = 1 << r[1]
      ip = str2ip(r[0])
      return [ip_add(ip, offset)
              for offset in (0, d, 2 * d, 0x1000000,
                             r[1] + 7 * 0x1000000 - ip[-1])]

    ifname = 'O0'
    oif = build_intf(netns, ifname, fake_ip_subnet(v6, 0), cp=cp, hwport=0)

    applied_routes = {}
    for it in range(iteration_count):
        # invent a new route
        while True:
          r = gen_route()
          if r not in applied_routes:
            break
        build_intf(netns, 'if%d'%it, kind='macvlan', state=None, link=oif,
                   address='%s/%d'%(ip2str(ip_add(str2ip(r[0]), 0x1000000)),r[1]))
        applied_routes[r] = [ '', (cicp_verinfo * 7)() ]

    netns.link('set', ifname='lo', state='up')
    netns.route('add', dst='default', gateway='::1' if v6 else '127.0.0.2',
                       oif=1)

    for it in range(-1,iteration_count*2):
        # putting interface up enables route, down disables
        if it >= 0:
            netns.link('set', ifname='if%d'%(it%iteration_count),
                       state='up' if it < iteration_count else 'down')

        compare_routing_tables(cp, netns, False, applied_routes, requery_always,
                               gen_ips2query, 'RTA_DST', True)


@pytest.mark.parametrize("v6", [False, True])
def test_link_route_requery(v6):
    ''' Only requery route if version changed as if keeping connections alive
        through route changes
    '''
    init_seed()
    do_test_link_route(v6, True)

@pytest.mark.parametrize("v6", [False, True])
def test_link_route_norequery(v6):
    ''' Only requery route if version changed as if keeping connections alive
        through route changes
    '''
    init_seed()
    do_test_link_route(v6, False)


@cpdecorate()
def do_combination(cpserver,cp,netns,combination):

    def make_bond(ifname,ifnames,**kwargs):
        create_bond(cpserver, netns, ifname, ifnames, kwargs['mode'])
        return [ifname]

    def make_vlan(ifname,ifnames,**kwargs):
        netns.link('add', ifname=ifname,
                    link=netns.link_lookup(ifname=ifnames[0])[0],
                    **kwargs)
        return [ifname]

    vlan = lambda ifname, vid: (make_vlan, dict(ifname=ifname, kind='vlan', vlan_id=vid))
    macvlan = lambda ifname: (make_vlan, dict(ifname=ifname, kind='macvlan'))
    ipvlan = lambda ifname: (make_vlan, dict(ifname=ifname, kind='ipvlan'))
    bond = lambda ifname: (make_bond, dict(ifname=ifname, mode=1))
    ALIEN = CICP_ROUTE_TYPE.ALIEN
    NORMAL = CICP_ROUTE_TYPE.NORMAL
    combination_data = {
      'vlan_over_vlan': (ALIEN,
          [vlan('v1',1), vlan('v2',2)]),
      'ipvlan_over_vlan': (NORMAL,
          [vlan('v1',1), ipvlan('v2')]),
      'vlan_over_macvlan': (NORMAL,
          [macvlan('mv'), vlan('v1',1)]),
      'bond_over_vlan': (ALIEN,
          [vlan('v1',1), bond('b1')]),
      'macvlan_over_macvlan': (NORMAL,
          [macvlan('mv1'), macvlan('mv2')]),
      'ipvlan_over_macvlan': (NORMAL,
          [macvlan('mv1'), ipvlan('ipv2')]),
      'macvlan_over_macvlan_over_vlan': (NORMAL,
          [vlan('v1',1), macvlan('mv'), macvlan('mv2')]),
      'ipvlan_over_macvlan_over_vlan': (NORMAL,
          [vlan('v1',1), macvlan('mv'), ipvlan('ipv2')]),
      'vlan_over_macvlan_over_macvlan': (NORMAL,
          [macvlan('mv'), macvlan('mv2'), vlan('v1',1)]),
      'vlan_over_macvlan_over_vlan': (ALIEN,
          [vlan('v1',1), macvlan('mv'), vlan('v2',2)]),
      'bond_over_macvlan_over_vlan': (ALIEN,
          [vlan('v1',1), macvlan('mv'), bond('b1')]),
    }
    route_type, specs = combination_data[combination]


    # create a fallback route - cp_server is never supposed to give it
    ifname = 'O1'
    build_intf(netns, ifname, '192.168.1.2/16', cp=cp, hwport=1)

    # create base inteface
    ifname = 'O0'
    build_intf(netns, ifname, None, cp=cp, hwport=0)

    # create interfaces as in spec
    ifnames = [ifname]
    all_ifnames = []
    for recipe, details in specs:
        details.update(ifnames=ifnames)
        ifnames = recipe(**details)
        all_ifnames += ifnames

    # last interface gets an address
    ifix = netns.link_lookup(ifname=all_ifnames[-1])[0]
    netns.addr('add', index=ifix, address='192.168.0.2', mask=24)

    # we only up interfaces now as e.g. bond cannot add upped slaves
    for ifname in all_ifnames:
        netns.link('set', ifname=ifname, state='up')

    # obtain route from cplane
    v = cicp_verinfo(0,0)
    k = cp_fwd_key(any_ip4, IP('192.168.0.1'))
    data = cpresolve(cp, v, k, 10)
    assert data

    # verify route is ALIEN and through
    d = getdict(data)
    print d
    assert ip2str(d['base']['next_hop']) == '192.168.0.1'
    assert (d['base']['ifindex'] == 0) == (route_type == ALIEN)


@pytest.mark.parametrize(
    "combination", [
      'vlan_over_vlan',
      pytest.param('ipvlan_over_vlan',marks=pytest.mark.skipif(
                   want_macandipvlan, reason="needs kernel >= 3.19")),
      'vlan_over_macvlan',
      'bond_over_vlan',
      'macvlan_over_macvlan',
      pytest.param('ipvlan_over_macvlan',marks=pytest.mark.skipif(
                   want_macandipvlan, reason="needs kernel >= 3.19")),
      'macvlan_over_macvlan_over_vlan',
      pytest.param('ipvlan_over_macvlan_over_vlan',marks=pytest.mark.skipif(
                   want_macandipvlan, reason="needs kernel >= 3.19")),
      'vlan_over_macvlan_over_macvlan',
      'vlan_over_macvlan_over_vlan',
      'bond_over_macvlan_over_vlan',
      ])
def test_combination(combination):
    do_combination(combination=combination)


def lower_incomplete_gamma(s, x):
    # https://math.stackexchange.com/questions/724068/expressing-upper-incomple
    # s is <= 8 for all uses in this code
    if s % 1 == 0:
        n = int(s)
        return math.gamma(n) * (1 - math.exp(-x) * sum(pow(x, m) / math.factorial(m) for m in range(n)))
    elif s == 0.5:
        return math.gamma(s) - math.sqrt(math.pi) * math.erfc(math.sqrt(x))
    elif (s * 2) % 1 == 0:
        return math.gamma(s) * (1 - math.erfc(math.sqrt(x)) - math.exp(-x) * sum(math.pow(x, j + 0.5) / (j + 0.5) / math.gamma(j + 0.5) for j in range(int(s - 0.5))))
    else:
        # not implemented
        assert False


def chi_squared_cdf(k, x):
    assert x >= 0

    return lower_incomplete_gamma(k / 2.0, x / 2.0) / math.gamma(k / 2.0)


chi_squared_ref = [
    #k  p<=0.90  p<=0.95  p<=0.99
    (1,   2.706,   3.841,   6.635),
    (2,   4.605,   5.991,   9.210),
    (3,   6.251,   7.815,  11.345),
    (7,  12.017,  14.067,  18.475),
    (8,  13.362,  15.507,  20.090),
]
for n, c90, c95, c99 in chi_squared_ref:
    assert abs(chi_squared_cdf(n, c90) - 0.90) < 0.0001
    assert abs(chi_squared_cdf(n, c95) - 0.95) < 0.0001
    assert abs(chi_squared_cdf(n, c99) - 0.99) < 0.0001


def check_multipath_distribution(cp, macs, ip, n, expect_multipath_lookup=True):
    # macs is the expected ratio (not normalized)

    hist = {}
    v = cicp_verinfo(0,0)
    for _ in range(n):
        k = cp_fwd_key(any_ip4, IP(ip))
        data = cpresolve(cp, v, k, 7)

        assert data
        d = getdict(data)

        mac = mac_to_str(d['src_mac']) if d['hwports'] else '00:00:00:00:00:00'
        if mac not in hist:
            hist[mac] = 0
        hist[mac] += 1

    # print measured and expected distributions
    print("weights: " + repr(macs))
    print("samples: " + repr(hist))

    for k in hist:
        assert k in macs, "unexpected route: " + k

    if len(macs) <= 1:
        return

    if expect_multipath_lookup:
        for mac in macs:
            assert mac in hist, "route never taken: " + mac
        # check the distribution
        # chi squared test
        macs_n = sum(macs.values())
        n = sum(hist.values())
        chi2 = 0
        for mac in macs:
            p = macs[mac] / float(macs_n)
            E = float(n * p)
            chi2 += pow(hist[mac] - E, 2) / E

        print("chi2 = %f" % (chi2,))

        k = len(macs) - 1
        cdf = chi_squared_cdf(k, chi2)
        print("p(x <= chi2) = %f" % (cdf,))
        assert cdf < 0.999999, cdf
    else:
        # Check that the lookups for the multipath routes always returned the
        # same result.
        assert len(hist) == 1, "Multiple paths not expected"


def do_multipath_trials(cpserver, cp, netns, v6, n, weights,
                        expect_multipath_lookup=True):
    interfaces = []
    for hwport in range(n):
        ifname = 'O%d' % (hwport,)
        ix = build_intf(netns, ifname, fake_ip_subnet(v6, hwport),
                        cp=cp, hwport=hwport)
        interfaces.append(ix)

    macs = {}
    multipath_spec = []
    for interface, weight in zip(interfaces, weights):
        multipath_spec.append(dict(oif=interface, hops=weight - 1))
        macs[mac_addr(netns, interface)] = weight

    ip = fake_ip_str(v6, (99,99,99,7))
    dst = fake_ip_subnet(v6, (99,99,99,0))

    link_scope = 253
    netns.route('add', dst=dst, scope=link_scope, multipath=multipath_spec)
    wait_for_route_update(netns, cp, v6)

    check_multipath_distribution(cp, macs, ip, 1000, expect_multipath_lookup)

    netns.route('del', dst=dst, scope=link_scope, multipath=multipath_spec)
    wait_for_route_update(netns, cp, v6)

    check_multipath_distribution(cp, {'00:00:00:00:00:00': 1}, ip, 1000)


@cpdecorate()
def do_multipath(*args, **kwargs):
    do_multipath_trials(*args, **kwargs)


hwport_max = 8
# Multipath IPv6 doesn't work in kernels <4.11. Bug 85779
# TODO: Implement the necessary detection and try these tests on a new kernel
@pytest.mark.parametrize("v6", [False])
@pytest.mark.parametrize("n", [1, 2, 3, hwport_max])
def test_multipath(v6, n):
    do_multipath(v6=v6, n=n, weights=[2] * n)


@pytest.mark.parametrize("v6", [False])
@pytest.mark.parametrize("n", [2, 3, 5, hwport_max])
def test_multipath_uneven(v6, n):
    do_multipath(v6=v6, n=n, weights=range(1, 1 + n))


@cpdecorate()
def test_multipath_add_del(cpserver,cp,netns):
    v6 = False
    interfaces = []
    weights = [1, 2, 1, 2]
    for hwport in range(4):
        ifname = 'O%d' % (hwport,)
        ix = build_intf(netns, ifname, '192.168.%d.1/24' % (hwport,),
                        cp=cp, hwport=hwport)
        interfaces.append(ix)

    ip = '99.99.99.7'
    dst = '99.99.99.0/24'

    # start with non-multipath route
    # this route will have weight 1 when promoted to a multipath route
    multipath = [{ 'oif': interfaces[0], 'hops': 0 }]
    macs = {}
    link_scope = 253
    netns.route('add', dst=dst, scope=link_scope, multipath=multipath)
    macs[mac_addr(netns, interfaces[0])] = 1

    check_multipath_distribution(cp, macs, ip, 1000)

    # add second route
    multipath.append({ 'oif': interfaces[1], 'hops': weights[1]-1 })
    netns.route('change', dst=dst, scope=link_scope, multipath=multipath)
    wait_for_route_update(netns, cp, v6)
    macs[mac_addr(netns, interfaces[1])] = weights[1]

    check_multipath_distribution(cp, macs, ip, 1000)

    # add third route, remove first route
    multipath.append({ 'oif': interfaces[2], 'hops': weights[2]-1 })
    del multipath[0]
    netns.route('change', dst=dst, scope=link_scope, multipath=multipath)
    wait_for_route_update(netns, cp, v6)
    macs[mac_addr(netns, interfaces[2])] = weights[2]
    del macs[mac_addr(netns, interfaces[0])]

    check_multipath_distribution(cp, macs, ip, 1000)

    # add fourth route
    multipath.append({ 'oif': interfaces[3], 'hops': weights[3]-1 })
    netns.route('change', dst=dst, scope=link_scope, multipath=multipath)
    wait_for_route_update(netns, cp, v6)
    macs[mac_addr(netns, interfaces[3])] = weights[3]

    check_multipath_distribution(cp, macs, ip, 1000)

    # remove fourth route
    del multipath[-1]
    netns.route('change', dst=dst, scope=link_scope, multipath=multipath)
    wait_for_route_update(netns, cp, v6)
    del macs[mac_addr(netns, interfaces[3])]

    check_multipath_distribution(cp, macs, ip, 1000)

    # remove second route
    del multipath[0]
    netns.route('change', dst=dst, scope=link_scope, multipath=multipath)
    wait_for_route_update(netns, cp, v6)
    del macs[mac_addr(netns, interfaces[1])]

    check_multipath_distribution(cp, macs, ip, 1000)

    # remove third route
    # there is now no route to 99.99.99.0/24
    netns.route('del', dst=dst, scope=link_scope)
    wait_for_route_update(netns, cp, v6)

    check_multipath_distribution(cp, {'00:00:00:00:00:00': 1}, ip, 1000)
