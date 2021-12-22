#! /usr/bin/env python3
#
# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2014-2020 Xilinx, Inc.


"""
Script to help test onload_remote_monitor.

Gets output from onload_remote_monitor and from 'onload_stackdump
lots' and compares some stats from both.

Because it is impossible to gather the stats at exactly the same time we take:
stackdump
ORM
stackdump

and verify that the ORM values are between the other two readings
"""

import os, sys, socket, json, time, subprocess, re

# Python 2 backwards compatibility
if sys.version_info < (3,0):
    from urllib2 import Request, urlopen, URLError
else:
    from urllib.request import Request, urlopen
    from urllib.error import URLError

def usage():
    print('Usage: %s [http] host:port' % sys.argv[0])
    sys.exit(1)


def my_cmp(a, b, c):
    # check that value b lies between a and c
    # As stats are gathered separately, they can be off by a little
    # bit, so we allow them to differ by epsilon percent beyond this.
    epsilon = 0.0
    smallest = min(a, c)
    largest = max(a, c)
    # take care when expanding the range as the values can be negative
    lower = smallest - (abs(smallest) * epsilon) / 100.0
    upper = largest + (abs(largest) * epsilon) / 100.0
    return (b >= lower and b <= upper)

def exact_cmp(a, b, c):
    # check all 3 values are the same
    return (a == b == c)

def run_cmd(cmd):
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    stdout = child.communicate()[0]
    assert child.returncode == 0, child.returncode
    return stdout


def osd_get():
    return run_cmd(['onload_stackdump', 'lots'])


def orm_get(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send('stack_state_get\n')
    out = ''
    while '\n' not in out:
        rc = sock.recv(1024)
        if not rc:
            break
        out += rc
    sock.close()
    if out.strip():
        return json.loads(out)
    else:
        return ''

def orm_get_http(host, port):
    req = Request("http://%s:%s/onload/lots" % (host, port))
    try:
        response = urlopen(req).read()
        if response.strip():
            return json.loads(response)
    except URLError as e:
        if hasattr(e, 'reason'):
            print('We failed to reach a server.')
            print('Reason: ', e.reason)
        elif hasattr(e, 'code'):
            print('The server couldn\'t fulfill the request.')
            print('Error code: ', e.code)
    return ''

############################################################
# Compare ci_netif_stats
############################################################

def osd_stats_get(output):
    stacks = output.split('=' * 60 + '\n')[1:]
    ret = {}
    for index, stack in enumerate(stacks):
        stack_id = int(re.match('\S+: stack=(\d+)',
                                stack.split('\n')[0]).group(1))
        stats = stack.split('-' * 60 + '\n')[-1].split('\n')

        # Drop options
        end_index = [i for i, line in enumerate(stats) if line.startswith(' ')][0]
        stats = stats[:end_index]

        # Remove headings
        stats = [line for line in stats if not line.startswith('-----')]

        ret[stack_id] = dict([line.split(': ', 1) for line in stats])
    return ret


def orm_stats_get(output):
    return dict([(int(next(iter(s.keys()))), next(iter(s.values()))['stats'])
                 for s in output['json']])


def netif_stats_cmp(osd_stats, orm_stats, osd_stats2):
    # Note that currently, 'onload_stackdump lots' outputs additional
    # data that 'onload_remote_monitor' doesn't.  So we loop over
    # orm_stats.  Ideally we should loop over osd_stats.
    for k in sorted(orm_stats.keys()):
        try:
            if not my_cmp(int(osd_stats[k]),
                          int(orm_stats[k]),
                          int(osd_stats2[k])):
                print('Fail: {0}=osd({1}),orm({2}),osd2({3})'.format(
                    k, osd_stats[k], orm_stats[k], osd_stats2[k]))
                sys.exit(1)
        except KeyError:
            print('Fail: Key {0} not found'.format(k))
            sys.exit(1)

############################################################
# Compare ci_netif_opts
############################################################

def osd_opts_get(output):
    stacks = output.split('=' * 60 + '\n')[1:]
    ret = {}
    for index, stack in enumerate(stacks):
        stack_id = int(re.match('\S+: stack=(\d+)',
                                stack.split('\n')[0]).group(1))
        opts = stack.split('-' * 60 + '\n')[-1].split('\n')
        opts = [line.strip() for line in opts]
        ret[stack_id] = dict([(line.split(': ')[0],
                               line.split(': ')[1].split(' ')[0])
                               for line in opts
                               if re.search('^EF.*:|^NDEBUG', line)])
    return ret


def orm_opts_get(output):
    return dict([(int(next(iter(s.keys()))), next(iter(s.values()))['opts'])
                 for s in output['json']])


def netif_opts_cmp(osd_opts, orm_opts, osd_opts2):
    for k in sorted(osd_opts.keys()):
        try:
            _type = type(osd_opts[k])
            c1, c2, c3 = osd_opts[k], _type(orm_opts[k]), _type(osd_opts2[k])
            if _type is str:
                c1 = c1.replace('"', '')
                c3 = c3.replace('"', '')
            if k in ['EF_INTERFACE_BLACKLIST', 'EF_INTERFACE_WHITELIST']:
                c1 = set(c1.split())
                c2 = set(c2.split())
                c3 = set(c3.split())
            if not exact_cmp(c1, c2, c3):
                print('Fail: {0}=osd({1}),orm({2}),osd2({3})'.format(
                    k, c1, c2, c3))
                sys.exit(1)
        except KeyError:
            print('Fail: Key {0} not found'.format(k))
            sys.exit(1)

############################################################
# Compare tcp/udp sockets
############################################################

'''
Per socket type dictionaries to relate the counters in
onload_stackdump lots and onload_remote_monitor.  Counters on the same
line in stackdump are grouped together.  Each stackdump counter has a
corresponding remote_monitor counter.

key[1] is the key in remote_monitor output.  key[0] is needed to make
the keys unique.
'''
tcp_state_dict = {
    (0, 's'): [
        ('rx_errno', 'rx_errno'),
        ('tx_errno', 'tx_errno'),
        ('so_error', 'so_error'),
        ],
    (1, 'stats'): [
        ('tx_stop_rwnd', 'rwnd'),
        ('tx_stop_cwnd', 'cwnd'),
        ('tx_stop_nagle', 'nagle'),
        ('tx_stop_more', 'more'),
        ('tx_stop_app', 'app'),
        ],
    (2, 'stats'): [
        ('tx_defer', 'defer'),
        ('tx_nomac_defer', 'nomac'),
        ('tx_msg_warm', 'warm'),
        ('tx_msg_warm_abort', 'warm_aborted'),
        ],
    (3, 'stats'): [
        ('tx_tmpl_send_fast', 'send_fast'),
        ('tx_tmpl_send_slow', 'send_slow'),
        ('tx_tmpl_active', 'active'),
        ],
    }

tcp_listen_state_dict = {
    (0, 'stats'): [
        ('n_listenq_overflow', 'l_overflow'),
        ('n_listenq_no_synrecv', 'l_no_synrecv'),
        ('n_acceptq_overflow', 'aq_overflow'),
        ('n_acceptq_no_sock', 'aq_no_sock'),
        ],
    (1, 'stats'): [
        ('n_accept_loop2_closed', 'a_loop2_closed'),
        ('n_accept_no_fd', 'a_no_fd'),
        ('n_acks_reset', 'ack_rsts'),
        ('n_accept_os', 'os'),
        ],
    }

udp_state_dict = {
    (0, 's'): [
        ('so_error', 'so_error'),
        ],
    (1, 'recv_q'): [
        ('pkts_added', 'tot_pkts')
        ],
    (2, 'stats'): [
        ('n_rx_overflow', 'oflow_drop'),
        ('n_rx_mem_drop', 'mem_drop'),
        ('n_rx_eagain', 'eagain'),
        ('n_rx_pktinfo', 'pktinfo'),
        ('max_recvq_pkts', 'q_max_pkts'),
        ],
    (3, 'stats'): [
        ('n_rx_os_slow', 'os_slow'),
        ('n_rx_os_error', 'os_error'),
        ],
    (4, 'stats'): [
        ('n_tx_os', 'os'),
        ],
    (5, 'stats'): [
        ('n_tx_lock_cp', 'cp'),
        ('n_tx_lock_pkt', 'pkt'),
        ('n_tx_lock_snd', 'snd'),
        ('n_tx_lock_poll', 'poll'),
        ('n_tx_lock_defer', 'defer'),
        ],
    (6, 'stats'): [
        ('n_tx_onload_uc', 'n'),
        ('n_tx_cp_match', 'match'),
        ('n_tx_cp_uc_lookup', 'lookup'),
        ],
    (7, 'stats'): [
        ('n_tx_eagain', 'eagain'),
        ('n_tx_spin', 'spin'),
        ('n_tx_block', 'block'),
        ],
    (8, 'stats'): [
        ('n_tx_poll_avoids_full', 'poll_avoids_full'),
        ('n_tx_fragments', 'fragments'),
        ('n_tx_msg_confirm', 'confirm'),
        ],
    (9, 'stats'): [
        ('n_tx_os_slow', 'os_slow'),
        ('n_tx_os_late', 'os_late'),
        ('n_tx_unconnect_late', 'unconnect_late'),
        ('n_tx_cp_no_mac', 'nomac'),
        ],
    }


def orm_socket_state_get(orm_output, socket_type):
    '''
    Build and return a dictionary containing UDP/TCP/TCP_LISTEN stats in
    remote_monitor output.  The format is:

    {stack_id: {'udp1'/'tcp1/tcp_listen1':
        {'ci_udp_state'/'ci_tcp_state/ci_tcp_socket_listen':
          {stats...}, ...}}, ...}

    The property and stat keys have been hardcoded into
    udp_state_dict/tcp_state_dict/tcp_listen_state_dict.
    '''

    assert socket_type in ['udp', 'tcp', 'tcp_listen']

    ret = {}
    for stack in orm_output['json']:
        assert len(stack.keys()) == 1
        stack_id = int(next(iter(stack.keys())))
        ret[stack_id] = {}
        stack_stats = next(iter(stack.values()))
        assert type(stack_stats) == dict
        for section in ['stats', 'more_stats', 'tcp_stats', 'tcp_ext_stats',
                        'opts']:
            assert section in stack_stats, section
        netif_stats = stack_stats['stack']
        assert type(netif_stats) == dict
        for key in netif_stats.keys():
            if key.startswith(socket_type):
                for socket_id, socket_state in netif_stats[key].items():
                    ret[stack_id][socket_id] = socket_state
    return ret


def osd_socket_state_get(output, socket_type):
    '''
    Build and return a dictionary based on udp_state_dict.  It has the
    same format as what is returned from orm_udp_state_get().
    '''

    assert socket_type in ['udp', 'tcp', 'tcp_listen'], socket_type
    socket_state_dict_lookup = {
        'udp': udp_state_dict,
        'tcp': tcp_state_dict,
        'tcp_listen': tcp_listen_state_dict,
        }
    socket_state_dict = socket_state_dict_lookup[socket_type]
    socket_type_dict = {
        'udp': 'udp_state',
        'tcp': 'tcp_state',
        'tcp_listen': 'tcp_listen_sockets',
        }
    state_type = socket_type_dict[socket_type]

    stacks = output.split('=' * 60 + '\n')[1:]

    # Build regex patterns for the lines in socket output
    state_pattern = {}
    for k, vals in socket_state_dict.items():
        orm_keys = [v[0] for v in vals]
        osd_keys = [v[1] for v in vals]
        pattern  = '[\s\S]+' + '=(\d+)[\s\S]+'.join(osd_keys) + '=(\d+)'
        state_pattern[k] = (orm_keys, pattern)

    # Look up and fill in all sockets in the stacks
    ret = {}
    for stack in stacks:
        stack_id = int(re.match('\S+: stack=(\d+)',
                                stack.split('\n')[0]).group(1))
        ret[stack_id] = {}

        sockets = stack.split('-' * 60 + '\n')[:-1]
        if len(sockets) > 0:
            header = '--------------------- sockets ------------------------------\n'
            sockets[0] = sockets[0][sockets[0].index(header) + len(header):]

        if socket_type == 'udp':
            sockets = [s for s in sockets if s.startswith('UDP')]
        elif socket_type == 'tcp':
            sockets = [s for s in sockets if s.startswith('TCP')]
            sockets = [s for s in sockets
                       if s.split('\n')[0].endswith('ESTABLISHED')]
        elif socket_type == 'tcp_listen':
            sockets = [s for s in sockets if s.startswith('TCP')]
            sockets = [s for s in sockets
                       if s.split('\n')[0].endswith('LISTEN')]
        else:
            assert 0

        for s in sockets:
            lines = s.split('\n')
            sock_id = re.match(
                '[\S]+ %d:(\d+) [\s\S]+' % stack_id, lines[0]).group(1)
            ret[stack_id][sock_id] = {state_type: {}}
            for k in state_pattern.keys():
                struct_key = k[1]
                ret[stack_id][sock_id][state_type][struct_key] = {}
            for k, v in state_pattern.items():
                matched = False
                struct_key = k[1]
                stat_keys = v[0]
                pattern = v[1]
                for line in lines:
                    m = re.match(pattern, line)
                    if m:
                        for i, stat_key in enumerate(stat_keys):
                            ret[stack_id][sock_id][state_type][
                                struct_key][stat_key] = int(m.group(i + 1))
                        matched = True
                if not matched:
                    print('warning, no matches for regexp ',pattern)
    return ret


def socket_state_cmp(osd_stats, orm_stats, osd_stats2, socket_type):
    assert socket_type in ['udp', 'tcp', 'tcp_listen']
    socket_type_dict = {
        'udp': 'udp_state',
        'tcp': 'tcp_state',
        'tcp_listen': 'tcp_listen_sockets'
        }
    state_type = socket_type_dict[socket_type]
    for sock_id, osd_sock_dict in osd_stats.items():
        osd_sock_dict = osd_sock_dict[state_type]
        orm_sock_dict = orm_stats[sock_id][state_type]
        osd_sock_dict2 = osd_stats2[sock_id][state_type]
        for stats_key, osd_stats_val in osd_sock_dict.items():
            orm_stats_val = orm_sock_dict[stats_key]
            osd_stats_val2 = osd_sock_dict2[stats_key]
            for stat_key, osd_stat_val in osd_stats_val.items():
                orm_stat_val = orm_stats_val[stat_key]
                osd_stat_val2 = osd_stats_val2[stat_key]
                if not my_cmp(osd_stat_val, orm_stat_val, osd_stat_val2):
                    print('Fail: {0}=stackdump({1}),remote_monitor({2}),'
                           'stackdump2({3})'.format(
                               stat_key, osd_stat_val, orm_stat_val,
                               osd_stat_val2))
                    sys.exit(1)


############################################################
# Main
############################################################

def main():
    if len(sys.argv) < 2 or len(sys.argv) > 3 :
        usage()
    host, port = sys.argv[len(sys.argv)-1].split(':')
    port = int(port)


    osd_output = osd_get()
    if sys.argv[1] == 'http' :
        orm_output = orm_get_http(host,port)
    else:
        orm_output = orm_get(host, port)

    if osd_output == '':
        assert orm_output == '', orm_output
        return
    else:
        assert orm_output != ''

    osd_output2 = osd_get()
    osd_stats = osd_stats_get(osd_output)
    orm_stats = orm_stats_get(orm_output)
    osd_stats2 = osd_stats_get(osd_output2)
    osd_opts = osd_opts_get(osd_output)
    orm_opts  = orm_opts_get(orm_output)
    osd_opts2 = osd_opts_get(osd_output2)

    print('Stacks: ' + ' '.join(map(str, osd_stats.keys())))

    # Check all outputs report the same stack ids
    if not (sorted(osd_stats.keys()) == sorted(orm_stats.keys())
            == sorted(osd_stats2.keys())):
        print('Fail: osd_stacks({0}) != orm_stacks({1}) != '
               'osd_stacks2({2})'.format(
                   list(osd_stats.keys()), list(orm_stats.keys()), list(osd_stats2.keys())))
        sys.exit(1)

    for stack_id in orm_stats.keys():
        netif_stats_cmp(osd_stats[stack_id],
                        orm_stats[stack_id],
                        osd_stats2[stack_id])
        netif_opts_cmp(osd_opts[stack_id],
                       orm_opts[stack_id],
                       osd_opts2[stack_id])

    osd_udp_state = osd_socket_state_get(osd_output, 'udp')
    orm_udp_state = orm_socket_state_get(orm_output, 'udp')
    osd_udp_state2 = osd_socket_state_get(osd_output2, 'udp')
    for stack_id in orm_stats.keys():
        print('  UDP: ' + ' '.join(osd_udp_state[stack_id].keys()))
        socket_state_cmp(osd_udp_state[stack_id],
                         orm_udp_state[stack_id],
                         osd_udp_state2[stack_id],
                         'udp')

    osd_tcp_state = osd_socket_state_get(osd_output, 'tcp')
    orm_tcp_state = orm_socket_state_get(orm_output, 'tcp')
    osd_tcp_state2 = osd_socket_state_get(osd_output2, 'tcp')
    for stack_id in orm_stats.keys():
        print('  TCP: ' + ' '.join(osd_tcp_state[stack_id].keys()))
        socket_state_cmp(osd_tcp_state[stack_id],
                         orm_tcp_state[stack_id],
                         osd_tcp_state2[stack_id],
                         'tcp')

    osd_listen_state = osd_socket_state_get(osd_output, 'tcp_listen')
    orm_listen_state = orm_socket_state_get(orm_output, 'tcp_listen')
    osd_listen_state2 = osd_socket_state_get(osd_output2, 'tcp_listen')
    for stack_id in orm_stats.keys():
        print('  LISTEN: ' + ' '.join(osd_listen_state[stack_id].keys()))
        socket_state_cmp(osd_listen_state[stack_id],
                         orm_listen_state[stack_id],
                         osd_listen_state2[stack_id],
                         'tcp_listen')


if __name__ == '__main__':
    main()
