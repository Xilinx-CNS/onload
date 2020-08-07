# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2010-2019 Xilinx, Inc.

# Library of routines for manipulating representations of sets of integers.

import re


# python 3 compat
import sys
if sys.version_info >= (3,0):
    long = int
    xrange = range


class BadMask(Exception):
    def __init__(self, msg):
        self.msg = msg


def is_int(x):
    return type(x) is int or type(x) is long


def is_int_list(x):
    if type(x) is not list:
        return False
    for c in x:
        if not is_int(c):
            return False
    return True


def is_hex_str_w_0x(s):
    """String formatted as a hexadecimal number with 0x prefix."""
    try:
        int(s, 16)
        return type(s) is str and s[0:2] == '0x'
    except:
        return False


def is_comma_sep_hex(mask):
    if type(mask) is not str:
        return False
    if ',' not in mask and len(mask) < 8:
        return is_hex_str_w_0x(mask)
    for s in mask.split(','):
        if len(s) != 8:
            return False
        try:
            int(s, 16)
        except:
            return False
    return True


def is_comma_sep_list(mask):
    if type(mask) is not str:
        return False
    for s in mask.split(','):
        if not re.match(r'[0-9]+(-[0-9]+)?', s):
            return False
        if len(s) > 7:
            return False
    return True


def is_mask(mask):
    return is_int(mask) or \
           is_int_list(mask) or \
           is_comma_sep_hex(mask) or \
           is_comma_sep_list(mask)


def int_list_to_int(mask):
    r = 0
    for c in mask:
        r |= 1 << c
    return r


def comma_sep_hex_to_int(cshm):
    assert type(cshm) is str
    mask = 0
    for i in cshm.split(','):
        mask <<= 32
        mask |= int(i, 16)
    return mask


def comma_sep_list_to_int(csl):
    assert type(csl) is str
    mask = 0
    for s in csl.split(','):
        if '-' in s:
            a, b = s.split('-')
            for i in range(int(a), int(b) + 1):
                mask |= 1 << i
        else:
            mask |= 1 << int(s)
    return mask


def int_to_comma_sep_list(mask):
    low = -1
    high = 0
    r = ""
    while 1:
        if mask & (1 << high):
            if low < 0:
                low = high
        elif low >= 0:
            if high - low > 1:
                r += ",%d-%d" % (low, high - 1)
            elif low >= 0:
                r += ",%d" % (low)
            low = -1
        if not mask:
            break
        mask &= ~(1 << high)
        high += 1
    if r:
        r = r[1:]
    return r


def int_to_comma_sep_hex(mask, minlen=False):
    assert is_int(mask)
    cshm = "%08x" % (mask & 0xffffffff)
    mask >>= 32
    while mask:
        cshm = "%08x," % (mask & 0xffffffff) + cshm
        mask >>= 32
    if minlen and ',' not in cshm:
        # strip leading zeros
        cshm = "%x" % int(cshm, 16)
    return cshm


def to_int(mask):
    if is_int(mask):
        return mask
    elif is_int_list(mask):
        return int_list_to_int(mask)
    elif is_comma_sep_hex(mask):
        return comma_sep_hex_to_int(mask)
    elif is_comma_sep_list(mask):
        return comma_sep_list_to_int(mask)
    else:
        raise BadMask(mask)


def to_comma_sep_hex(mask):
    return int_to_comma_sep_hex(to_int(mask))


def to_comma_sep_list(mask):
    return int_to_comma_sep_list(to_int(mask))


def to_int_list(mask):
    mask = to_int(mask)
    r = []
    for i in xrange(0, 1000000):
        if mask & (1 << i):
            r.append(i)
            mask &= ~(1 << i)
        if not mask:
            break
    return r

######################################################################

def selftest():
    mask = 'ffffffff,12345678'
    assert is_comma_sep_hex(mask)
    assert not is_comma_sep_hex('1,2,3')
    maski = to_int(mask)
    assert is_int(maski)
    assert not is_hex_str_w_0x('ff')
    assert is_hex_str_w_0x('0xff')
    assert not is_hex_str_w_0x(0xff)
    assert is_comma_sep_list('1,2,3')
    assert is_comma_sep_list('1')
    assert is_comma_sep_list('1234567')
    assert not is_comma_sep_list('12345678')
    assert is_mask('0x3')
    assert to_comma_sep_list(4) == '2'

    if 0:
        for mask in [23, 0, 0xfef, '0-64', '1']:
            i = to_int(mask)
            csl = to_comma_sep_list(mask)
            cshm = to_comma_sep_hex(mask)
            import sys
            sys.stdout.write("%s: hex(%x) csl(%s) cshm(%s)\n" % \
                                 (mask, i, csl, cshm))


if __name__ == '__main__':
    selftest()
