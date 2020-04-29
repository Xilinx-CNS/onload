#!/usr/bin/python2
# SPDX-License-Identifier: Solarflare-Binary
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
from __future__ import print_function
import sys, os, os.path, re, argparse, urlparse, collections, fnmatch


def is_binary_header(header):
    return (header.startswith('!<arch>./       ')
            or header.startswith('\x7fELF'))


_error_count = 0

def err(path, linenum, line, msg):
    global _error_count
    _error_count += 1
    print('%s:%d: %s' % (path, linenum, msg), file=sys.stderr)


class Tag(object):
    __slots__ = ('validator', 'min', 'max')
    def __init__(self, validator, min=0, max=1):
        self.validator = validator
        self.min = min
        self.max = max

def no_validation(*args):
    return True

# Set of licences which we allow in our source tree, in order to catch typos
# and to provide a flag to incur extra legal review if new licences are used
_known_licences = set((
    'GPL-2.0',
    'GPL-2.0-only',
    'GPL-2.0-or-later',
    '(LGPL-2.1 OR BSD-2-Clause)',
    'GPL-2.0 WITH Linux-syscall-note',
    'BSD-2-Clause',
    'BSD-3-Clause',
    'LGPL-2.1',
    'GPL-2.0 OR BSD-2-Clause',
))
def is_known_licence(value):
    return value in _known_licences

def is_url(value):
    try:
        urlparse.urlparse(value)
        return True
    except ValueError:
        return False


_known_tags = {
    'SPDX-License-Identifier': Tag(is_known_licence, min=1),
    'X-SPDX-Source-URL': Tag(is_url),
    'X-SPDX-Source-Tag': Tag(no_validation),
    'X-SPDX-Source-File': Tag(no_validation),
    'X-SPDX-Copyright-Text': Tag(no_validation),
    'X-SPDX-Comment': Tag(no_validation, max=1000000),
}

def check_tagset(path, tags):
    '''Validates a group of SPDX tags, which can either be the set at the
    top of a file or a snippet header group in the middle.'''
    counts = collections.defaultdict(int)
    for k,v in tags:
        kt = _known_tags.get(k)
        if kt is None:
            err(path, 0, '', "Unknown SPDX tag '%s'" % k)
            continue
        counts[k] += 1
        if not kt.validator(v):
            err(path, 0, '', "Malformed SPDX value %s: '%s'" % (k, v))
    for k,t in _known_tags.iteritems():
        if not (t.min <= counts[k] <= t.max):
            if not counts[k]:
                err(path, 0, '', "Missing required SPDX tag '%s'" % k)
            else:
                err(path, 0, '', "Too many occurrences of SPDX tag '%s' (%d)"
                                 % (k, counts[k]))


class Snippet(object):
    __slots__ = ('tags', 'start', 'end')
    def __init__(self):
        self.tags = []


# Our SPDX tags must strictly match this first regex
_strict_re = re.compile(r'^(?://|%|;|#|/\*|\.\.|\.\\") ' +
                        r'((?:X-)?SPDX-[a-zA-Z0-9-]+): (.*?)\s*$')
# ...however we also look for other things in order to try to detect possible
# typos and/or breaking of the rules, so as to avoid potential for something
# which looks to a human like it's legally binding but which our tools do not
# think is so
_loose_re = re.compile(r'^[./*# \t]*[X-]*S[PD]+X.*$', re.IGNORECASE)

# Normally the SPDX tags must be at the top of the file, however here are a
# few special-cases of things which are allowed to precede it. Currently
# shbang or emacs mode lines
_ignore_file_header = re.compile(r'(?:^#!)|(?:-\*-.*-\*-)')


def validate(path):
    '''Check that a single file is sanely SPDX-tagged. A group of tags is
    a contiguous set of lines like:
        X-SPDX-Something: value
    where 'value' may be split across multiple lines by prepending subsequent
    lines with at least 4 spaces (like HTTP/MIME headers).

    A file contains multiple groups of tags: the one at the top of the file
    defines the default for the whole file. Later groups define the properties
    of the snippet beginning at that group and ending at EOF, the next group,
    or the magic X-SPDX-Restore line (whichever comes first).'''
    f = open(path, 'rb')
    header = f.read(4096)
    f.seek(0)
    if header == '':
        return    # Empty files aren't copyrightable
    if is_binary_header(header):
        return

    file_tags = []
    snippets = []
    cur_snip = None

    in_header = True
    maybe_continuation = False
    linenum = 0
    for line in f:
        linenum += 1
        m = _strict_re.match(line)
        if m:
            maybe_continuation = False
            k,v = m.groups()
            if line.startswith('/*'):
                if v.endswith('*/'):
                    v = v[:-2].rstrip()
                else:
                    maybe_continuation = True
            if in_header:
                file_tags.append((k,v))
            else:
                if cur_snip:
                    if linenum == cur_snip.start:
                        cur_snip.start += 1
                    else:
                        cur_snip.end = linenum - 1
                        cur_snip = None
                if m.group(1) == 'X-SPDX-Restore':
                    maybe_continuation = False
                    if cur_snip:
                        cur_snip.end = linenum - 1
                        cur_snip = None
                    else:
                        err(path, linenum, line,
                            'Got X-SPDX-Restore when no snippet is active')
                else:
                    if cur_snip is None:
                        cur_snip = Snippet()
                        cur_snip.start = linenum + 1
                        snippets.append(cur_snip)
                    cur_snip.tags.append((k,v))
        else:  # this line is not an SPDX tag
            if maybe_continuation:
                # the previous line didn't clearly end, so look for more text
                # on the next line (preceeded by a sufficiently-large indent)
                v = line.rstrip().expandtabs()
                if v.endswith('*/'):
                    maybe_continuation = False
                    v = v[:-2].rstrip()
                v2 = v.lstrip('* #')
                if len(v) - len(v2) >= 4:
                    if cur_snip is None:
                        t = file_tags[-1]
                        file_tags[-1] = (t[0], t[1] + ' ' + v2)
                    else:
                        cur_snip.start += 1
                        t = cur_snip.tags[-1]
                        cur_snip.tags[-1] = (t[0], t[1] + ' ' + v2)
                    continue
            if linenum != 1 or not _ignore_file_header.search(line):
                in_header = False
            if _loose_re.match(line):
                err(path, linenum, line, 'Suspicious/malformed SPDX tag')

    if cur_snip:
        cur_snip.end = linenum

    if not file_tags and snippets:
        err(path, snippets[0].start, '',
            "File contains SPDX snippets but doesn't use SPDX header")

    check_tagset(path, file_tags)
    for s in snippets:
        check_tagset(path, s.tags)

    # This would be the point at which to add code to output a standard XML
    # SPDX file with the details which were found in this file


parser = argparse.ArgumentParser(
            description='Scan through a tree of files, ensuring that they ' +
                        'all have correctly-formed SPDX data')
parser.add_argument('--blacklist-file', action='append', default=[])
parser.add_argument('--blacklist', action='append', default=[])
parser.add_argument('root', default='.', nargs='?')
args = parser.parse_args()

blacklist = set(args.blacklist)
for bf in args.blacklist_file:
    blacklist.update(line.strip() for line in open(bf, 'rt')
                     if not line.strip().startswith('#'))
if blacklist:
    blacklist_re = re.compile('|'.join(fnmatch.translate(b)
                                       for b in blacklist))
else:
    # no blacklist: create a regex which cannot possibly match any filename
    blacklist_re = re.compile('/')

def in_blacklist(name):
    return blacklist_re.match(name) is not None

for dirpath, dirnames, filenames in os.walk(args.root):
    i = 0
    while i < len(dirnames):
        if in_blacklist(os.path.join(dirpath[len(args.root)+1:], dirnames[i])):
            del dirnames[i]
        else:
            i += 1
    for f in filenames:
        if not in_blacklist(os.path.join(dirpath[len(args.root)+1:], f)):
            validate(os.path.join(dirpath, f))

sys.exit(1 if _error_count else 0)
