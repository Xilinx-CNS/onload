#!/usr/bin/env python
# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Solarflare Communications Inc
######################################################################
# Report stats on dataset.
######################################################################

def data_generator(lines, delimiter=None, field_no=0, pass_comments=False,
                   comment_prefix='#'):
    for l in lines:
        if not delimiter:
            l = l.strip()
        if len(l) == 0:
            continue
        if l[0] == comment_prefix:
            if pass_comments:
                print l
            continue
        fields = l.split(delimiter)
        yield fields[field_no]


class B:
    pass


def get_stats_1pass(b, dataset, val_t):
    b.n = 0
    first = True
    sum = val_t(0)
    for v in dataset:
        v = val_t(v)
        if first:
            b.min = b.max = v
            first = False
        else:
            if v < b.min:
                b.min = v
            elif v > b.max:
                b.max = v
        b.n += 1
        sum += v
    if b.n:
        b.mean = sum / b.n
        b.sum = sum

get_stats_1pass_outputs = ['n', 'min', 'max', 'mean', 'sum']


def get_stats(b, dataset, val_t):
    dataset = [val_t(v) for v in dataset]
    dataset.sort()
    b.n = len(dataset)
    if b.n:
        b.min = dataset[0]
        b.max = dataset[-1]
        b.median = dataset[b.n / 2]
        b.p90 = dataset[b.n * 90 / 100]
        b.p95 = dataset[b.n * 95 / 100]
        b.p99 = dataset[b.n * 99 / 100]
        b.sum = sum(dataset)
        b.mean = b.sum / b.n
        var = val_t(0)
        for v in dataset:
            d = v - b.mean
            var += d * d
        if b.n == 1:
            b.variance = 1
        else:
            b.variance = var / (b.n - 1)
        import math
        b.stddev = val_t(math.sqrt(b.variance))

get_stats_outputs = ['n', 'min', 'max', 'mean', 'median', 'sum',
                     'variance', 'stddev', 'p90', 'p95', 'p99']


def get_mode(b, dataset, val_t):
    d = {}
    for v in dataset:
        v = val_t(v)
        if v not in d:
            d[v] = 0
        d[v] += 1
    tmp = d.items()
    if tmp:
        tmp.sort(cmp=lambda a, b: cmp(a[1], b[1]))
        b.mode = tmp[-1][0]
        b.mode_n = tmp[-1][1]


def main():
    import optparse
    op = optparse.OptionParser()
    op.set_usage('%prog [options] [subset-wanted]...')
    op.add_option("--int", action="store_true", dest='use_int',
                  default=False, help="Use integer arithmetic")
    op.add_option("--float", action="store_true", dest='use_float',
                  default=False, help="Use floating-point arithmetic")
    op.add_option("--big", action="store_true",
                  default=False, help="Dataset is big, do not store in memory")
    op.add_option("-f", "--field", action="store", type='int',
                  default=1, help="Select field (first field is 1)")
    op.add_option("-d", "--delimiter", action="store", type='string',
                  default=None, help="Set field delimiter")
    op.add_option("-c", action="store_false", dest='pass_comments',
                  default=True, help="Don't forward comments to output")
    opts, args = op.parse_args()

    assert opts.field >= 1

    import sys
    dataset = data_generator(sys.stdin, opts.delimiter, opts.field - 1,
                             pass_comments=opts.pass_comments)

    if opts.use_float:
        val_t = float
    elif opts.use_int:
        val_t = long
    elif opts.big:
        sys.stderr.write("ERROR: Must specify --int or --float with --big\n")
        sys.exit(1)
    else:
        # Work out whether we need floating pt or not.
        dataset = list(dataset)
        try:
            (d for d in dataset if '.' in d).next()
            val_t = float
        except StopIteration:
            val_t = long

    processors = []
    if not args:
        if opts.big:
            processors = [get_stats_1pass]
        else:
            processors = [get_stats, get_mode]
    will_store_dataset = False
    for a in args:
        if a in get_stats_1pass_outputs:
            p = get_stats_1pass
        elif a in get_stats_outputs:
            p = get_stats
            will_store_dataset = True
        elif a == 'mode':
            p = get_mode
            will_store_dataset = True
        else:
            sys.stderr.write("ERROR: Unknown field '%s'\n" % a)
            sys.exit(1)
        if p not in processors:
            processors.append(p)

    if get_stats_1pass in processors and get_stats in processors:
        processors.remove(get_stats_1pass)
    if opts.big and will_store_dataset:
        m =  "ERROR: Selected field(s) incompatible with --big because they\n"
        m += "       require more than one pass over the dataset.\n"
        sys.stderr.write(m)
        sys.exit(1)

    if len(processors) > 1:
        dataset = list(dataset)

    s = B()
    for p in processors:
        p(s, dataset, val_t)

    if args:
        keys = args
    else:
        keys = s.__dict__.keys()
        keys.sort()
    if not args:
        for k in keys:
            print k, getattr(s, k)
    else:
        for k in keys:
            print getattr(s, k),
        print


if __name__ == '__main__':
    main()
    import sys
    sys.exit(0)
