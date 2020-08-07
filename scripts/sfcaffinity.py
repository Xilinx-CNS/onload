# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2010-2019 Xilinx, Inc.

# Library of routines related to cpu affinity for processes and interrupts.

import os, re
import sfcmask as mask


class NoCores(Exception):
    pass


class BadCoreId(Exception):
    def __init__(self, core_id):
        self.core_id = core_id

######################################################################

# Last external command invoked via system(), popen() etc.
last_sys_cmd = None


# User can replace this to redefine logging behaviour.
def log_system(cmd):
    pass


def do_system(cmd):
    log_system(cmd)
    global last_sys_cmd
    last_sys_cmd = cmd
    return os.system(cmd)


# User can replace this to redefine logging behaviour.
def log_popen(cmd):
    pass


def do_popen(command):
    global last_sys_cmd
    last_sys_cmd = command
    return os.popen(command)

######################################################################

def file_get(fname):
    return open(fname).read()


def file_get_strip(fname):
    return open(fname).read().strip()


def file_get_int(fname):
    f = open(fname)
    return int(f.read())

######################################################################

def task_set_affinity(pid, cpumask):
    csl = mask.to_comma_sep_list(cpumask)
    cmd = "taskset -c -p %s %d >/dev/null" % (csl, int(pid))
    if do_system(cmd) != 0:
        raise something#??


def process_set_affinity(pid, cpumask):
    # todo: set affinity of all tasks in the process
    assert 0


def process_get_pid(procname):
    cmd = "pgrep -x '%s'" % (procname)
    f = do_popen(cmd)
    return int(f.read())


def try_get_pid(procname):
    try:
        cmd = "pgrep '%s'" % (procname)
        f = do_popen(cmd)
        return int(f.read())
    except:
        return -1

######################################################################

irq_vec2names = None
irq_name2vec = None


def __irq_make_maps():
    global irq_vec2names, irq_name2vec
    lines = open('/proc/interrupts').readlines()
    lines = [l.split() for l in lines]
    # Only want interrupts that have a vector number.
    lines = [l for l in lines if re.match('^[0-9]+:$', l[0])]
    irq_vec2names = dict()
    irq_name2vec = dict()
    for l in lines:
        # Filter out interrupt counts -- they are the pure integer fields.
        l = [f for f in l if not re.match('^[0-9]+$', f)]
        vec = int(l[0][0:-1])  # chop off ':' suffix
        names = [re.sub(',', '', n) for n in l[2:]]
        irq_vec2names[vec] = names
        irq_name2vec.update([(n, vec) for n in names])


def irq_get_name2vec_map():
    if not irq_name2vec:
        __irq_make_maps()
    return irq_name2vec


def irq_get_vec2names_map():
    if not irq_vec2names:
        __irq_make_maps()
    return irq_vec2names

######################################################################

def cmp_irq_name(a, b):
    try:
        a_pre, a_suf = a.rsplit('-', 1)
        b_pre, b_suf = b.rsplit('-', 1)
        c = a_pre < b_pre
        if c:
            return c
        return int(a_suf) < int(b_suf)
    except:
        return a < b


# Python 3 compat.  They really shouldn't have killed cmp.
def sort_irq_names(irq_names):
    import sys
    if sys.version_info >= (3,0):
        import functools
        irq_names.sort(key=functools.cmp_to_key(cmp_irq_name))
    else:
        irq_names.sort(cmp=cmp_irq_name)


def irq_names_matching_pattern(pattern):
    """Return list of interrupt names that match the given pattern.  The
    list is sorted nicely."""
    n2v = irq_get_name2vec_map()
    irq_names = [n for n in n2v.keys() if re.match(pattern, n)]
    sort_irq_names(irq_names)
    return irq_names


def irq_get_name(irq):
    """Returns the name associated with the given irq.  Caveat: If multiple
    sources share the interrupt, this returns only one of them."""
    cmd = "grep '^ *%d:' /proc/interrupts" % (int(irq))
    s = os.popen(cmd).read().split()
    if s:
        return s[-1]
    else:
        return None


def irq_get_pid(irq):
    """Returns the pid of the kernel thread handling the given IRQ.
    Returns -1 if no such thread is found."""
    # The name of the thread used to handle an interrupt has changed over
    # time...
    pid = try_get_pid('^IRQ-%d$' % int(irq))
    if pid > 0:
        return pid
    pid = try_get_pid('^\[IRQ-%d\]$' % int(irq))
    if pid > 0:
        return pid
    pid = try_get_pid('^irq/%d-' % int(irq))
    if pid > 0:
        return pid
    return -1


def irq_set_affinity(irq, cpumask):
    cshm = mask.to_comma_sep_hex(cpumask)
    cmd = "echo %s >/proc/irq/%d/smp_affinity" % (cshm, int(irq))
    if do_system(cmd) != 0:
        raise something#??
    irq_pid = irq_get_pid(irq)
    if irq_pid > 0:
        task_set_affinity(irq_pid, cpumask)

######################################################################

sys_cpus = "/sys/devices/system/cpu"
sys_package_f = sys_cpus + "/cpu%d/topology/physical_package_id"
sys_thread_sibs_f = sys_cpus + "/cpu%d/topology/thread_siblings"
sys_core_sibs_f = sys_cpus + "/cpu%d/topology/core_siblings"
sys_cache_cpu_map_f = sys_cpus + "/cpu%d/cache/index%d/shared_cpu_map"
sys_cache_level_f = sys_cpus + "/cpu%d/cache/index%d/level"

"""Map from core ID to package ID."""
core_id_to_package_id = {}
"""Map from core ID to thread siblings."""
core_id_to_thread_siblings = {}
"""Map from core ID to core siblings."""
core_id_to_core_siblings = {}
"""Set of tuples (level, cpumask)."""
shared_caches = None


class Package(object):
    def __init__(self, id):
        self.id = id
        self.core_ids = []
        self.cores_mask = 0
    def add_core(self, core_id):
        self.core_ids.append(core_id)
        self.cores_mask |= 1 << core_id
    def __str__(self):
        return "pkg(%d)" % (self.id)
    def __repr__(self):
        return str(self)


class Core(object):
    def __init__(self, topology, id, pkg, thread_sibs, core_sibs):
        # thread_sibs and core_sibs include this core
        assert (thread_sibs & (1 << id)) != 0
        assert (core_sibs & (1 << id)) != 0
        self.topology = topology
        self.id = id
        self.pkg = pkg
        self.thread_siblings_mask = mask.to_int(thread_sibs)
        self.thread_siblings_list = mask.to_int_list(thread_sibs)
        thread_sibs &= ~(1 << id)
        self.thread_siblings_ex_mask = mask.to_int(thread_sibs)
        self.thread_siblings_ex_list = mask.to_int_list(thread_sibs)
        self.core_siblings_mask = mask.to_int(core_sibs)
        self.core_siblings_list = mask.to_int_list(core_sibs)
        core_sibs &= ~(1 << id)
        self.core_siblings_ex_mask = mask.to_int(core_sibs)
        self.core_siblings_ex_list = mask.to_int_list(core_sibs)
        self.real_core = self.thread_siblings_list[0]
        self.shared_caches = {}
    def __str__(self):
        return "core(id=%d, pkg=%d)" % (self.id, self.pkg.id)
    def __repr__(self):
        return str(self)


class Cache(object):
    def __init__(self, level, cpumask):
        self.level = level
        self.core_ids = mask.to_int_list(cpumask)
        self.cores_mask = mask.to_int(cpumask)
    def __str__(self):
        return "cache(level=%d, cores=%s)" % (self.level, self.core_ids)
    def __repr__(self):
        return str(self)


class Topology(object):
    def get_cores(self):
        return list(self.id2core.values())
    def get_packages(self):
        return list(self.id2package.values())
    def get_cache_levels(self):
        if self.shared_caches:
            return list(self.shared_caches.keys())
        else:
            return []
    def get_top_level_shared_caches(self):
        if not self.shared_caches:
            return []
        return self.shared_caches[min(self.get_cache_levels())]


def __get_core_info():
    if core_id_to_package_id:
        return
    core_id = 0
    while True:
        try:
            pkg_i = file_get_int(sys_package_f % core_id)
        except:
            break
        core_id_to_package_id[core_id] = pkg_i
        core_id_to_thread_siblings[core_id] = \
          mask.comma_sep_hex_to_int(file_get_strip(sys_thread_sibs_f %
                                                   core_id))
        core_id_to_core_siblings[core_id] = \
          mask.comma_sep_hex_to_int(file_get_strip(sys_core_sibs_f % core_id))
        core_id += 1


def __get_cache_info():
    global shared_caches, core_id_to_package_id
    if shared_caches:
        return
    if not core_id_to_package_id:
        __get_core_info()
    shared_caches = set()
    for core_id in core_id_to_package_id.keys():
        for index in range(0, 100):
            try:
                cpumask = file_get_strip(sys_cache_cpu_map_f % (core_id,index))
            except:
                break
            cpumask = mask.comma_sep_hex_to_int(cpumask)
            cpulist = mask.to_int_list(cpumask)
            if len(cpulist) > 1:
                level = file_get_int(sys_cache_level_f % (core_id, index))
                cpumask = mask.to_int(cpumask)
                c = (level, cpumask)
                shared_caches.add(c)


def __build_topology(all_cores):
    if all_cores is None:
        all_cores = (1 << len(core_id_to_package_id)) - 1
    if type(all_cores) is list:
        if len(all_cores) > 0 and type(all_cores[0]) is Core:
            all_cores = [c.id for c in all_cores]
    if not all_cores:
        raise NoCores
    cores_mask = mask.to_int(all_cores)
    if not cores_mask:
        raise NoCores
    cores_list = mask.to_int_list(cores_mask)

    top = Topology()
    top.cores_mask = cores_mask
    top.id2core = {}
    top.id2package = {}

    for core_id in cores_list:
        try:
            pkg_i = core_id_to_package_id[core_id]
        except:
            raise BadCoreId(core_id)
        if pkg_i not in top.id2package:
            top.id2package[pkg_i] = Package(pkg_i)
        pkg = top.id2package[pkg_i]
        pkg.add_core(core_id)
        ts = core_id_to_thread_siblings[core_id] & cores_mask
        cs = core_id_to_core_siblings[core_id] & cores_mask
        top.id2core[core_id] = Core(top, core_id, pkg, ts, cs)

    top.core_ids = list(top.id2core.keys())
    top.core_ids.sort()
    top.cores_mask = mask.to_int(top.core_ids)
    top.package_ids = list(top.id2package.keys())
    top.package_ids.sort()
    top.real_cores = dict([(c.id, c) for c in top.id2core.values()
                           if c.id == c.real_core])
    top.real_core_ids = list(top.real_cores.keys())
    top.real_core_ids.sort()
    top.real_cores_mask = mask.to_int(top.real_core_ids)

    caches = [Cache(c[0], c[1] & cores_mask) for c in shared_caches
              if len(mask.to_int_list(c[1] & cores_mask)) > 1]
    top.shared_caches = {}
    for cache in caches:
        if cache.level not in top.shared_caches:
            top.shared_caches[cache.level] = []
        top.shared_caches[cache.level].append(cache)
        for core_id in cache.core_ids:
            core = top.id2core[core_id]
            core.shared_caches[cache.level] = cache

    return top


def get_topology(cores=None):
    __get_core_info()
    __get_cache_info()
    return __build_topology(cores)


def get_top_level_cache_siblings(topology, core):
    """Return the ids of the cores that share a cache with the given core.
    [core] may be a core-id of an instance of class Core."""
    if isinstance(core, Core):
        core_id = core.id
    else:
        core_id = core
    tl_caches = topology.get_top_level_shared_caches()
    if not tl_caches:
        return []
    my_caches = [c for c in tl_caches if core_id in c.core_ids]
    assert len(my_caches) == 1
    sib_ids = list(my_caches[0].core_ids)
    sib_ids.remove(core_id)
    return sib_ids


def get_close_cores(topology, core):
    """Return a list of lists containing all cores except [core].  Each
    sublist includes cores at a certain level of "closeness" to [core],
    with the closest cores first.  [core] may be a core-id or an instance
    of class Core"""

    if isinstance(core, Core):
        core_id = core.id
    else:
        core_id = core
        core = topology.id2core[core_id]

    unused_cores = set(range(len(core.topology.core_ids)))
    unused_cores.discard(core.id)
    cc = []
    def addcores1(unused_cores, core_ids):
        core_ids = unused_cores & set(core_ids)
        if core_ids:
            unused_cores -= core_ids
            cc.append(list(core_ids))
    addcores = lambda x: addcores1(unused_cores, x)
    addcores(core.thread_siblings_list)
    addcores(get_top_level_cache_siblings(core.topology, core))
    addcores(core.core_siblings_list)
    addcores(unused_cores)
    return cc

######################################################################
sys_ethname_local_cpus_f = "/sys/class/net/%s/device/local_cpus"

def get_local_cores(ethname):
    """Return a list of cores which are NUMA-local to the specified NIC"""
    try:
        cpumask = file_get_strip(sys_ethname_local_cpus_f % ethname)
    except:
        cpumask = '0' # in case kernel doesn't support local_cpus return no cores
    cpumask = mask.comma_sep_hex_to_int(cpumask)
    cpulist = mask.to_int_list(cpumask)
    return cpulist

######################################################################

def outl(x):
    import sys
    sys.stdout.write("%s\n" % x)


def dump_topology(top):
    outl("                 id2core: %s" % top.id2core)
    outl("                core_ids: %s" % top.core_ids)
    outl("              real_cores: %s" % top.real_cores)
    outl("           real_core_ids: %s" % top.real_core_ids)
    outl("                packages: %s" % top.id2package)
    outl("             package_ids: %s" % top.package_ids)
    outl("           shared_caches: %s" % top.shared_caches)

    for core in top.get_cores():
        outl("%s" % core)
        outl("               real_core: %s" % core.real_core)
        outl("    thread_siblings_list: %s" % core.thread_siblings_list)
        outl(" thread_siblings_ex_list: %s" % core.thread_siblings_ex_list)
        outl("      core_siblings_list: %s" % core.core_siblings_list)
        outl("   core_siblings_ex_list: %s" % core.core_siblings_ex_list)
        outl("           shared_caches: %s" % core.shared_caches)

    for pkg_i in top.package_ids:
        pkg = top.id2package[pkg_i]
        outl("%s" % pkg)
        outl("           cores: %s" % pkg.core_ids)


def dump_irqs():
    outl("irq_get_name2vec_map():")
    for irq_name, vector in irq_get_name2vec_map().items():
        outl("%20s: %d" % (irq_name, vector))
    outl("irq_get_vec2names_map():")
    v2n = irq_get_vec2names_map()
    vectors = list(v2n.keys())
    vectors.sort()
    for v in vectors:
        outl("%20d: %s" % (v, v2n[v]))


def dump_all(top):
    outl('=' * 78)
    dump_topology(top)
    outl('=' * 78)
    dump_irqs()
    outl('=' * 78)
    if 0:
        outl('=' * 78)
        dump_topology(get_topology(0x3))
        outl('=' * 78)
        dump_topology(get_topology(0x5))


if __name__ == '__main__':
    import sys
    top = get_topology()
    if len(sys.argv) == 1 or sys.argv[1] == 'dump':
        dump_all(top)
    elif sys.argv[1] == 'close_cores':
        outl(get_close_cores(top, int(sys.argv[2])))
