# SPDX-License-Identifier: BSD-2-Clause
# X-SPDX-Copyright-Text: (c) Copyright 2017-2020 Xilinx, Inc.

from ctypes import *
import sys, os, errno, tempfile, time, signal, shutil
from threading import Lock

MY_DIR = os.path.abspath(os.path.dirname(__file__))


# FIXME make sure the definitions below are in sync with mib.h
# FIXME add mechanism to verify their correctness automatically

CI_CFG_IPV6 = True

'''
/* Keys for forward cache table. */
struct cp_fwd_key {
    ci_addr_sh_t  src;
    ci_addr_sh_t  dst;
    ci_ifid_t     ifindex;
    cicp_ip_tos_t tos;

    ci_ifid_t     iif_ifindex;

    ci_uint8      flag;
    #define CP_FWD_KEY_REQ_REFRESH  0x80
    #define CP_FWD_KEY_REQ_WAIT     0x40
    #define CP_FWD_KEY_TRANSPARENT  0x20
    #define CP_FWD_KEY_SOURCELESS   0x08
};
'''
class CI_IFID:
    BAD  = 0
    LOOP = 1

class CICP_ROUTE_TYPE:
    NORMAL = 0
    LOCAL = 1
    ALIEN = 2

class CICP_LLAP_TYPE:
    NONE              = 0x0
    VLAN              = 0x1
    BOND              = 0x2
    SLAVE             = 0x4
    XMIT_HASH_LAYER2  = 0x8
    XMIT_HASH_LAYER34 = 0x10
    XMIT_HASH_LAYER23 = 0x20
    LOOP              = 0x40
    MACVLAN           = 0x80
    VETH              = 0x100
    ROUTE_ACROSS_NS   = 0x200
    IPVLAN            = 0x400

class CP_FWD_KEY:
    NONE        = 0
    REQ_REFRESH = 0x80
    REQ_WAIT    = 0x40
    TRANSPARENT = 0x20
    SOURCELESS  = 0x08

ipaddr_t = c_uint * 4 if CI_CFG_IPV6 else c_uint

class cp_fwd_key(Structure):
    _fields_ = [("src", ipaddr_t), ("dst", ipaddr_t),
                ("ifindex", c_short), ("tos", c_ubyte),
                ("iif_ifindex", c_short),
                ('flag', c_ubyte) # CP_FWD_KEY
               ]

'''
typedef struct
{
    cicp_mac_rowid_t id;
    cp_version_t     version;
} cicp_verinfo_t;
'''

class cicp_verinfo(Structure):
    _fields_ = [("id", c_uint), ("dst", c_uint)]


'''
/* Basic routing data, obtained from the routing table */
struct cp_fwd_data_base {
    ci_addr_sh_t      src;
    ci_addr_sh_t      next_hop;
    ci_mtu_t          mtu;
    ci_ifid_t         ifindex;
    /* Stores RTAX_HOPLIMIT attribute value. It would contain IPv4 TTL or
    * IPv6 Hop Limit after parsing NETLINK route message. */
    ci_uint8          hop_limit;
};

/* Routing info in the forward cache table. */
struct cp_fwd_data {
    struct cp_fwd_data_base base;

    ci_uint8          flags;
    ci_mac_addr_t     src_mac;
    cicp_hwport_mask_t hwports;
    ci_mac_addr_t     dst_mac;
    cicp_encap_t      encap;

    struct cp_fwd_multipath_weight weight;
};

typedef struct {
    cicp_llap_type_t type;
    ci_uint16 vlan_id;
    ci_ifid_t link_ifindex;     /*< ifindex for VLAN master, veth-peer, etc. */
} cicp_encap_t;

struct cp_fwd_multipath_weight {
    ci_uint32 end;  /* End of weight range serviced by this entry */
    ci_uint16 val;  /* Weight of this path: range 1:0x100 */
    ci_uint16 flag;
    /* This entry has the maximum end value among the paths for this route */
    #define CP_FWD_MULTIPATH_FLAG_LAST 1
};
'''

class cp_fwd_multipath_weight(Structure):
    _fields_ = [('end', c_uint),
        ('val', c_ushort),
        ('flag', c_ushort)]

class cicp_encap_t(Structure):
    _fields_ = [('type', c_uint),
        ('vlan_id', c_ushort),
        ('link_ifindex', c_short)]

class cp_fwd_data_base(Structure):
    _fields_ = [
        ("src", ipaddr_t), ("next_hop", ipaddr_t),
        ("mtu", c_ushort), ("ifindex", c_short),
        ("hop_limit", c_ubyte)]

class cp_fwd_data(Structure):
    _fields_ = [
        ("base", cp_fwd_data_base),
        ('flags', c_ubyte),  ('src_mac', c_ubyte * 6),
        ('hwports', c_uint), ('dst_mac', c_ubyte * 6),
        ('encap', cicp_encap_t),
        ('weight', cp_fwd_multipath_weight)
      ]


# helper function to convert a nested Structure object to dict
def getdict(struct):
    result = {}
    for field, _ in struct._fields_:
         value = getattr(struct, field)

         primitive_types = {int, float, bool}
         # Python 2 backwards compatibility
         if sys.version_info < (3,0):
             primitive_types.add(long)
         # if the type is not a primitive and it evaluates to False ...
         if (type(value) not in primitive_types) and not bool(value):
             # it's a null pointer
             value = None
         elif hasattr(value, "_length_") and hasattr(value, "_type_"):
             # Probably an array
             value = list(value)
         elif hasattr(value, "_fields_"):
             # Probably another struct
             value = getdict(value)
         result[field] = value
    return result


def cp_intf_ver():
    header_path = os.path.join(MY_DIR, '../../../cp_intf_ver.h')
    if not os.path.isfile(header_path):
        raise Exception("Version header '%s' does not exist" % (header_path,))

    prefix = '#define OO_CP_INTF_VER'
    with open(header_path) as f:
        for line in f:
            if line.startswith(prefix):
                return line[len(prefix):].strip()
    raise Exception("'%s' does not define OO_CP_INTF_VER" % (header_path,))


class CPlane(object):
    # pull the shared lib from the same directory the module resides in
    cp = CDLL(os.path.join(MY_DIR, 'shim_cplane_lib.so'))
    fd = c_int()
    handle = None

    def __init__(self):
        rc = self.cp.oo_fd_open(byref(self.fd))
        if rc == 0:
            # FIXME guessing 4kB is enough for cplane_handle state
            self.handle = (c_ubyte * 4096)()
            # The symbol for oo_cp_create in the library is suffixed with
            # the cplane interface version to ensure that client and server
            # are talking the same language. A header file specifying the
            # interface version is generated as part of the build.
            symbol = 'oo_cp_create_%s' % (cp_intf_ver(),)
            oo_cp_create = getattr(self.cp, symbol)
            rc = oo_cp_create(self.fd, byref(self.handle), 0, 0)
        if rc != 0:
            raise Exception("Opening cplane failed with error %d"%rc)

        # make sure types are verified on function call
        self.cp.py_oo_cp_route_resolve.argtypes = [
            type(self.handle), POINTER(cicp_verinfo),
            POINTER(cp_fwd_key), c_int]

    def routeResolve(self, af, verinfo, key, ask_server=True):
        #Fixme: af is not used
        data = cp_fwd_data()
        rc = self.cp.py_oo_cp_route_resolve(
            self.handle,
            byref(verinfo),
            byref(key),
            ask_server,
            byref(data))
        if rc == -errno.ENOENT:
            return None
        if rc != 0:
            raise Exception("Failed to resolve route, error %d"%rc)
        return data

    def newHwport(self, ifindex, hwport):
        rc = self.cp.py_oo_cp_set_hwport(self.handle, ifindex, hwport)
        if rc < 0:
            raise Exception("Setting new hwport failed %d"%rc)

    def getHwportIfindex(self, hwport):
        ''' Find out the "best" interface index by hwport ID.  The resultant
            index might not be the one announced with the above newHwport()
            due to the network namespaces whose boundaries we won't cross.

            Return CI_IFID_BAD on failure.
        '''
        return self.cp.py_oo_cp_get_hwport_ifindex(self.handle, hwport)


''' The class manages CPServer process life within its own private
    anonymous network namespace and the state backed with temporary file.
    Allows instantiating cplane clients referring to the namespace.
'''

class CPServer(object):
    # pull the server_executable from the same directory the module resides in
    server_executable = os.path.join(MY_DIR, 'shim_cp_server')
    shim_file = None

    CP_SHIM_FILE_lock = Lock()

    # Create new instance of cp_server.
    # The instance will be monitoring a new anonymous namespace or the namespace
    # indicated by netns_pid.  The monitoring will take place as in production
    # using actual OS netlink messages.
    # By default an entirely new cp_state state will be created in a mapped
    # temporary shim file. The cp_server instance will be convinced it runs in
    # the main netspace and is the main instance.
    # However, if main_shim_file is specified cp_server will run as a non-main
    # becoming a client of the instance indicated with main_ns_file.
    def __init__(self, name='cp_server_', netns_pid=None, main_shim_file=None,
                 extra_opts=''):
        f = tempfile.NamedTemporaryFile(prefix=name)
        data = (c_ubyte * 1024)()
        for i in range(4096 * 8):
          f.write(data)
        f.flush()
        cp_shim_file = f.name

        server_pid = os.fork()
        if server_pid == 0:
            # launch server
            executable = self.server_executable
            if netns_pid:
                executable='nsenter -t %d --mount --net %s'%(netns_pid, executable)
            opts = extra_opts
            if main_shim_file:
                # Note: confusing implementation detail
                # in this case CP_SHIM_FILE needs to be set to the shim file of main ns
                # and the actual shim file is with network-namespace-file option
                #
                # Workaround:
                #   On some systems sysfs still points to old netns incorrectly, (RHEL7 3.10.0-862.el7.x86_64).
                #   the workaround is to mount proper sysfs and rebind at the old location.
                #   This is for testing only e.g. for sysfs based bond set-up.
                #
                # Note: exec is used to retain PID.
                opts += ' --network-namespace-file %s'%cp_shim_file
                cp_shim_file = main_shim_file
            os.execlp('/bin/bash', '/bin/bash', '-c',
                      '''CP_SHIM_FILE=%s exec unshare --net --mount bash -x -c '
                           MNT=`mktemp -d` && mount -t sysfs none $MNT &&
                           mount --bind $MNT/ /sys/ &&
                           exec %s %s
                        '
                      '''%(cp_shim_file,executable,opts))

        # remember pid of the server to use it later to switch namespaces
        self.pid = server_pid
        self.shim_file = f

        timeout = 5
        if not self.waitForPipePath(timeout=timeout):
            raise Exception("The pipe {0} wasn't created within {1} seconds"\
                            .format(self.getPipePath(), timeout))

    def getCmdPrefix(self):
        return 'nsenter -t %d --net --mount --'%self.pid

    def getNetNsPath(self):
        return '/proc/%d/ns/net'%self.pid

    def getPipePath(self):
        return '/tmp/onload_cp_server.%d'%self.pid

    def waitForPipePath(self, timeout=5):
        time_to_finish = time.time() + timeout
        while time.time() < time_to_finish:
            if os.path.exists(self.getPipePath()):
                return True
            time.sleep(0.5)
        return os.path.exists(self.getPipePath())

    def getClient(self):
        self.CP_SHIM_FILE_lock.acquire()
        try:
            # FIXME: do not select cplane file with environment variable
            os.environ['CP_SHIM_FILE'] = self.shim_file.name
            os.putenv('CP_SHIM_FILE', self.shim_file.name)
            cplane = CPlane()
        finally:
            self.CP_SHIM_FILE_lock.release()
        return cplane

    def cleanup(self):
        os.kill(self.pid, signal.SIGTERM)
        os.unlink(self.getPipePath())
        self.shim_file.close()

    def mibdump(self, args=""):
        os.system("CP_SHIM_FILE=%s nsenter -t %d --net %s %s"%(
                  self.shim_file.name,
                  self.pid,
                  os.path.join(MY_DIR, 'shim_mibdump'),
                  args))
