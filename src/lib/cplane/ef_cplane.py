import ctypes, os.path, socket, typing, os
from sys import base_prefix

_libcp = None

class CplaneException(OSError):
    def __init__(self, rc):
        self.errno = rc
        self.strerror = os.strerror(rc)

def _check_rc(rc):
    if rc < 0:
        raise CplaneException(-rc)
    return rc

class _StructWithTools(ctypes.Structure):
    def __repr__(self):
        return f'ef_cplane.{self.__class__.__name__}({", ".join(f"{k}={getattr(self,k)!r}" for k,v in self._fields_)})'

INTF_F_UP = 0x01
INTF_F_ALIEN = 0x02

ENCAP_F_VLAN = 0x0001
ENCAP_F_BOND = 0x0002
ENCAP_F_BOND_PORT = 0x0004
ENCAP_F_LOOP = 0x0040
ENCAP_F_MACVLAN = 0x0080
ENCAP_F_VETH = 0x0100
ENCAP_F_IPVLAN = 0x0400

class Intf(_StructWithTools):
    _fields_ = [
        ('ifindex', ctypes.c_int),
        ('encap', ctypes.c_uint32),
        ('encap_data', ctypes.c_uint32 * 4),
        ('flags', ctypes.c_uint64),
        ('_registered_cookie', ctypes.c_void_p),
        ('mtu', ctypes.c_int),
        ('_mac', ctypes.c_byte * 6),
        ('name', ctypes.c_char * 17),
    ]
    def _realize(self):
        self.mac = bytes(self._mac)
        if self._registered_cookie:
            self.registered_cookie = ctypes.cast(self._registered_cookie, ctypes.py_object).value
        else:
            self.registered_cookie = None
    def __repr__(self):
        return f'ef_cplane.Intf(ifindex={self.ifindex}, owner_ifindex={self.owner_ifindex}, flags={self.flags}, registered_cookie={self.registered_cookie}, mtu={self.mtu}, encap={self.encap}, mac={self.mac} name={self.name})'

class IntfVerInfo(_StructWithTools):
    _fields_ = [
        ('generation', ctypes.c_uint),
        ('version', ctypes.c_uint),
    ]
    def __init__(self):
        self.generation = 0
        self.version = 0

class IpAddr(ctypes.Structure):
    _fields_ = [
        ('addr', ctypes.c_uint32 * 4)
    ]
    def is_v4(self) -> bool:
        if self.addr[0] or self.addr[1]:
            return False
        if self.addr[2] == socket.htonl(0xffff):
            return True
        if self.addr[2] == 0 and self.addr[3] == 0:
            return True
        return False
    def __str__(self):
        if self.is_v4():
            return socket.inet_ntop(socket.AF_INET, bytes(self.addr)[-4:])
        return socket.inet_ntop(socket.AF_INET6, bytes(self.addr))
    def __repr__(self):
        return repr(str(self))

class IntfAddr(_StructWithTools):
    _fields_ = [
        ('ifindex', ctypes.c_int),
        ('scope', ctypes.c_int),
        ('flags', ctypes.c_uint64),
        ('prefix_len', ctypes.c_int),
        ('ip', IpAddr),
        ('bcast', IpAddr),
    ]

class FwdMeta(_StructWithTools):
    _fields_ = [
        ('ifindex', ctypes.c_int),
        ('iif_ifindex', ctypes.c_int),
        ('intf_cookie', ctypes.c_void_p),
        ('mtu', ctypes.c_int),
    ]

class RouteVerInfo(_StructWithTools):
    _fields_ = [
        ('row', ctypes.c_uint),
        ('version', ctypes.c_uint),
        ('generation', ctypes.c_uint),
    ]
    def __init__(self):
        self.row = 0
        self.version = 0
        self.generation = 0

def _load_libefcp():
    global _libcp
    if _libcp is not None:
        return _libcp
    soname = 'libefcp.so.1'
    try:
        _libcp = ctypes.CDLL(soname)
    except OSError:
        here = os.path.dirname(__file__)
        try:
            _libcp = ctypes.CDLL(os.path.join(here, soname))
        except OSError:
            _libcp = ctypes.CDLL(os.path.join(here, '../../../build/gnu_x86_64/lib/cplane', soname))
    _libcp.ef_cp_init.argtypes = (ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint)
    _libcp.ef_cp_init.restype = ctypes.c_int
    _libcp.ef_cp_fini.argtypes = (ctypes.c_void_p,)
    _libcp.ef_cp_fini.restype = None
    _libcp.ef_cp_get_all_intfs.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_size_t, ctypes.c_uint)
    _libcp.ef_cp_get_all_intfs.restype = ctypes.c_int
    _libcp.ef_cp_get_lower_intfs.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_size_t, ctypes.c_uint)
    _libcp.ef_cp_get_lower_intfs.restype = ctypes.c_int
    _libcp.ef_cp_get_upper_intfs.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_size_t, ctypes.c_uint)
    _libcp.ef_cp_get_upper_intfs.restype = ctypes.c_int
    _libcp.ef_cp_get_intf.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(Intf), ctypes.c_uint)
    _libcp.ef_cp_get_intf.restype = ctypes.c_int
    _libcp.ef_cp_intf_version_get.argtypes = (ctypes.c_void_p,)
    _libcp.ef_cp_intf_version_get.restype = IntfVerInfo
    _libcp.ef_cp_intf_version_verify.argtypes = (ctypes.c_void_p, ctypes.POINTER(IntfVerInfo))
    _libcp.ef_cp_intf_version_verify.restype = ctypes.c_bool
    _libcp.ef_cp_get_intf_by_name.argtypes = (ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(Intf), ctypes.c_uint)
    _libcp.ef_cp_get_intf_by_name.restype = ctypes.c_int
    _libcp.ef_cp_get_intf_addrs.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(IntfAddr), ctypes.c_size_t, ctypes.c_uint)
    _libcp.ef_cp_get_intf_addrs.restype = ctypes.c_int
    _libcp.ef_cp_register_intf.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.py_object, ctypes.c_uint)
    _libcp.ef_cp_register_intf.restype = ctypes.c_int
    _libcp.ef_cp_unregister_intf.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_uint)
    _libcp.ef_cp_unregister_intf.restype = ctypes.c_int
    _libcp.ef_cp_resolve.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(FwdMeta), ctypes.POINTER(RouteVerInfo), ctypes.c_uint64)
    _libcp.ef_cp_resolve.restype = ctypes.c_int64
    _libcp.ef_cp_route_verify.argtypes = (ctypes.c_void_p, ctypes.POINTER(RouteVerInfo))
    _libcp.ef_cp_route_verify.restype = ctypes.c_bool
    return _libcp

GET_INTFS_F_NATIVE = 0x0001
GET_INTFS_F_GENERIC = 0x0002
GET_INTFS_F_OTHER = 0x0004
GET_INTFS_F_UP = 0x0100
GET_INTFS_F_MOST_DERIVED = 0x10000

RESOLVE_F_BIND_SRC = 0x0001
RESOLVE_F_TRANSPARENT = 0x0002
RESOLVE_F_UNREGISTERED = 0x0004
RESOLVE_F_NO_CTXT_SW = 0x0008
RESOLVE_F_NO_ARP = 0x0010

RESOLVE_S_LOOPBACK = 0x0001
RESOLVE_S_UNREGISTERED = 0x0002
RESOLVE_S_ARP_INVALID = 0x0004

class ResolveResult(object):
    __slots__ = ('flags', 'ifindex', 'intf_cookie', 'mtu', 'pkt')
    def __repr__(self):
        return f'ef_cplane.ResolveResult({", ".join(f"{k}={getattr(self,k)!r}" for k in self.__slots__)})'


class Cplane(object):
    def __init__(self, flags=0):
        self._cp = ctypes.c_void_p()
        self._registered_cookies = {}
        _load_libefcp()
        _check_rc(_libcp.ef_cp_init(ctypes.byref(self._cp), flags))

    def __del__(self):
        if self._cp:
            _libcp.ef_cp_fini(self._cp)

    def _intfs_getter(self, op):
        n = 32
        while True:
            intfs = (ctypes.c_int * n)()
            rc = op(intfs, n)
            if rc <= n:
                break
            n = rc
        if rc < 0:
            raise CplaneException(-rc)
        return intfs[:rc]

    def get_all_intfs(self, flags=GET_INTFS_F_NATIVE) -> typing.List[int]:
        return self._intfs_getter(lambda i,n: _libcp.ef_cp_get_all_intfs(self._cp, i, n, flags))

    def get_lower_intfs(self, child_ifindex : int, flags=GET_INTFS_F_NATIVE) -> typing.List[int]:
        return self._intfs_getter(lambda i,n: _libcp.ef_cp_get_lower_intfs(self._cp, child_ifindex, i, n, flags))

    def get_upper_intfs(self, parent_ifindex : int, flags=GET_INTFS_F_NATIVE) -> typing.List[int]:
        return self._intfs_getter(lambda i,n: _libcp.ef_cp_get_upper_intfs(self._cp, parent_ifindex, i, n, flags))

    def get_intf(self, intf : typing.Union[int,str], flags=0) -> Intf:
        result = Intf()
        if isinstance(intf, int):
            _check_rc(_libcp.ef_cp_get_intf(self._cp, intf, ctypes.byref(result), flags))
        elif isinstance(intf, (str,bytes)):
            if isinstance(intf, str):
                intf = intf.encode()
            _check_rc(_libcp.ef_cp_get_intf_by_name(self._cp, intf, ctypes.byref(result), flags))
        else:
            raise TypeError('get_intf() requires an int or str')
        result._realize()
        return result

    def intf_version_get(self) ->IntfVerInfo:
        return _libcp.ef_cp_intf_version_get(self._cp)

    def intf_version_verify(self, ver : IntfVerInfo) ->bool:
        return _libcp.ef_cp_intf_version_verify(self._cp, ctypes.byref(ver))

    def get_intf_addrs(self, ifindex : int, flags=0) -> typing.List[IntfAddr]:
        n = 16
        while True:
            addrs = (IntfAddr * n)()
            rc = _libcp.ef_cp_get_intf_addrs(self._cp, ifindex, addrs, n, flags)
            if rc <= n:
                break
            n = rc
        if rc < 0:
            raise CplaneException(-rc)
        return addrs[:rc]

    def register_intf(self, ifindex : int, cookie, flags=0) ->None:
        _check_rc(_libcp.ef_cp_register_intf(self._cp, ifindex, ctypes.py_object(cookie), flags))
        self._registered_cookies[ifindex] = cookie

    def unregister_intf(self, ifindex : int, flags=0) ->None:
        _check_rc(_libcp.ef_cp_unregister_intf(self._cp, ifindex, flags))
        self._registered_cookies.pop(ifindex)

    def resolve(self, pkt : bytes, ifindex=-1, iif_ifindex=-1, ver : RouteVerInfo =None, flags=0) ->ResolveResult:
        meta = FwdMeta(ifindex=ifindex, iif_ifindex=iif_ifindex)
        if ver is None:
            ver = RouteVerInfo()
        base_prefix_space = 128
        prefix_space = ctypes.c_size_t(base_prefix_space)
        buf = ctypes.create_string_buffer(b'\0' * base_prefix_space + pkt)
        rc = _check_rc(_libcp.ef_cp_resolve(self._cp,
                            ctypes.addressof(buf) + base_prefix_space,
                            ctypes.byref(prefix_space), ctypes.byref(meta),
                            ctypes.byref(ver), flags))
        result = ResolveResult()
        result.flags = rc
        result.ifindex = meta.ifindex
        if meta.intf_cookie:
            result.intf_cookie = ctypes.cast(meta.intf_cookie, ctypes.py_object).value
        else:
            result.intf_cookie = None
        result.mtu = meta.mtu
        result.pkt = buf[base_prefix_space - prefix_space.value:]
        return result

    def route_verify(self, ver : RouteVerInfo) ->bool:
        return _libcp.ef_cp_route_verify(self._cp, ctypes.byref(ver))
