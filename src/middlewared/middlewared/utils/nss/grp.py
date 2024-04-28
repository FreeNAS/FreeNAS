import ctypes

from collections import namedtuple
from .nss_common import get_nss_func, NssError, NssModule, NssOperation, NssReturnCode

GROUP_BUFLEN = 8096


class Group(ctypes.Structure):
    _fields_ = [
        ("gr_name", ctypes.c_char_p),
        ("gr_passwd", ctypes.c_char_p),
        ("gr_gid", ctypes.c_int),
        ("gr_mem", ctypes.POINTER(ctypes.c_char_p))
    ]


group_struct = namedtuple('group_struct', ['gr_name', 'gr_gid', 'gr_mem', 'source'])


def __parse_nss_result(result, as_dict, module_name):
    name = result.gr_name.decode()
    members = list()

    i = 0
    while result.gr_mem[i]:
        members.append(result.gr_mem[i].decode())
        i += 1

    if as_dict:
        return {
            'gr_name': name,
            'gr_gid': result.gr_gid,
            'gr_mem': members,
            'source': module_name
        }

    return group_struct(name, result.gr_gid, members, module_name)


def __getgrnam_r(name, result_p, buffer_p, buflen, nss_module):
    """ctypes wrapper for _nss_##module##_getgrnam_r"""
    func = get_nss_func(NssOperation.GETGRNAM, nss_module)
    func.restype = ctypes.c_int
    func.argtypes = [
        ctypes.c_char_p,
        ctypes.POINTER(Group),
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_int)
    ]

    err = ctypes.c_int()
    name = name.encode('utf-8')
    res = func(ctypes.c_char_p(name), result_p, buffer_p, buflen, ctypes.byref(err))

    return (int(res), err.value, result_p)


def __getgrgid_r(gid, result_p, buffer_p, buflen, nss_module):
    """ctypes wrapper for _nss_##module##_getgrgid_r"""
    func = get_nss_func(NssOperation.GETGRGID, nss_module)
    func.restype = ctypes.c_int
    func.argtypes = [
        ctypes.c_ulong,
        ctypes.POINTER(Group),
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_int)
    ]
    err = ctypes.c_int()
    res = func(gid, result_p, buffer_p, buflen, ctypes.byref(err))

    return (int(res), err.value, result_p)


def __getgrent_r(result_p, buffer_p, buflen, nss_module):
    """ctypes wrapper for _nss_##module##_getgrent_r"""
    func = get_nss_func(NssOperation.GETGRENT, nss_module)
    func.restype = ctypes.c_int
    func.argtypes = [
        ctypes.POINTER(Group),
        ctypes.c_char_p,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_int)
    ]

    err = ctypes.c_int()
    res = func(result_p, buffer_p, buflen, ctypes.byref(err))

    return (int(res), err.value, result_p)


def __setgrent(nss_module):
    """
    ctypes wrapper for _nss_##module##_setgrent

    NOTE: this calls thread-safe per-module variant of setgrent
    """
    func = get_nss_func(NssOperation.SETGRENT, nss_module)
    func.argtypes = []

    res = func()

    if res != NssReturnCode.SUCCESS:
        raise NssError(ctypes.get_errno(), NssOperation.SETGRENT, res, nss_module)


def __endgrent(nss_module):
    """
    ctypes wrapper for _nss_##module##_setgrent

    NOTE: this calls thread-safe per-module variant of endgrent
    """
    func = get_nss_func(NssOperation.ENDGRENT, nss_module)
    func.argtypes = []

    res = func()

    if res != NssReturnCode.SUCCESS:
        raise NssError(ctypes.get_errno(), NssOperation.ENDGRENT, res, nss_module)


def __getgrent_impl(mod, as_dict):
    result = Group()
    buf = ctypes.create_string_buffer(GROUP_BUFLEN)

    res, errno, result_p = __getgrent_r(ctypes.byref(result), buf,
                                        GROUP_BUFLEN, mod)
    if errno != 0:
        raise NssError(errno, NssOperation.GETGRENT, res, mod)

    if res != NssReturnCode.SUCCESS:
        return None

    return  __parse_nss_result(result, as_dict, mod.name)


def __getgrall_impl(module, as_dict):
    mod = NssModule[module]
    __setgrent(mod)
    group_list = []

    group = __getgrent_impl(mod, as_dict)
    while group is not None:
        if (group := __getgrent_impl(mod, as_dict)):
            group_list.append(group)

    __endgrent(mod)
    return group_list


def __getgrnam_impl(name, module, as_dict):
    mod = NssModule[module]
    result = Group()
    buf = ctypes.create_string_buffer(GROUP_BUFLEN)

    res, errno, result_p = __getgrnam_r(name, ctypes.byref(result),
                                        buf, GROUP_BUFLEN, mod)
    if errno != 0:
        raise NssError(errno, NssOperation.GETGRNAM, res, mod)

    if res == NssReturnCode.NOTFOUND:
        return None

    return  __parse_nss_result(result, as_dict, mod.name)


def __getgrgid_impl(gid, module, as_dict):
    mod = NssModule[module]
    result = Group()
    buf = ctypes.create_string_buffer(GROUP_BUFLEN)

    res, errno, result_p = __getgrgid_r(gid, ctypes.byref(result),
                                        buf, GROUP_BUFLEN, mod)
    if errno != 0:
        raise NssError(errno, NssOperation.GETGRGID, res, mod)

    if res == NssReturnCode.NOTFOUND:
        return None

    return  __parse_nss_result(result, as_dict, mod.name)


def getgrgid(gid, module=NssModule.ALL.name, as_dict=False):
    if module != NssModule.ALL.name:
        if (result := __getgrgid_impl(gid, module, as_dict)):
            return result

        raise KeyError(f"getgrgid(): gid not found: '{gid}'")

    # We're querying all modules
    for mod in NssModule:
        if mod == NssModule.ALL:
            continue

        try:
            if (result := __getgrgid_impl(gid, mod.name, as_dict)):
                return result
        except NssError as e:
            if e.return_code != NssReturnCode.UNAVAIL:
                raise e from None

    raise KeyError(f"getgrgid(): gid not found: '{gid}'")


def getgrnam(name, module=NssModule.ALL.name, as_dict=False):
    if module != NssModule.ALL.name:
        if (result := __getgrnam_impl(name, module, as_dict)):
            return result

        raise KeyError(f"getgrnam(): name not found: '{name}'")

    # We're querying all modules
    for mod in NssModule:
        if mod == NssModule.ALL:
            continue

        try:
            if (result := __getgrnam_impl(name, mod.name, as_dict)):
                return result
        except NssError as e:
            if e.return_code != NssReturnCode.UNAVAIL:
                raise e from None

    raise KeyError(f"getgrnam(): name not found: '{name}'")


def getgrall(module=NssModule.ALL.name, as_dict=False):
    if module != NssModule.ALL.name:
        return {module: __getgrall_impl(module, as_dict)}

    results = {}
    for mod in NssModule:
        if mod == NssModule.ALL:
            continue

        try:
            if (entries := __getgrall_impl(mod.name, as_dict)):
                results[mod.name] = entries
        except NssError as e:
            if e.return_code != NssReturnCode.UNAVAIL:
                raise e from None

    return results
