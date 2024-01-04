import os
import ctypes
from enum import IntFlag

AT_FDCWD = -100  # special fd value meaning no FD


class ATFlags(IntFlag):
    # fcntl.h
    STATX_SYNC_AS_STAT = 0x0000
    SYMLINK_NOFOLLOW = 0x0100
    EMPTY_PATH = 0x1000
    VALID_FLAGS = 0x1100


class StatxAttr(IntFlag):
    # uapi/linux/stat.h
    COMPRESSED = 0x00000004
    IMMUTABLE = 0x00000010
    APPEND = 0x00000020
    NODUMP = 0x00000040
    ENCRYPTED = 0x00000800
    AUTOMOUNT = 0x00001000
    MOUNT_ROOT = 0x00002000
    VERIFY = 0x00100000
    DAX = 0x00200000


class Mask(ctypes.c_uint):
    TYPE = 0x00000001  # stx_mode & S_IFMT
    MODE = 0x00000002  # stx_mode & ~S_IFMT
    NLINK = 0x00000004  # stx_nlink
    UID = 0x00000008  # stx_uid
    GID = 0x00000010  # stx_gid
    ATIME = 0x00000020  # stx_atime
    MTIME = 0x00000040  # stx_mtime
    CTIME = 0x00000080  # stx_ctime
    INO = 0x00000100  # stx_ino
    SIZE = 0x00000200  # stx_size
    BLOCKS = 0x00000400  # stx_blocks
    BASIC_STATS = 0x000007FF  # info in normal stat struct

    # Extensions
    BTIME = 0x00000800  # stx_btime
    MNT_ID = 0x00001000  # stx_mnt_id
    ALL = 0x00000FFF  # All supported flags
    _RESERVED = 0x80000000  # Reserved for future struct statx expansion


class StructStatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_uint64),
        ("tv_nsec", ctypes.c_uint32),
        ("__reserved", ctypes.c_uint32),
    ]


class StructStatx(ctypes.Structure):
    _fields_ = [
        # 0x00
        ("stx_mask", Mask),
        ("stx_blksize", ctypes.c_uint32),
        ("stx_attributes", ctypes.c_uint64),

        # 0x10
        ("stx_nlink", ctypes.c_uint32),
        ("stx_uid", ctypes.c_uint32),
        ("stx_gid", ctypes.c_uint32),
        ("stx_mode", ctypes.c_uint16),
        ("__spare0", ctypes.c_uint16 * 1),

        # 0x20
        ("stx_ino", ctypes.c_uint64),
        ("stx_size", ctypes.c_uint64),
        ("stx_blocks", ctypes.c_uint64),
        ("stx_attributes_mask", ctypes.c_uint64),

        # 0x40
        ("stx_atime", StructStatxTimestamp),
        ("stx_btime", StructStatxTimestamp),
        ("stx_ctime", StructStatxTimestamp),
        ("stx_mtime", StructStatxTimestamp),

        # 0x80
        ("stx_rdev_major", ctypes.c_uint32),
        ("stx_rdev_minor", ctypes.c_uint32),
        ("stx_dev_major", ctypes.c_uint32),
        ("stx_dev_minor", ctypes.c_uint32),

        # 0x90
        ("stx_mnt_id", ctypes.c_uint64),
        ("__spare2", ctypes.c_uint64),

        # 0xa0 (Spare space)
        ("__spare3", ctypes.c_uint64 * 12),
    ]


def statx(path, options=None):
    opts = options or {}
    dirfd = opts.get('dir_fd', AT_FDCWD)
    flags = opts.get('flags', ATFlags.STATX_SYNC_AS_STAT)
    mask = Mask.BASIC_STATS | Mask.BTIME
    path = path.encode() if isinstance(path, str) else path

    invalid_flags = flags & ~ATFlags.VALID_FLAGS
    if invalid_flags:
        raise ValueError(f'{hex(invalid_flags)}: unsupported statx flags')

    _libc = ctypes.CDLL('libc.so.6', use_errno=True)
    _func = _libc.statx
    _func.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(StructStatx)
    )
    data = StructStatx()
    result = _func(dirfd, path, flags, mask, ctypes.byref(data))
    if result < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    else:
        return data
