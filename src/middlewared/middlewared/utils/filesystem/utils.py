# This file provides various utilities that don't fit cleanly
# into specific categories of filesystem areas.
#
# timespec_convert_float() has test coverage via stat_x util tests
# timespec_convert_int() has test coverage via copytree util tests
# path_in_ctldir() has test coverage via api tests for filesystem.stat
# and filesystem.listdir methods since it requires access to zpool.

from .constants import ZFSCTL
from pathlib import Path


def path_in_ctldir(path_in):
    """
    Determine whether the given path is located within the ZFS
    ctldir. The intention for this is to determine whether a given
    path is inside a ZFS snapshot so that we can raise meaningful
    validation errors in situations like the user trying to set
    permissions on a file in a snapshot directory.
    """
    path = Path(path_in)
    if not path.is_absolute():
        raise ValueError(f'{path_in}: not an absolute path')

    is_in_ctldir = False
    while path.as_posix() != '/':
        if not path.name == '.zfs':
            path = path.parent
            continue

        if path.stat().st_ino == ZFSCTL.INO_ROOT:
            is_in_ctldir = True
            break

        path = path.parent

    return is_in_ctldir


def timespec_convert_float(timespec):
    """
    Convert a timespec struct into float. This is for use where
    ctype function returns timespec (for example statx())
    """
    return timespec.tv_sec + timespec.tv_nsec / 1000000000


def timespec_convert_int(timespec):
    """
    Convert a timespec struct into int. This is suitable for
    when a timespec needs to be passed to os.utime()
    """
    return timespec.tv_sec * 1000000000 + timespec.tv_nsec
