import logging
import os
import base64
import subprocess
import stat

from contextlib import suppress

logger = logging.getLogger(__name__)
kdir = "/etc/kerberos"
keytabfile = "/etc/krb5.keytab"


def mit_copy(temp_keytab):
    kt_copy = subprocess.run(
        ['ktutil'],
        input=f'rkt {temp_keytab}\nwkt /etc/mit_tmp.keytab'.encode(),
        capture_output=True
    )
    if kt_copy.stderr:
        logger.debug("%s: failed to generate keytab: %s",
                     keytabfile, kt_copy.stderr.decode())


def write_keytab(db_keytabname, db_keytabfile):
    dirfd = None

    def opener(path, flags):
        return os.open(path, flags, mode=0o600, dir_fd=dirfd)

    with suppress(FileExistsError):
        os.mkdir(kdir, mode=0o700)

    try:
        dirfd = os.open(kdir, os.O_DIRECTORY)
        st = os.fstat(dirfd)
        if stat.S_IMODE(st.st_mode) != 0o700:
            os.fchmod(dirfd, 0o700)

        with open(db_keytabname, "wb", opener=opener) as f:
            f.write(db_keytabfile)
            kt_name = os.readlink(f'/proc/self/fd/{f.fileno()}')

        mit_copy(kt_name)
        os.remove(db_keytabname, dir_fd=dirfd)

    finally:
        os.close(dirfd)


def render(service, middleware):
    keytabs = middleware.call_sync('kerberos.keytab.query')
    if not keytabs:
        logger.trace('No keytabs in configuration database, skipping keytab generation')
        return

    for keytab in keytabs:
        db_keytabfile = base64.b64decode(keytab['file'].encode())
        db_keytabname = f'keytab_{keytab["id"]}'
        write_keytab(db_keytabname, db_keytabfile)

    with suppress(FileNotFoundError):
        os.unlink(keytabfile)

    os.rename("/etc/mit_tmp.keytab", keytabfile)
