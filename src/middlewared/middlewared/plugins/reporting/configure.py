import os
import shutil
import subprocess
import tarfile
import time

from middlewared.service import private, Service


def get_members(tar, prefix):
    for tarinfo in tar.getmembers():
        if tarinfo.name.startswith(prefix):
            tarinfo.name = tarinfo.name[len(prefix):]
            yield tarinfo


class ReportingService(Service):

    @private
    def setup(self):
        systemdatasetconfig = self.middleware.call_sync('systemdataset.config')
        if not systemdatasetconfig['path']:
            self.middleware.logger.error('System dataset is not mounted')
            return False

        rrd_mount = f'{systemdatasetconfig["path"]}/rrd-{systemdatasetconfig["uuid"]}'
        if not os.path.exists(rrd_mount):
            self.middleware.logger.error(f'{rrd_mount} does not exist or is not a directory')
            return False

        # Ensure that collectd working path is a symlink to system dataset
        base_collectd = '/var/db/collectd'
        pwd = os.path.join(base_collectd, 'rrd')
        if os.path.islink(pwd):
            if os.path.realpath(pwd) != rrd_mount:
                os.unlink(pwd)
        else:
            if os.path.exists(pwd):
                shutil.move(pwd, f'{pwd}.{time.strftime("%Y%m%d%H%M%S")}')
        if not os.path.exists(pwd):
            os.makedirs(base_collectd, exist_ok=True)
            os.symlink(rrd_mount, pwd)

        # Migrate legacy RAMDisk
        persist_file = '/data/rrd_dir.tar.bz2'
        if os.path.isfile(persist_file):
            with tarfile.open(persist_file) as tar:
                if 'collectd/rrd' in tar.getnames():
                    tar.extractall(pwd, get_members(tar, 'collectd/rrd/'))

            os.unlink('/data/rrd_dir.tar.bz2')

        network_config = self.middleware.call_sync('network.configuration.config')
        hostname = f"{network_config['hostname_local']}.{network_config['domain']}"

        # Migrate from old version, where `hostname` was a real directory and `localhost` was a symlink.
        # Skip the case where `hostname` is "localhost", so symlink was not (and is not) needed.
        if (
            hostname != 'localhost' and
            os.path.isdir(os.path.join(pwd, hostname)) and
            not os.path.islink(os.path.join(pwd, hostname))
        ):
            if os.path.exists(os.path.join(pwd, 'localhost')):
                if os.path.islink(os.path.join(pwd, 'localhost')):
                    os.unlink(os.path.join(pwd, 'localhost'))
                else:
                    # This should not happen, but just in case
                    shutil.move(
                        os.path.join(pwd, 'localhost'),
                        os.path.join(pwd, f'localhost.bak.{time.strftime("%Y%m%d%H%M%S")}')
                    )
            shutil.move(os.path.join(pwd, hostname), os.path.join(pwd, 'localhost'))

        for item in os.listdir(pwd):
            if item == 'localhost' or item.startswith('localhost.bak.'):
                continue

            path = os.path.join(pwd, item)

            if os.path.islink(path):
                # Remove all symlinks (that are stale if hostname was changed)
                os.unlink(path)
            elif os.path.isdir(path):
                # Remove all directories except "localhost" and its backups (that may be erroneously created by
                # running collectd before this script)
                subprocess.run(['rm', '-rfx', path])
            else:
                os.unlink(path)

        # Create "localhost" directory if it does not exist
        if not os.path.exists(os.path.join(pwd, 'localhost')):
            os.makedirs(os.path.join(pwd, 'localhost'))

        # Create "${hostname}" -> "localhost" symlink if necessary
        if hostname != 'localhost':
            os.symlink(os.path.join(pwd, 'localhost'), os.path.join(pwd, hostname))

        # Let's return a positive value to indicate that necessary collectd operations were performed successfully
        return True
