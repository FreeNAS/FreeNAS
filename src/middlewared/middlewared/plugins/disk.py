from collections import defaultdict
import os
import re
import sys
import sysctl

from bsd import geom
from middlewared.service import filterable, private, CRUDService
from middlewared.utils import run

# FIXME: temporary import of SmartAlert until alert is implemented
# in middlewared
if '/usr/local/www' not in sys.path:
    sys.path.insert(0, '/usr/local/www')
from freenasUI.services.utils import SmartAlert

MIRROR_MAX = 5
RE_ISDISK = re.compile(r'^(da|ada|vtbd|mfid|nvd)[0-9]+$')


class DiskService(CRUDService):

    @filterable
    def query(self, filters=None, options=None):
        if filters is None:
            filters = []
        if options is None:
            options = {}
        options['prefix'] = 'disk_'
        filters.append(('enabled', '=', True))
        options['extend'] = 'disk.disk_extend'
        return self.middleware.call('datastore.query', 'storage.disk', filters, options)

    @private
    def disk_extend(self, disk):
        disk.pop('enabled', None)
        return disk

    @private
    def swaps_configure(self):
        """
        Configures swap partitions in the system.
        We try to mirror all available swap partitions to avoid a system
        crash in case one of them dies.
        """
        self.middleware.threaded(geom.scan)

        used_partitions = set()
        mirrors = []
        klass = geom.class_by_name('MIRROR')
        if klass:
            for g in klass.geoms:
                # Skip gmirror that is not swap*
                if not g.name.startswith('swap') or g.name.endswith('.sync'):
                    continue
                mirrors.append(f'mirror/{g.name}')
                for c in g.consumers:
                    # Add all partitions used in swap, removing .eli
                    used_partitions.add(c.provider.name.strip('.eli'))

        klass = geom.class_by_name('PART')
        if not klass:
            return

        # Get all partitions of swap type, indexed by size
        swap_partitions_by_size = defaultdict(list)
        for g in klass.geoms:
            for p in g.providers:
                if p.name in used_partitions:
                    continue
                # if swap partition
                if p.config['rawtype'] == '516e7cb5-6ecf-11d6-8ff8-00022d09712b':
                    swap_partitions_by_size[p.mediasize].append(p.name)

        for size, partitions in swap_partitions_by_size.items():
            for i in range(int(len(partitions) / 2)):
                part_a = partitions[i * 2]
                part_b = partitions[i * 2 + 1]
                try:
                    name = new_swap_name()
                    run('gmirror', 'create', '-b', 'prefer', name, part_a, part_b)
                except Exception:
                    self.logger.warn(f'Failed to create gmirror {name}', exc_info=True)
                    continue
                mirrors.append(f'mirror/{name}')

        for mirror in mirrors:
            if not os.path.exists(f'/dev/{mirror}.eli'):
                run('geli', 'onetime', mirror)
            run('swapon', f'/dev/{mirror}.eli', check=False)

        return mirrors

    @private
    def swaps_remove_disk(self, disk):
        """
        Remove a given disk (e.g. da0) from swap.
        it will offline if from swap, remove it from the gmirror (if exists)
        and detach the geli.
        """
        self.middleware.threaded(geom.scan)
        partgeom = geom.geom_by_name('PART', disk)
        if not partgeom:
            return
        provider = None
        for p in partgeom.providers:
            if p.config['rawtype'] == '516e7cb5-6ecf-11d6-8ff8-00022d09712b':
                provider = p
                break
        if not provider:
            return

        klass = geom.class_by_name('MIRROR')
        if not klass:
            return

        mirror = None
        for g in klass.geoms:
            for c in g.consumers:
                if c.provider.id == provider.id:
                    mirror = g
                    break
        if not mirror:
            return

        run('swapoff', f'/dev/mirror/{mirror.name}.eli')
        if os.path.exists(f'/dev/mirror/{mirror.name}.eli'):
            run('geli', 'detach', f'{mirror.name}.eli')
        run('gmirror', 'destroy', mirror.name)


def new_swap_name():
    """
    Get a new name for a swap mirror

    Returns:
        str: name of the swap mirror
    """
    for i in range(MIRROR_MAX):
        name = f'swap{i}'
        if not os.path.exists(f'/dev/mirror/{name}'):
            return name
    raise RuntimeError('All mirror names are taken')


def _event_devfs(middleware, event_type, args):
    data = args['data']
    if data.get('subsystem') != 'CDEV':
        return

    if data['type'] == 'CREATE':
        disks = middleware.threaded(lambda: sysctl.filter('kern.disks')[0].value.split())
        # Device notified about is not a disk
        if data['cdev'] not in disks:
            return
        # TODO: hack so every disk is not synced independently during boot
        # This is a performance issue
        if os.path.exists('/tmp/.sync_disk_done'):
            middleware.call('notifier.sync_disk', data['cdev'])
            try:
                with SmartAlert() as sa:
                    sa.device_delete(data['cdev'])
            except Exception:
                pass
    elif data['type'] == 'DESTROY':
        # Device notified about is not a disk
        if not RE_ISDISK.match(data['cdev']):
            return
        # TODO: hack so every disk is not synced independently during boot
        # This is a performance issue
        if os.path.exists('/tmp/.sync_disk_done'):
            middleware.call('notifier.sync_disks')
            middleware.call('notifier.multipath_sync')
            try:
                with SmartAlert() as sa:
                    sa.device_delete(data['cdev'])
            except Exception:
                pass


def setup(middleware):
    # Listen to DEVFS events so we can sync on disk attach/detach
    middleware.event_subscribe('devd.devfs', _event_devfs)
