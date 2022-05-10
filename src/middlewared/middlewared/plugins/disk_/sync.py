import asyncio
import os
import time
from datetime import datetime, timedelta

from middlewared.schema import accepts, Str
from middlewared.service import job, private, Service, ServiceChangeMixin


class DiskService(Service, ServiceChangeMixin):

    DISK_EXPIRECACHE_DAYS = 7

    @private
    def disks_are_multipath(self, disk1, disk2, all_disks):
        disk1_path = os.path.join('/dev', disk1)
        disk2_path = os.path.join('/dev', disk2)
        result = False
        if disk1 != disk2 and os.path.exists(disk1_path) and os.path.exists(disk2_path):
            disk1_serial = all_disks.get(disk1, {}).get('serial', '')
            disk1_lunid = all_disks.get(disk1, {}).get('lunid', '')
            disk1_val = f'{disk1_serial}_{disk1_lunid}'

            disk2_serial = all_disks.get(disk2, {}).get('serial', '')
            disk2_lunid = all_disks.get(disk2, {}).get('lunid', '')
            disk2_val = f'{disk2_serial}_{disk2_lunid}'
            result = disk1_val == disk2_val

        return result

    @private
    @accepts(Str('name'))
    async def sync(self, name):
        """
        Syncs a disk `name` with the database cache.
        """
        if await self.middleware.call('failover.licensed'):
            if await self.middleware.call('failover.status') == 'BACKUP':
                return

        # Do not sync geom classes like multipath/hast/etc
        if name.find('/') != -1:
            return

        disks = await self.middleware.call('device.get_disks')
        if name not in disks:
            # return early if the disk is not recognized as an available disk
            return

        ident = await self.middleware.call('disk.device_to_identifier', name, disks)
        qs = await self.middleware.call(
            'datastore.query', 'storage.disk', [('disk_identifier', '=', ident)], {'order_by': ['disk_expiretime']}
        )
        if ident and qs:
            disk = qs[0]
            if await self.middleware.run_in_thread(self.disks_are_multipath, disk['disk_name'], name, disks):
                # this means we have 2 different disks with same serial and lunid and they both
                # exist which implies multipath. However, it doesn't mean it was meant to be a
                # multipath disk. It could be that an expansion shelf was plugged in, a zpool created
                # using disks from that enclosure AND THEN the same expansion shelf be plugged in
                # to cause it to be multipath. We do not want to overwrite the db information for
                # the disks because they have zpool mapping information. Furthermore, multipath_sync
                # won't do anything because the disks are "in use" and so multipath providers will
                # not be created. In this instance, we just return here so we don't blow-up the db.
                return
            new = False
        else:
            new = True
            qs = await self.middleware.call('datastore.query', 'storage.disk', [('disk_name', '=', name)])
            for i in qs:
                i['disk_expiretime'] = datetime.utcnow() + timedelta(days=self.DISK_EXPIRECACHE_DAYS)
                await self.middleware.call('datastore.update', 'storage.disk', i['disk_identifier'], i)
            disk = {'disk_identifier': ident}

        disk.update({'disk_name': name, 'disk_expiretime': None})

        await self.middleware.run_in_thread(self._map_device_disk_to_db, disk, disks[name])

        if not new:
            await self.middleware.call('datastore.update', 'storage.disk', disk['disk_identifier'], disk)
        else:
            disk['disk_identifier'] = await self.middleware.call('datastore.insert', 'storage.disk', disk)

        await self.restart_services_after_sync()

        await self.middleware.call('enclosure.sync_disk', disk['disk_identifier'])

    @private
    def wait_on_devd(self, seconds_to_wait=10):
        seconds_to_wait = 10 if (seconds_to_wait <= 0 or seconds_to_wait >= 300) else seconds_to_wait
        if not self.middleware.call_sync('device.devd_connected'):
            # wait on devd up to `seconds_to_wait` to become connected
            for i in range(seconds_to_wait):
                if i > 0:
                    time.sleep(1)

                if self.middleware.call_sync('device.devd_connected'):
                    break
            else:
                self.logger.warning('Starting disk.sync_all when devd is not connected yet')

    @private
    def log_disk_info(self, sys_disks):
        number_of_disks = len(sys_disks)
        if number_of_disks <= 25:
            # output logging information to middlewared.log in case we sync disks
            # when not all the disks have been resolved
            log_info = {
                ok: {
                    ik: iv for ik, iv in ov.items() if ik in ('name', 'ident', 'lunid', 'serial')
                } for ok, ov in sys_disks.items()
            }
            self.logger.info('Found disks: %r', log_info)
        else:
            self.logger.info('Found %d disks', number_of_disks)

    @private
    @accepts()
    @job(lock='disk.sync_all')
    def sync_all(self, job):
        """
        Synchronize all disks with the cache in database.
        """
        licensed = self.middleware.call_sync('failover.licensed')
        if licensed and self.middleware.call_sync('failover.status') == 'BACKUP':
            return

        job.set_progress(None, 'Waiting on devd connection')
        self.wait_on_devd()

        job.set_progress(None, 'Enumerating system disks')
        sys_disks = self.middleware.call_sync('device.get_disks')
        self.log_disk_info(sys_disks)

        job.set_progress(None, 'Enumerating geom disk XML information')
        geom_xml = self.middleware.call_sync('geom.cache.get_class_xml', 'DISK')

        seen_disks = {}
        serials = []
        changed = set()
        deleted = set()
        for disk in self.middleware.call_sync('datastore.query', 'storage.disk', [], {'order_by': ['disk_expiretime']}):
            original_disk = disk.copy()

            name = self.middleware.call_sync('disk.identifier_to_device', disk['disk_identifier'], False, geom_xml)
            if (
                    not name or
                    name in seen_disks or
                    self.middleware.call_sync('disk.device_to_identifier', name, sys_disks) != disk['disk_identifier']
            ):
                # If we cant translate the identifier to a device, give up
                # If name has already been seen once then we are probably
                # dealing with with multipath here
                if not disk['disk_expiretime']:
                    disk['disk_expiretime'] = datetime.utcnow() + timedelta(days=self.DISK_EXPIRECACHE_DAYS)
                    self.middleware.call_sync(
                        'datastore.update', 'storage.disk', disk['disk_identifier'], disk, {'send_events': False}
                    )
                    changed.add(disk['disk_identifier'])
                elif disk['disk_expiretime'] < datetime.utcnow():
                    # Disk expire time has surpassed, go ahead and remove it
                    for extent in self.middleware.call_sync(
                        'iscsi.extent.query', [['type', '=', 'DISK'], ['path', '=', disk['disk_identifier']]]
                    ):
                        self.middleware.call_sync('iscsi.extent.delete', extent['id'])
                    if disk['disk_kmip_uid']:
                        asyncio.ensure_future(self.middleware.call(
                            'kmip.reset_sed_disk_password', disk['disk_identifier'], disk['disk_kmip_uid']
                        ))
                    self.middleware.call_sync(
                        'datastore.delete', 'storage.disk', disk['disk_identifier'], {'send_events': False}
                    )
                    deleted.add(disk['disk_identifier'])
                continue
            else:
                disk['disk_expiretime'] = None
                disk['disk_name'] = name

            if name in sys_disks:
                self._map_device_disk_to_db(disk, sys_disks[name])

            serial = (disk['disk_serial'] or '') + (sys_disks.get(name, {}).get('lunid') or '')
            if serial:
                serials.append(serial)

            # If for some reason disk is not identified as a system disk
            # mark it to expire.
            if name not in sys_disks and not disk['disk_expiretime']:
                disk['disk_expiretime'] = datetime.utcnow() + timedelta(days=self.DISK_EXPIRECACHE_DAYS)
            # Do not issue unnecessary updates, they are slow on HA systems and cause severe boot delays
            # when lots of drives are present
            if self._disk_changed(disk, original_disk):
                self.middleware.call_sync(
                    'datastore.update', 'storage.disk', disk['disk_identifier'], disk, {'send_events': False}
                )
                changed.add(disk['disk_identifier'])

            seen_disks[name] = disk

        qs = None
        for name in sys_disks:
            if name not in seen_disks:
                disk_identifier = self.middleware.call_sync('disk.device_to_identifier', name, sys_disks)
                if qs is None:
                    qs = self.middleware.call_sync('datastore.query', 'storage.disk')

                if disk := [i for i in qs if i['disk_identifier'] == disk_identifier]:
                    new = False
                    disk = disk[0]
                else:
                    new = True
                    disk = {'disk_identifier': disk_identifier}
                original_disk = disk.copy()
                disk['disk_name'] = name
                self._map_device_disk_to_db(disk, sys_disks[name])
                serial = disk['disk_serial'] + (sys_disks[name]['lunid'] or '')
                if serial:
                    if serial in serials:
                        # Probably dealing with multipath here, do not add another
                        continue
                    else:
                        serials.append(serial)

                if not new:
                    # Do not issue unnecessary updates, they are slow on HA systems and cause severe boot delays
                    # when lots of drives are present
                    if self._disk_changed(disk, original_disk):
                        self.middleware.call_sync(
                            'datastore.update', 'storage.disk', disk['disk_identifier'], disk, {'send_events': False}
                        )
                        changed.add(disk['disk_identifier'])
                else:
                    self.middleware.call_sync('datastore.insert', 'storage.disk', disk, {'send_events': False})
                    changed.add(disk['disk_identifier'])

        # make sure the database entries for enclosure slot information for each disk
        # matches with what is reported by the OS
        self.middleware.call_sync('enclosure.sync_disks')

        if changed or deleted:
            self.middleware.call_sync('disk.restart_services_after_sync')
            disks = {i['identifier']: i for i in self.middleware.call_sync('disk.query', [], {'prefix': 'disk_'})}
            for change in changed:
                self.middleware.send_event('disk.query', 'CHANGED', id=change, fields=disks[change])
            for delete in deleted:
                self.middleware.send_event('disk.query', 'CHANGED', id=delete, cleared=True)

        return 'OK'

    def _disk_changed(self, disk, original_disk):
        # storage_disk.disk_size is a string
        return dict(disk, disk_size=None if disk.get('disk_size') is None else str(disk['disk_size'])) != original_disk

    def _map_device_disk_to_db(self, db_disk, disk):
        only_update_if_true = ('size',)
        update_keys = ('serial', 'lunid', 'rotationrate', 'type', 'size', 'subsystem', 'number', 'model', 'bus')
        for key in filter(lambda k: k in update_keys and (k not in only_update_if_true or disk[k]), disk):
            db_disk[f'disk_{key}'] = disk[key]

    @private
    async def restart_services_after_sync(self):
        await self.middleware.call('disk.update_hddstandby_force')
        await self.middleware.call('disk.update_smartctl_args_for_disks')
        if await self.middleware.call('service.started', 'collectd'):
            await self.middleware.call('service.restart', 'collectd')
        await self._service_change('smartd', 'restart')
        await self._service_change('snmp', 'restart')

    expired_disks = set()

    @private
    async def init_datastore_events_processor(self):
        self.expired_disks = {
            disk["identifier"]
            for disk in await self.middleware.call(
                "datastore.query",
                "storage.disk",
                [("expiretime", "!=", None)],
                {"prefix": "disk_"},
            )
        }

    @private
    async def process_datastore_event(self, type, kwargs):
        if type == "CHANGED" and "fields" in kwargs:
            if kwargs["fields"]["expiretime"] is not None:
                if kwargs["fields"]["identifier"] not in self.expired_disks:
                    self.expired_disks.add(kwargs["fields"]["identifier"])
                    return "CHANGED", {"id": kwargs["id"], "cleared": True}

                return None
            else:
                if kwargs["fields"]["identifier"] in self.expired_disks:
                    self.expired_disks.remove(kwargs["fields"]["identifier"])
                    return "ADDED", {"id": kwargs["id"], "fields": kwargs["fields"]}

        return type, kwargs


async def setup(middleware):
    await middleware.call("disk.init_datastore_events_processor")

    await middleware.call("datastore.register_event", {
        "description": "Sent on disk changes.",
        "datastore": "storage.disk",
        "plugin": "disk",
        "prefix": "disk_",
        "extra": {"include_expired": True},
        "id": "identifier",
        "process_event": "disk.process_datastore_event",
    })
