from middlewared.schema import accepts, Str
from middlewared.service import filterable, private, Service
from middlewared.utils import filter_list
from middlewared.utils.disks import valid_zfs_partition_uuids


class DiskService(Service):

    @private
    @filterable
    async def list_all_partitions(self, filters, options):
        """
        Returns list of all partitions present in the system
        """
        disks = await self.middleware.call('device.get_disks')
        parts = []
        for disk in disks:
            parts.extend(await self.middleware.call('disk.list_partitions', disk))
        return filter_list(parts, filters, options)

    @private
    @accepts(Str('disk'))
    async def get_partition(self, disk):
        # Will retrieve zfs partition on disk if any
        return await self.get_partition_with_uuids(disk, [await self.middleware.call('disk.get_zfs_part_type')])

    @private
    async def get_partition_with_uuids(self, disk, uuids):
        part = next(
            (p for p in await self.middleware.call('disk.list_partitions', disk) if p['partition_type'] in uuids),
            None
        )
        return part

    @private
    async def get_partition_uuid_from_name(self, part_type_name):
        mapping = {
            'freebsd-zfs': '516e7cba-6ecf-11d6-8ff8-00022d09712b',
            'freebsd-swap': '516e7cb5-6ecf-11d6-8ff8-00022d09712b',
            'freebsd-boot': '83bd6b9d-7f41-11dc-be0b-001560b84f0f',
        }
        return mapping.get(part_type_name)

    @private
    async def get_valid_zfs_partition_type_uuids(self):
        return list(valid_zfs_partition_uuids())
