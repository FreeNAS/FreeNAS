from asyncio import ensure_future

from middlewared.schema import accepts, Dict, Int, Str
from middlewared.service import CallError, job, Service, ValidationErrors


class PoolService(Service):

    @accepts(
        Int('oid'),
        Dict(
            'pool_attach',
            Str('target_vdev', required=True),
            Str('new_disk', required=True),
            Str('passphrase'),
        )
    )
    @job(lock=lambda args: f'pool_attach_{args[0]}')
    async def attach(self, job, oid, options):
        """
        For TrueNAS Core/Enterprise platform, if the `oid` pool is passphrase GELI encrypted, `passphrase`
        must be specified for this operation to succeed.

        `target_vdev` is the GUID of the vdev where the disk needs to be attached. In case of STRIPED vdev, this
        is the STRIPED disk GUID which will be converted to mirror. If `target_vdev` is mirror, it will be converted
        into a n-way mirror.
        """
        pool = await self.get_instance(oid)

        verrors = ValidationErrors()
        if not pool['is_decrypted']:
            verrors.add('oid', 'Pool must be unlocked for this action.')
            verrors.check()

        topology = pool['topology']
        topology_type = vdev = None
        for i in topology:
            for v in topology[i]:
                if v['guid'] == options['target_vdev']:
                    topology_type = i
                    vdev = v
                    break
            if topology_type:
                break
        else:
            verrors.add('pool_attach.target_vdev', 'Unable to locate VDEV')
            verrors.check()

        if topology_type in ('cache', 'spares'):
            verrors.add('pool_attach.target_vdev', f'Attaching disks to {topology_type} not allowed.')
        elif topology_type == 'data':
            # We would like to make sure here that we don't have inconsistent vdev types across data
            if vdev['type'] not in ('DISK', 'MIRROR'):
                verrors.add('pool_attach.target_vdev', f'Attaching disk to {vdev["type"]} vdev is not allowed.')

        if pool['encrypt'] == 2:
            if not options.get('passphrase'):
                verrors.add('pool_attach.passphrase', 'Passphrase is required for encrypted pool.')
            elif not await self.middleware.call('disk.geli_testkey', pool, options['passphrase']):
                verrors.add('pool_attach.passphrase', 'Passphrase is not valid.')

        # Let's validate new disk now
        await self.middleware.call('disk.check_disks_availability', verrors, [options['new_disk']], 'pool_attach')
        verrors.check()

        disks = {options['new_disk']: {'create_swap': topology_type == 'data'}}
        await self.middleware.call(
            'pool.format_and_encrypt_disks', job, disks,
            {'enc_keypath': pool['encryptkey_path'], 'passphrase': options.get('passphrase')}
        )
        # just formatted and encrypted the disk so have to invalidate
        # the in-memory cache of disk info
        await self.middleware.call('geom.invalidate_cache')

        devname = await self.middleware.call(
            'disk.gptid_from_part_type',
            options['new_disk'],
            await self.middleware.call('disk.get_zfs_part_type')
        )
        if pool['encrypt'] > 0:
            devname = f'/dev/{devname}.eli'

        guid = vdev['guid'] if vdev['type'] == 'DISK' else vdev['children'][0]['guid']
        extend_job = await self.middleware.call('zfs.pool.extend', pool['name'], None, [
            {'target': guid, 'type': 'DISK', 'path': devname}
        ])
        try:
            await job.wrap(extend_job)
        except CallError:
            if pool['encrypt'] > 0:
                try:
                    # If replace has failed lets detach geli to not keep disk busy
                    await self.middleware.call('disk.geli_detach_single', devname)
                except Exception:
                    self.logger.warning(f'Failed to geli detach {devname}', exc_info=True)
            raise

        enc_disks = {'disk': options['new_disk'], 'devname': devname}
        disk = await self.middleware.call('disk.query', [['devname', '=', options['new_disk']]], {'get': True})
        await self.middleware.call('pool.save_encrypteddisks', oid, enc_disks, {disk['devname']: disk})
        ensure_future(self.middleware.call('disk.swaps_configure'))
