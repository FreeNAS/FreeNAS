import asyncio
import threading
import os

from middlewared.schema import accepts, Bool, Ref, Str, returns
from middlewared.service import job, Service


CHUNK = 1048576  # 1MB binary


class DiskService(Service):

    def _wipe_impl(self, job, dev, mode, event):
        disk_path = f'/dev/{dev}'
        with open(os.open(disk_path, os.O_WRONLY | os.O_EXCL), 'wb') as f:
            size = os.lseek(f.fileno(), 0, os.SEEK_END)
            if size == 0:
                # no size means nothing else will work
                self.logger.error('Unable to determine size of "%s"', dev)
                return
            elif size < 33554432 and mode == 'QUICK':
                # we wipe the first and last 33554432 bytes (32MB) of the
                # device when it's the "QUICK" mode so if the device is smaller
                # than that, ignore it.
                return

            # seek back to the beginning of the disk
            os.lseek(f.fileno(), 0, os.SEEK_SET)

            # no reason to write more than 1MB at a time
            # or kernel will break them into smaller chunks
            if mode in ('QUICK', 'FULL'):
                to_write = bytearray(CHUNK).zfill(0)
            else:
                to_write = bytearray(os.urandom(CHUNK))

            if mode == 'QUICK':
                _32 = 32
                for i in range(_32):
                    # wipe first 32MB
                    os.write(f.fileno(), to_write)
                    os.fsync(f.fileno())
                    if event.is_set():
                        return
                    # we * 50 since we write a total of 64MB
                    # so this will be 50% of the total
                    job.set_progress(round(((i / _32) * 50), 2))

                # seek to 32MB before end of drive
                os.lseek(f.fileno(), (size - (CHUNK * _32)), os.SEEK_SET)
                _64 = _32 * 2
                for i in range(_32, _64):  # this is done to have accurate reporting
                    # wipe last 32MB
                    os.write(f.fileno(), to_write)
                    os.fsync(f.fileno())
                    if event.is_set():
                        return
                    job.set_progress(round(((i / _64) * 100), 2))
            else:
                iterations = (size // CHUNK)
                for i in range(iterations):
                    os.write(f.fileno(), to_write)
                    # Linux allocates extremely large buffers for some disks. Even after everything is written and the
                    # device is successfully closed, disk activity might still continue for quite a while. This will
                    # give a false sense of data on the disk being completely destroyed while in reality it is still
                    # not.
                    # Additionally, such a behavior causes issues when aborting the disk wipe. Even after the file
                    # descriptor is closed, OS will prevent any other program from opening the disk with O_EXCL until
                    # all the buffers are flushed, resulting in a "Device or resource busy" error.
                    os.fsync(f.fileno())
                    if event.is_set():
                        return
                    job.set_progress(round(((i / iterations) * 100), 2))

        with open(disk_path, 'wb'):
            # we overwrote partition label information by the time
            # we get here, so we need to close device and re-open
            # it in write mode to trigger udev to rescan the
            # device for new information
            pass

    @accepts(
        Str('dev'),
        Str('mode', enum=['QUICK', 'FULL', 'FULL_RANDOM'], required=True),
        Bool('synccache', default=True),
        Ref('swap_removal_options'),
    )
    @returns()
    @job(
        lock=lambda args: args[0],
        description=lambda dev, mode, *args: f'{mode.replace("_", " ").title()} wipe of disk {dev}',
        abortable=True,
    )
    async def wipe(self, job, dev, mode, sync, options):
        """
        Performs a wipe of a disk `dev`.
        It can be of the following modes:
          - QUICK: clean the first and last 32 megabytes on `dev`
          - FULL: write whole disk with zero's
          - FULL_RANDOM: write whole disk with random bytes
        """
        await self.middleware.call('disk.swaps_remove_disks', [dev], options)
        event = threading.Event()
        try:
            await self.middleware.run_in_thread(self._wipe_impl, job, dev, mode, event)
        except asyncio.CancelledError:
            event.set()
            raise
        if sync:
            await self.middleware.call('disk.sync', dev)
