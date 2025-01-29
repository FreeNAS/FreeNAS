from middlewared.api import api_method
from middlewared.api.current import (
    VMImportDiskImageArgs, VMImportDiskImageResult, VMExportDiskImageArgs, VMExportDiskImageResult,
)
from middlewared.service import job, Service


class VMService(Service):

    @api_method(VMImportDiskImageArgs, VMImportDiskImageResult, roles=['VM_WRITE'])
    @job(lock_queue_size=1, lock=lambda args: f"zvol_disk_image_{args[-1]['zvol']}")
    async def import_disk_image(self, job, data):
        """
        Imports a specified disk image. 

        Utilized qemu-img with the auto-detect functionality to auto-convert
        any supported disk image format to RAW -> ZVOL

        As of this implementation it supports:

        - QCOW2
        - QED
        - RAW
        - VDI
        - VPC
        - VMDK

        `diskimg` is an required parameter for the incoming disk image
        `zvol` is the required target for the imported disk image
        """
        return await job.wrap(await self.middleware.call('virt.device.import_disk_image', data))

    @api_method(VMExportDiskImageArgs, VMExportDiskImageResult, roles=['VM_WRITE'])
    @job(lock_queue_size=1, lock=lambda args: f"zvol_disk_image_{args[-1]['zvol']}")
    async def export_disk_image(self, job, data):
        """
        Exports a zvol to a formatted VM disk image.

        Utilized qemu-img with the conversion functionality to export a zvol to
        any supported disk image format, from RAW -> ${OTHER}. The resulting file
        will be set to inherit the permissions of the target directory.

        As of this implementation it supports the following {format} options :

        - QCOW2
        - QED
        - RAW
        - VDI
        - VPC
        - VMDK

        `format` is an required parameter for the exported disk image
        `directory` is an required parameter for the export disk image
        `zvol` is the source for the disk image
        """
        return await job.wrap(await self.middleware.call('virt.device.export_disk_image', data))
