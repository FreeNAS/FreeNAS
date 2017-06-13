from middlewared.schema import accepts, Int, Str, Dict, List, Bool, Patch
from middlewared.service import filterable, CRUDService, job, private
from middlewared.utils import Nid, Popen
from middlewared.client import Client, CallTimeout
from urllib.request import urlretrieve

import middlewared.logger
import errno
import gevent
import netif
import os
import stat
import subprocess
import sysctl
import bz2

logger = middlewared.logger.Logger('vm').getLogger()

CONTAINER_IMAGES = {
    "CoreOS": "https://stable.release.core-os.net/amd64-usr/current/coreos_production_image.bin.bz2",
}
BUFSIZE = 65536


class VMManager(object):

    def __init__(self, service):
        self.service = service
        self.logger = self.service.logger
        self._vm = {}

    def start(self, id):
        vm = self.service.query([('id', '=', id)], {'get': True})
        self._vm[id] = VMSupervisor(self, vm)
        try:
            gevent.spawn(self._vm[id].run)
            return True
        except:
            raise

    def stop(self, id):
        supervisor = self._vm.get(id)
        if not supervisor:
            return False

        err = supervisor.stop()
        return err

    def restart(self, id):
        supervisor = self._vm.get(id)
        if supervisor:
            supervisor.restart()
            return True
        else:
            return False

    def status(self, id):
        supervisor = self._vm.get(id)
        if supervisor is None:
            vm = self.service.query([('id', '=', id)], {'get': True})
            self._vm[id] = VMSupervisor(self, vm)
            supervisor = self._vm.get(id)

        if supervisor and supervisor.running():
            return {
                'state': 'RUNNING',
            }
        else:
            return {
                'state': 'STOPPED',
            }


class VMSupervisor(object):

    def __init__(self, manager, vm):
        self.manager = manager
        self.logger = self.manager.logger
        self.vm = vm
        self.proc = None
        self.taps = []
        self.bhyve_error = None
        self.vmutils = VMUtils

    def run(self):
        args = [
            'bhyve',
            '-H',
            '-w',
            '-c', str(self.vm['vcpus']),
            '-m', str(self.vm['memory']),
            '-s', '0:0,hostbridge',
            '-s', '31,lpc',
            '-l', 'com1,/dev/nmdm{}A'.format(self.vm['id']),
        ]

        if self.vm['bootloader'] in ('UEFI', 'UEFI_CSM'):
            args += [
                '-l', 'bootrom,/usr/local/share/uefi-firmware/BHYVE_UEFI{}.fd'.format('_CSM' if self.vm['bootloader'] == 'UEFI_CSM' else ''),
            ]

        if self.vmutils.is_container(self.vm) is True:
            logger.debug("====> RUNNING CONTAINER")

        nid = Nid(3)
        for device in self.vm['devices']:
            if device['dtype'] == 'DISK' or device['dtype'] == 'RAW':
                if device['attributes'].get('type') == 'AHCI':
                    args += ['-s', '{},ahci-hd,{}'.format(nid(), device['attributes']['path'])]
                else:
                    args += ['-s', '{},virtio-blk,{}'.format(nid(), device['attributes']['path'])]
            elif device['dtype'] == 'CDROM':
                args += ['-s', '{},ahci-cd,{}'.format(nid(), device['attributes']['path'])]
            elif device['dtype'] == 'NIC':
                tapname = netif.create_interface('tap')
                tap = netif.get_interface(tapname)
                tap.up()
                self.taps.append(tapname)
                # If Bridge
                if True:
                    bridge = None
                    for name, iface in list(netif.list_interfaces().items()):
                        if name.startswith('bridge'):
                            bridge = iface
                            break
                    if not bridge:
                        bridge = netif.get_interface(netif.create_interface('bridge'))

                    if bridge.mtu > tap.mtu:
                        self.logger.debug("===> Set tap(4) mtu to {0} like in bridge(4) mtu {1}".format(tap.mtu, bridge.mtu))
                        tap.mtu = bridge.mtu

                    bridge.add_member(tapname)

                    defiface = Popen("route -nv show default|grep -w interface|awk '{ print $2 }'", stdout=subprocess.PIPE, shell=True).communicate()[0].strip()
                    if defiface and defiface not in bridge.members:
                        bridge.add_member(defiface)
                    bridge.up()
                if device['attributes'].get('type') == 'VIRTIO':
                    nictype = 'virtio-net'
                else:
                    nictype = 'e1000'
                mac_address = device['attributes'].get('mac', None)

                # By default we add one NIC and the MAC address is an empty string.
                # Issue: 24222
                if mac_address == "":
                    mac_address = None

                if mac_address == '00:a0:98:FF:FF:FF' or mac_address is None:
                    args += ['-s', '{},{},{}'.format(nid(), nictype, tapname)]
                else:
                    args += ['-s', '{},{},{},mac={}'.format(nid(), nictype, tapname, mac_address)]
            elif device['dtype'] == 'VNC':
                if device['attributes'].get('wait'):
                    wait = 'wait'
                else:
                    wait = ''

                vnc_resolution = device['attributes'].get('vnc_resolution', None)
                vnc_port = int(device['attributes'].get('vnc_port', 5900 + self.vm['id']))

                if vnc_resolution is None:
                    args += [
                        '-s', '29,fbuf,tcp=0.0.0.0:{},w=1024,h=768,{}'.format(vnc_port, wait),
                        '-s', '30,xhci,tablet',
                    ]
                else:
                    vnc_resolution = vnc_resolution.split('x')
                    width = vnc_resolution[0]
                    height = vnc_resolution[1]
                    args += [
                        '-s', '29,fbuf,tcp=0.0.0.0:{},w={},h={},{}'.format(vnc_port, width, height, wait),
                        '-s', '30,xhci,tablet',
                    ]

        args.append(self.vm['name'])

        self.logger.debug('Starting bhyve: {}'.format(' '.join(args)))
        self.proc = Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        for line in self.proc.stdout:
            self.logger.debug('{}: {}'.format(self.vm['name'], line))

        # bhyve returns the following status code:
        # 0 - VM has been reset
        # 1 - VM has been powered off
        # 2 - VM has been halted
        # 3 - VM generated a triple fault
        # all other non-zero status codes are errors
        self.bhyve_error = self.proc.wait()
        if self.bhyve_error == 0:
            self.logger.info("===> Rebooting VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], self.bhyve_error))
            self.manager.restart(self.vm['id'])
            self.manager.start(self.vm['id'])
        elif self.bhyve_error == 1:
            # XXX: Need a better way to handle the vmm destroy.
            self.logger.info("===> Powered off VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], self.bhyve_error))
            self.destroy_vm()
        elif self.bhyve_error in (2, 3):
            self.logger.info("===> Stopping VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], self.bhyve_error))
            self.manager.stop(self.vm['id'])
        elif self.bhyve_error not in (0, 1, 2, 3, None):
            self.logger.info("===> Error VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], self.bhyve_error))
            self.destroy_vm()

    def destroy_vm(self):
        self.logger.warn("===> Destroying VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], self.bhyve_error))
        # XXX: We need to catch the bhyvectl return error.
        bhyve_error = Popen(['bhyvectl', '--destroy', '--vm={}'.format(self.vm['name'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE).wait()
        self.manager._vm.pop(self.vm['id'], None)
        self.destroy_tap()

    def destroy_tap(self):
        while self.taps:
            netif.destroy_interface(self.taps.pop())

    def kill_bhyve_pid(self):
        if self.proc:
            try:
                os.kill(self.proc.pid, 15)
            except ProcessLookupError as e:
                # Already stopped, process do not exist anymore
                if e.errno != errno.ESRCH:
                    raise

            self.destroy_vm()
            return True

    def restart(self):
        bhyve_error = Popen(['bhyvectl', '--force-reset', '--vm={}'.format(self.vm['name'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE).wait()
        self.logger.debug("==> Reset VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], bhyve_error))
        self.destroy_tap()

    def stop(self):
        bhyve_error = Popen(['bhyvectl', '--force-poweroff', '--vm={}'.format(self.vm['name'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE).wait()
        self.logger.debug("===> Stopping VM: {0} ID: {1} BHYVE_CODE: {2}".format(self.vm['name'], self.vm['id'], self.bhyve_error))

        if bhyve_error:
            self.logger.error("===> Stopping VM error: {0}".format(bhyve_error))

        return self.kill_bhyve_pid()

    def running(self):
        bhyve_error = Popen(['bhyvectl', '--vm={}'.format(self.vm['name'])], stdout=subprocess.PIPE, stderr=subprocess.PIPE).wait()
        if bhyve_error == 0:
            if self.proc:
                try:
                    os.kill(self.proc.pid, 0)
                except OSError:
                    self.logger.error("===> VMM {0} is running without bhyve process.".format(self.vm['name']))
                    return False
                return True
            else:
                self.logger.error("===> NO PROC STATE")
                # XXX: We return true for now to keep the vm.status sane.
                # It is necessary handle in a better way the bhyve process associated with the vmm.
                return True
        elif bhyve_error == 1:
            return False


class VMUtils(object):

    def is_container(data):
        if data.get('vm_type') == 'Container Provider':
            return True
        else:
            return False

    def create_images_path(data):
        images_path = data.get('container_path') + '/.container_images/'
        dir_path = os.path.dirname(images_path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        return dir_path


class VMService(CRUDService):

    class Config:
        namespace = 'vm'

    def __init__(self, *args, **kwargs):
        super(VMService, self).__init__(*args, **kwargs)
        self._manager = VMManager(self)
        self.vmutils = VMUtils

    @accepts()
    def flags(self):
        """Returns a dictionary with CPU flags for bhyve."""
        data = {}

        vmx = sysctl.filter('hw.vmm.vmx.initialized')
        data['intel_vmx'] = True if vmx and vmx[0].value else False

        ug = sysctl.filter('hw.vmm.vmx.cap.unrestricted_guest')
        data['unrestricted_guest'] = True if ug and ug[0].value else False

        rvi = sysctl.filter('hw.vmm.svm.features')
        data['amd_rvi'] = True if rvi and rvi[0].value != 0 else False

        asids = sysctl.filter('hw.vmm.svm.num_asids')
        data['amd_asids'] = True if asids and asids[0].value != 0 else False

        return data

    @filterable
    def query(self, filters=None, options=None):
        options = options or {}
        options['extend'] = 'vm._extend_vm'
        return self.middleware.call('datastore.query', 'vm.vm', filters, options)

    def _extend_vm(self, vm):
        vm['devices'] = []
        for device in self.middleware.call('datastore.query', 'vm.device', [('vm__id', '=', vm['id'])]):
            device.pop('id', None)
            device.pop('vm', None)
            vm['devices'].append(device)
        return vm

    @accepts(Int('id'))
    def get_vnc(self, id):
        """
        Get the vnc devices from a given guest.

        Returns:
            list(dict): with all attributes of the vnc device or an empty list.
        """
        vnc_devices = []
        for device in self.middleware.call('datastore.query', 'vm.device', [('vm__id', '=', id)]):
            if device['dtype'] == 'VNC':
                vnc = device['attributes']
                vnc_devices.append(vnc)
        return vnc_devices

    @accepts(Int('id'))
    def get_console(self, id):
        """
        Get the console device from a given guest.

        Returns:
            str: with the device path or False.
        """
        try:
            guest_status = self.status(id)
        except:
            guest_status = None

        if guest_status and guest_status['state'] == 'RUNNING':
            device = "/dev/nmdm{0}B".format(id)
            if stat.S_ISCHR(os.stat(device).st_mode) is True:
                    return device

        return False

    @accepts(Dict(
        'vm_create',
        Str('name'),
        Str('description'),
        Int('vcpus'),
        Int('memory'),
        Str('bootloader'),
        List("devices"),
        Str('vm_type'),
        Str('container_path'),
        Bool('autostart'),
        register=True,
    ))
    def do_create(self, data):
        """Create a VM."""
        devices = data.pop('devices')

        pk = self.middleware.call('datastore.insert', 'vm.vm', data)

        if self.vmutils.is_container(data) is True:
            image_url = CONTAINER_IMAGES.get('CoreOS')
            image_path = self.vmutils.create_images_path(data) + '/' + image_url.split('/')[-1]

            with Client() as c:
                try:
                    c.call('vm.fetch_image', image_url, image_path)
                except CallTimeout:
                    logger.debug("===> Problem to connect with the middlewared.")
                    raise

            logger.debug("===> Fetching image: %s" % (image_path))

        for device in devices:
            device['vm'] = pk
            self.middleware.call('datastore.insert', 'vm.device', device)
        return pk

    @private
    def do_update_devices(self, id, devices):
        if devices and isinstance(devices, list) is True:
            device_query = self.middleware.call('datastore.query', 'vm.device', [('vm__id', '=', int(id))])

            # Make sure both list has the same size.
            if len(device_query) != len(devices):
                return False

            get_devices = []
            for q in device_query:
                q.pop('vm')
                get_devices.append(q)

            while len(devices) > 0:
                update_item = devices.pop(0)
                old_item = get_devices.pop(0)
                if old_item['dtype'] == update_item['dtype']:
                    old_item['attributes'] = update_item['attributes']
                    device_id = old_item.pop('id')
                    self.middleware.call('datastore.update', 'vm.device', device_id, old_item)
            return True

    @accepts(Int('id'), Patch(
        'vm_create',
        'vm_update',
        ('attr', {'update': True}),
    ))
    def do_update(self, id, data):
        """Update all information of a specific VM."""
        devices = data.pop('devices', None)
        if devices:
            update_devices = self.do_update_devices(id, devices)
        if data:
            return self.middleware.call('datastore.update', 'vm.vm', id, data)
        else:
            return update_devices

    @accepts(Int('id'),
        Dict('devices', additional_attrs=True),
    )
    def create_device(self, id, data):
        """Create a new device in an existing vm."""
        devices_type = ('NIC', 'DISK', 'CDROM', 'VNC')
        devices = data.get('devices', None)

        if devices:
            devices[0].update({"vm": id})
            dtype = devices[0].get('dtype', None)
            if dtype in devices_type and isinstance(devices, list) is True:
                devices = devices[0]
                self.middleware.call('datastore.insert', 'vm.device', devices)
                return True
            else:
                return False
        else:
            return False

    @accepts(Int('id'))
    def do_delete(self, id):
        """Delete a VM."""
        return self.middleware.call('datastore.delete', 'vm.vm', id)

    @accepts(Int('id'))
    def start(self, id):
        """Start a VM."""
        return self._manager.start(id)

    @accepts(Int('id'))
    def stop(self, id):
        """Stop a VM."""
        return self._manager.stop(id)

    @accepts(Int('id'))
    def restart(self, id):
        """Restart a VM."""
        return self._manager.restart(id)

    @accepts(Int('id'))
    def status(self, id):
        """Get the status of a VM, if it is RUNNING or STOPPED."""
        return self._manager.status(id)

    def fetch_hookreport(self, blocknum, blocksize, totalsize, job, file_name):
        """Hook to report the download progress."""
        readchunk = blocknum * blocksize
        if totalsize > 0:
            percent = readchunk * 1e2 / totalsize
            job.set_progress(int(percent), 'Downloading', {'downloaded': readchunk, 'total': totalsize})

        if int(percent) == 100:
            with Client() as c:
                try:
                    c.call('vm.decompress_bzip', file_name, '/mnt/ssd/coreos.img')
                except CallTimeout:
                    logger.debug("===> Problem to connect with the middlewared.")


    @accepts(Str('url'), Str('file_name'))
    @job(lock='container')
    def fetch_image(self, job, url, file_name):
        """Fetch an image from a given URL and save to a file."""
        if os.path.exists(file_name) is False:
            logger.debug("===> Downloading: %s" % (url))
            urlretrieve(url, file_name,
                        lambda nb, bs, fs, job=job: self.fetch_hookreport(nb, bs, fs, job, file_name))
        else:
            with Client() as c:
                try:
                    c.call('vm.decompress_bzip', file_name, '/mnt/ssd/coreos.img')
                except CallTimeout:
                    logger.debug("===> Problem to connect with the middlewared.")

    def decompress_hookreport(self, dst_file, job):
        totalsize = 4756340736 # XXX: It will be parsed from a sha256 file.
        fd = os.open(dst_file, os.O_RDONLY)
        try:
            size = os.lseek(fd, 0, os.SEEK_END)
        finally:
            os.close(fd)

        percent = (size / totalsize) * 100
        job.set_progress(int(percent), 'Decompress', {'decompressed': size, 'total': totalsize})

    @accepts(Str('src'), Str('dst'))
    @job(lock='decompress', process=True)
    def decompress_bzip(self, job, src, dst):
        logger.debug("==> SRC: %s DST: %s" % (src, dst))
        with open(dst, 'wb') as dst_file, bz2.BZ2File(src, 'rb') as src_file:
            for data in iter(lambda: src_file.read(BUFSIZE), b''):
                self.decompress_hookreport(dst, job)
                dst_file.write(data)


def kmod_load():
    kldstat = Popen(['/sbin/kldstat'], stdout=subprocess.PIPE).communicate()[0]
    if 'vmm.ko' not in kldstat:
        Popen(['/sbin/kldload', 'vmm'])
    if 'nmdm.ko' not in kldstat:
        Popen(['/sbin/kldload', 'nmdm'])


def _event_system_ready(middleware, event_type, args):
    """
    Method called when system is ready, supposed to start VMs
    flagged that way.
    """
    if args['id'] != 'ready':
        return

    for vm in middleware.call('vm.query', [('autostart', '=', True)]):
        middleware.call('vm.start', vm['id'])


def setup(middleware):
    gevent.spawn(kmod_load)
    middleware.event_subscribe('system', _event_system_ready)
