# Copyright (c) - iXsystems Inc.
#
# Licensed under the terms of the TrueNAS Enterprise License Agreement
# See the file LICENSE.IX for complete terms and conditions

from libsg3.ses import EnclosureDevice
from middlewared.schema import accepts, Dict, Str, Int
from middlewared.service import Service, filterable
from middlewared.service_exception import MatchNotFound, ValidationError
from middlewared.utils import filter_list
from middlewared.plugins.truenas import TRUENAS_UNKNOWN

from .jbof_enclosures import map_jbof
from .map2 import combine_enclosures
from .nvme2 import map_nvme
from .r30_drive_identify import set_slot_status as r30_set_slot_status
from .fseries_drive_identify import set_slot_status as fseries_set_slot_status
from .ses_enclosures2 import get_ses_enclosures


class Enclosure2Service(Service):

    class Config:
        cli_namespace = 'storage.enclosure2'
        private = True

    def get_ses_enclosures(self, dmi=None):
        """This generates the "raw" list of enclosures detected on the system. It
        serves as the "entry" point to "enclosure2.query" and is foundational in
        how all of the structuring of the final data object is returned.

        We use pyudev to enumerate enclosure type devices using a socket to the
        udev database. While we're at it, we also add some useful keys to the
        object (/dev/bsg, /dev/sg, and dmi). Then we use SCSI commands (issued
        directly to the enclosure) to generate an object of all elements and the
        information associated to each element.

        It's _VERY_ important to understand that the "dmi" key is the hingepoint for
        identifying what platform we're on. This is SMBIOS data and is burned into
        the motherboard before we ship to our customers. This is also how we map the
        enclosure's array device slots (disk drives) to a human friendly format.

        The `Enclosure` class is where all the magic happens wrt to taking in all the
        raw data and formatting it into a structured object that will be consumed by
        the webUI team as well as on the backend (alerts, drive identifiction, etc).
        """
        if dmi is None:
            dmi = self.middleware.call_sync('system.dmidecode_info')['system-product-name']
        return get_ses_enclosures(dmi)

    def map_jbof(self, jbof_qry=None):
        """This method serves as an endpoint to easily be able to test
        the JBOF mapping logic specifically without having to call enclosure2.query
        which includes the head-unit and all other attached JBO{D/F}s.
        """
        if jbof_qry is None:
            jbof_qry = self.middleware.call_sync('jbof.query')
        return map_jbof(jbof_qry)

    def map_nvme(self, dmi=None):
        """This method serves as an endpoint to easily be able to test
        the nvme mapping logic specifically without having to call enclosure2.query
        which includes the head-unit and all attached JBODs.
        """
        if dmi is None:
            dmi = self.middleware.call_sync('system.dmidecode_info')['system-product-name']
        return map_nvme(dmi)

    def get_original_disk_slot(self, slot, enc_info):
        """Get the original slot based on the `slot` passed to us via the end-user.
        NOTE: Most drives original slot will match their "mapped" slot because there
        is no need to map them. We always include an "original" slot key for all
        enclosures as to keep this for loop as simple as possible and it also allows
        more flexbiility when we do get an enclosure that maps drives differently.
        (i.e. the ES102G2 is a prime example of this (enumerates drives at 1 instead of 0))
        """
        sgdev = origslot = None
        for encslot, devinfo in filter(lambda x: x[0] == slot, enc_info['elements']['Array Device Slot'].items()):
            sgdev = devinfo['original']['enclosure_sg']
            origslot = devinfo['original']['slot']

        return sgdev, origslot

    @accepts(Dict(
        Str('enclosure_id', required=True),
        Int('slot', required=True),
        Str('status', required=True, enum=['CLEAR', 'IDENT', 'FAULT'])
    ))
    def set_slot_status(self, data):
        """Set enclosure bay number `slot` to `status` for `enclosure_id`.

        `enclosure_id` str: represents the enclosure logical identifier of the enclosure
        `slot` int: the enclosure drive bay number to send the status command
        `status` str: the status for which to send to the command
        """
        try:
            enc_info = self.middleware.call_sync(
                'enclosure2.query', [['id', '=', data['enclosure_id']]], {'get': True}
            )
        except MatchNotFound:
            raise ValidationError('enclosure2.set_slot_status', f'Enclosure with id: {data["enclosure_id"]} not found')

        if enc_info['id'].endswith('_nvme_enclosure'):
            if enc_info['id'].startswith('r30'):
                # an all nvme flash system so drive identification is handled
                # in a completely different way than sata/scsi
                return r30_set_slot_status(data['slot'], data['status'])
            elif enc_info['id'].startswith(('f60', 'f100', 'f130')):
                return fseries_set_slot_status(data['slot'], data['status'])
            else:
                # mseries, and some rseries have mapped nvme enclosures but they
                # don't support drive LED identification
                return

        sgdev, origslot = self.get_original_disk_slot(data['slot'], enc_info)
        if sgdev is None:
            raise ValidationError('enclosure2.set_slot_status', 'Unable to find scsi generic device for enclosure')
        elif origslot is None:
            raise ValidationError('enclosure2.set_slot_status', f'Slot {data["slot"]!r} not found in enclosure')

        if data['status'] == 'CLEAR':
            actions = ('clear=ident', 'clear=fault')
        else:
            actions = (f'set={data["status"].lower()}',)

        encdev = EnclosureDevice(sgdev)
        try:
            for action in actions:
                encdev.set_control(str(origslot), action)
        except OSError:
            self.logger.warning(f'Failed to {data["status"]} slot {data["slot"]!r} on enclosure {enc_info["id"]}')

    @filterable
    def query(self, filters, options):
        enclosures = []
        if self.middleware.call_sync('truenas.get_chassis_hardware') == TRUENAS_UNKNOWN:
            # this feature is only available on hardware that ix sells
            return enclosures

        labels = {
            label['encid']: label['label']
            for label in self.middleware.call_sync('datastore.query', 'truenas.enclosurelabel')
        }
        dmi = self.middleware.call_sync('system.dmidecode_info')['system-product-name']
        jbofs = self.middleware.call_sync('jbof.query')
        for i in self.get_ses_enclosures(dmi) + self.map_nvme(dmi) + self.map_jbof(jbofs):
            if i.pop('should_ignore'):
                continue

            # this is a user-provided string to label the enclosures so we'll add it at as a
            # top-level dictionary key "label", if the user hasn't provided a label then we'll
            # fill in the info with whatever is in the "name" key. The "name" key is the
            # t10 vendor, product and revision information combined as a single space separated
            # string reported by the enclosure itself via a standard inquiry command
            i['label'] = labels.get(i['id']) or i['name']
            enclosures.append(i)

        combine_enclosures(enclosures)
        return filter_list(enclosures, filters, options)
