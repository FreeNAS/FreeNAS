import logging

from middlewared.utils.scsi_generic import inquiry

from .constants import MINI_MODEL_BASE
from .element_types import ELEMENT_TYPES, ELEMENT_DESC
from .enums import ControllerModels, ElementDescriptorsToIgnore, ElementStatusesToIgnore, JbodModels
from .sysfs_disks import map_disks_to_enclosure_slots
from .slot_mappings import get_slot_info, SYSFS_SLOT_KEY, MAPPED_SLOT_KEY

logger = logging.getLogger(__name__)


class Enclosure:
    def __init__(self, bsg, sg, dmi, enc_stat):
        self.bsg, self.sg, self.pci, self.dmi = bsg, sg, bsg.removeprefix('/dev/bsg/'), dmi
        self.encid, self.status = enc_stat['id'], list(enc_stat['status'])
        self.vendor, self.product, self.revision, self.encname = self._get_vendor_product_revision_and_encname()
        self._get_model_and_controller()
        self._should_ignore_enclosure()
        self.sysfs_map, self.disks_map, self.elements = dict(), dict(), dict()
        if not self.should_ignore:
            self.sysfs_map = map_disks_to_enclosure_slots(self.pci)
            self.disks_map = self._get_array_device_mapping_info()
            self.elements = self._parse_elements(enc_stat['elements'])

    def asdict(self):
        """This method is what is returned in enclosure2.query"""
        return {
            'should_ignore': self.should_ignore,  # enclosure device we dont need or expect
            'name': self.encname,  # vendor, product and revision joined by whitespace
            'model': self.model,  # M60, F100, MINI-R, etc
            'controller': self.controller,  # if True, represents the "head-unit"
            'dmi': self.dmi,  # comes from system.dmidecode_info[system-product-name]
            'status': self.status,  # the overall status reported by the enclosure
            'id': self.encid,
            'vendor': self.vendor,  # t10 vendor from INQUIRY
            'product': self.product,  # product from INQUIRY
            'revision': self.revision,  # revision from INQUIRY
            'bsg': self.bsg,  # the path for which this maps to a bsg device (/dev/bsg/0:0:0:0)
            'sg': self.sg,  # the scsi generic device (/dev/sg0)
            'pci': self.pci,  # the pci info (0:0:0:0)
            'elements': self.elements  # dictionary with all element types and their relevant information
        }

    def _should_ignore_enclosure(self):
        if not self.model:
            # being unable to determine the model means many other things will not work
            self.should_ignore = True
        elif all((
            (not any((self.is_r20_series, self.is_mini))),
            self.vendor == 'AHCI',
            self.product == 'SGPIOEnclosure',
        )):
            # if this isn't an R20 or MINI platform and this is the Virtual AHCI
            # enclosure, then we can ignore them
            self.should_ignore = True
        elif all((
            self.is_r20_series,
            (self.model in (
                ControllerModels.MINI3XP.value,
                ControllerModels.MINI3E.value,
            )),
            self.encid == '3000000000000002'
        )):
            # These platforms have 2x virtual AHCI enclosures but we only map the
            # drives on 1 of them
            self.should_ignore = True
        else:
            self.should_ignore = False

    def _get_vendor_product_revision_and_encname(self):
        """Sends a standard INQUIRY command to the enclosure device
        so we can parse the vendor/prodcut/revision(and /serial if we ever wanted
        to use that information) for the enclosure device. It's important
        that we parse this information into their own top-level keys since we
        base some of our drive mappings (potentially) on the "revision" (aka firmware)
        for the enclosure
        """
        inq = inquiry(self.sg)
        data = [inq['vendor'], inq['product'], inq['revision']]
        data.append(' '.join(data))
        return data

    def _get_model_and_controller(self):
        """This determines the model and whether or not this a controller enclosure.
        The term "controller" refers to the enclosure device where the TrueNAS OS
        is installed (sometimes referred to as the head-unit). We check 2 different
        values to determine the model/controller.

        1. We check SMBIOS DMI type "system" buffer, specifically the product name
        2. We check the t10 vendor and product strings returned from the enclosure
            using a standard inquiry command
        """
        model = self.dmi.removeprefix('TRUENAS-').removeprefix('FREENAS-')
        model = model.removesuffix('-HA').removesuffix('-S')
        try:
            dmi_model = ControllerModels[model]
        except KeyError:
            try:
                # the member names of this enum just so happen to line
                # up with the string we get from DMI, however, the MINIs
                # get flashed with strings that have invalid characters
                # for members of an enum. If we get here, then we change
                # to using the parenthesis approach because that matches
                # an entry in the enum by value
                dmi_model = ControllerModels(model)
            except KeyError:
                # this shouldn't ever happen because the instantiator of this class
                # checks DMI before we even get here but better safe than sorry
                logger.warning('Unexpected model: %r from dmi: %r', model, self.dmi)
                self.model = ''
                self.controller = False
                return

        t10vendor_product = f'{self.vendor}_{self.product}'
        match t10vendor_product:
            case 'ECStream_4024Sp' | 'ECStream_4024Ss' | 'iX_4024Sp' | 'iX_4024Ss':
                # M series
                self.model = dmi_model.value
                self.controller = True
            case 'CELESTIC_P3215-O' | 'CELESTIC_P3217-B':
                # X series
                self.model = dmi_model.value
                self.controller = True
            case 'BROADCOM_VirtualSES':
                # H series
                self.model = dmi_model.value
                self.controller = True
            case 'ECStream_FS1' | 'ECStream_FS2' | 'ECStream_DSS212Sp' | 'ECStream_DSS212Ss':
                # R series
                self.model = dmi_model.value
                self.controller = True
            case 'iX_FS1L' | 'iX_FS2' | 'iX_DSS212Sp' | 'iX_DSS212Ss':
                # more R series
                self.model = dmi_model.value
                self.controller = True
            case 'iX_TrueNASR20p' | 'iX_2012Sp' | 'iX_TrueNASSMCSC826-P':
                # R20
                self.model = dmi_model.value
                self.controller = True
            case 'AHCI_SGPIOEnclosure':
                # R20 variants or MINIs
                self.model = dmi_model.value
                self.controller = True
            case 'iX_eDrawer4048S1' | 'iX_eDrawer4048S2':
                # R50
                self.model = dmi_model.value
                self.controller = True
            case 'CELESTIC_X2012':
                self.model = JbodModels.ES12.value
                self.controller = False
            case 'ECStream_4024J' | 'iX_4024J':
                self.model = JbodModels.ES24.value
                self.controller = False
            case 'ECStream_2024Jp' | 'ECStream_2024Js' | 'iX_2024Jp' | 'iX_2024Js':
                self.model = JbodModels.ES24F.value
                self.controller = False
            case 'CELESTIC_R0904-F0001-01':
                self.model = JbodModels.ES60.value
                self.controller = False
            case 'HGST_H4060-J':
                self.model = JbodModels.ES60G2.value
                self.controller = False
            case 'HGST_H4102-J':
                self.model = JbodModels.ES102.value
                self.controller = False
            case 'VikingES_NDS-41022-BB' | 'VikingES_VDS-41022-BB':
                self.model = JbodModels.ES102G2.value
                self.controller = False
            case _:
                logger.warning(
                    'Unexpected t10 vendor: %r and product: %r combination',
                    self.vendor, self.product
                )
                self.model = ''
                self.controller = False

    def _ignore_element(self, parsed_element_status, element):
        """We ignore certain elements reported by the enclosure, for example,
        elements that report as unsupported. Our alert system polls enclosures
        for elements that report "bad" statuses and these elements need to be
        ignored. NOTE: every hardware platform is different for knowing which
        elements are to be ignored"""
        desc = element['descriptor'].lower()
        return any((
            (parsed_element_status.lower() == ElementStatusesToIgnore.UNSUPPORTED.value),
            (self.is_xseries and desc == ElementDescriptorsToIgnore.ADISE0.value),
            (self.model == JbodModels.ES60.value and desc == ElementDescriptorsToIgnore.ADS.value),
            (not self.is_hseries and desc in (
                ElementDescriptorsToIgnore.EMPTY.value,
                ElementDescriptorsToIgnore.AD.value,
                ElementDescriptorsToIgnore.DS.value,
            )),
        ))

    def _get_array_device_mapping_info(self):
        mapped_info = get_slot_info(self)
        if not mapped_info:
            return

        # we've gotten the disk mapping information based on the
        # enclosure but we need to check if this enclosure has
        # different revisions
        vers_key = 'DEFAULT'
        if not mapped_info['any_version']:
            for key, vers in mapped_info['versions'].items():
                if self.revision == key:
                    vers_key = vers
                    break

        # Now we need to check this specific enclosure's disk slot
        # mapping information
        idkey, idvalue = 'model', self.model
        if all((
            self.vendor == 'AHCI',
            self.product == 'SGPIOEnclosure',
            any((self.is_mini, self.is_r20_series))
        )):
            idkey, idvalue = 'id', self.encid
        elif self.is_r50_series:
            idkey, idvalue = 'product', self.product

        # Now we know the specific enclosure we're on and the specific
        # key we need to use to pull out the drive slot mapping
        for mapkey, mapslots in mapped_info['versions'][vers_key].items():
            if mapkey == idkey and (found := mapslots.get(idvalue)):
                return found

    def _parse_elements(self, elements):
        final = {}
        for slot, element in elements.items():
            try:
                element_type = ELEMENT_TYPES[element['type']]
            except KeyError:
                # means the element type that's being
                # reported to us is unknown so log it
                # and continue on
                logger.warning('Unknown element type: %r for %r', element['type'], self.devname)
                continue

            try:
                element_status = ELEMENT_DESC[element['status'][0]]
            except KeyError:
                # means the elements status reported by the enclosure
                # is not mapped so just report unknown
                element_status = 'UNKNOWN'

            if self._ignore_element(element_status, element):
                continue

            if element_type[0] not in final:
                # first time seeing this element type so add it
                final[element_type[0]] = {}

            # convert list of integers representing the elements
            # raw status to an integer so it can be converted
            # appropriately based on the element type
            value_raw = 0
            for val in element['status']:
                value_raw = (value_raw << 8) + val

            mapped_slot = slot
            parsed = {
                'descriptor': element['descriptor'].strip(),
                'status': element_status,
                'value': element_type[1](value_raw),
                'value_raw': value_raw,
            }
            if element_type[0] == 'Array Device Slot' and self.disks_map:
                try:
                    parsed['dev'] = self.sysfs_map[self.disks_map[slot][SYSFS_SLOT_KEY]]
                except KeyError:
                    # this happens on some of the MINI platforms, for example,
                    # the MINI-3.0-XL+ because we map the 1st drive and only
                    # the 1st drive from the Virtual AHCI controller with id
                    # that ends with 002. However, we send a standard enclosure
                    # diagnostics command so all the other elements will return
                    continue

                mapped_slot = self.disks_map[slot][MAPPED_SLOT_KEY]
                parsed['original'] = {
                    'enclosure_id': self.encid,
                    'enclosure_sg': self.sg,
                    'enclosure_bsg': self.bsg,
                    'descriptor': f'slot{slot}',
                    'slot': slot,
                }

            final[element_type[0]].update({mapped_slot: parsed})

        return final

    @property
    def model(self):
        return self.__model

    @model.setter
    def model(self, val):
        self.__model = val

    @property
    def controller(self):
        return self.__controller

    @controller.setter
    def controller(self, val):
        self.__controller = val

    @property
    def should_ignore(self):
        """This property serves as an easy way to determine if the enclosure
        that we're parsing meets a certain set of criteria. If the criteria
        is not met, then we set this value to False so that we can short-circuit
        some of the parsing logic as well as provide a value to any caller of
        this class to more easily apply filters as necessary.
        """
        return self.__ignore

    @should_ignore.setter
    def should_ignore(self, val):
        self.__ignore = val

    @property
    def is_jbod(self):
        """Determine if the enclosure device is a JBOD
        (just a bunch of disks) unit.

        Args:
        Returns: bool
        """
        return self.model in (i.value for i in JbodModels)

    @property
    def is_rseries(self):
        """Determine if the enclosure device is a r-series controller.

        Args:
        Returns: bool
        """
        return all((self.controller, self.model[0] == 'R'))

    @property
    def is_r20_series(self):
        """Determine if the enclosure device is a r20-series controller.

        Args:
        Returns: bool
        """
        return all((
            self.is_rseries,
            self.model.startswith((
                ControllerModels.R20.value,
                ControllerModels.R20A.value,
                ControllerModels.R20B.value,
            ))
        ))

    @property
    def is_r50_series(self):
        """Determine if the enclosure device is a r50-series controller.

        Args:
        Returns: bool
        """
        return all((
            self.is_rseries,
            self.model.startswith((
                ControllerModels.R50.value,
                ControllerModels.R50B.value,
                ControllerModels.R50BM.value,
            ))
        ))

    @property
    def is_fseries(self):
        """Determine if the enclosure device is a f-series controller.

        Args:
        Returns: bool
        """
        return all((self.controller, self.model[0] == 'F'))

    @property
    def is_hseries(self):
        """Determine if the enclosure device is a h-series controller.

        Args:
        Returns: bool
        """
        return all((self.controller, self.model[0] == 'H'))

    @property
    def is_mseries(self):
        """Determine if the enclosure device is a m-series controller.

        Args:
        Returns: bool
        """
        return all((
            self.controller, not self.is_mini, self.model[0] == 'M'
        ))

    @property
    def is_xseries(self):
        """Determine if the enclosure device is a x-series controller.

        Args:
        Returns: bool
        """
        return all((
            self.controller, self.model[0] == 'X'
        ))

    @property
    def is_mini(self):
        """Determine if the enclosure device is a mini-series controller.

        Args:
        Returns: bool
        """
        return all((
            self.controller, self.model.startswith(MINI_MODEL_BASE)
        ))

    @property
    def is_24_bay_jbod(self):
        """Determine if the enclosure device is a 24 bay JBOD.

        Args:
        Returns: bool
        """
        return all((
            self.is_jbod,
            self.model in (
                JbodModels.ES24.value,
                JbodModels.ES24F.value,
            )
        ))

    @property
    def is_60_bay_jbod(self):
        """Determine if the enclosure device is a 60 bay JBOD.

        Args:
        Returns: bool
        """
        return all((
            self.is_jbod,
            self.model in (
                JbodModels.ES60.value,
                JbodModels.ES60G2.value,
            )
        ))
