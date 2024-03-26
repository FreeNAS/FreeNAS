# Copyright (c) - iXsystems Inc.
#
# Licensed under the terms of the TrueNAS Enterprise License Agreement
# See the file LICENSE.IX for complete terms and conditions

from os.path import exists

from bsd.enclosure import Enclosure
from middlewared.service import Service, private


class EnclosureService(Service):

    @private
    def get_ses_enclosures(self):
        """
        Return enclosure status for all detected enclosures.
        """
        result = {}
        encnum = 0
        while exists(f'/dev/ses{encnum}'):
            result[encnum] = Enclosure(f'/dev/ses{encnum}').status()
            encnum += 1
        return result
