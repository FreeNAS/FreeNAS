# Copyright (c) - iXsystems Inc.
#
# Licensed under the terms of the TrueNAS Enterprise License Agreement
# See the file LICENSE.IX for complete terms and conditions

from middlewared.alert.base import AlertClass, AlertCategory, AlertLevel, Alert, AlertSource


class EnclosureUnhealthyAlertClass(AlertClass):
    category = AlertCategory.HARDWARE
    level = AlertLevel.CRITICAL
    title = "Enclosure Status Is Not Healthy"
    text = "Enclosure /dev/ses%d (%s): %s at slot %s (in hex %s) is reporting %s."

    products = ("ENTERPRISE",)


class EnclosureHealthyAlertClass(AlertClass):
    category = AlertCategory.HARDWARE
    level = AlertLevel.INFO
    title = "Enclosure Status Is Healthy"
    text = "Enclosure /dev/ses%d (%s): is healthy."

    products = ("ENTERPRISE",)


class EnclosureStatusAlertSource(AlertSource):
    products = ("ENTERPRISE",)
    failover_related = True
    run_on_backup_node = False
    bad = ('Critical', 'Noncritical', 'Unknown', 'Unrecoverable')

    bad_elements = []

    async def check(self):
        good_enclosures = []
        bad_elements = []
        for enc in await self.middleware.call('enclosure.query'):
            good_enclosures.append([enc['number'], enc['name']])

            for element_type, element_values in enc['elements'].items():
                for slot, value in element_values.items():
                    if value['status'] in self.bad:
                        if enc['name'] == 'ECStream 3U16+4R-4X6G.3 d10c' and value['descriptor'] == '1.8V Sensor':
                            # The 1.8V sensor is bugged on the echostream enclosure (Z-series).
                            # The management chip loses it's mind and claims undervoltage, but
                            # scoping this confirms the voltage is fine.
                            # Ignore alerts from this element. Redmine # 10077
                            continue

                        # getting here means that we came across an element that isn't reporting
                        # a status we expect AND the overall enclosure status isn't "OK"
                        # (or isn't reported at all)
                        args = [
                            enc['number'],
                            enc['name'],
                            value['descriptor'],
                            slot,
                            hex(slot),
                            value['status']
                        ]
                        for i, (another_args, count) in enumerate(self.bad_elements):
                            if another_args == args:
                                bad_elements.append((args, count + 1))
                                break
                        else:
                            bad_elements.append((args, 1))

        self.bad_elements = bad_elements

        alerts = []
        for args, count in bad_elements:
            # We only report unhealthy enclosure elements if they were unhealthy 5 probes in a row (1 probe = 1 minute)
            if count >= 5:
                try:
                    good_enclosures.remove(args[:2])
                except ValueError:
                    pass

                alerts.append(Alert(EnclosureUnhealthyAlertClass, args=args))

        for args in good_enclosures:
            alerts.append(Alert(EnclosureHealthyAlertClass, args=args))

        return alerts
