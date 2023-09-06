from pathlib import Path

from pyroute2 import NDB

from middlewared.service import Service
from middlewared.utils.functools import cache


class InternalInterfaceService(Service):

    class Config:
        private = True
        namespace = 'failover.internal_interface'

    @cache
    def detect(self):
        hardware = self.middleware.call_sync('failover.hardware')
        if hardware == 'BHYVE':
            return ['enp0s6f1']
        elif hardware == 'ECHOSTREAM':
            # z-series
            for i in Path('/sys/class/net/').iterdir():
                try:
                    data = (i / 'device/uevent').read_text()
                    if 'PCI_ID=8086:10D3' in data and 'PCI_SUBSYS_ID=8086:A01F' in data:
                        return [i.name]
                except FileNotFoundError:
                    continue
        elif hardware in ('PUMA', 'ECHOWARP', 'LAJOLLA2'):
            # {x/m/f}-series
            return ['ntb0']
        else:
            return []

    async def pre_sync(self):
        if not await self.middleware.call('system.is_enterprise'):
            return

        node = await self.middleware.call('failover.node')
        if node == 'A':
            internal_ip = '169.254.10.1'
        elif node == 'B':
            internal_ip = '169.254.10.2'
        else:
            self.logger.error('Node position could not be determined.')
            return

        iface = await self.middleware.call('failover.internal_interfaces')
        if not iface:
            self.logger.error('Internal interface not found.')
            return

        iface = iface[0]

        await self.middleware.run_in_thread(self.sync, iface, internal_ip)

    def sync(self, iface, internal_ip):
        default_table, rtn_blackhole = 254, 6
        with NDB(log='off') as ndb:
            try:
                with ndb.interfaces[iface] as dev:
                    dev.add_ip(f'{internal_ip}/24').set(state='up')
            except KeyError:
                # ip address already exists on this interface
                pass

            # add a blackhole route of 169.254.10.0/23 which is 1 bit larger than
            # ip address we put on the internal interface. We do this because the
            # f-series platform uses AMD ntb driver and the behavior for when the
            # B controller is active and the A controller reboots, is that the ntb0
            # interface is removed from the B controller. This means any src/dst
            # traffic on the 169.254.10/24 subnet will be forwarded out of the gateway
            # of last resort (default route). Since this is internal traffic, we
            # obviously don't want to forward this traffic to the default gateway.
            # This just routes the data into oblivion (drops it).
            try:
                ndb.routes.create(dst='169.254.10.0/23', table=default_table, type=rtn_blackhole).commit()
            except KeyError:
                # blackhole route already exists
                pass
