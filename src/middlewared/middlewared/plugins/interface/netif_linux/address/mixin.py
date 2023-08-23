import ipaddress

from pyroute2 import IPRoute

from middlewared.plugins.interface.netif_linux.utils import run

from .ipv6 import ipv6_netmask_to_prefixlen
from .types import AddressFamily, InterfaceAddress, LinkAddress

__all__ = ["AddressMixin"]


class AddressMixin:
    def add_address(self, address):
        self._address_op("add", address)

    def flush(self):
        # Remove all configured ip addresses
        run(['ip', 'addr', 'flush', 'dev', self.name, 'scope', 'global'])

    def remove_address(self, address):
        self._address_op("del", address)

    def replace_address(self, address):
        self._address_op("replace", address)

    def _address_op(self, op, address):
        if isinstance(address.address, LinkAddress):
            return

        netmask = str(address.netmask)
        if isinstance(address.address, ipaddress.IPv6Address):
            netmask = ipv6_netmask_to_prefixlen(netmask)

        cmd = ["ip", "addr", op, f"{address.address}/{netmask}"]
        if op == 'add':
            # make sure we tell linux to assign proper broadcast address
            # when adding an IPv4 address to an interface
            # (doesn't apply to IPv6)
            cmd.extend(["brd", "+"]) if ':' not in f'{address.address}' else None
        cmd.extend(["dev", self.name])

        run(cmd)

    def _get_addresses(self):
        addresses = []
        with IPRoute(strict_check=True) as ipr:
            # strict_check forces kernel to do the filtering increasing performance
            if index := (ipr.link_lookup(ifname=self.name) or [None])[0]:
                # The kernel doesn't return IFA_LABEL for IPv6 addresses so we have
                # to lookup the index for a given interface
                for addr in ipr.addr('dump', index=index):
                    if addr['family'] == AddressFamily.INET.value:
                        addresses.append(InterfaceAddress(
                            AddressFamily.INET,
                            ipaddress.IPv4Interface(f'{addr.get_attr("IFA_ADDRESS")}/{addr["prefixlen"]}'),
                        ))
                    elif addr['family'] == AddressFamily.INET6.value:
                        addresses.append(InterfaceAddress(
                            AddressFamily.INET6,
                            ipaddress.IPv6Interface(f'{addr.get_attr("IFA_ADDRESS")}/{addr["prefixlen"]}'),
                        ))

                for mac in ipr.link('dump', index=index):
                    if mac_addr := mac.get_attr('IFLA_ADDRESS'):
                        addresses.append(InterfaceAddress(AddressFamily.LINK, LinkAddress(self.name, mac_addr)))

        return addresses

    @property
    def addresses(self):
        return self._get_addresses()
