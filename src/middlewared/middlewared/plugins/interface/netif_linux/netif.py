from pyroute2 import IPRoute

from .bridge import create_bridge
from .interface import Interface, CLONED_PREFIXES
from .lagg import AggregationProtocol, create_lagg
from .utils import run
from .vlan import create_vlan

__all__ = ["AggregationProtocol", "create_vlan", "create_interface", "destroy_interface", "get_interface",
           "list_interfaces", "CLONED_PREFIXES"]


def create_interface(name):
    if name.startswith("br"):
        create_bridge(name)
        return name

    if name.startswith("bond"):
        create_lagg(name)
        return name

    raise ValueError(f"Invalid interface name: {name!r}")


def destroy_interface(name):
    if name.startswith(("bond", "br", "vlan", "kube-bridge")):
        run(["ip", "link", "delete", name])
    else:
        run(["ip", "link", "set", name, "down"])


def get_interface(name, safe_retrieval=False):
    ifaces = list_interfaces()
    return ifaces.get(name) if safe_retrieval else ifaces[name]


def list_interfaces():
    info = dict()
    with IPRoute() as ipr:
        for dev in ipr.get_links():
            name = dev.get_attr('IFLA_IFNAME')
            info[name] = Interface(name)
    return info
