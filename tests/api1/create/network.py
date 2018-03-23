#!/usr/bin/env python3.6

# Author: Eric Turgeon
# License: BSD

import pytest
import sys
import os

apifolder = os.getcwd()
sys.path.append(apifolder)
from auto_config import interface
from functions import POST, PUT

from config import *

Reason = "BRIDGEDOMAIN BRIDGEHOST BRIDGEDNS BRIDGEGW "
Reason += "are missing in ixautomation.conf"

route_and_dns_cfg = pytest.mark.skipif(all(["BRIDGEDOMAIN" in locals(),
                                            "BRIDGEHOST" in locals(),
                                            "BRIDGEDNS" in locals(),
                                            "BRIDGEGW" in locals()
                                            ]) is False, reason=Reason)


def test_01_configure_interface_dhcp(self):
    payload = {"int_dhcp": "true",
               "int_name": "ext",
               "int_interface": interface}
    assert POST("/network/interface/", payload) == 201


@route_and_dns_cfg
def test_02_Setting_default_route_and_DNS(self):
    payload = {"gc_domain": BRIDGEDOMAIN,
               "gc_hostname": BRIDGEHOST,
               "gc_ipv4gateway": BRIDGEGW,
               "gc_nameserver1": BRIDGEDNS}
    assert PUT("/network/globalconfiguration/", payload) == 200
