#!/usr/bin/env python3

# Author: Eric Turgeon
# License: BSD

import pytest
import sys
import os
import random
from pytest_dependency import depends
apifolder = os.getcwd()
sys.path.append(apifolder)
from auto_config import ip, ha
from functions import GET, PUT, POST

if ha and 'virtual_ip' in os.environ:
    interface = os.environ['iface']
    controller1_ip = os.environ['controller1_ip']
    controller2_ip = os.environ['controller2_ip']
    virtual_ip = os.environ['virtual_ip']
    vhid = os.environ['vhid']
else:
    from auto_config import interface

aliases = {'address': ip}
# Create a random IP
vlan1_ip = f'192.168.0.{random.randint(10, 250)}'


if not ha:
    @pytest.mark.dependency(name='GET_NAME')
    def test_01_get_interface_name():
        results = GET(f'/interface?name={interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), list) is True, results.text
        assert results.json()[0]['name'] == interface, results.text

    @pytest.mark.dependency(name='GET_ALIASES')
    def test_02_get_interface_aliases_ip(request):
        depends(request, ['GET_NAME'])
        results = GET(f'/interface?name={interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), list) is True, results.text
        for aliases_list in results.json()[0]['state']['aliases']:
            assert isinstance(aliases_list['address'], str) is True, results.text
            # no break to look all address value are string
            if ip in aliases_list['address']:
                interface_ip = aliases_list['address']
        assert interface_ip == ip, results.text

    @pytest.mark.dependency(name='GET_ALIASES_BROADCAST')
    def test_03_get_interface_aliases_broadcast_ip(request):
        depends(request, ['GET_ALIASES'])
        results = GET(f'/interface?name={interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), list) is True, results.text
        for aliases_list in results.json()[0]['state']['aliases']:
            if ip in aliases_list['address']:
                broadcast_ip = aliases_list['broadcast']
                break
        assert isinstance(broadcast_ip, str) is True, results.text
        aliases['broadcast'] = broadcast_ip

    @pytest.mark.dependency(name='GET_ALIASES_TYPE')
    def test_04_get_interface_aliases_type(request):
        depends(request, ['GET_ALIASES_BROADCAST'])
        results = GET(f'/interface?name={interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), list) is True, results.text
        for aliases_list in results.json()[0]['state']['aliases']:
            assert isinstance(aliases_list['type'], str) is True, results.text
            # no break to look all address value are string
            if ip in aliases_list['address']:
                types = aliases_list['type']
        assert types in ('INET', 'INET6'), results.text
        aliases['type'] = types

    @pytest.mark.dependency(name='GET_ALIASES_NETMASK')
    def test_05_get_interface_aliases_netmask(request):
        depends(request, ['GET_ALIASES_TYPE'])
        results = GET(f'/interface?name={interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), list) is True, results.text
        for aliases_list in results.json()[0]['state']['aliases']:
            if ip in aliases_list['address']:
                netmask = aliases_list['netmask']
                break
        assert isinstance(netmask, int) is True, results.text
        aliases['netmask'] = netmask

    @pytest.mark.dependency(name='IN_USE')
    def test_06_get_interface_ipv4_in_use(request):
        depends(request, ['GET_ALIASES_NETMASK'])
        global results
        results = POST('/interface/ip_in_use/', {'ipv4': True})
        assert results.status_code == 200, results.text

    @pytest.mark.dependency(name='VERIFY_IN_USE')
    @pytest.mark.parametrize('dkey', ['type', 'address', 'netmask', 'broadcast'])
    def test_07_look_at_interface_ipv4_in_use_output_(dkey, request):
        depends(request, ['IN_USE'])
        for dictionary in results.json():
            if dictionary[dkey] == aliases[dkey]:
                assert dictionary[dkey] == aliases[dkey], results.text
                break
        else:
            assert False, results.text

    @pytest.mark.dependency(name='INITIAL_CONFIG')
    def test_08_set_main_interface_ipv4_to_false(request):
        depends(request, ['VERIFY_IN_USE'])
        payload = {
            'ipv4_dhcp': False,
            'aliases': [
                {
                    'address': ip,
                    'netmask': aliases['netmask']
                }
            ]
        }
        results = PUT(f'/interface/id/{interface}/', payload)
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict) is True, results.text
        assert results.json()['ipv4_dhcp'] is False, results.text

    @pytest.mark.dependency(name='DHCP_IS_FALSE')
    def test_09_looking_main_interface_ipv4_dhcp_if_is_false(request):
        depends(request, ['INITIAL_CONFIG'])
        results = GET(f'/interface/id/{interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict) is True, results.text
        assert results.json()['ipv4_dhcp'] is False, results.text

    @pytest.mark.dependency(name='ALIAS_VERIFICATION')
    @pytest.mark.parametrize('dkey', ['type', 'address', 'netmask'])
    def test_10_look_at_interface_aliases_output_(dkey, request):
        depends(request, ['DHCP_IS_FALSE'])
        results = GET(f'/interface/id/{interface}')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict) is True, results.text
        assert results.json()['aliases'][0][dkey] == aliases[dkey], results.text

    @pytest.mark.dependency(name='CREATE_VLAN1')
    def test_11_creating_vlan1_interface(request):
        depends(request, ['ALIAS_VERIFICATION'])
        global payload
        payload = {
            'ipv4_dhcp': False,
            'aliases': [
                {
                    'address': vlan1_ip,
                    'netmask': aliases['netmask']
                }
            ],
            'vlan_parent_interface': interface,
            'name': 'vlan1',
            'type': 'VLAN',
            'vlan_tag': 1,
            'vlan_pcp': 1
        }
        global results
        results = POST('/interface/', payload)
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict) is True, results.text
        global interfaces_id
        interfaces_id = results.json()['id']

    @pytest.mark.dependency(name='VERIFY_VLAN1')
    @pytest.mark.parametrize('dkey', ['ipv4_dhcp', 'name', 'vlan_parent_interface',
                                      'type', 'vlan_tag', 'vlan_pcp'])
    def test_12_compare_payload_with_created_vlan1_interface_result_output_(dkey, request):
        depends(request, ['CREATE_VLAN1'])
        assert results.json()[dkey] == payload[dkey], results.text

    @pytest.mark.dependency(name='GET_VLAN1')
    def test_13_get_the_vlan1_interface_results(request):
        depends(request, ['VERIFY_VLAN1'])
        global results
        results = GET(f'/interface/id/{interfaces_id}/')
        assert results.status_code == 200, results.text
        assert isinstance(results.json(), dict) is True, results.text

    @pytest.mark.parametrize('dkey', ['ipv4_dhcp', 'name', 'vlan_parent_interface',
                                      'type', 'vlan_tag', 'vlan_pcp'])
    def test_14_compare_payload_with_get_vlan1_interface_result_output_(dkey, request):
        depends(request, ['GET_VLAN1'])
        assert results.json()[dkey] == payload[dkey], results.text


if ha and 'virtual_ip' in os.environ:
    @pytest.mark.dependency(name='INITIAL_CONFIG')
    def test_15_set_interface_for_ha():
        payload = {
            'ipv4_dhcp': False,
            'failover_critical': True,
            'failover_vhid': vhid,
            'failover_group': 1,
            'aliases': [
                {
                    'type': 'INET',
                    'address': controller1_ip,
                    'netmask': 23
                }
            ],
            'failover_aliases': [
                {
                    'type': 'INET',
                    'address': controller2_ip,
                }
            ],
            'failover_virtual_aliases': [
                {
                    'type': 'INET',
                    'address': virtual_ip,
                }
            ],
        }

        results = PUT(f'/interface/id/{interface}/', payload, controller_a=ha)
        assert results.status_code == 200, results.text
        global interfaces_id
        interfaces_id = results.json()['id']


@pytest.mark.dependency(name='PENDING_TRUE')
def test_16_get_interface_has_pending_changes(request):
    depends(request, ['INITIAL_CONFIG'])
    results = GET('/interface/has_pending_changes', controller_a=ha)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), bool) is True, results.text
    assert results.json() is True, results.text


@pytest.mark.dependency(name='COMMIT')
def test_17_commit_interface(request):
    depends(request, ['PENDING_TRUE'])
    results = POST('/interface/commit/', {'rollback': True, 'checkin_timeout': 10}, controller_a=ha)
    assert results.status_code == 200, results.text


@pytest.mark.dependency(name='CHECKIN_WAITING')
def test_18_get_interface_checkin_waiting(request):
    depends(request, ['COMMIT'])
    results = GET('/interface/checkin_waiting/', controller_a=ha)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), float), results.text


@pytest.mark.dependency(name='CHECKIN')
def test_19_get_interface_checkin(request):
    depends(request, ['CHECKIN_WAITING'])
    results = GET('/interface/checkin/', controller_a=ha)
    assert results.status_code == 200, results.text
    assert results.json() is None, results.text


@pytest.mark.dependency(name='PENDING_FALSE')
def test_20_get_interface_has_pending_changes(request):
    depends(request, ['CHECKIN'])
    results = GET('/interface/has_pending_changes', controller_a=ha)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), bool) is True, results.text
    assert results.json() is False, results.text


def test_21_get_the_vlan1_interface_from_id(request):
    depends(request, ['PENDING_FALSE'])
    results = GET(f'/interface/id/{interfaces_id}/', controller_a=ha)
    assert results.status_code == 200, results.text
