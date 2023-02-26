#!/usr/bin/env python3

# License: BSD

import os
import random
import string
import sys
from time import sleep

import pytest
from pytest_dependency import depends

apifolder = os.getcwd()
sys.path.append(apifolder)
from auto_config import dev_test, hostname, ip, pool_name
from functions import DELETE, GET, POST, PUT, SSH_TEST
from protocols import iscsi_scsi_connection

from assets.REST.pool import dataset
from assets.REST.snapshot import snapshot, snapshot_rollback

MB=1024*1024
MB_100=100*MB
MB_512=512*MB

# comment pytestmark for development testing with --dev-test
pytestmark = pytest.mark.skipif(dev_test, reason='Skipping for test development testing')

digit = ''.join(random.choices(string.digits, k=2))

file_mountpoint = f'/tmp/iscsi-file-{hostname}'
zvol_mountpoint = f'/tmp/iscsi-zvol-{hostname}'
target_name = f"target{digit}"
dataset_name = f"iscsids{digit}"
file_name = f"iscsi{digit}"
basename = "iqn.2005-10.org.freenas.ctl"
zvol_name = f"ds{digit}"
zvol = f'{pool_name}/{zvol_name}'

import contextlib

from auto_config import ip


@contextlib.contextmanager
def iscsi_auth(tag, user, secret, peeruser=None, peersecret=None):
    payload = {
        'tag': tag,
        'user': user,
        'secret': secret,
    }
    if peeruser and peersecret:
        payload.update({
            'peeruser': peeruser,
            'peersecret': peersecret
        })
    results = POST("/iscsi/auth/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    auth_config = results.json()

    try:
        yield auth_config
    finally:
        results = DELETE(f"/iscsi/auth/id/{auth_config['id']}/")
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def initiator(comment='Default initiator', initiators=[]):
    payload = {
        'comment': comment,
        'initiators': initiators,
    }
    results = POST("/iscsi/initiator/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    initiator_config = results.json()

    try:
        yield initiator_config
    finally:
        results = DELETE(f"/iscsi/initiator/id/{initiator_config['id']}/")
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def portal(listen=[{'ip':'0.0.0.0',}], comment='Default portal',discovery_authmethod='NONE'):
    payload = {
        'listen': listen,
        'comment': comment,
        'discovery_authmethod': discovery_authmethod
    }
    results = POST("/iscsi/portal/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    portal_config = results.json()

    try:
        yield portal_config
    finally:
        results = DELETE(f"/iscsi/portal/id/{portal_config['id']}/")
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def target(target_name, groups, alias=None):
    payload = {
        'name': target_name,
        'groups': groups,
    }
    if alias:
        payload.update({'alias':alias})
    results = POST("/iscsi/target/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    target_config = results.json()

    try:
        yield target_config
    finally:
        results = DELETE(f"/iscsi/target/id/{target_config['id']}/", True)
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def file_extent(pool_name, dataset_name, file_name, filesize=MB_512, extent_name='extent'):
    payload = {
        'type': 'FILE',
        'name': extent_name,
        'filesize': filesize, 
        'path': f'/mnt/{pool_name}/{dataset_name}/{file_name}'
    }
    results = POST("/iscsi/extent/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    extent_config = results.json()

    try:
        yield extent_config
    finally:
        payload = {
            'remove': True
        }
        results = DELETE(f"/iscsi/extent/id/{extent_config['id']}/", payload)
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def zvol_dataset(zvol, volsize=MB_512):
    payload = {
        'name': zvol,
        'type': 'VOLUME',
        'volsize': volsize,
        'volblocksize': '16K'
    }
    results = POST("/pool/dataset/", payload)
    assert results.status_code == 200, results.text
    dataset_config = results.json()

    try:
        yield dataset_config
    finally:
        zvol_url = zvol.replace('/', '%2F')
        results = DELETE(f'/pool/dataset/id/{zvol_url}')
        assert results.status_code == 200, results.text

@contextlib.contextmanager
def zvol_extent(zvol):
    payload = {
        'type': 'DISK',
        'disk': f'zvol/{zvol}',
        'name': 'zvol_extent',
    }
    results = POST("/iscsi/extent/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    extent_config = results.json()

    try:
        yield extent_config
    finally:
        payload = {
            'remove': True
        }
        results = DELETE(f"/iscsi/extent/id/{extent_config['id']}/", payload)
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def target_extent_associate(target_id, extent_id, lun_id=0):
    payload = {
        'target': target_id,
        'lunid': lun_id,
        'extent': extent_id
    }
    results = POST("/iscsi/targetextent/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    associate_config = results.json()

    try:
        yield associate_config
    finally:
        results = DELETE(f"/iscsi/targetextent/id/{associate_config['id']}/", True)
        assert results.status_code == 200, results.text
        assert results.json(), results.text

@contextlib.contextmanager
def configured_target_to_file_extent(target_name, pool_name, dataset_name, file_name, alias=None):
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            with target(target_name, [{'portal': portal_id}], alias) as target_config:
                target_id = target_config['id']
                with dataset(pool_name, dataset_name) as dataset_config:
                    with file_extent(pool_name, dataset_name, file_name) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            yield {
                                'initiator': initiator_config,
                                'portal': portal_config,
                                'target': target_config,
                                'dataset': dataset_config,
                                'extent': extent_config,
                            }

@contextlib.contextmanager
def configured_target_to_zvol_extent(target_name, zvol, alias=None):
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            with target(target_name, [{'portal': portal_id}], alias) as target_config:
                target_id = target_config['id']
                with zvol_dataset(zvol) as dataset_config:
                    with zvol_extent(zvol) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            yield {
                                'initiator': initiator_config,
                                'portal': portal_config,
                                'target': target_config,
                                'dataset': dataset_config,
                                'extent': extent_config,
                            }


def TUR(s):
    """
    Perform a TEST UNIT READY.

    :param s: a pyscsi.SCSI instance

    Will retry once, if necessary.
    """
    try:
        s.testunitready()
    except TypeError:
        s.testunitready()

def _verify_inquiry(s):
    """
    Verify that the supplied SCSI has the expected INQUIRY response.

    :param s: a pyscsi.SCSI instance
    """
    TUR(s)
    r = s.inquiry()
    data = r.result
    assert data['t10_vendor_identification'].decode('utf-8').startswith("TrueNAS"), str(data)
    assert data['product_identification'].decode('utf-8').startswith("iSCSI Disk"), str(data)

def _extract_luns(rl):
    """
    Return a list of LUNs.

    :param rl: a ReportLuns instance (response)
    :return result a list of int LUNIDs

    Currently the results from pyscsi.ReportLuns.unmarshall_datain are (a) subject
    to change & (b) somewhat lacking for our purposes.  Therefore we will parse
    the datain here in a manner more useful for us.
    """
    result = []
    # First 4 bytes are LUN LIST LENGTH
    lun_list_length = int.from_bytes(rl.datain[:4], "big")
    # Next 4 Bytes are RESERVED
    # Remaining bytes are LUNS (8 bytes each)
    luns = rl.datain[8:]
    assert len(luns) >= lun_list_length
    for i in range(0,lun_list_length, 8):
        lun = luns[i:i+8]
        addr_method = (lun[0] >> 6) & 0x3;
        assert addr_method == 0, f"Unsupported Address Method: {addr_method}"
        if addr_method == 0:
            # peripheral device addressing method, don't care about bus.
            result.append(lun[1])
    return result

def _verify_luns(s, expected_luns):
    """
    Verify that the supplied SCSI has the expected LUNs.

    :param s: a pyscsi.SCSI instance
    :param expected_luns: a list of int LUNIDs
    """
    TUR(s)
    # REPORT LUNS
    rl = s.reportluns()
    data = rl.result
    assert isinstance(data, dict), data
    assert 'luns' in data, data
    # Check that we only have LUN 0
    luns = _extract_luns(rl)
    assert len(luns) == len(expected_luns), luns
    assert set(luns) == set(expected_luns), luns

def _verify_capacity(s, expected_capacity):
    """
    Verify that the supplied SCSI has the expected capacity.

    :param s: a pyscsi.SCSI instance
    :param expected_capacity: an int
    """
    TUR(s)
    # READ CAPACITY (16)
    data = s.readcapacity16().result
    returned_size = (data['returned_lba'] + 1 -data['lowest_aligned_lba']) * data['block_length']
    assert returned_size == expected_capacity, {data['returned_lba'], data['block_length']}

def get_targets():
    """
    Return a dictionary of target JSON data, keyed by target name.
    """
    result = {}
    results = GET("/iscsi/target")
    assert results.status_code == 200, results.text
    for target in results.json():
        result[target['name']] = target
    return result

def modify_target(targetid, payload):
    results = PUT(f"/iscsi/target/id/{targetid}/", payload)
    assert results.status_code == 200, results.text

def set_target_alias(targetid, newalias):
    modify_target(targetid, {'alias': newalias})

@pytest.mark.dependency(name="iscsi_cmd_00")
def test_00_setup(request):
    # Enable iSCSI service
    payload = {"enable": True}
    results = PUT("/service/id/iscsitarget/", payload)
    assert results.status_code == 200, results.text
    # Start iSCSI service
    result = POST(
        '/service/start', {
            'service': 'iscsitarget',
        }
    )
    assert result.status_code == 200, result.text
    sleep(1)
    # Verify running
    results = GET("/service/?service=iscsitarget")
    assert results.status_code == 200, results.text
    assert results.json()[0]["state"] == "RUNNING", results.text

def test_01_inquiry(request):
    """
    This tests the Vendor and Product information in an INQUIRY response
    are 'TrueNAS' and 'iSCSI Disk' respectively.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            with target(target_name, [{'portal': portal_id}]) as target_config:
                target_id = target_config['id']
                with dataset(pool_name, dataset_name) as dataset_config:
                    with file_extent(pool_name, dataset_name, file_name) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            iqn = f'{basename}:{target_name}'
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_inquiry(s)

def test_02_read_capacity16(request):
    """
    This tests that the target created returns the correct size to READ CAPACITY (16).

    It performs this test with a couple of sizes for both file & zvol based targets.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            with target(target_name, [{'portal': portal_id}]) as target_config:
                target_id = target_config['id']
                with dataset(pool_name, dataset_name) as dataset_config:
                    # 100 MB file extent
                    with file_extent(pool_name, dataset_name, file_name, MB_100) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            iqn = f'{basename}:{target_name}'
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_capacity(s, MB_100)
                    # 512 MB file extent
                    with file_extent(pool_name, dataset_name, file_name, MB_512) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            iqn = f'{basename}:{target_name}'
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_capacity(s, MB_512)
                # 100 MB zvol extent
                with zvol_dataset(zvol, MB_100):
                    with zvol_extent(zvol) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            iqn = f'{basename}:{target_name}'
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_capacity(s, MB_100)
                # 512 MB zvol extent
                with zvol_dataset(zvol):
                    with zvol_extent(zvol) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            iqn = f'{basename}:{target_name}'
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_capacity(s, MB_512)

def target_test_readwrite16(ip, iqn):
    """
    This tests WRITE SAME (16), READ (16) and WRITE (16) 
    operations on the specified target.
    """
    zeros = bytearray(512)
    deadbeef = bytearray.fromhex('deadbeef') * 128
    deadbeef_lbas = [1,5,7]

    with iscsi_scsi_connection(ip, iqn) as s:
        TUR(s)
        s.blocksize = 512

        # First let's write zeros to the first 12 blocks using WRITE SAME (16)
        w = s.writesame16(0, 12, zeros)

        # Check results using READ (16)
        for lba in range(0,12):
            r = s.read16(lba,1)
            assert r.datain == zeros, r.datain

        # Now let's write DEADBEEF to a few LBAs using WRITE (16)
        for lba in deadbeef_lbas:
            s.write16(lba, 1, deadbeef)
                            
        # Check results using READ (16)
        for lba in range(0,12):
            r = s.read16(lba,1)
            if lba in deadbeef_lbas:
                assert r.datain == deadbeef, r.datain
            else:
                assert r.datain == zeros, r.datain

    # Drop the iSCSI connection and login again
    with iscsi_scsi_connection(ip, iqn) as s:
        TUR(s)
        s.blocksize = 512

        # Check results using READ (16)
        for lba in range(0,12):
            r = s.read16(lba,1)
            if lba in deadbeef_lbas:
                assert r.datain == deadbeef, r.datain
            else:
                assert r.datain == zeros, r.datain

        # Do a WRITE for > 1 LBA
        s.write16(10, 2, deadbeef*2)

        # Check results using READ (16)
        deadbeef_lbas.extend([10, 11])
        for lba in range(0,12):
            r = s.read16(lba,1)
            if lba in deadbeef_lbas:
                assert r.datain == deadbeef, r.datain
            else:
                assert r.datain == zeros, r.datain

        # Do a couple of READ (16) for > 1 LBA
        # At this stage we have written deadbeef to LBAs 1,5,7,10,11
        r = s.read16(0,2)
        assert r.datain == zeros + deadbeef, r.datain
        r = s.read16(1,2)
        assert r.datain == deadbeef + zeros, r.datain
        r = s.read16(2,2)
        assert r.datain == zeros*2, r.datain
        r = s.read16(10,2)
        assert r.datain == deadbeef*2, r.datain

def test_03_readwrite16_file_extent(request):
    """
    This tests WRITE SAME (16), READ (16) and WRITE (16) operations with
    a file extent based iSCSI target.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    with configured_target_to_file_extent(target_name, pool_name, dataset_name, file_name):
        iqn = f'{basename}:{target_name}'
        target_test_readwrite16(ip, iqn)

def test_04_readwrite16_zvol_extent(request):
    """
    This tests WRITE SAME (16), READ (16) and WRITE (16) operations with
    a zvol extent based iSCSI target.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    with configured_target_to_zvol_extent(target_name, zvol):
        iqn = f'{basename}:{target_name}'
        target_test_readwrite16(ip, iqn)

def test_05_chap(request):
    """
    This tests that CHAP auth operates as expected.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    user = "user1"
    secret = 'sec1' + ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            auth_tag = 1
            with iscsi_auth(auth_tag, user, secret) as auth_config:
                with target(target_name, [{'portal': portal_id, 'authmethod': 'CHAP', 'auth': auth_tag}]) as target_config:
                    target_id = target_config['id']
                    with dataset(pool_name, dataset_name) as dataset_config:
                        with file_extent(pool_name, dataset_name, file_name) as extent_config:
                            extent_id = extent_config['id']
                            with target_extent_associate(target_id, extent_id):
                                iqn = f'{basename}:{target_name}'

                                # Try and fail to connect without supplying CHAP creds
                                with pytest.raises(RuntimeError) as ve:
                                    with iscsi_scsi_connection(ip, iqn) as s:
                                        TUR(s)
                                        assert False, "Should not have been able to connect without CHAP credentials."
                                assert 'Unable to connect to' in str(ve), ve

                                # Try and fail to connect supplying incorrect CHAP creds
                                with pytest.raises(RuntimeError) as ve:
                                    with iscsi_scsi_connection(ip, iqn, 0, user, "WrongSecret") as s:
                                        TUR(s)
                                        assert False, "Should not have been able to connect without CHAP credentials."
                                assert 'Unable to connect to' in str(ve), ve

                                # Finally ensure we can connect with the right CHAP creds
                                with iscsi_scsi_connection(ip, iqn, 0, user, secret) as s:
                                    _verify_inquiry(s)

def test_06_mutual_chap(request):
    """
    This tests that Mutual CHAP auth operates as expected.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    user = "user1"
    secret = 'sec1' + ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))
    peer_user = "user2"
    peer_secret = 'sec2' + ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=10))
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            auth_tag = 1
            with iscsi_auth(auth_tag, user, secret, peer_user, peer_secret) as auth_config:
                with target(target_name, [{'portal': portal_id, 'authmethod': 'CHAP_MUTUAL', 'auth': auth_tag}]) as target_config:
                    target_id = target_config['id']
                    with dataset(pool_name, dataset_name) as dataset_config:
                        with file_extent(pool_name, dataset_name, file_name) as extent_config:
                            extent_id = extent_config['id']
                            with target_extent_associate(target_id, extent_id):
                                iqn = f'{basename}:{target_name}'

                                # Try and fail to connect without supplying Mutual CHAP creds
                                with pytest.raises(RuntimeError) as ve:
                                    with iscsi_scsi_connection(ip, iqn) as s:
                                        TUR(s)
                                        assert False, "Should not have been able to connect without CHAP credentials."
                                assert 'Unable to connect to' in str(ve), ve

                                # Try and fail to connect supplying incorrect CHAP creds (not mutual)
                                with pytest.raises(RuntimeError) as ve:
                                    with iscsi_scsi_connection(ip, iqn, 0, user, "WrongSecret") as s:
                                        TUR(s)
                                        assert False, "Should not have been able to connect with incorrect CHAP credentials."
                                assert 'Unable to connect to' in str(ve), ve

                                # Ensure we can connect with the right CHAP creds, if we *choose* not
                                # to validate things.
                                with iscsi_scsi_connection(ip, iqn, 0, user, secret) as s:
                                    _verify_inquiry(s)

                                # Try and fail to connect supplying incorrect Mutual CHAP creds
                                with pytest.raises(RuntimeError) as ve:
                                    with iscsi_scsi_connection(ip, iqn, 0, user, secret, peer_user, "WrongSecret") as s:
                                        TUR(s)
                                        assert False, "Should not have been able to connect with incorrect Mutual CHAP credentials."
                                assert 'Unable to connect to' in str(ve), ve

                                # Finally ensure we can connect with the right Mutual CHAP creds
                                with iscsi_scsi_connection(ip, iqn, 0, user, secret, peer_user, peer_secret) as s:
                                    _verify_inquiry(s)

def test_07_report_luns(request):
    """
    This tests REPORT LUNS and accessing multiple LUNs on a target.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    iqn = f'{basename}:{target_name}'
    with initiator() as initiator_config:
        with portal() as portal_config:
            portal_id = portal_config['id']
            with target(target_name, [{'portal': portal_id}]) as target_config:
                target_id = target_config['id']
                with dataset(pool_name, dataset_name) as dataset_config:
                    # LUN 0 (100 MB file extent)
                    with file_extent(pool_name, dataset_name, file_name, MB_100) as extent_config:
                        extent_id = extent_config['id']
                        with target_extent_associate(target_id, extent_id):
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_luns(s, [0])
                                _verify_capacity(s, MB_100)
                            # Now create a 512 MB zvol and associate with LUN 1
                            with zvol_dataset(zvol):
                                with zvol_extent(zvol) as extent_config:
                                    extent_id = extent_config['id']
                                    with target_extent_associate(target_id, extent_id, 1):
                                        # Connect to LUN 0
                                        with iscsi_scsi_connection(ip, iqn, 0) as s0:
                                            _verify_luns(s0, [0, 1])
                                            _verify_capacity(s0, MB_100)
                                        # Connect to LUN 1
                                        with iscsi_scsi_connection(ip, iqn, 1) as s1:
                                            _verify_luns(s1, [0, 1])
                                            _verify_capacity(s1, MB_512)
                            # Check again now that LUN 1 has been removed again.
                            with iscsi_scsi_connection(ip, iqn) as s:
                                _verify_luns(s, [0])
                                _verify_capacity(s, MB_100)

def target_test_snapshot_single_login(ip, iqn, dataset_id):
    """
    This tests snapshots with an iSCSI target using a single
    iSCSI session.
    """
    zeros = bytearray(512)
    deadbeef = bytearray.fromhex('deadbeef') * 128
    deadbeef_lbas = [1,5,7]
    all_deadbeef_lbas = [1,5,7,10,11]

    with iscsi_scsi_connection(ip, iqn) as s:
        TUR(s)
        s.blocksize = 512

        # First let's write zeros to the first 12 blocks using WRITE SAME (16)
        w = s.writesame16(0, 12, zeros)

        # Check results using READ (16)
        for lba in range(0,12):
            r = s.read16(lba,1)
            assert r.datain == zeros, r.datain

        # Take snap0
        with snapshot(dataset_id, "snap0") as snap0_config:

            # Now let's write DEADBEEF to a few LBAs using WRITE (16)
            for lba in deadbeef_lbas:
                s.write16(lba, 1, deadbeef)

            # Check results using READ (16)
            for lba in range(0,12):
                r = s.read16(lba,1)
                if lba in deadbeef_lbas:
                    assert r.datain == deadbeef, r.datain
                else:
                    assert r.datain == zeros, r.datain

            # Take snap1
            with snapshot(dataset_id, "snap1") as snap1_config:

                # Do a WRITE for > 1 LBA
                s.write16(10, 2, deadbeef*2)

                # Check results using READ (16)
                for lba in range(0,12):
                    r = s.read16(lba,1)
                    if lba in all_deadbeef_lbas:
                        assert r.datain == deadbeef, r.datain
                    else:
                        assert r.datain == zeros, r.datain

                # Now revert to snap1
                snapshot_rollback(snap1_config['id'])


                # Check results using READ (16)
                for lba in range(0,12):
                    r = s.read16(lba,1)
                    if lba in deadbeef_lbas:
                        assert r.datain == deadbeef, r.datain
                    else:
                        assert r.datain == zeros, r.datain

            # Now revert to snap0
            snapshot_rollback(snap0_config['id'])

            # Check results using READ (16)
            for lba in range(0,12):
                r = s.read16(lba,1)
                assert r.datain == zeros, r.datain

def target_test_snapshot_multiple_login(ip, iqn, dataset_id):
    """
    This tests snapshots with an iSCSI target using multiple
    iSCSI sessions.
    """
    zeros = bytearray(512)
    deadbeef = bytearray.fromhex('deadbeef') * 128
    deadbeef_lbas = [1,5,7]
    all_deadbeef_lbas = [1,5,7,10,11]

    with iscsi_scsi_connection(ip, iqn) as s:
        TUR(s)
        s.blocksize = 512

        # First let's write zeros to the first 12 blocks using WRITE SAME (16)
        w = s.writesame16(0, 12, zeros)

        # Check results using READ (16)
        for lba in range(0,12):
            r = s.read16(lba,1)
            assert r.datain == zeros, r.datain

    # Take snap0
    with snapshot(dataset_id, "snap0") as snap0_config:

        with iscsi_scsi_connection(ip, iqn) as s:
            TUR(s)
            s.blocksize = 512

            # Now let's write DEADBEEF to a few LBAs using WRITE (16)
            for lba in deadbeef_lbas:
                s.write16(lba, 1, deadbeef)

            # Check results using READ (16)
            for lba in range(0,12):
                r = s.read16(lba,1)
                if lba in deadbeef_lbas:
                    assert r.datain == deadbeef, r.datain
                else:
                    assert r.datain == zeros, r.datain

        # Take snap1
        with snapshot(dataset_id, "snap1") as snap1_config:

            with iscsi_scsi_connection(ip, iqn) as s:
                TUR(s)
                s.blocksize = 512

                # Do a WRITE for > 1 LBA
                s.write16(10, 2, deadbeef*2)

                # Check results using READ (16)
                for lba in range(0,12):
                    r = s.read16(lba,1)
                    if lba in all_deadbeef_lbas:
                        assert r.datain == deadbeef, r.datain
                    else:
                        assert r.datain == zeros, r.datain

                # Now revert to snap1
                snapshot_rollback(snap1_config['id'])

        with iscsi_scsi_connection(ip, iqn) as s:
            TUR(s)
            s.blocksize = 512

            # Check results using READ (16)
            for lba in range(0,12):
                r = s.read16(lba,1)
                if lba in deadbeef_lbas:
                    assert r.datain == deadbeef, r.datain
                else:
                    assert r.datain == zeros, r.datain

        # Now revert to snap0
        snapshot_rollback(snap0_config['id'])

        with iscsi_scsi_connection(ip, iqn) as s:
            TUR(s)
            s.blocksize = 512
            # Check results using READ (16)
            for lba in range(0,12):
                r = s.read16(lba,1)
                assert r.datain == zeros, r.datain

def test_08_snapshot_zvol_extent(request):
    """
    This tests snapshots with a zvol extent based iSCSI target.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    iqn = f'{basename}:{target_name}'
    with configured_target_to_zvol_extent(target_name, zvol) as iscsi_config:
        target_test_snapshot_single_login(ip, iqn, iscsi_config['dataset']['id'])
    with configured_target_to_zvol_extent(target_name, zvol) as iscsi_config:
        target_test_snapshot_multiple_login(ip, iqn, iscsi_config['dataset']['id'])

def test_09_snapshot_file_extent(request):
    """
    This tests snapshots with a file extent based iSCSI target.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    iqn = f'{basename}:{target_name}'
    with configured_target_to_file_extent(target_name, pool_name, dataset_name, file_name) as iscsi_config:
        target_test_snapshot_single_login(ip, iqn, iscsi_config['dataset']['id'])
    with configured_target_to_zvol_extent(target_name, zvol) as iscsi_config:
        target_test_snapshot_multiple_login(ip, iqn, iscsi_config['dataset']['id'])

def test_10_target_alias(request):
    """
    This tests iSCSI target alias.

    At the moment SCST does not use the alias usefully (e.g. TargetAlias in
    LOGIN response).  When this is rectified this test should be extended.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")

    data = {}
    for t in ["A", "B"]:
       data[t] = {}
       data[t]['name'] = f"{target_name}{t.lower()}"
       data[t]['alias'] = f"{target_name}{t}_alias"
       data[t]['file'] = f"{target_name}{t}_file"

    A = data['A']
    B = data['B']
    with configured_target_to_file_extent(A['name'], pool_name, dataset_name, A['file'], A['alias']) as iscsi_config:
        with target(B['name'], [{'portal': iscsi_config['portal']['id']}]) as targetB_config:
            with file_extent(pool_name, dataset_name, B['file'], extent_name="extentB") as extentB_config:
                with target_extent_associate(targetB_config['id'], extentB_config['id']):
                    # Created two targets, one with an alias, one without.  Check them.
                    targets = get_targets()
                    assert targets[A['name']]['alias'] == A['alias'], targets[A['name']]['alias']
                    assert targets[B['name']]['alias'] is None, targets[B['name']]['alias']

                    # Update alias for B
                    set_target_alias(targets[B['name']]['id'], B['alias'])
                    targets = get_targets()
                    assert targets[A['name']]['alias'] == A['alias'], targets[A['name']]['alias']
                    assert targets[B['name']]['alias'] == B['alias'], targets[B['name']]['alias']

                    # Clear alias for A
                    set_target_alias(targets[A['name']]['id'], "")
                    targets = get_targets()
                    assert targets[A['name']]['alias'] is None, targets[A['name']]['alias']
                    assert targets[B['name']]['alias'] == B['alias'], targets[B['name']]['alias']

                    # Clear alias for B
                    set_target_alias(targets[B['name']]['id'], "")
                    targets = get_targets()
                    assert targets[A['name']]['alias'] is None, targets[A['name']]['alias']
                    assert targets[B['name']]['alias'] is None, targets[B['name']]['alias']

def test_11_modify_portal(request):
    """
    Test that we can modify a target portal.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    with portal() as portal_config:
        portal_id = portal_config['id']
        assert portal_config['comment'] == 'Default portal', portal_config
        # First just change the comment
        payload = {'comment' : 'New comment'}
        results = PUT(f"/iscsi/portal/id/{portal_config['id']}", payload)
        # Then try to reapply everything
        payload = {'comment': 'test1', 'discovery_authmethod': 'NONE', 'discovery_authgroup': None, 'listen': [{'ip': '0.0.0.0'}]}
        # payload = {'comment': 'test1', 'discovery_authmethod': 'NONE', 'discovery_authgroup': None, 'listen': [{'ip': '0.0.0.0'}, {'ip': '::'}]}
        results = PUT(f"/iscsi/portal/id/{portal_config['id']}", payload)
        assert results.status_code == 200, results.text

def test_12_pblocksize_setting(request):
    """
    This tests whether toggling pblocksize has the desired result on READ CAPACITY 16, i.e.
    whether setting it results in LOGICAL BLOCKS PER PHYSICAL BLOCK EXPONENT being zero.
    """
    depends(request, ["pool_04", "iscsi_cmd_00"], scope="session")
    iqn = f'{basename}:{target_name}'
    with configured_target_to_file_extent(target_name, pool_name, dataset_name, file_name) as iscsi_config:
        extent_config = iscsi_config['extent']
        with iscsi_scsi_connection(ip, iqn) as s:
            TUR(s)
            data = s.readcapacity16().result
            # By default 512 << 3 == 4096
            assert data['lbppbe'] == 3, data

            # First let's just change the blocksize to 2K
            payload = {'blocksize' : 2048}
            results = PUT(f"/iscsi/extent/id/{extent_config['id']}", payload)
            assert results.status_code == 200, results.text

            TUR(s)
            data = s.readcapacity16().result
            assert data['block_length'] == 2048, data
            assert data['lbppbe'] == 1, data

            # Now let's change it back to 512, but also set pblocksize
            payload = {'blocksize' : 512, 'pblocksize' : True}
            results = PUT(f"/iscsi/extent/id/{extent_config['id']}", payload)
            assert results.status_code == 200, results.text

            TUR(s)
            data = s.readcapacity16().result
            assert data['block_length'] == 512, data
            assert data['lbppbe'] == 0, data

    with configured_target_to_zvol_extent(target_name, zvol) as iscsi_config:
        extent_config = iscsi_config['extent']
        with iscsi_scsi_connection(ip, iqn) as s:
            TUR(s)
            data = s.readcapacity16().result
            # We created a vol with volblocksize == 16K (512 << 5)
            assert data['lbppbe'] == 5, data

            # First let's just change the blocksize to 4K
            payload = {'blocksize' : 4096}
            results = PUT(f"/iscsi/extent/id/{extent_config['id']}", payload)
            assert results.status_code == 200, results.text

            TUR(s)
            data = s.readcapacity16().result
            assert data['block_length'] == 4096, data
            assert data['lbppbe'] == 2, data

            # Now let's also set pblocksize
            payload = {'pblocksize' : True}
            results = PUT(f"/iscsi/extent/id/{extent_config['id']}", payload)
            assert results.status_code == 200, results.text

            TUR(s)
            data = s.readcapacity16().result
            assert data['block_length'] == 4096, data
            assert data['lbppbe'] == 0, data

def test_99_teardown(request):
    # Disable iSCSI service
    depends(request, ["iscsi_cmd_00"])
    payload = {'enable': False}
    results = PUT("/service/id/iscsitarget/", payload)
    assert results.status_code == 200, results.text
    # Stop iSCSI service.
    results = POST('/service/stop/', {'service': 'iscsitarget'})
    assert results.status_code == 200, results.text
    sleep(1)
    # Verify stopped
    results = GET("/service/?service=iscsitarget")
    assert results.status_code == 200, results.text
    assert results.json()[0]["state"] == "STOPPED", results.text

