#!/usr/bin/env python3.6

# Author: Eric Turgeon
# License: BSD
# Location for tests into REST API of FreeNAS

import unittest
import pytest
import sys
import os

apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST, GET_OUTPUT, DELETE, DELETE_ALL, OSX_TEST
from auto_config import ip
try:
    from config import BRIDGEHOST
except ImportError:
    RunTest = False
else:
    MOUNTPOINT = "/tmp/afp-osx" + BRIDGEHOST
    RunTest = True

DATASET = "afp-osx"
AFP_NAME = "MyAFPShare"
AFP_PATH = "/mnt/tank/" + DATASET
VOL_GROUP = "qa"
Reason = "BRIDGEHOST BRIDGETEST are not in ixautomation.conf"


class update_afp_osx_test(unittest.TestCase):

    # Clean up any leftover items from previous failed AD LDAP or SMB runs
    @classmethod
    def setUpClass(inst):
        PUT("/services/afp/", {"afp_srv_guest": False})
        payload = {"afp_name": AFP_NAME, "afp_path": AFP_PATH}
        DELETE_ALL("/sharing/afp/", payload)
        DELETE("/storage/volume/1/datasets/%s/" % DATASET)
        # cmd = 'umount -f "%s"; rmdir "%s"; exit 0;' % (MOUNTPOINT, MOUNTPOINT)
        # OSX_TEST(cmd)

    def test_01_Creating_AFP_dataset(self):
        assert POST("/storage/volume/tank/datasets/", {"name": DATASET}) == 201

    def test_02_Updating_AFP_service(self):
        payload = {"afp_srv_connections_limit": "100"}
        assert PUT("/services/afp/", payload) == 200

    def test_03_Enabling_AFP_service(self):
        payload = {"afp_srv_guest": True, "afp_srv_bindip": ip}
        assert PUT("/services/afp/", payload) == 200

    # Now start the service
    def test_04_Starting_AFP_service(self):
        assert PUT("/services/services/afp/", {"srv_enable": True}) == 200

    def test_05_Checking_to_see_if_AFP_service_is_enabled(self):
        assert GET_OUTPUT("/services/services/afp/", "srv_state") == "RUNNING"

    def test_06_Changing_permissions_on_AFP_PATH(self):
        payload = {"mp_path": AFP_PATH,
                   "mp_acl": "unix",
                   "mp_mode": "777",
                   "mp_user": "root",
                   "mp_group": "wheel"}
        assert PUT("/storage/permission/", payload) == 201

    def test_07_Creating_a_AFP_share_on_AFP_PATH(self):
        payload = {"afp_name": AFP_NAME, "afp_path": AFP_PATH}
        assert POST("/sharing/afp/", payload) == 201

    # Mount share on OSX system and create a test file
    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_08_Create_mount_point_for_AFP_on_OSX_system(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        assert OSX_TEST('mkdir -p "%s"' % MOUNTPOINT,
                        username, password, host) is True

    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_09_Mount_AFP_share_on_OSX_system(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        cmd = 'mount -t afp "afp://%s/%s" "%s"' % (ip, AFP_NAME, MOUNTPOINT)
        assert OSX_TEST(cmd, username, password, host) is True

    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_11_Create_file_on_AFP_share_via_OSX_to_test_permissions(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        assert OSX_TEST('touch "%s/testfile.txt"' % MOUNTPOINT,
                        username, password, host) is True

    # Move test file to a new location on the AFP share
    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_12_Moving_AFP_test_file_into_a_new_directory(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        cmd = 'mkdir -p "%s/tmp" && ' % MOUNTPOINT
        cmd += 'mv "%s/testfile.txt" ' % MOUNTPOINT
        cmd += '"%s/tmp/testfile.txt"' % MOUNTPOINT
        assert OSX_TEST(cmd, username, password, host) is True

    # Delete test file and test directory from AFP share
    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_13_Deleting_test_file_and_directory_from_AFP_share(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        cmd = 'rm -f "%s/tmp/testfile.txt" && ' % MOUNTPOINT
        cmd += 'rmdir "%s/tmp"' % MOUNTPOINT
        assert OSX_TEST(cmd, username, password, host) is True

    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_14_Verifying_test_file_directory_were_successfully_removed(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        cmd = 'find -- "%s/" -prune -type d -empty | grep -q .' % MOUNTPOINT
        assert OSX_TEST(cmd, username, password, host) is True

    # Clean up mounted AFP share
    @pytest.mark.skipif(RunTest is False, reason=Reason)
    def test_15_Unmount_AFP_share(self):
        host = pytest.importorskip("config.OSX_HOST")
        username = pytest.importorskip("config.OSX_USERNAME")
        password = pytest.importorskip("config.OSX_PASSWORD")
        assert OSX_TEST('umount -f "%s"' % MOUNTPOINT,
                        username, password, host) is True

    # Test disable AFP
    def test_16_Verify_AFP_service_can_be_disabled(self):
        assert PUT("/services/afp/", {"afp_srv_guest": False}) == 200

    # Test delete AFP dataset
    def test_17_Verify_AFP_dataset_can_be_destroyed(self):
        assert DELETE("/storage/volume/1/datasets/%s/" % DATASET) == 204
