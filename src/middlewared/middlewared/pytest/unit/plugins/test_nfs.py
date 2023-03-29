from mock import ANY, Mock, patch

from middlewared.plugins.nfs import SharingNFSService


def test__sharing_nfs_service__validate_hosts_and_networks__host_is_32_network():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
        "/mnt/data/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [
                {
                    "path": "/mnt/data/a",
                    "hosts": ["192.168.0.1"],
                    "networks": [],
                },
            ],
            {
                "path": "/mnt/data/b",
                "hosts": ["192.168.0.1"],
                "networks": [],
            },
            "sharingnfs_update",
            verrors,
            {
                "192.168.0.1": "192.168.0.1",
            },
        )

        verrors.add.assert_called_once_with("sharingnfs_update.hosts", ANY)


def test__sharing_nfs_service__validate_hosts_and_networks__dataset_is_already_exported():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
        "/mnt/data/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [
                {
                    "path": "/mnt/data/a",
                    "hosts": [],
                    "networks": ["192.168.0.0/24"],
                },
            ],
            {
                "path": "/mnt/data/b",
                "hosts": [],
                "networks": ["192.168.0.0/24"],
            },
            "sharingnfs_update",
            verrors,
            {
                "192.168.0.1": "192.168.0.1",
            },
        )

        verrors.add.assert_called_once_with("sharingnfs_update.networks", ANY)


def test__sharing_nfs_service__validate_hosts_and_networks__fs_is_already_exported_for_world():
    with patch("middlewared.plugins.nfs.os.stat", lambda dev: {
        "/mnt/data/a": Mock(st_dev=1),
        "/mnt/data/b": Mock(st_dev=1),
    }[dev]):
        middleware = Mock()

        verrors = Mock()

        SharingNFSService(middleware).validate_hosts_and_networks(
            [
                {
                    "path": "/mnt/data/a",
                    "hosts": ["192.168.0.1"],
                    "networks": [],
                },
            ],
            {
                "path": "/mnt/data/b",
                "hosts": [],
                "networks": [],
            },
            "sharingnfs_update",
            verrors,
            {
                "192.168.0.1": "192.168.0.1",
            },
        )
        # This is now a passing condition: NAS-120957
        verrors.add.assert_not_called()
