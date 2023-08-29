import errno

import pytest

from middlewared.service_exception import CallError
from middlewared.test.integration.assets.pool import another_pool
from middlewared.test.integration.utils import call, pool


@pytest.fixture(scope="session")
def passphrase_encrypted_pool_session():
    with another_pool({"encryption": True, "encryption_options": {"passphrase": "passphrase"}}) as p:
        yield p["name"]


@pytest.fixture(scope="function")
def passphrase_encrypted_pool(passphrase_encrypted_pool_session):
    config = call("systemdataset.config")
    assert config["pool"] == pool

    try:
        call("pool.dataset.delete", passphrase_encrypted_pool_session, {"recursive": True})
    except CallError as e:
        if e.errno != errno.ENOENT:
            raise

    yield passphrase_encrypted_pool_session


@pytest.mark.parametrize("lock", [False, True])
def test_migrate_to_a_pool_with_passphrase_encrypted_root_dataset(passphrase_encrypted_pool, lock):
    if lock:
        call("pool.dataset.lock", passphrase_encrypted_pool, job=True)

    assert passphrase_encrypted_pool in call("systemdataset.pool_choices")

    call("systemdataset.update", {"pool": passphrase_encrypted_pool}, job=True)

    ds = call("zfs.dataset.get_instance", f"{passphrase_encrypted_pool}/.system")
    assert ds["properties"]["encryption"]["value"] == "off"

    call("systemdataset.update", {"pool": pool}, job=True)


def test_lock_passphrase_encrypted_pool_with_system_dataset(passphrase_encrypted_pool):
    call("systemdataset.update", {"pool": passphrase_encrypted_pool}, job=True)

    call("pool.dataset.lock", passphrase_encrypted_pool, job=True)

    ds = call("zfs.dataset.get_instance", f"{passphrase_encrypted_pool}/.system")
    assert ds["properties"]["mounted"]["value"] == "yes"

    call("systemdataset.update", {"pool": pool}, job=True)
