#!/usr/bin/env python3

import pytest
import sys
import os
from pytest_dependency import depends
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import fail, POST, GET, wait_on_job
from auto_config import pool_name, ha

IMAGES = {}
loops = {
    'msdosfs': '/dev/loop8',
    'msdosfs-nonascii': '/dev/loop9',
    'ntfs': '/dev/loop10'
}
nas_disk = GET('/boot/get_disks/', controller_a=ha).json()
disk_list = list(POST('/device/get_info/', 'DISK', controller_a=ha).json().keys())
disk_pool = sorted(list(set(disk_list) - set(nas_disk)))
# Take all disk from ada1 and after to keep ada0 for dataset encryption test.
tank_disk_pool = (disk_pool[:1])


@pytest.fixture(scope='module')
def pool_data():
    return {}


def test_01_get_pool():
    results = GET("/pool/")
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), list), results.text


def test_02_wipe_all_pool_disk():
    for disk in disk_pool:
        payload = {
            "dev": f"{disk}",
            "mode": "QUICK",
            "synccache": True
        }
        results = POST('/disk/wipe/', payload)
        job_id = results.json()
        job_status = wait_on_job(job_id, 180)
        assert job_status['state'] == 'SUCCESS', str(job_status['results'])


@pytest.mark.dependency(name="pool_04")
def test_04_creating_a_pool(pool_data):
    global payload
    payload = {
        "name": pool_name,
        "encryption": False,
        "topology": {
            "data": [
                {"type": "STRIPE", "disks": tank_disk_pool}
            ],
        }
    }
    results = POST("/pool/", payload)
    if results.status_code != 200:
        fail(f'Failed to start job to create first pool: {results.text}')

    job_id = results.json()
    job_status = wait_on_job(job_id, 180)
    if job_status['state'] != 'SUCCESS':
        fail(f'Failed to create first pool: {job_status["results"]}')

    pool_data['id'] = job_status['results']['result']['id']


def test_05_get_pool_info_by_name(request):
    depends(request, ["pool_04"])
    results = GET(f"/pool?name={pool_name}")
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), list), results.text
    assert results.json(), results.text


def test_06_get_pool_info_by_id(request, pool_data):
    depends(request, ["pool_04"])
    results = GET(f"/pool/id/{pool_data['id']}/")
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text
    pool_data['results'] = results


@pytest.mark.parametrize('pool_keys', ["name", "topology:data:disks"])
def test_07_looking_pool_info_of_(request, pool_keys, pool_data):
    depends(request, ["pool_04"])
    if ':' in pool_keys:
        keys_list = pool_keys.split(':')
        if 'disks' in keys_list:
            info = pool_data['results'].json()[keys_list[0]][keys_list[1]]
            disk_list = payload[keys_list[0]][keys_list[1]][0][keys_list[2]]
            for props in info:
                device = props['device'].partition('p')[0]
                assert device in disk_list, pool_data['results'].text
                assert props['disk'] in disk_list, pool_data['results'].text
        else:
            info = pool_data['results'].json()[keys_list[0]][keys_list[1]][keys_list[2]]
    else:
        assert payload[pool_keys] == pool_data['results'].json()[pool_keys], pool_data['results'].text
