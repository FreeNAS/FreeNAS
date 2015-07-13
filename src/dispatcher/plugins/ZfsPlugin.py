#+
# Copyright 2014 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import os
import errno
import libzfs
from gevent.event import Event
from task import (Provider, Task, TaskStatus, TaskException,
                  VerifyException, TaskAbortException, query)
from dispatcher.rpc import RpcException, accepts, returns, description
from dispatcher.rpc import SchemaHelper as h
from balancer import TaskState
from resources import Resource
from fnutils import first_or_default
from fnutils.query import wrap


@description("Provides information about ZFS pools")
class ZpoolProvider(Provider):
    @description("Lists ZFS pools")
    @query('zfs-pool')
    def query(self, filter=None, params=None):
        zfs = libzfs.ZFS()
        return wrap(zfs).query(*(filter or []), **(params or {}))

    @accepts()
    @returns(h.array(h.ref('zfs-pool')))
    def find(self):
        zfs = libzfs.ZFS()
        return list(map(lambda p: p.__getstate__(), zfs.find_import()))

    @accepts()
    @returns(h.ref('zfs-pool'))
    def get_boot_pool(self):
        name = self.configstore.get('system.boot_pool_name')
        zfs = libzfs.ZFS()
        return zfs.get(name).__getstate__()

    @accepts(str)
    @returns(h.array(str))
    def get_disks(self, name):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(name)
            return pool.disks
        except libzfs.ZFSException, err:
            raise RpcException(errno.EFAULT, str(err))

    @returns(h.object())
    def get_capabilities(self):
        return {
            'vdev-types': {
                'disk': {
                    'min-devices': 1,
                    'max-devices': 1
                },
                'mirror': {
                    'min-devices': 2
                },
                'raidz1': {
                    'min-devices': 2
                },
                'raidz2': {
                    'min-devices': 3
                },
                'raidz3': {
                    'min-devices': 4
                },
                'spare': {
                    'min-devices': 1
                }
            },
            'vdev-groups': {
                'data': {
                    'allowed-vdevs': ['disk', 'file', 'mirror',
                                      'raidz1', 'raidz2', 'raidz3', 'spare']
                },
                'log': {
                    'allowed-vdevs': ['disk', 'mirror']
                },
                'cache': {
                    'allowed-vdevs': ['disk']
                }
            }
        }


class ZfsProvider(Provider):
    pass


@description("Scrubs ZFS pool")
@accepts(str)
class ZpoolScrubTask(Task):
    def __init__(self, dispatcher):
        super(ZpoolScrubTask, self).__init__(dispatcher)
        self.pool = None
        self.started = False
        self.finish_event = Event()
        self.abort_flag = False

    def __scrub_finished(self, args):
        if args["pool"] == self.pool:
            self.state = TaskState.FINISHED
            self.finish_event.set()

    def __scrub_aborted(self, args):
        if args["pool"] == self.pool:
            self.state = TaskState.ABORTED
            self.finish_event.set()

    def describe(self, pool):
        return "Scrubbing pool {0}".format(pool)

    def run(self, pool):
        self.pool = pool
        self.dispatcher.register_event_handler("fs.zfs.scrub.finish",
                                               self.__scrub_finished)
        self.dispatcher.register_event_handler("fs.zfs.scrub.abort",
                                               self.__scrub_aborted)
        self.finish_event.clear()

        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(self.pool)
            pool.start_scrub()
            self.started = True
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        self.finish_event.wait()
        if self.abort_flag:
            raise TaskAbortException(errno.EINTR,
                                     str("User invoked Task.abort()"))

    def abort(self):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(self.pool)
            pool.stop_scrub()
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        self.finish_event.set()
        # set the abort flag to True so that run() can raise
        # propoer exception
        self.abort_flag = True
        return True

    def get_status(self):
        if not self.started:
            return TaskStatus(0, "Waiting to start...")

        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(self.pool)
            scrub = pool.scrub
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        if scrub.state == libzfs.ScanState.SCANNING:
            self.progress = scrub.percentage
            return TaskStatus(self.progress, "In progress...")

        if scrub.state == libzfs.ScanState.CANCELED:
            self.finish_event.set()
            return TaskStatus(self.progress, "Canceled")

        if scrub.state == libzfs.ScanState.FINISHED:
            self.finish_event.set()
            return TaskStatus(100, "Finished")

    def verify(self, pool):
        zfs = libzfs.ZFS()
        pool = zfs.get(pool)
        return get_disk_names(self.dispatcher, pool)


@description("Creates new ZFS pool")
@accepts(str, h.ref('zfs-topology'), h.object())
class ZpoolCreateTask(Task):
    def __partition_to_disk(self, part):
        result = self.dispatcher.call_sync('disks.get_partition_config', part)
        return os.path.basename(result['disk'])

    def __get_disks(self, topology):
        result = []
        for gname, vdevs in topology.items():
            for vdev in vdevs:
                if vdev['type'] == 'disk':
                    result.append(self.__partition_to_disk(vdev['path']))
                    continue

                if 'children' in vdev:
                    result += [self.__partition_to_disk(i['path']) for i in vdev['children']]

        return map(lambda d: 'disk:{0}'.format(d), result)

    def verify(self, name, topology, params=None):
        zfs = libzfs.ZFS()
        if name in zfs.pools:
            raise VerifyException(errno.EEXIST,
                                  'Pool with same name already exists')

        return self.__get_disks(topology)

    def run(self, name, topology, params=None):
        params = params or {}
        zfs = libzfs.ZFS()
        mountpoint = params.get('mountpoint', '/volumes/{0}'.format(name))

        opts = {
            'feature@async_destroy': 'enabled',
            'feature@empty_bpobj': 'enabled',
            'feature@lz4_compress': 'enabled',
            'feature@enabled_txg': 'enabled',
            'feature@extensible_dataset': 'enabled',
            'feature@bookmarks': 'enabled',
            'feature@filesystem_limits': 'enabled',
            'feature@embedded_data': 'enabled',
            'cachefile': '/data/zfs/zpool.cache',
            'failmode': 'continue',
            'autoexpand': 'on',
        }

        fsopts = {
            'compression': 'lz4',
            'aclmode': 'passthrough',
            'aclinherit': 'passthrough',
            'mountpoint': mountpoint
        }

        nvroot = convert_topology(zfs, topology)

        try:
            pool = zfs.create(name, nvroot, opts, fsopts)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


class ZpoolBaseTask(Task):
    def verify(self, *args, **kwargs):
        name = args[0]
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(name)
        except libzfs.ZFSException:
            raise VerifyException(errno.ENOENT,
                                  "Pool {0} not found".format(name))

        return get_disk_names(self.dispatcher, pool)


@accepts(str, h.object())
class ZpoolConfigureTask(ZpoolBaseTask):
    def verify(self, pool, updated_props):
        super(ZpoolConfigureTask, self).verify(pool)

    def run(self, pool, updated_props):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(pool)
            for name, value in updated_props:
                prop = pool.properties[name]
                prop.value = value
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


@accepts(str)
class ZpoolDestroyTask(ZpoolBaseTask):
    def run(self, name):
        try:
            zfs = libzfs.ZFS()
            zfs.destroy(name)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        # self.dispatcher.unregister_resource('zpool:{0}'.format(name))


@accepts(str, h.ref('zfs-topology'), h.object())
class ZpoolExtendTask(ZpoolBaseTask):
    def run(self, pool, new_vdevs, updated_vdevs):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(pool)
            nvroot = convert_topology(zfs, new_vdevs)
            pool.attach_vdevs(nvroot)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


@accepts(str, str, h.object())
class ZpoolImportTask(Task):
    def verify(self, guid, name=None, properties=None):
        zfs = libzfs.ZFS()
        pool = first_or_default(
                   lambda p: str(p.guid) == guid, zfs.find_import())
        if not pool:
            raise VerifyException(errno.ENOENT,
                                  'Pool with GUID {0} not found'.format(guid))

        return get_disk_names(self.dispatcher, pool)

    def run(self, guid, name=None, properties=None):
        zfs = libzfs.ZFS()
        opts = properties or {}
        try:
            pool = first_or_default(
                       lambda p: str(p.guid) == guid, zfs.find_import())
            zfs.import_pool(pool, name, opts)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


@accepts(str)
class ZpoolExportTask(ZpoolBaseTask):
    def verify(self, name):
        super(ZpoolExportTask, self).verify(name)

    def run(self, name):
        zfs = libzfs.ZFS()
        try:
            pool = zfs.get(name)
            zfs.export_pool(pool)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


class ZfsBaseTask(Task):
    def verify(self, *args, **kwargs):
        path = args[0]
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(path)
            if not dataset:
                raise VerifyException(errno.ENOENT,
                                      'Dataset {0} not found'.format(path))
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        return ['system']


@accepts(str, bool)
class ZfsDatasetMountTask(ZfsBaseTask):
    def run(self, name, recursive=False):
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(name)
            if recursive:
                dataset.mount_recursive()
            else:
                dataset.mount()
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


@accepts(str)
class ZfsDatasetUmountTask(ZfsBaseTask):
    def run(self, name):
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(name)
            dataset.umount()
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


@accepts(str, str, h.object())
class ZfsDatasetCreateTask(Task):
    def verify(self, pool_name, path, params=None):
        return ['zpool:{0}'.format(pool_name)]

    def run(self, pool_name, path, params=None):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(pool_name)
            pool.create(path, params)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        # self.dispatcher.register_resource(
        #     Resource('zfs:{0}'.format(path)),
        #     parents=['zpool:{0}'.format(pool_name)])


@accepts(str, str, int, h.object())
class ZfsVolumeCreateTask(Task):
    def verify(self, pool_name, path, size, params=None):
        return ['zpool:{0}'.format(pool_name)]

    def run(self, pool_name, path, size, params=None):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(pool_name)
            pool.create(path, params)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        # self.dispatcher.register_resource(
        #     Resource('zfs:{0}'.format(path)),
        #     parents=['zpool:{0}'.format(pool_name)])


class ZfsSnapshotCreateTask(Task):
    def verify(self, pool_name, path, size, params=None):
        return ['zpool:{0}'.format(pool_name)]

    def run(self, pool_name, path, size, params=None):
        try:
            zfs = libzfs.ZFS()
            pool = zfs.get(pool_name)
            pool.create(path, params)
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        # self.dispatcher.register_resource(
        #     Resource('zfs:{0}'.format(path)),
        #     parents=['zpool:{0}'.format(pool_name)])


class ZfsConfigureTask(ZfsBaseTask):
    def verify(self, name, properties):
        super(ZfsConfigureTask, self).verify(name)

    def run(self, name, properties):
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(name)
            for k, v in properties.items():
                dataset.properties[k].value = v
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


class ZfsDestroyTask(ZfsBaseTask):
    def run(self, path):
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(path)
            dataset.delete()
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))

        # self.dispatcher.unregister_resource('zfs:{0}'.format(path))


class ZfsRenameTask(ZfsBaseTask):
    def run(self, path):
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(path)
            dataset.delete()
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


class ZfsCloneTask(ZfsBaseTask):
    def run(self, path):
        try:
            zfs = libzfs.ZFS()
            dataset = zfs.get_dataset(path)
            dataset.delete()
        except libzfs.ZFSException, err:
            raise TaskException(errno.EFAULT, str(err))


def convert_topology(zfs, topology):
    nvroot = {}
    for group, vdevs in topology.items():
        nvroot[group] = []
        for i in vdevs:
            vdev = libzfs.ZFSVdev(zfs)
            vdev.type = i['type']

            if i['type'] == 'disk':
                vdev.path = i['path']

            if 'children' in i:
                ret = []
                for c in i['children']:
                    cvdev = libzfs.ZFSVdev(zfs)
                    cvdev.type = c['type']
                    cvdev.path = c['path']
                    ret.append(cvdev)

                vdev.children = ret

            nvroot[group].append(vdev)

    return nvroot


def get_disk_names(dispatcher, pool):
    return ['disk:' + dispatcher.call_sync('disks.partition_to_disk', x) for x in pool.disks]


def zpool_create_resources(dispatcher, pool):
    def iter_dataset(ds):
        dispatcher.register_resource(
            Resource('zfs:{0}'.format(ds.name)),
            parents=['zpool:{0}'.format(pool.name)])

        for i in ds.children:
            iter_dataset(i)

    dispatcher.register_resource(
        Resource('zpool:{0}'.format(pool.name)),
        parents=get_disk_names(dispatcher, pool))

    iter_dataset(pool.root_dataset)


def zpool_remove_resources(dispatcher, pool):
    dispatcher.unregister_resource(Resource('zpool:{0}'.format(pool.name)))


def _depends():
    return ['DevdPlugin', 'DiskPlugin']


def zfsprop_schema_creator(**kwargs):
    """
    A little helper function to programmatically create zfs property type
    schmeas. It returns a schema dict with top level 'type' being an object.

    Note: If nothing is specified then it defaults to a source='string'
    and value='string'.

    Usage: zfsprop_schema_creator(propety_name=schema_type_as_str)
    Examples:
        Call: zfsprop_schema_creator(value='long')
        Returns: {
            type: 'object',
            properties: {
                'source': {'type': 'string'},
                'value': {'type': 'long'},
            }
        }
        zfsprop_schema_creator(source='string', value='integer')
        Returns: {
            type: 'object',
            properties: {
                'source': {'type': 'string'},
                'value': {'type': 'integer'},
            }
        }
    """
    result = {
        'type': 'object',
        'properties': {
            'source': 'string',
            'value': 'string',
        }
    }
    for key, value in kwargs.iteritems():
        result['properties'][key] = {'type': value}
    return result


def _init(dispatcher, plugin):
    def on_pool_create(args):
        guid = args['guid']
        name = args['pool']

        dispatcher.dispatch_event('zfs.pool.changed', {
            'operation': 'create',
            'ids': [guid]
        })

        # Register resources for pool and root dataset
        dispatcher.register_resource(Resource('zpool:{0}'.format(name)),
                                     parents=[])
        dispatcher.register_resource(Resource('zfs:{0}'.format(name)),
                                     parents=['zpool:{0}'.format(name)])

    def on_pool_destroy(args):
        guid = args['guid']
        dispatcher.dispatch_event('zfs.pool.changed', {
            'operation': 'delete',
            'ids': [guid]
        })

        dispatcher.unregister_resource('zpool:{0}'.format(args['pool']))

    def on_dataset_create(args):
        guid = args['guid']
        plugin.register_resource(
            Resource('zfs:{0}'.format(args['ds'])),
            parents=['zpool:{0}'.format(args['pool'])])
        dispatcher.dispatch_event('zfs.pool.changed', {
            'operation': 'create',
            'ids': [guid]
        })

    def on_dataset_delete(args):
        guid = args['guid']
        plugin.unregister_resource('zfs:{0}'.format(args['ds']))
        dispatcher.dispatch_event('zfs.pool.changed', {
            'operation': 'update',
            'ids': [guid]
        })

    def on_dataset_rename(args):
        guid = args['guid']
        dispatcher.dispatch_event('zfs.pool.changed', {
            'operation': 'update',
            'ids': [guid]
        })

    plugin.register_schema_definition('zfs-vdev', {
        'type': 'object',
        'properties': {
            'path': {'type': 'string'},
            'type': {
                'type': 'string',
                'enum': ['disk', 'file', 'mirror',
                         'raidz1', 'raidz2', 'raidz3']
            },
            'children': {
                'type': 'array',
                'items': {'$ref': 'zfs-vdev'}
            }
        }
    })

    # Plugin Schema definitions

    plugin.register_schema_definition('zfs-topology', {
        'type': 'object',
        'properties': {
            'data': {
                'type': 'array',
                'items': {'$ref': 'zfs-vdev'},
            },
            'logs': {
                'type': 'array',
                'items': {'$ref': 'zfs-vdev'},
            },
            'cache': {
                'type': 'array',
                'items': {'$ref': 'zfs-vdev'},
            },
            'spare': {
                'type': 'array',
                'items': {'$ref': 'zfs-vdev'},
            },
        }
    })

    # TODO: Add ENUM to the 'state' property below
    plugin.register_schema_definition('zfs-scan', {
        'type': 'object',
        'properties': {
            'errors': {'type': 'integer'},
            'start_time': {'type': 'string'},
            'bytes_to_process': {'type': 'long'},
            'state': {'type': 'string'},
            'end_time': {'type': 'string'},
            'func': {'type': 'integer'},
            'bytes_processed': {'type': 'long'},
            'percentage': {'type': 'float'},
        }
    })

    # A dict containing the zfs property name: dict of their properties
    # (optional if empty the zfsprop_schema_creator defaults kickin)
    # for example 'comment': [{'source': string, 'value': 'boolean'}]
    zfsprops_dict = {
        'comment': {},
        'freeing': {},
        'listsnapshots': {},
        'leaked': {},
        'version': {},
        'free': {},
        'delegation': {},
        'dedupditto': {},
        'failmode': {},
        'autoexpand': {},
        'allocated': {},
        'guid': {},
        'altroot': {},
        'size': {},
        'fragmentation': {},
        'capacity': {},
        'name': {},
        'maxblocksize': {},
        'cachefile': {},
        'bootfs': {},
        'autoreplace': {},
        'readonly': {},
        'dedupratio': {},
        'health': {},
        'expandsize': {},
    }

    zfsproperty_schema = {'type': 'object', 'properties': {}}

    for key, value in zfsprops_dict.iteritems():
        zfsproperty_schema['properties'][key] = zfsprop_schema_creator(**value)

    plugin.register_schema_definition('zfs-properties', zfsproperty_schema)

    # A dict containing the zfs dataset property name: dict of their properties
    # (optional if empty the zfsprop_schema_creator defaults kickin)
    # for example 'comment': [{'source': string, 'value': 'boolean'}]
    zfs_datasetprops_dict = {
        'origin': {},
        'referenced': {},
        'numclones': {},
        'primarycache': {},
        'logbias': {},
        'inconsistent': {},
        'reservation': {},
        'casesensitivity': {},
        'guid': {},
        'usedbysnapshots': {},
        'stmf_sbd_lu': {},
        'mounted': {},
        'compression': {},
        'snapdir': {},
        'copies': {},
        'aclinherit': {},
        'compressratio': {},
        'recordsize': {},
        'mlslabel': {},
        'jailed': {},
        'snapshot_count': {},
        'volsize': {},
        'clones': {},
        'atime': {},
        'usedbychildren': {},
        'volblocksize': {},
        'objsetid': {},
        'name': {},
        'defer_destroy': {},
        'type': {},
        'devices': {},
        'useraccounting': {},
        'iscsioptions': {},
        'setuid': {},
        'usedbyrefreservation': {},
        'logicalused': {},
        'userrefs': {},
        'creation': {},
        'sync': {},
        'volmode': {},
        'sharenfs': {},
        'sharesmb': {},
        'createtxg': {},
        'mountpoint': {},
        'xattr': {},
        'utf8only': {},
        'aclmode': {},
        'exec': {},
        'dedup': {},
        'snapshot_limit': {},
        'readonly': {},
        'version': {},
        'filesystem_limit': {},
        'secondarycache': {},
        'prevsnap': {},
        'available': {},
        'used': {},
        'written': {},
        'refquota': {},
        'refcompressratio': {},
        'quota': {},
        'vscan': {},
        'canmount': {},
        'normalization': {},
        'usedbydataset': {},
        'unique': {},
        'checksum': {},
        'redundant_metadata': {},
        'filesystem_count': {},
        'refreservation': {},
        'logicalreferenced': {},
        'nbmand': {},
    }

    zfs_datasetproperty_schema = {'type': 'object', 'properties': {}}

    for key, value in zfs_datasetprops_dict.iteritems():
        zfs_datasetproperty_schema['properties'][key] = zfsprop_schema_creator(**value)

    plugin.register_schema_definition('zfs-datasetproperties',
                                      zfs_datasetproperty_schema)

    plugin.register_schema_definition('zfs-dataset', {
        'type': 'object',
        'properties': {
            'name': {'type': 'string'},
            'properties': {'$ref': 'zfs-datasetproperties'},
            'children': {
                'type': 'array',
                'items': {'$ref': 'zfs-dataset'},
            },
        }
    })
    # TODO: Fix zfs-pools.groups.(cache and logs items' schema)
    plugin.register_schema_definition('zfs-pool', {
        'type': 'object',
        'properties': {
            'status': {
                'type': 'string',
                'enum': ['ONLINE', 'OFFLINE', 'DEGRADED', 'FAULTED',
                         'REMOVED', 'UNAVAIL']
            },
            'name': {'type': 'string'},
            'scan': {'$ref': 'zfs-scan'},
            'hostname': {'type': 'string'},
            'root_dataset': {'$ref': 'zfs-dataset'},
            'groups': {
                'type': 'object',
                'properties': {
                    'cache': {'type': 'array'},
                    'data': {'$ref': 'zfs-vdev'},
                    'log': {'type': 'array'},
                }
            },
            'guid': {'type': 'long'},
            'properties': {'$ref': 'zfs-properties'},
        }
    })

    # Register Event Types
    plugin.register_event_type('zfs.pool.changed')

    plugin.register_event_handler('fs.zfs.pool.created', on_pool_create)
    plugin.register_event_handler('fs.zfs.pool.destroyed', on_pool_destroy)
    plugin.register_event_handler('fs.zfs.dataset.created', on_dataset_create)
    plugin.register_event_handler('fs.zfs.dataset.deleted', on_dataset_delete)
    plugin.register_event_handler('fs.zfs.dataset.renamed', on_dataset_rename)

    # Register Providers
    plugin.register_provider('zfs.pool', ZpoolProvider)

    # Register Task Handlers
    plugin.register_task_handler('zfs.pool.create', ZpoolCreateTask)
    plugin.register_task_handler('zfs.pool.configure', ZpoolConfigureTask)
    plugin.register_task_handler('zfs.pool.extend', ZpoolExtendTask)
    plugin.register_task_handler('zfs.pool.import', ZpoolImportTask)
    plugin.register_task_handler('zfs.pool.export', ZpoolExportTask)
    plugin.register_task_handler('zfs.pool.destroy', ZpoolDestroyTask)
    plugin.register_task_handler('zfs.pool.scrub', ZpoolScrubTask)

    plugin.register_task_handler('zfs.mount', ZfsDatasetMountTask)
    plugin.register_task_handler('zfs.umount', ZfsDatasetUmountTask)
    plugin.register_task_handler('zfs.create_dataset', ZfsDatasetCreateTask)
    plugin.register_task_handler('zfs.create_snapshot', ZfsSnapshotCreateTask)
    plugin.register_task_handler('zfs.create_zvol', ZfsVolumeCreateTask)
    plugin.register_task_handler('zfs.configure', ZfsConfigureTask)
    plugin.register_task_handler('zfs.destroy', ZfsDestroyTask)
    plugin.register_task_handler('zfs.rename', ZfsRenameTask)
    plugin.register_task_handler('zfs.clone', ZfsCloneTask)

    try:
        zfs = libzfs.ZFS()
        # Try to reimport Pools into the system after upgrade, this checks
        # for any non-imported pools in the system via the python binding
        # analogous of `zpool import` and then tries to verify its guid with
        # the pool's in the database. In the event two pools with the same guid
        # are found (Very rare and only happens in special broken cases) it
        # logs said guid with pool name and skips that import.
        unimported_unique_pools = {}
        unimported_duplicate_pools = []
        for pool in zfs.find_import():
            if pool.guid in unimported_unique_pools:
                # This means that the pool is prolly a duplicate
                # Thus remove it from this dict of pools
                # and put it in the duplicate dict
                del unimported_unique_pools[pool.guid]
                unimported_duplicate_pools.append(pool)
            else:
                # Since there can be more than two duplicate copies
                # of a pool might exist, we still need to check for
                # it in the unimported pool list
                duplicate_guids = map(lambda x: x.guid,
                                      unimported_duplicate_pools)
                if pool.guid in duplicate_guids:
                    continue
                else:
                    unimported_unique_pools[pool.guid] = pool
        # Logging the duplicate pool naes and guids, if any
        if unimported_duplicate_pools:
            dispatcher.logger.warning(
                'The following pools were unimported because of duplicates' +
                'being found: ')
            for duplicate_pool in unimported_duplicate_pools:
                dispatcher.logger.warning(
                    'Unimported Pool Name: {0}, GUID: {1}'.format(
                        duplicate_pool.name, duplicate_pool.guid))
        # Finally, Importing the unique unimported pools that are present in
        # the database
        for vol in dispatcher.datastore.query('volumes'):
            if long(vol['id']) in unimported_unique_pools:
                pool_to_import = unimported_unique_pools[long(vol['id'])]
                # Check if the volume name is also the same
                if vol['name'] == pool_to_import.name:
                    opts = {}
                    zfs.import_pool(pool_to_import, pool_to_import.name, opts)
                else:
                    # What to do now??
                    # When in doubt log it!
                    dispatcher.logger.error(
                        'Cannot Import pool with guid: {0}'.format(vol['id']) +
                        ' because it is named as: {0} in'.format(vol['name']) +
                        ' the database but the actual system found it named' +
                        ' as {0}'.format(pool_to_import.name))
        for pool in zfs.pools:
            zpool_create_resources(dispatcher, pool)
    except libzfs.ZFSException as err:
        # Log what happened
        dispatcher.logger.error('ZfsPlugin init error: {0}'.format(str(err)))
