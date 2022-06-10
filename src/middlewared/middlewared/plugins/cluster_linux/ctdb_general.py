import json
import os

from middlewared.schema import Dict, Bool
from middlewared.service import CallError, Service, accepts, private, filterable
from middlewared.utils import run, filter_list
from middlewared.plugins.cluster_linux.utils import CTDBConfig


CTDB_VOL = CTDBConfig.CTDB_VOL_NAME.value


class CtdbGeneralService(Service):

    class Config:
        namespace = 'ctdb.general'
        cli_namespace = 'service.ctdb.general'

    this_node = None

    @private
    async def wrapper(self, command):

        command.insert(0, 'ctdb')
        command.insert(1, '-j')

        result = {}

        cp = await run(command, check=False)
        if not cp.returncode:
            try:
                result = json.loads(cp.stdout)
            except Exception as e:
                raise CallError(f'ctdb parsing failed with error: {e}')
        else:
            raise CallError(
                f'ctdb command failed with error {cp.stderr.decode().strip()}'
            )

        return result

    @private
    @filterable
    async def getdbmap(self, filters, options):
        """
        List all clustered TDB databases that the CTDB daemon has attached to.
        """
        result = await self.middleware.call('ctdb.general.wrapper', ['getdbmap'])
        return filter_list(result['dbmap'], filters, options)

    @accepts(Dict(
        'ctdb_status',
        Bool('all_nodes', default=True)
    ))
    async def status(self, data):
        """
        List the status of nodes in the ctdb cluster.

        `all_nodes`: Boolean if True, return status
            for all nodes in the cluster else return
            status of this node.
        """

        command = ['status' if data['all_nodes'] else 'nodestatus']
        result = await self.middleware.call('ctdb.general.wrapper', command)
        if result:
            result = result['nodes'] if not data['all_nodes'] else result['nodemap']['nodes']

        return result

    @accepts()
    async def listnodes(self):
        """
        Return a list of nodes in the ctdb cluster.
        """

        result = await self.middleware.call('ctdb.general.wrapper', ['listnodes', '-v'])
        return result['nodelist'] if result else result

    @accepts(Dict(
        'ctdb_ips',
        Bool('all_nodes', default=True)
    ))
    async def ips(self, data):
        """
        Return a list of public ip addresses in the ctdb cluster.
        """

        command = ['ip', 'all'] if data['all_nodes'] else ['ip']
        return (await self.middleware.call('ctdb.general.wrapper', command))['nodes']

    @accepts()
    def healthy(self):
        """
        Returns a boolean if the ctdb cluster is healthy.
        """
        # TODO: ctdb has event scripts that can be run when the
        # health of the cluster has changed. We should use this
        # approach and use a lock on a file as a means of knowing
        # if the cluster status is changing when we try to read it.
        # something like:
        #   writer does this:
        #       health_file = LockFile('/file/on/disk')
        #       open('/file/on/disk').write('True or False')
        #   reader does this:
        #       health_file = LockFile('/file/on/disk')
        #       while not health_file.is_locked():
        #           return bool(open('/file/on/disk', 'r').read())
        # or something...
        try:
            # gluster volume root has inode of 1.
            # if gluster isn't mounted it will be different
            # if volume is unhealthy this will fail
            if os.stat(f'/cluster/{CTDB_VOL}').st_ino != 1:
                return False
        except Exception:
            return False

        try:
            status = self.middleware.call_sync('ctdb.general.status', {'all_nodes': True})
        except Exception:
            return False

        return not any(map(lambda x: x['flags_str'] != 'OK', status)) if status else False

    @accepts()
    async def pnn(self):
        """
        Return node number for this node. This value should be static for life of cluster.
        """
        if self.this_node is not None:
            return self.this_node

        if not await self.middleware.call('gluster.fuse.is_mounted', {'name': CTDB_VOL}):
            raise CallError('%s is not fuse mounted locally', CTDB_VOL)

        get_pnn = await run(['ctdb', 'pnn'], check=False)
        if get_pnn.returncode != 0:
            raise CallError("Failed to get pnn: %s", get_pnn.stderr.decode())

        self.this_node = int(get_pnn.stdout.decode().strip())
        return self.this_node
