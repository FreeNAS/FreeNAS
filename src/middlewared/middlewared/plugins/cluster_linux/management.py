import errno
import secrets
from time import sleep

from middlewared.client import Client, ClientException
from middlewared.utils import filter_list
from middlewared.schema import Bool, Dict, IPAddr, Int, List, OROperator, Ref, returns, Str
from middlewared.service import accepts, job, private, Service, ValidationErrors
from middlewared.service_exception import CallError
from middlewared.plugins.cluster_linux.utils import CTDBConfig
from middlewared.plugins.gluster_linux.utils import get_parsed_glusterd_uuid, GlusterConfig
from middlewared.plugins.pwenc import PWENC_BLOCK_SIZE


class ClusterPeerConnection:
    def __do_connect(self):
        c = Client(f'ws://{self.private_address}:6000/websocket')
        cred = self.credentials
        if (api_key := cred.get('api_key')):
            authenticated = c.call('auth.login_with_api_key', api_key)
        else:
            authenticated = c.call('auth.login', cred['username'], cred['password'])

        if not authenticated:
            c.close()
            raise CallError(f'{self.hostname}: failed to authenticate.')

        self.conn = c
        self.call_fn = c.call

    def __init__(self, **kwargs):
        self.hostname = kwargs.get('hostname')
        self.brick_path = kwargs.get('brick_path')
        self.private_address = kwargs.get('private_address')
        self.credentials = kwargs.get('remote_credential')
        self.middleware = kwargs.get('middleware')
        self.local = kwargs.get('local')
        self.conn = None
        self.call_fn = None

        if not self.local:
            self.__do_connect()
        else:
            self.call_fn = self.middleware.call_sync

    def __del__(self):
        if self.conn:
            self.conn.close()

    def __validate_ntp(self, schema_name, ntp_peers, verrors):
        active = filter_list(ntp_peers, [['active', '=', True]])
        if not active:
            verrors.add(f'{schema_name}.hostname', 'No active NTP peers on host')
            return

        if abs(active[0]['offset']) > CTDBConfig.MAX_CLOCKSKEW.value:
            verrors.add(
                f'{schema_name}.hostname',
                'offset from NTP peer exceeds {CTDBConfig.MAX_CLOCKSKEW.value} seconds'
            )

    def __validate_brick_path(self, schema_name, verrors):
        try:
            self.call_fn('filesystem.stat', self.brick_path)
        except CallError as e:
            if e.errno != errno.ENOENT:
                raise

            verrors.add(
                f'{schema_name}.brick_path',
                f'{self.brick_path}: path does not exist on host {self.hostname}.'
            )
        except ClientException as e:
            if e.errno != errno.ENOENT:
                raise

            verrors.add(
                f'{schema_name}.brick_path',
                f'{self.brick_path}: path does not exist on host {self.hostname}.'
            )

    def __validate_dns(self, schema_name, hosts, verrors):
        for host in hosts:
            error = None
            try:
                self.call_fn('cluster.utils.resolve_hostnames', [host])
            except ClientException as e:
                error = e.error
            except Exception as e:
                error = e

            if error:
                verrors.add(
                    f'{schema_name}.hostname',
                    f'Failed to resolve hostname [{host}] of proposed peer: {error}'
                )

    def __validate_private_address(self, schema_name, verrors):
        ips = self.call_fn('gluster.peer.ips_available')
        if self.private_address not in ips:
            verrors.add(
                f'{schema_name}.private_address',
                f'{self.private_address}: IP address not available on host '
                f'{self.hostname}. Available options are: {", ".join(ips)}.'
            )

    def validate_peer(self, schema_name, data, verrors):
        """
        data is expected to have following keys:
        `expected_version` - results of system.version from calling node
        `hosts` - list of hostnames of all cluster nodes
        """
        expected_version = data.get('expected_version')
        hosts_to_check = data.get('hosts')

        ntp_peers = self.call_fn('system.ntpserver.peers')
        self.__validate_ntp(schema_name, ntp_peers, verrors)

        if expected_version:
            this_version = self.call_fn('system.version')
            if this_version != expected_version:
                verrors.add(
                    f'{schema_name}.hostname',
                    f'{this_version}: remote version does not match local version [{expected_version}]'
                )

        if not self.call_fn('system.ready'):
            verrors.add(
                f'{schema_name}.hostname',
                f'{self.hostname}: remote server middleware is not in a READY state'
            )

        if self.call_fn('cluster.utils.is_clustered'):
            verrors.add(
                f'{schema_name}.hostname',
                f'{self.hostname}: server is already member of a cluster'
            )

        self.__validate_brick_path(schema_name, verrors)
        self.__validate_dns(schema_name, hosts_to_check, verrors)
        self.__validate_private_address(schema_name, verrors)


class ClusterManagement(Service):

    class Config:
        namespace = 'cluster.management'
        cli_namespace = 'service.cluster.management'

    @private
    def wait_for_ctdb_healthy(self, timeout):
        remaining = timeout
        while remaining > 0:
            status = self.middleware.call_sync('ctdb.general.status')
            if status['all_healthy']:
                return

            sleep(10)
            remaining -= 10

        unhealthy = [x['address']['address'] for x in status['nodemap']['nodes']]
        raise CallError(
            f'Timed out waiting for following nodes to become healthy: {", ".join(unhealthy)}'
        )

    @accepts(Dict(
        'add_cluster_nodes',
        List('new_cluster_nodes', items=[
            Dict(
                'cluster_peer',
                OROperator(
                    Dict(
                        'plain_cred',
                        Str('username', required=True),
                        Str('password', required=True, private=True)
                    ),
                    Str('api_key', required=True, private=True),
                    name='remote_credential',
                ),
                Str('hostname', required=True),
                IPAddr('private_address', required=True),
                Str('brick_path', required=True),
                required=True,
                register=True
            )
        ], required=True),
        Dict('options', Bool('skip_brick_add', default=False))
    ))
    @returns(Dict(
        'cluster_information',
        List('gluster_volume', items=[Ref('gluster_volume_entry')]),
        List('gluster_peers', items=[Ref('gluster_peer_entry')]),
        Ref('ctdb_configuration'),
        register=True
    ))
    @job(lock='CLUSTER_ADD_NODE')
    def add_nodes(self, job, data):
        """
        WARNING: clustering APIs are not intended for 3rd-party consumption and may result
        in a misconfigured SCALE cluster, production outage, or data loss.

        Add one or more peers to an existing TrueNAS cluster.

        `new_cluster_nodes` list of proposed cluster nodes to add to existing cluster
        `remote_credential` - credentials with which to authenticate with specified
        node during the setup process.
        `hostname` - hostname of new node. Must be resolvable by all cluster nodes.
        `private_address` - IP address on private dedicated storage network.
        This address will be used for unencrypted backend traffic and must not
        be publicly exposed in any way.
        `brick_path` - local filesystem path where gluster brick will be
        located. We will try to expand the gluster volume underlying our ctdb
        root directory with bricks on every node added to the cluster.
        `options.skip_brick_add` - Non-default parameter to skip adding bricks.
        """
        if not self.middleware.call_sync('cluster.utils.is_clustered'):
            raise CallError('New node must be added via existing cluster member')

        if not self.middleware.call_sync('ctdb.general.healthy'):
            raise CallError('Cluster must be healthy before adding new node')

        this_version = self.middleware.call_sync('system.version')
        verrors = ValidationErrors()

        hostnames = [x['hostname'] for x in self.middleware.call_sync('gluster.peer.query')]
        hostnames.extend([x['hostname'] for x in data['new_cluster_nodes']])

        conns = []
        for idx, peer in enumerate(data['new_cluster_nodes']):
            peer_conn = ClusterPeerConnection(**{'middleware': self.middleware} | peer)
            peer_conn.validate_peer(
                f'cluster_add_node.new_cluster_nodes.{idx}',
                {'hosts': hostnames, 'expected_version': this_version},
                verrors
            )
            conns.append(peer_conn)

        if not data['options']['skip_brick_add']:
            config = self.middleware.call_sync('ctdb.root_dir.config')
            gvol = self.middleware.call_sync('gluster.volume.get_instance', config['volume_name'])
            required_nodes = None
            if 'REPLICATED' in gvol['type']:
                required_nodes = gvol['replica']
            elif 'DISPERSED' in gvol['type']:
                required_nodes = gvol['disperse'] + gvol['disperse_redundancy']

            if required_nodes is not None:
                if len(data['new_cluster_nodes']) != required_nodes:
                    verrors.add(
                        'cluster_add_node.new_cluster_nodes',
                        f'{gvol["name"]}: insufficient number of new nodes to safely '
                        f'expand volume of type [{gvol["type"]}]. Minimum required nodes '
                        f'is {required_nodes}'
                    )

        verrors.check()

        secret = self.middleware.call_sync('gluster.localevents.get_set_jwt_secret')

        for peer_conn in conns:
            peer_conn.call_fn('service.update', 'glusterd', {'enable': True})
            peer_conn.call_fn('service.start', 'glusterd')

            peer_job = self.middleware.call_sync('gluster.peer.create', {
                'hostname': peer_conn.hostname,
                'private_address': peer_conn.private_address
            })
            peer_job.wait_sync(raise_error=True)

            peer_conn.call_fn('gluster.localevents.add_jwt_secret', {"secret": secret, "force": True})

        # The following will send local event to new node to mount the volume containing
        # ctdb metadata and start ctdbd. This will be enough to get cluster "healthy" again
        # even if we don't have bricks spread to new node.

        root_dir_setup = self.middleware.call_sync('ctdb.root_dir.setup')
        ctdb_config = root_dir_setup.wait_sync(raise_error=True)
        self.middleware.call_sync('ctdb.private.ips.reload')

        job.set_progress(90, 'Waiting for cluster to become healthy.')
        self.wait_for_ctdb_healthy(300)
        gluster_peers = self.middleware.call_sync('gluster.peer.query')

        if data['options']['skip_brick_add']:
            # While not ideal, there is no techincal requirement to spread the
            # gluster volume onto all nodes. This allows TC option to for error
            # recovery via adding more cluster nodes in case of incorrect brick
            # count being added, perhaps going so far as to allow users to
            # temporarily run without the volume spread to all servers while
            # shipping hardware
            vol = self.middleware.call_sync('gluster.volume.get_instance', root_dir_setup['volume_name'])
        else:
            # Cluster has expanded and we're healthy now. If following fails, the cluster will still
            # continue serving data / be healthy, but manual intervention may be required to complete
            # the spreading of bricks
            bricks = [{
                'peer_name': peer['hostname'],
                'peer_path': peer['brick_path']
            } for peer in data['new_cluster_nodes']]

            add_bricks_job = self.middleware.call_sync('gluster.bricks.add', {
                'name': ctdb_config['root_dir_config']['volume_name'],
                'bricks': bricks
            })
            vol = add_bricks_job.wait_sync(raise_error=True)

        return {
            'gluster_volume': vol,
            'gluster_peers': gluster_peers,
            'ctdb_configuration': ctdb_config,
        }

    @accepts(Dict(
        'cluster_configuration',
        Dict(
            'volume_configuration',
            Str('name', required=True),
            Int('replica'),
            Int('arbiter'),
            Int('disperse'),
            Int('disperse_data'),
            Int('redundancy'),
        ),
        Dict(
            'local_node_configuration',
            Str('hostname', required=True),
            IPAddr('private_address', required=True),
            Str('brick_path', required=True),
            required=True,
        ),
        List('peers', items=[Ref('cluster_peer')], required=True),
    ))
    @returns(Ref('cluster_information'))
    @job(lock='CLUSTER_CREATE')
    def cluster_create(self, job, data):
        """
        WARNING: clustering APIs are not intended for 3rd-party consumption and may result
        in a misconfigured SCALE cluster, production outage, or data loss.

        Create a cluster based on specified payload. Some prior configuration
        is required.

        PRE-REQUISITES:
        - Minimum of 3 TrueNAS servers available (this node and two additional
        peers)
        - All members of cluster must have same version of TrueNAS installed.
        - None of the servers may be members of existing clusters or have prior
        cluster-related configuration files populated
        - Private network must be provided for backend (ctdb and glusterfs) traffic
        - All gluster peer hostnames must be resolvable from all cluster nodes
          and lookups return the private address specified in the above payload.

        PAYLOAD INFORMATION:

        `volume_configuration` -configuration details of gluster volume that
        will be created during cluster creation.
        `local_node_configuration` - the hostname, private_address, and brick path of
        the current cluster node.
        `peers` - list of additional gluster peers with which to form this cluster.
        Peer information includes the following:
        `hostname` - the hostname by which `private_address` will be resolvable
        via lookups on all cluster nodes.
        `private_address` - IP address on private dedicated storage network.
        This address will be used for unencrypted backend traffic and must not
        be publicly exposed in any way.
        `brick_path` - local filesystem path where gluster brick will be located
        when creating the gluster volume specified in `volume_configuration`.
        `remote_credential` - credentials (either username and password or API key)
        for one-time authentication with gluster peer during cluster creation.

        RETURNS:
        dictionary containing:
        `gluster_volume` - gluster volume information for created volume
        `gluster_peers` - gluster peer information for gluster cluster
        `ctdb_configuration` - CTDB configuration directory information and
        contents of nodes file.
        """
        if self.middleware.call_sync('gluster.peer.query'):
            raise CallError('Trusted storage pool already exists')

        if self.middleware.call_sync('cluster.utils.is_clustered'):
            raise CallError('Server is already clustered')

        this_version = self.middleware.call_sync('system.version')

        verrors = ValidationErrors()
        if len(data['peers']) + 1 < GlusterConfig.MIN_PEERS.value:
            verrors.add(
                'cluster_config.peers',
                f'A minimum of {GlusterConfig.MIN_PEERS.value} peers (including this node) are required'
            )

        cluster_hostnames = [data['local_node_configuration']['hostname']]
        for peer in data['peers']:
            cluster_hostnames.append(peer['hostname'])

        client_connections = [ClusterPeerConnection(**{
            'middleware': self.middleware,
            'local': True
        } | data['local_node_configuration'])]

        client_connections[0].validate_peer(
            'cluster_config.local_node_configuration',
            {'hosts': cluster_hostnames},
            verrors
        )

        verrors.check()

        job.set_progress(5, 'Opening websocket connections to cluster peers.')
        for idx, peer in enumerate(data['peers']):
            job.set_progress(5, f'{peer["hostname"]}: validating peer.')
            try:
                peer_connection = ClusterPeerConnection(**{
                    'middleware': self.middleware,
                } | peer)
            except OSError as e:
                verrors.add(
                    f'cluster_config.peers.{idx}.private_address',
                    f'Failed to establish websocket session with host {peer["hostname"]} '
                    f'via private address [{peer["private_address"]}].',
                    e.errno
                )
                break

            peer_connection.validate_peer(
                f'cluster_config.peers.{idx}',
                {'hosts': cluster_hostnames, 'expected_version': this_version},
                verrors
            )
            client_connections.append(peer_connection)

        verrors.check()

        # The following sections relies on remote middleware calls
        job.set_progress(10, 'Enabling and starting glusterd process on cluster peers.')
        for c in client_connections:
            c.call_fn('service.update', 'glusterd', {'enable': True})
            c.call_fn('service.start', 'glusterd')

        job.set_progress(15, 'Configuring gluster peers for trusted storage pool.')
        for peer in data['peers']:
            peer_job = self.middleware.call_sync('gluster.peer.create', {'hostname': peer['hostname']})
            peer_job.wait_sync(raise_error=True)

        job.set_progress(25, 'Configuring shared secret.')
        secret = secrets.token_hex(PWENC_BLOCK_SIZE)
        for c in client_connections:
            c.call_fn('gluster.localevents.add_jwt_secret', {"secret": secret, "force": True})

        job.set_progress(50, 'Creating gluster volume.')

        bricks = [{
            'peer_path': entry.brick_path,
            'peer_name': entry.hostname
        } for entry in client_connections]

        create_payload = data['volume_configuration'] | {'bricks': bricks, 'force': True}
        volume_create_job = self.middleware.call_sync('gluster.volume.create', create_payload)
        try:
            vol = volume_create_job.wait_sync(raise_error=True)
        except Exception:
            self.logger.error('Failed to create gluster volume', exc_info=True)
            raise

        job.set_progress(75, 'Configuring CTDB.')
        current_node_uuid = get_parsed_glusterd_uuid()
        ctdb_ip_payload = [{
            'ip': data['local_node_configuration']['private_address'],
            'node_uuid': current_node_uuid
        }]
        for gluster_peer in self.middleware.call_sync('gluster.peer.query'):
            if gluster_peer['uuid'] == current_node_uuid:
                continue

            found = filter_list(data['peers'], [['hostname', 'C=', gluster_peer['hostname']]])
            if not found:
                raise CallError(f'{gluster_peer["hostname"]}: not present in creation payload')

            ctdb_ip_payload.append({
                'ip': found[0]['private_address'],
                'node_uuid': gluster_peer['uuid']
            })

        root_dir_setup = self.middleware.call_sync('ctdb.root_dir.setup', {'new_nodes': ctdb_ip_payload})
        ctdb_config = root_dir_setup.wait_sync(raise_error=True)
        job.set_progress(90, 'Waiting for cluster to become healthy.')
        self.wait_for_ctdb_healthy(300)

        gluster_peers = self.middleware.call_sync('gluster.peer.query')
        return {
            'gluster_volume': vol,
            'gluster_peers': gluster_peers,
            'ctdb_configuration': ctdb_config,
        }
