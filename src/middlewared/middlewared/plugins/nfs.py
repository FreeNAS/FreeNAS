import contextlib
import enum
import errno
import ipaddress
import itertools

from middlewared.common.attachment import LockableFSAttachmentDelegate
from middlewared.common.listen import SystemServiceListenMultipleDelegate
from middlewared.schema import accepts, Bool, Dict, Dir, Int, IPAddr, List, Patch, returns, Str
from middlewared.async_validators import check_path_resides_within_volume, validate_port
from middlewared.validators import Match, NotMatch, Range, IpAddress
from middlewared.service import private, SharingService, SystemServiceService
from middlewared.service import CallError, ValidationError, ValidationErrors
import middlewared.sqlalchemy as sa
from middlewared.utils.asyncio_ import asyncio_map
from middlewared.plugins.nfs_.utils import get_domain, leftmost_has_wildcards, get_wildcard_domain


class NFSProtocol(str, enum.Enum):
    NFSv3 = 'NFSV3'
    NFSv4 = 'NFSV4'

    def choices():
        return [x.value for x in NFSProtocol]


class NFSModel(sa.Model):
    __tablename__ = 'services_nfs'

    id = sa.Column(sa.Integer(), primary_key=True)
    nfs_srv_servers = sa.Column(sa.Integer(), default=4)
    nfs_srv_udp = sa.Column(sa.Boolean(), default=False)
    nfs_srv_allow_nonroot = sa.Column(sa.Boolean(), default=False)
    nfs_srv_protocols = sa.Column(sa.JSON(type=list), default=[NFSProtocol.NFSv3, NFSProtocol.NFSv4])
    nfs_srv_v4_v3owner = sa.Column(sa.Boolean(), default=False)
    nfs_srv_v4_krb = sa.Column(sa.Boolean(), default=False)
    nfs_srv_bindip = sa.Column(sa.MultiSelectField())
    nfs_srv_mountd_port = sa.Column(sa.SmallInteger(), nullable=True)
    nfs_srv_rpcstatd_port = sa.Column(sa.SmallInteger(), nullable=True)
    nfs_srv_rpclockd_port = sa.Column(sa.SmallInteger(), nullable=True)
    nfs_srv_16 = sa.Column(sa.Boolean(), default=False)
    nfs_srv_mountd_log = sa.Column(sa.Boolean(), default=True)
    nfs_srv_statd_lockd_log = sa.Column(sa.Boolean(), default=False)
    nfs_srv_v4_domain = sa.Column(sa.String(120))
    nfs_srv_v4_owner_major = sa.Column(sa.String(1023), default='')


class NFSService(SystemServiceService):

    class Config:
        service = "nfs"
        service_verb = "restart"
        datastore = "services.nfs"
        datastore_prefix = "nfs_srv_"
        datastore_extend = 'nfs.nfs_extend'
        cli_namespace = "service.nfs"

    ENTRY = Dict(
        'nfs_entry',
        Int('id', required=True),
        Int('servers', validators=[Range(min=1, max=256)], required=True),
        Bool('udp', required=True),
        Bool('allow_nonroot', required=True),
        List('protocols', items=[Str('protocol', enum=NFSProtocol.choices())], required=True),
        Bool('v4_v3owner', required=True),
        Bool('v4_krb', required=True),
        Str('v4_domain', required=True),
        List('bindip', items=[IPAddr('ip')], required=True),
        Int('mountd_port', null=True, validators=[Range(min=1, max=65535)], required=True),
        Int('rpcstatd_port', null=True, validators=[Range(min=1, max=65535)], required=True),
        Int('rpclockd_port', null=True, validators=[Range(min=1, max=65535)], required=True),
        Bool('mountd_log', required=True),
        Bool('statd_lockd_log', required=True),
        Bool('v4_krb_enabled', required=True),
        Bool('userd_manage_gids', required=True),
    )

    @private
    async def nfs_extend(self, nfs):
        keytab_has_nfs = await self.middleware.call("kerberos.keytab.has_nfs_principal")
        nfs["v4_krb_enabled"] = (nfs["v4_krb"] or keytab_has_nfs)
        nfs["userd_manage_gids"] = nfs.pop("16")
        nfs["v4_owner_major"] = nfs.pop("v4_owner_major")
        return nfs

    @private
    async def nfs_compress(self, nfs):
        nfs.pop("v4_krb_enabled")
        nfs["16"] = nfs.pop("userd_manage_gids")
        return nfs

    @accepts()
    @returns(Dict(additional_attrs=True))
    async def bindip_choices(self):
        """
        Returns ip choices for NFS service to use
        """
        return {
            d['address']: d['address'] for d in await self.middleware.call(
                'interface.ip_in_use', {'static': True}
            )
        }

    @private
    async def bindip(self, config):
        bindip = [addr for addr in config['bindip'] if addr not in ['0.0.0.0', '::']]
        if bindip:
            found = False
            for iface in await self.middleware.call('interface.query'):
                for alias in iface['state']['aliases']:
                    if alias['address'] in bindip:
                        found = True
                        break
                if found:
                    break
        else:
            found = True

        if found:
            await self.middleware.call('alert.oneshot_delete', 'NFSBindAddress', None)

            return bindip
        else:
            if await self.middleware.call('cache.has_key', 'interfaces_are_set_up'):
                await self.middleware.call('alert.oneshot_create', 'NFSBindAddress', None)

            return []

    @accepts(Patch(
        'nfs_entry', 'nfs_update',
        ('rm', {'name': 'id'}),
        ('rm', {'name': 'v4_krb_enabled'}),
        ('attr', {'update': True}),
    ))
    async def do_update(self, data):
        """
        Update NFS Service Configuration.

        `servers` represents number of servers to create.

        When `allow_nonroot` is set, it allows non-root mount requests to be served.

        `bindip` is a list of IP's on which NFS will listen for requests. When it is unset/empty, NFS listens on
        all available addresses.

        `protocols` specifies whether NFSv3, NFSv4, or both are enabled.

        `v4_v3owner` when set means that system will use NFSv3 ownership model for NFSv4.

        `v4_krb` will force NFS shares to fail if the Kerberos ticket is unavailable.

        `v4_domain` overrides the default DNS domain name for NFSv4.

        `mountd_port` specifies the port mountd(8) binds to.

        `rpcstatd_port` specifies the port rpc.statd(8) binds to.

        `rpclockd_port` specifies the port rpclockd_port(8) binds to.

        .. examples(websocket)::

          Update NFS Service Configuration to listen on 192.168.0.10 and use NFSv4

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "pool.resilver.update",
                "params": [{
                    "bindip": [
                        "192.168.0.10"
                    ],
                    "protocols": ["NFSV3", "NFSV4"]
                }]
            }
        """
        if 'protocols' in data:
            if not data['protocols']:
                raise ValidationError(
                    'nfs_update.protocols',
                    'Must specify at least one value ("NFSV3", "NFSV4") in the "protocols" list.'
                )
            if NFSProtocol.NFSv4 not in data.get("protocols"):
                data.setdefault("v4_v3owner", False)

        old = await self.config()

        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        keytab_has_nfs = await self.middleware.call("kerberos.keytab.has_nfs_principal")
        new_v4_krb_enabled = new["v4_krb"] or keytab_has_nfs

        for k in ['mountd_port', 'rpcstatd_port', 'rpclockd_port']:
            for bindip in (new['bindip'] or ['0.0.0.0']):
                verrors.extend(await validate_port(self.middleware, f'nfs_update.{k}', new[k], 'nfs', bindip))

        if await self.middleware.call("failover.licensed") and NFSProtocol.NFSv4 in new["protocols"] and new_v4_krb_enabled:
            gc = await self.middleware.call("datastore.config", "network.globalconfiguration")
            if not gc["gc_hostname_virtual"] or not gc["gc_domain"]:
                verrors.add(
                    "nfs_update.v4",
                    "Enabling kerberos authentication on TrueNAS HA requires setting the virtual hostname and "
                    "domain"
                )

        bindip_choices = await self.bindip_choices()
        for i, bindip in enumerate(new['bindip']):
            if bindip not in bindip_choices:
                verrors.add(f'nfs_update.bindip.{i}', 'Please provide a valid ip address')

        if NFSProtocol.NFSv4 in new["protocols"] and new_v4_krb_enabled:
            """
            In environments with kerberized NFSv4 enabled, we need to tell winbindd to not prefix
            usernames with the short form of the AD domain. Directly update the db and regenerate
            the smb.conf to avoid having a service disruption due to restarting the samba server.
            """
            ad_config = await self.middleware.call('activedirectory.config')
            if ad_config['enable'] and not ad_config['use_default_domain']:
                await self.middleware.call(
                    'activedirectory.direct_update',
                    {'use_default_domain': True}
                )
                await self.middleware.call('activedirectory.synchronize')
                await self.middleware.call('service.reload', 'idmap')

        if NFSProtocol.NFSv4 not in new["protocols"] and new["v4_v3owner"]:
            verrors.add("nfs_update.v4_v3owner", "This option requires enabling NFSv4")

        if new["v4_v3owner"] and new["userd_manage_gids"]:
            verrors.add(
                "nfs_update.userd_manage_gids", "This option is incompatible with NFSv3 ownership model for NFSv4")

        if NFSProtocol.NFSv4 not in new["protocols"] and new["v4_domain"]:
            verrors.add("nfs_update.v4_domain", "This option does not apply to NFSv3")

        verrors.check()

        await self.nfs_compress(new)

        await self._update_service(old, new, "restart")

        return await self.config()


class NFSShareModel(sa.Model):
    __tablename__ = 'sharing_nfs_share'

    id = sa.Column(sa.Integer(), primary_key=True)
    nfs_path = sa.Column(sa.Text())
    nfs_aliases = sa.Column(sa.JSON(type=list))
    nfs_comment = sa.Column(sa.String(120))
    nfs_network = sa.Column(sa.Text())
    nfs_hosts = sa.Column(sa.Text())
    nfs_ro = sa.Column(sa.Boolean(), default=False)
    nfs_maproot_user = sa.Column(sa.String(120), nullable=True, default='')
    nfs_maproot_group = sa.Column(sa.String(120), nullable=True, default='')
    nfs_mapall_user = sa.Column(sa.String(120), nullable=True, default='')
    nfs_mapall_group = sa.Column(sa.String(120), nullable=True, default='')
    nfs_security = sa.Column(sa.MultiSelectField())
    nfs_enabled = sa.Column(sa.Boolean(), default=True)


class SharingNFSService(SharingService):

    share_task_type = 'NFS'

    class Config:
        namespace = "sharing.nfs"
        datastore = "sharing.nfs_share"
        datastore_prefix = "nfs_"
        datastore_extend = "sharing.nfs.extend"
        cli_namespace = "sharing.nfs"

    ENTRY = Patch(
        'sharingnfs_create', 'sharing_nfs_entry',
        ('add', Int('id')),
        ('add', Bool('locked')),
        register=True,
    )

    @accepts(Dict(
        "sharingnfs_create",
        Dir("path", required=True),
        List("aliases", items=[Str("path", validators=[Match(r"^/.*")])]),
        Str("comment", default=""),
        List("networks", items=[IPAddr("network", network=True)], unique=True),
        List(
            "hosts", items=[Str("host", validators=[NotMatch(
                r'.*[\s"]', explanation='Name cannot contain spaces or quotes')]
            )],
            unique=True
        ),
        Bool("ro", default=False),
        Str("maproot_user", required=False, default=None, null=True),
        Str("maproot_group", required=False, default=None, null=True),
        Str("mapall_user", required=False, default=None, null=True),
        Str("mapall_group", required=False, default=None, null=True),
        List(
            "security",
            items=[Str("provider", enum=["SYS", "KRB5", "KRB5I", "KRB5P"])],
        ),
        Bool("enabled", default=True),
        register=True,
        strict=True,
    ))
    async def do_create(self, data):
        """
        Create a NFS Share.

        `path` local path to be exported.

        `aliases` IGNORED, for now.

        `networks` is a list of authorized networks that are allowed to access the share having format
        "network/mask" CIDR notation. If empty, all networks are allowed.

        `hosts` is a list of IP's/hostnames which are allowed to access the share. If empty, all IP's/hostnames are
        allowed.

        """
        verrors = ValidationErrors()

        await self.validate(data, "sharingnfs_create", verrors)

        verrors.check()

        await self.compress(data)
        data["id"] = await self.middleware.call(
            "datastore.insert", self._config.datastore, data,
            {
                "prefix": self._config.datastore_prefix
            },
        )
        await self.extend(data)

        await self._service_change("nfs", "reload")

        return await self.get_instance(data["id"])

    @accepts(
        Int("id"),
        Patch(
            "sharingnfs_create",
            "sharingnfs_update",
            ("attr", {"update": True})
        )
    )
    async def do_update(self, id, data):
        """
        Update NFS Share of `id`.
        """
        verrors = ValidationErrors()
        old = await self.get_instance(id)

        new = old.copy()
        new.update(data)

        await self.validate(new, "sharingnfs_update", verrors, old=old)

        verrors.check()

        await self.compress(new)
        await self.middleware.call(
            "datastore.update", self._config.datastore, id, new,
            {
                "prefix": self._config.datastore_prefix
            }
        )

        await self._service_change("nfs", "reload")

        return await self.get_instance(id)

    @returns()
    async def do_delete(self, id):
        """
        Delete NFS Share of `id`.
        """
        await self.middleware.call("datastore.delete", self._config.datastore, id)
        await self._service_change("nfs", "reload")

    @private
    async def validate(self, data, schema_name, verrors, old=None):
        if len(data["aliases"]):
            data['aliases'] = []
            # This feature was originally intended to be provided by nfs-ganesha
            # since we no longer have ganesha, planning will need to be made about
            # how to implement for kernel NFS server. One candidate is using bind mounts,
            # but this will require careful design and testing. For now we will keep it disabled.
            """
            if len(data["aliases"]) != len(data["paths"]):
                verrors.add(
                    f"{schema_name}.aliases",
                    "This field should be either empty of have the same number of elements as paths",
                )
            """

        # need to make sure that the nfs share is within the zpool mountpoint
        await check_path_resides_within_volume(
            verrors, self.middleware, f'{schema_name}.path', data['path'],
        )

        filters = []
        if old:
            filters.append(["id", "!=", old["id"]])
        other_shares = await self.middleware.call("sharing.nfs.query", filters)

        self.validate_share_hosts_input(data['hosts'], schema_name, verrors)
        # Stop here if the input generated errors for the user to fix
        verrors.check()

        dns_cache = await self.resolve_hostnames(
            sum([share["hosts"] for share in other_shares], []) + data['hosts']
        )

        self.validate_share_networks_input(data['networks'], dns_cache, schema_name, verrors)
        # Stop here if the input generated errors for the user to fix
        verrors.check()

        await self.validate_hosts_and_networks(
            other_shares, data, schema_name, verrors, dns_cache
        )

        # Confirm the share will not collide with an existing share
        await self.validate_share_path(other_shares, data, schema_name, verrors)

        for k in ["maproot", "mapall"]:
            if not data[f"{k}_user"] and not data[f"{k}_group"]:
                pass
            elif not data[f"{k}_user"] and data[f"{k}_group"]:
                verrors.add(f"{schema_name}.{k}_user", "This field is required when map group is specified")
            else:
                user = group = None
                with contextlib.suppress(KeyError):
                    user = await self.middleware.call('dscache.get_uncached_user', data[f'{k}_user'])

                if not user:
                    verrors.add(f"{schema_name}.{k}_user", "User not found")

                if data[f'{k}_group']:
                    with contextlib.suppress(KeyError):
                        group = await self.middleware.call('dscache.get_uncached_group', data[f'{k}_group'])

                    if not group:
                        verrors.add(f"{schema_name}.{k}_group", "Group not found")

        if data["maproot_user"] and data["mapall_user"]:
            verrors.add(f"{schema_name}.mapall_user", "maproot_user disqualifies mapall_user")

        v4_sec = list(filter(lambda sec: sec != "SYS", data.get("security", [])))
        if v4_sec:
            nfs_config = await self.middleware.call("nfs.config")
            if NFSProtocol.NFSv4 not in nfs_config["protocols"]:
                verrors.add(
                    f"{schema_name}.security",
                    f"The following security flavor(s) require NFSv4 to be enabled: {','.join(v4_sec)}."
                )

    @private
    def validate_share_hosts_input(self, hosts, schema_name, verrors):
        """
        Validate:
        * List of hosts cannot contain repeated 'host' names
        * The host '*' cannot be used in combination of other hosts
        """
        # Check for the 'everybody' (*) host entry.
        if '*' in hosts and len(set(hosts)) > 1:
            verrors.add(
                f"{schema_name}.hosts",
                "ERROR - '*', i.e. 'everybody', cannot be included with other entries on same share path"
            )

    @private
    def validate_share_networks_input(self, networks, dns_cache, schema_name, verrors):
        """
        The network field is strictly limited to CIDR formats:
        The input validator should enforce the CIDR format and a single address per entry.
        This validation is limited to detecting repeats and overlapping subnets.
        """
        dns_cache_values = list(dns_cache.values())
        for IPaddr in networks:
            IPinterface = ipaddress.ip_interface(IPaddr)

            if str(IPinterface.ip) in dns_cache_values:
                key = next(key for key, value in dns_cache.items() if value == str(IPinterface.ip))
                verrors.add(
                    f"{schema_name}.networks",
                    f"ERROR - Resolved hostname to duplicate address: host '{key}' resolves to '{IPaddr}'"
                )

        overlaps = []
        for n1, n2 in itertools.combinations(networks, 2):
            # Check for overlapped networks
            ipn1 = ipaddress.ip_network(n1)
            ipn2 = ipaddress.ip_network(n2)
            if ipn1.overlaps(ipn2):
                overlaps.append((n1, n2))

        if overlaps:
            verrors.add(
                f"{schema_name}.networks",
                f"ERROR - Overlapped subnets: {overlaps}"
            )

    @private
    async def resolve_hostnames(self, hostnames):
        hostnames = list(set(hostnames))

        async def resolve(hostname):
            try:
                try:
                    # If this is an IP address, just return it
                    ip = IpAddress()
                    ip(hostname)
                    return hostname
                except ValueError:
                    # Not an IP address, should be a name
                    if domain := get_wildcard_domain(hostname):
                        hostname = domain

                    if leftmost_has_wildcards(hostname):
                        # We know this will not resolve
                        return None
                    else:
                        try:
                            dns_addresses = [x['address'] for x in await self.middleware.call('dnsclient.forward_lookup', {
                                'names': [hostname]
                            })]
                            # We might get both IPv4 and IPv6 addresses, the caller expects a single response
                            return dns_addresses[0]
                        except Exception as e:
                            self.logger.warning("Unable to resolve host %r: %r", hostname, e)
                            return None
            except Exception as e:
                self.logger.warning("Unable to resolve or invalid host %r: %r", hostname, e)
                return None

        resolved_hostnames = await asyncio_map(resolve, hostnames, 8)

        return dict(zip(hostnames, resolved_hostnames))

    @private
    async def validate_hosts_and_networks(self, other_shares, data, schema_name, verrors, dns_cache):
        """
        We attempt to prevent share situation where the same host is provided access to a
        share but with potentially different permissions.
        """
        tgt_realpath = (await self.middleware.call('filesystem.stat', data['path']))['realpath']

        used_networks = set()
        used_hosts = set()  # host names without an entry in the cache
        for share in other_shares:
            try:
                shr_realpath = (await self.middleware.call('filesystem.stat', share['path']))['realpath']
            except CallError as e:
                if e.errno != errno.ENOENT:
                    raise
                # Allow for locked filesystems
                shr_realpath = share['path']

            if tgt_realpath == shr_realpath:
                for host in share["hosts"]:
                    host_ip = dns_cache.get(host)
                    if host_ip is None:
                        used_hosts.add(host)
                        continue

                    if host.startswith('@'):
                        continue

                    try:
                        network = ipaddress.ip_network(host_ip)
                    except Exception:
                        self.logger.warning("Got invalid host %r", host)
                        continue
                    else:
                        used_networks.add(network)

                for network in share["networks"]:
                    try:
                        network = ipaddress.ip_network(network, strict=False)
                    except Exception:
                        self.logger.warning("Got invalid network %r", network)
                        continue
                    else:
                        used_networks.add(network)

                if not share["hosts"] and not share["networks"]:
                    used_networks.add(ipaddress.ip_network("0.0.0.0/0"))
                    used_networks.add(ipaddress.ip_network("::/0"))

        for host in set(data["hosts"]):
            # check for duplicate 'hosts' in other shares
            # netgroups are valid, but limited to same duplicate restrictions
            if host in used_hosts:
                verrors.add(
                    f"{schema_name}.hosts",
                    f"Another NFS share already exports {data['path']} for {host}"
                )
                continue

            if host.startswith('@'):
                continue

            # wildcarded names without a 'domain' are valid
            if leftmost_has_wildcards(host) and get_domain(host) is None:
                continue

            # Everything else should be resolvable
            host_ip = dns_cache[host]
            if host_ip is None:
                verrors.add(
                    f"{schema_name}.hosts",
                    f"Unable to resolve host '{host}'"
                )
                continue

            # Nothing more to check with wildcard names
            if leftmost_has_wildcards(host):
                continue

            network = ipaddress.ip_network(host_ip)
            if network in used_networks:
                verrors.add(
                    f"{schema_name}.hosts",
                    f"Another NFS share already exports {data['path']} for {host_ip} ({host})"
                )

            used_networks.add(network)

        for network in set(data["networks"]):
            network = ipaddress.ip_network(network, strict=False)

            # Look for exact match
            if network in used_networks:
                verrors.add(
                    f"{schema_name}.networks",
                    f"Another NFS share already exports {data['path']} for {network}"
                )
            # Look for subnet or supernet (NOTE: support for IPv4 only)
            if network.version == 4:
                for other_net in used_networks:
                    if network.overlaps(other_net):
                        verrors.add(
                            f"{schema_name}.networks",
                            f"Another NFS share exports {data['path']} as {other_net} which overlaps {network}"
                        )

            used_networks.add(network)

    @private
    async def validate_share_path(self, other_shares, data, schema_name, verrors):
        """
        A share path centric test. Checks new share path against existing.
        There are multiple ways to get duplicate entries for a given share path
        1) A share path could be set for everyone and another host entries only, e.g.
            /mnt/tank/dataset 192.168.1.1(rw)
            /mnt/tank/dataset *(ro)
        2) A host could be part of a network subnet, e.g.
            /mnt/tank/dataset 192.168.1.1(rw)
            /mnt/tank/dataset 192.168.1.0/24(ro)
            Note: The 192.168.1.0/24 is a 'networks' specification
        This function checks for common conditions.
        """
        # We test other shares that are sharing the same path
        tgt_stat = await self.middleware.call('filesystem.stat', data["path"])

        # Sanity check: no symlinks
        if tgt_stat['type'] == "SYMLINK":
            verrors.add(
                f"{schema_name}.path",
                f"Symbolic links are not allowed: {data['path']}."
            )

        tgt_realpath = tgt_stat['realpath']
        for share in other_shares:
            try:
                shr_realpath = (await self.middleware.call('filesystem.stat', share['path']))['realpath']
            except CallError as e:
                if e.errno != errno.ENOENT:
                    raise
                # Allow for locked filesystems
                shr_realpath = share['path']

            if tgt_realpath == shr_realpath:
                # Test hosts
                # An empty 'hosts' list == '*' == 'everybody.  Workaround: remove '*' as a host entry
                datahosts = [host for host in data["hosts"] if host != "*"]
                sharehosts = [host for host in share["hosts"] if host != "*"]

                commonHosts = set(datahosts) & set(sharehosts)
                commonNetworks = set(data["networks"]) & set(share["networks"])
                other_share_everybody = not bool(set(sharehosts) | set(share['networks']))
                this_share_everybody = not bool(datahosts) and not bool(data['networks'])
                everybody = other_share_everybody or this_share_everybody

                if bool(commonHosts) | bool(commonNetworks) | everybody:
                    reason = "'everybody', i.e. '*'"
                    other_share_desc = "Another share with the same path"
                    this_share_desc = "This share is exported to everybody and another share"
                    if commonHosts:
                        desc = other_share_desc
                        reason = str(commonHosts)
                    elif commonNetworks:
                        desc = other_share_desc
                        reason = str(commonNetworks)
                    elif this_share_everybody:
                        desc = this_share_desc
                        reason = f"{', '.join(sharehosts)}"
                    else:
                        desc = other_share_desc
                    verrors.add(
                        f"{schema_name}.path",
                        f"ERROR - Export conflict. {desc} exports {share['path']} for {reason}"
                    )
                    # Found an export of the same path to the same 'hosts'. Report it.
                    break

    @private
    async def extend(self, data):
        data["networks"] = data.pop("network").split()
        data["hosts"] = data["hosts"].split()
        data["security"] = [s.upper() for s in data["security"]]
        return data

    @private
    async def compress(self, data):
        data["network"] = " ".join(data.pop("networks"))
        data["hosts"] = " ".join(data["hosts"])
        data["security"] = [s.lower() for s in data["security"]]
        data.pop(self.locked_field, None)
        return data


async def pool_post_import(middleware, pool):
    """
    Makes sure to reload NFS if a pool is imported and there are shares configured for it.
    """
    if pool is None:
        middleware.create_task(middleware.call('etc.generate', 'nfsd'))
        return

    path = f'/mnt/{pool["name"]}'
    for share in await middleware.call('sharing.nfs.query'):
        if share['path'].startswith(path):
            middleware.create_task(middleware.call('service.reload', 'nfs'))
            break


class NFSFSAttachmentDelegate(LockableFSAttachmentDelegate):
    name = 'nfs'
    title = 'NFS Share'
    service = 'nfs'
    service_class = SharingNFSService
    resource_name = 'path'

    async def restart_reload_services(self, attachments):
        await self._service_change('nfs', 'reload')


async def setup(middleware):
    await middleware.call(
        'interface.register_listen_delegate',
        SystemServiceListenMultipleDelegate(middleware, 'nfs', 'bindip'),
    )
    await middleware.call('pool.dataset.register_attachment_delegate', NFSFSAttachmentDelegate(middleware))

    middleware.register_hook('pool.post_import', pool_post_import, sync=True)
