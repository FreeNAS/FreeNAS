from middlewared.schema import Bool, Dict, IPAddr, List, Str, Int, Patch
from middlewared.service import (SystemServiceService, ValidationErrors,
                                 accepts, private, CRUDService)
from middlewared.async_validators import check_path_resides_within_volume
from middlewared.service_exception import CallError
from middlewared.utils import Popen, run

import asyncio
import binascii
import codecs
import enum
import errno
import os
import re
import subprocess
import uuid
from samba import samba3
from samba import param

LOGLEVEL_MAP = {
    '0': 'NONE',
    '1': 'MINIMUM',
    '2': 'NORMAL',
    '3': 'FULL',
    '10': 'DEBUG',
}
RE_NETBIOSNAME = re.compile(r"^[a-zA-Z0-9\.\-_!@#\$%^&\(\)'\{\}~]{1,15}$")


class smbhamode(enum.Enum):
    """
    'standalone' - Not an HA system.
    'legacy' - Two samba instances simultaneously running on active and passive controllers with no shared state.
    'unified' - Single set of state files migrating between controllers. Single netbios name.
    """
    STANDALONE = 0
    LEGACY = 1
    UNIFIED = 2


class lsa_sidType(enum.Enum):
    """
    Defined in MS-SAMR (2.2.2.3) and lsa.idl
    Samba's group mapping database will primarily contain SID_NAME_ALIAS entries (local groups)
    """
    SID_NAME_USE_NONE = 0
    SID_NAME_USER = 1
    SID_NAME_DOM_GRP = 2
    SID_NAME_DOMAIN = 3
    SID_NAME_ALIAS = 4
    SID_NAME_WKN_GRP = 5
    SID_NAME_DELETED = 6
    SID_NAME_INVALID = 7
    SID_NAME_UNKNOWN = 8
    SID_NAME_COMPUTER = 9
    SID_NAME_LABEL = 10


class samr_AcctFlags(enum.IntFlag):
    """
    Defined in MS-SAMR (2.2.1.12) and samr.idl
    """
    DISABLED = 0x00000001
    HOMEDIRREQ = 0x00000002
    PWNOTREQ = 0x00000004
    TEMPDUP = 0x00000008
    NORMAL = 0x00000010
    MNS = 0x00000020
    DOMTRUST = 0x00000040
    WSTRUST = 0x00000080
    SVRTRUST = 0x00000100
    PWNOEXP = 0x00000200
    AUTOLOCK = 0x00000400
    ENC_TXT_PWD_ALLOWED = 0x00000800
    SMARTCARD_REQUIRED = 0x00001000
    TRUSTED_FOR_DELEGATION = 0x00002000
    NOT_DELEGATED = 0x00004000
    USE_DES_KEY_ONLY = 0x00008000
    DONT_REQUIRE_PREAUTH = 0x00010000
    PW_EXPIRED = 0x00020000
    TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x00040000
    NO_AUTH_DATA_REQD = 0x00080000
    PARTIAL_SECRETS_ACCOUNT = 0x00100000
    USE_AES_KEYS = 0x00200000


class SMBService(SystemServiceService):

    class Config:
        service = 'cifs'
        service_verb = 'restart'
        datastore = 'services.cifs'
        datastore_extend = 'smb.smb_extend'
        datastore_prefix = 'cifs_srv_'

    @private
    async def smb_extend(self, smb):
        """Extend smb for netbios."""
        if not await self.middleware.call('system.is_freenas') and await self.middleware.call('failover.node') == 'B':
            smb['netbiosname'] = smb['netbiosname_b']

        for i in ('aio_enable', 'aio_rs', 'aio_ws'):
            smb.pop(i, None)

        smb['netbiosalias'] = (smb['netbiosalias'] or '').split()

        smb['loglevel'] = LOGLEVEL_MAP.get(smb['loglevel'])

        return smb

    async def __validate_netbios_name(self, name):
        return RE_NETBIOSNAME.match(name)

    async def unixcharset_choices(self):
        return await self.generate_choices(
            ['UTF-8', 'ISO-8859-1', 'ISO-8859-15', 'GB2312', 'EUC-JP', 'ASCII']
        )

    @private
    async def generate_choices(self, initial):
        def key_cp(encoding):
            cp = re.compile(r"(?P<name>CP|GB|ISO-8859-|UTF-)(?P<num>\d+)").match(encoding)
            if cp:
                return tuple((cp.group('name'), int(cp.group('num'), 10)))
            else:
                return tuple((encoding, float('inf')))

        charset = await self.common_charset_choices()
        return {
            v: v for v in [
                c for c in sorted(charset, key=key_cp) if c not in initial
            ] + initial
        }

    @private
    async def common_charset_choices(self):

        def check_codec(encoding):
            try:
                return encoding.upper() if codecs.lookup(encoding) else False
            except LookupError:
                return False

        proc = await Popen(
            ['/usr/bin/iconv', '-l'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        output = (await proc.communicate())[0].decode()

        encodings = set()
        for line in output.splitlines():
            enc = [e for e in line.split() if check_codec(e)]

            if enc:
                cp = enc[0]
                for e in enc:
                    if e in ('UTF-8', 'ASCII', 'GB2312', 'HZ-GB-2312', 'CP1361'):
                        cp = e
                        break

                encodings.add(cp)

        return encodings

    @private
    async def store_ldap_admin_password(self):
        """
        This is required if the LDAP directory service is enabled. The ldap admin dn and
        password are stored in private/secrets.tdb file.
        """
        ldap = await self.middleware.call('datastore.config', 'directoryservice.ldap')
        if not ldap['ldap_enable']:
            return True

        set_pass = await run(['usr/local/bin/smbpasswd', '-w', ldap['ldap_bindpw']], check=False)
        if set_pass.returncode != 0:
            self.logger.debug(f"Failed to set set ldap bindpw in secrets.tdb: {set_pass.stdout.decode()}")
            return False

        return True

    @private
    def groupmap_list(self):
        groupmap_list = []
        statedir = self.getparm('state directory', 'global')
        if not os.path.exists(f'{statedir}/group_mapping.tdb'):
            return []

        samba3.passdb.set_smb_config("/usr/local/etc/smb4.conf")

        groupmaps = samba3.passdb.PDB("tdbsam").enum_group_mapping()
        for g in groupmaps:
            groupmap_list.append({
                'comment': g.comment,
                'gid': g.gid,
                'ntgroup': g.nt_name,
                'SID': str(g.sid),
                'sid_type': lsa_sidType(g.sid_name_use).name,
            })
        return groupmap_list

    @private
    async def groupmap_add(self, group):
        """
        Map Unix group to NT group. This is required for group members to be
        able to access the SMB share. Name collisions with well-known and
        builtin groups must be avoided. Mapping groups with the same
        names as users should also be avoided.
        """
        passdb_backend = await self.middleware.run_in_thread(self.getparm, 'passdb backend', 'global')
        if passdb_backend == 'ldapsam':
            return

        disallowed_list = ['USERS', 'ADMINISTRATORS', 'GUESTS']
        existing_groupmap = await self.middleware.run_in_thread(self.groupmap_list)
        for user in (await self.middleware.call('user.query')):
            disallowed_list.append(user['username'].upper())
        for g in existing_groupmap:
            disallowed_list.append(g['ntgroup'].upper())

        if group.upper() in disallowed_list:
            self.logger.debug('Setting group map for %s is not permitted', group)
            return False
        gm_add = await run(
            ['net', '-d', '0', 'groupmap', 'add', 'type=local', f'unixgroup={group}', f'ntgroup={group}'],
            check=False
        )
        if gm_add.returncode != 0:
            raise CallError(f'Failed to generate groupmap for [{group}]: ({gm_add.stderr.decode})')

    @private
    def passdb_list(self, verbose=False):
        """
        passdb entries for local SAM database. This will be populated with
        local users in an AD environment. Immediately return in ldap enviornment.
        """
        pdbentries = []
        privatedir = self.getparm('privatedir', 'global')
        passdb_backend = self.getparm('passdb backend', 'global')
        if not os.path.exists(f'{privatedir}/passdb.tdb') or passdb_backend == 'ldapsam':
            return []

        samba3.passdb.set_smb_config("/usr/local/etc/smb4.conf")
        pdb = samba3.passdb.PDB("tdbsam").search_users(samr_AcctFlags.NORMAL.value)
        if not verbose:
            for p in pdb:
                acct_flags = []
                for flag in samr_AcctFlags:
                    if int(p['acct_flags']) & flag:
                        acct_flags.append(flag.name)
                pdbentries.append({
                    'username': p['account_name'],
                    'full_name': p['fullname'],
                    'comment': p['description'],
                    'rid': p['rid'],
                    'acct_ctrl': acct_flags
                })
            return pdbentries

        for p in pdb:
            u = samba3.passdb.PDB("tdbsam").getsampwnam(p['account_name'])
            acct_flags = []
            for flag in samr_AcctFlags:
                if int(u.acct_ctrl) & flag:
                    acct_flags.append(flag.name)

            pdbentries.append({
                'username': u.username,
                'full_name': u.full_name,
                'user_sid': str(u.user_sid),
                'profile_path': u.profile_path,
                'home_dir': u.home_dir,
                'domain': str(u.domain),
                'comment': str(u.comment),
                'logon_count': u.logon_count,
                'acct_ctrl': acct_flags
            })
        return pdbentries

    @private
    def update_passdb_user(self, username):
        """
        Updates a user's passdb entry to reflect the current server configuration.
        """
        privatedir = self.getparm('privatedir', 'global')
        if self.getparm('passdb backend', 'global') == 'ldapsam':
            return

        if not os.path.exists(f'{privatedir}/passdb.tdb'):
            raise CallError(f'Unable to add [{username}] to passdb.tdb. File does not exist.', errno.ENOENT)

        bsduser = self.middleware.call_sync('user.query', [('username', '=', username)])
        if len(bsduser) == 0 or not bsduser[0]['smbhash']:
            return
        smbpasswd_string = bsduser[0]['smbhash'].split(':')
        samba3.passdb.set_smb_config("/usr/local/etc/smb4.conf")
        try:
            p = samba3.passdb.PDB('tdbsam').getsampwnam(username)
        except Exception:
            self.logger.debug("User [%s] does not exist in the passdb.tdb file. Creating entry.", username)
            samba3.passdb.PDB('tdbsam').create_user(username, samr_AcctFlags.NORMAL)
            p = samba3.passdb.PDB('tdbsam').getsampwnam(username)

        pdb_entry_changed = False

        try:
            nt_passwd = binascii.hexlify(p.nt_passwd).decode().upper()
        except Exception:
            nt_passwd = ''

        if smbpasswd_string[3] != nt_passwd:
            p.nt_passwd = binascii.unhexlify(smbpasswd_string[3])
            pdb_entry_changed = True
        if 'D' in smbpasswd_string[4] and not (p.acct_ctrl & samr_AcctFlags.DISABLED):
            p.acct_ctrl |= samr_AcctFlags.DISABLED
            pdb_entry_changed = True
        elif 'D' not in smbpasswd_string[4] and (p.acct_ctrl & samr_AcctFlags.DISABLED):
            p.acct_ctrl = samr_AcctFlags.NORMAL
            pdb_entry_changed = True
        if pdb_entry_changed:
            samba3.passdb.PDB('tdbsam').update_sam_account(p)

    @private
    def synchronize_passdb(self):
        """
        Create any missing entries in the passdb.tdb.
        Replace NT hashes of users if they do not match what is the the config file.
        Synchronize the "disabled" state of users
        Delete any entries in the passdb_tdb file that don't exist in the config file.
        """
        privatedir = self.getparm('privatedir', 'global')
        passdb_backend = self.getparm('passdb backend', 'global')
        if not os.path.exists(f'{privatedir}/passdb.tdb'):
            self.logger.debug('passdb.tdb file does not exist yet. Unable to synchronize.')
            return

        if passdb_backend == 'ldapsam':
            self.logger.debug('Refusing to synchronize passdb.tdb while LDAP is enabled.')
            return

        samba3.passdb.set_smb_config("/usr/local/etc/smb4.conf")
        conf_users = self.middleware.call_sync('user.query', [
            ['OR', [
                ('smbhash', '~', r'^.+:.+:[X]{32}:.+$'),
                ('smbhash', '~', r'^.+:.+:[A-F0-9]{32}:.+$'),
            ]]
        ])
        for u in conf_users:
            smbpasswd_string = u['smbhash'].split(':')
            pdb_entry_changed = False
            try:
                p = samba3.passdb.PDB('tdbsam').getsampwnam(u['username'])
            except Exception:
                self.logger.debug("User [%s] does not exist in the passdb.tdb file. Creating entry.", u['username'])
                samba3.passdb.PDB('tdbsam').create_user(u['username'], samr_AcctFlags.NORMAL)
                p = samba3.passdb.PDB('tdbsam').getsampwnam(u['username'])

            try:
                nt_passwd = binascii.hexlify(p.nt_passwd).decode().upper()
            except Exception:
                nt_passwd = ''

            if smbpasswd_string[3] != nt_passwd:
                p.nt_passwd = binascii.unhexlify(smbpasswd_string[3])
                pdb_entry_changed = True
            if 'D' in smbpasswd_string[4] and not (p.acct_ctrl & samr_AcctFlags.DISABLED):
                p.acct_ctrl |= samr_AcctFlags.DISABLED
                pdb_entry_changed = True
            elif 'D' not in smbpasswd_string[4] and (p.acct_ctrl & samr_AcctFlags.DISABLED):
                p.acct_ctrl = samr_AcctFlags.NORMAL
                pdb_entry_changed = True
            if pdb_entry_changed:
                samba3.passdb.PDB('tdbsam').update_sam_account(p)

        pdb_users = self.passdb_list()
        if len(pdb_users) > len(conf_users):
            for entry in pdb_users:
                if not any(filter(lambda x: entry['username'] == x['username'], conf_users)):
                    self.logger.debug('Synchronizing passdb with config file: deleting user [%s] from passdb.tdb', entry['username'])
                    user_to_delete = samba3.passdb.PDB('tdbsam').getsampwnam(entry['username'])
                    samba3.passdb.PDB('tdbsam').delete_user(user_to_delete)

    @private
    def getparm(self, parm, section):
        """
        Get a parameter from the smb4.conf file. This is more reliable than
        'testparm --parameter-name'. testparm will fail in a variety of
        conditions without returning the parameter's value.
        """
        try:
            res = param.LoadParm('usr/local/etc/smb4.conf').get(parm, section)
            return res
        except Exception as e:
            raise CallError(f'Attempt to query smb4.conf parameter [{parm}] failed with error: {e}')

    @private
    async def get_smb_ha_mode(self):
        if await self.middleware.call('cache.has_key', 'SMB_HA_MODE'):
            return await self.middleware.call('cache.get', 'SMB_HA_MODE')

        if not await self.middleware.call('system.is_freenas') and await self.middleware.call('failover.licensed'):
            system_dataset = await self.middleware.call('systemdataset.config')
            if system_dataset['pool'] != 'freenas-boot':
                hamode = smbhamode['UNIFIED'].name
            else:
                hamode = smbhamode['LEGACY'].name
        else:
            hamode = smbhamode['STANDALONE'].name

        await self.middleware.call('cache.put', 'SMB_HA_MODE', hamode)
        return hamode

    @private
    async def reset_smb_ha_mode(self):
        await self.middleware.call('cache.pop', 'SMB_HA_MODE')
        return await self.get_smb_ha_mode()

    @accepts(Dict(
        'smb_update',
        Str('netbiosname'),
        Str('netbiosname_b'),
        List('netbiosalias', default=[]),
        Str('workgroup'),
        Str('description'),
        Bool('enable_smb1'),
        Str('unixcharset'),
        Str('loglevel', enum=['NONE', 'MINIMUM', 'NORMAL', 'FULL', 'DEBUG']),
        Bool('syslog'),
        Bool('localmaster'),
        Bool('domain_logons'),
        Bool('timeserver'),
        Str('guest'),
        Str('filemask'),
        Str('dirmask'),
        Bool('nullpw'),
        Bool('unixext'),
        Bool('zeroconf'),
        Bool('hostlookup'),
        Bool('allow_execute_always'),
        Bool('obey_pam_restrictions'),
        Bool('ntlmv1_auth'),
        List('bindip', items=[IPAddr('ip')], default=[]),
        Str('smb_options'),
        update=True,
    ))
    async def do_update(self, data):
        """
        Update SMB Service Configuration.

        `netbiosname` defaults to the original hostname of the system.

        `workgroup` and `netbiosname` should have different values.

        `enable_smb1` allows legacy SMB clients to connect to the server when enabled.

        `localmaster` when set, determines if the system participates in a browser election.

        `domain_logons` is used to provide netlogin service for older Windows clients if enabled.

        `guest` attribute is specified to select the account to be used for guest access. It defaults to "nobody".

        `nullpw` when enabled allows the users to authorize access without a password.

        `zeroconf` should be enabled if macOS Clients will be connecting to the SMB share.

        `hostlookup` when enabled, allows using hostnames rather then IP addresses in "hostsallow"/"hostsdeny" fields
        of SMB Shares.
        """
        old = await self.config()

        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        if data.get('unixcharset') and data['unixcharset'] not in await self.unixcharset_choices():
            verrors.add(
                'smb_update.unixcharset',
                'Please provide a valid value for unixcharset'
            )

        for i in ('workgroup', 'netbiosname', 'netbiosname_b', 'netbiosalias'):
            if i not in data or not data[i]:
                continue
            if i == 'netbiosalias':
                for idx, item in enumerate(data[i]):
                    if not await self.__validate_netbios_name(item):
                        verrors.add(f'smb_update.{i}.{idx}', f'Invalid NetBIOS name: {item}')
            else:
                if not await self.__validate_netbios_name(data[i]):
                    verrors.add(f'smb_update.{i}', f'Invalid NetBIOS name: {data[i]}')

        if new['netbiosname'] and new['netbiosname'].lower() == new['workgroup'].lower():
            verrors.add('smb_update.netbiosname', 'NetBIOS and Workgroup must be unique')

        for i in ('filemask', 'dirmask'):
            if i not in data or not data[i]:
                continue
            try:
                if int(data[i], 8) & ~0o11777:
                    raise ValueError('Not an octet')
            except (ValueError, TypeError):
                verrors.add(f'smb_update.{i}', 'Not a valid mask')

        if verrors:
            raise verrors

        # TODO: consider using bidict
        for k, v in LOGLEVEL_MAP.items():
            if new['loglevel'] == v:
                new['loglevel'] = k
                break

        await self.compress(new)

        await self._update_service(old, new)
        await self.reset_smb_ha_mode()

        return await self.config()

    @private
    async def compress(self, data):
        data['netbiosalias'] = ' '.join(data['netbiosalias'])

        return data


class SharingSMBService(CRUDService):
    class Config:
        namespace = 'sharing.smb'
        datastore = 'sharing.cifs_share'
        datastore_prefix = 'cifs_'
        datastore_extend = 'sharing.smb.extend'

    @accepts(Dict(
        'sharingsmb_create',
        Str('path', required=True),
        Bool('home', default=False),
        Str('name'),
        Str('comment'),
        Bool('ro', default=False),
        Bool('browsable', default=True),
        Bool('timemachine', default=False),
        Bool('recyclebin', default=False),
        Bool('showhiddenfiles', default=False),
        Bool('guestok', default=False),
        Bool('guestonly', default=False),
        Bool('abe', default=False),
        List('hostsallow', default=[]),
        List('hostsdeny', default=[]),
        List('vfsobjects', default=['zfs_space', 'zfsacl', 'streams_xattr']),
        Bool('shadowcopy', default=False),
        Str('auxsmbconf'),
        Bool('default_permissions'),
        register=True
    ))
    async def do_create(self, data):
        """
        Create a SMB Share.

        `timemachine` when set, enables Time Machine backups for this share.

        `default_permissions` when set makes ACLs grant read and write for owner or group and read-only for others. It
        is advised to be disabled when creating shares on a sytem with custom ACLs.

        `ro` when enabled, prohibits write access to the share.

        `guestok` when enabled, allows access to this share without a password.

        `hostsallow` is a list of hostnames / IP addresses which have access to this share.

        `hostsdeny` is a list of hostnames / IP addresses which are not allowed access to this share. If a handful
        of hostnames are to be only allowed access, `hostsdeny` can be passed "ALL" which means that it will deny
        access to ALL hostnames except for the ones which have been listed in `hostsallow`.

        `vfsobjects` is a list of keywords which aim to provide virtual file system modules to enhance functionality.

        `auxsmbconf` is a string of additional smb4.conf parameters not covered by the system's API.
        """
        verrors = ValidationErrors()
        path = data['path']

        default_perms = data.pop('default_permissions', True)

        await self.clean(data, 'sharingsmb_create', verrors)
        await self.validate(data, 'sharingsmb_create', verrors)

        if verrors:
            raise verrors

        if path and not os.path.exists(path):
            try:
                os.makedirs(path)
            except OSError as e:
                raise CallError(f'Failed to create {path}: {e}')

        await self.compress(data)
        vuid = await self.generate_vuid(data['timemachine'])
        data.update({'vuid': vuid})
        data['id'] = await self.middleware.call(
            'datastore.insert', self._config.datastore, data,
            {'prefix': self._config.datastore_prefix})
        await self.extend(data)  # We should do this in the insert call ?

        await self._service_change('cifs', 'reload')
        await self.apply_default_perms(default_perms, path, data['home'])

        return data

    @accepts(
        Int('id'),
        Patch(
            'sharingsmb_create',
            'sharingsmb_update',
            ('attr', {'update': True})
        )
    )
    async def do_update(self, id, data):
        """
        Update SMB Share of `id`.
        """
        verrors = ValidationErrors()
        path = data.get('path')
        default_perms = data.pop('default_permissions', False)

        old = await self.middleware.call(
            'datastore.query', self._config.datastore, [('id', '=', id)],
            {'extend': self._config.datastore_extend,
             'prefix': self._config.datastore_prefix,
             'get': True})

        new = old.copy()
        new.update(data)

        new['vuid'] = await self.generate_vuid(new['timemachine'], new['vuid'])
        await self.clean(new, 'sharingsmb_update', verrors, id=id)
        await self.validate(new, 'sharingsmb_update', verrors, old=old)

        if verrors:
            raise verrors

        if path and not os.path.exists(path):
            try:
                os.makedirs(path)
            except OSError as e:
                raise CallError(f'Failed to create {path}: {e}')

        await self.compress(new)
        await self.middleware.call(
            'datastore.update', self._config.datastore, id, new,
            {'prefix': self._config.datastore_prefix})
        await self.extend(new)  # same here ?

        await self._service_change('cifs', 'reload')
        await self.apply_default_perms(default_perms, path, data['home'])

        return new

    @accepts(Int('id'))
    async def do_delete(self, id):
        """
        Delete SMB Share of `id`.
        """
        share = await self._get_instance(id)
        result = await self.middleware.call('datastore.delete', self._config.datastore, id)
        await self.middleware.call('notifier.sharesec_delete', share['name'])
        await self._service_change('cifs', 'reload')
        return result

    @private
    async def clean(self, data, schema_name, verrors, id=None):
        data['name'] = await self.name_exists(data, schema_name, verrors, id)

    @private
    async def validate(self, data, schema_name, verrors, old=None):
        home_result = await self.home_exists(
            data['home'], schema_name, verrors, old)

        if home_result:
            verrors.add(f'{schema_name}.home',
                        'Only one share is allowed to be a home share.')
        elif not home_result and not data['path']:
            verrors.add(f'{schema_name}.path', 'This field is required.')

        if data['path']:
            await check_path_resides_within_volume(
                verrors, self.middleware, f"{schema_name}.path", data['path']
            )

        if data.get('name') and data['name'] == 'global':
            verrors.add(
                f'{schema_name}.name',
                'Global is a reserved section name, please select another one'
            )

    @private
    async def home_exists(self, home, schema_name, verrors, old=None):
        home_filters = [('home', '=', True)]
        home_result = None

        if home:
            if old and old['id'] is not None:
                id = old['id']

                if not old['home']:
                    home_filters.append(('id', '!=', id))
                    # The user already had this set as the home share
                    home_result = await self.middleware.call(
                        'datastore.query', self._config.datastore,
                        home_filters, {'prefix': self._config.datastore_prefix})

        return home_result

    @private
    async def name_exists(self, data, schema_name, verrors, id=None):
        name = data['name']
        path = data['path']

        if path and not name:
            name = path.rsplit('/', 1)[-1]

        name_filters = [('name', '=', name)]

        if id is not None:
            name_filters.append(('id', '!=', id))

        name_result = await self.middleware.call(
            'datastore.query', self._config.datastore,
            name_filters,
            {'prefix': self._config.datastore_prefix})

        if name_result:
            verrors.add(f'{schema_name}.name',
                        'A share with this name already exists.')

        return name

    @private
    async def extend(self, data):
        data['hostsallow'] = data['hostsallow'].split()
        data['hostsdeny'] = data['hostsdeny'].split()

        return data

    @private
    async def compress(self, data):
        data['hostsallow'] = ' '.join(data['hostsallow'])
        data['hostsdeny'] = ' '.join(data['hostsdeny'])

        return data

    @private
    async def apply_default_perms(self, default_perms, path, is_home):
        if default_perms:
            try:
                stat = await self.middleware.call('filesystem.stat', path)
                owner = stat['user'] or 'root'
                group = stat['group'] or 'wheel'
            except Exception:
                (owner, group) = ('root', 'wheel')

            await self.middleware.call(
                'notifier.winacl_reset', path, owner, group, None, not is_home
            )

    @private
    async def generate_vuid(self, timemachine, vuid=""):
        try:
            if timemachine and vuid:
                uuid.UUID(vuid, version=4)
        except ValueError:
            self.logger.debug(f"Time machine VUID string ({vuid}) is invalid. Regenerating.")
            vuid = ""

        if timemachine and not vuid:
            vuid = str(uuid.uuid4())

        return vuid

    @accepts()
    def vfsobjects_choices(self):
        """
        Returns a list of valid virtual file system module choices which can be used with SMB Shares to enable virtual
        file system modules.
        """
        vfs_modules_path = '/usr/local/lib/shared-modules/vfs'
        vfs_modules = []
        vfs_exclude = {
            'acl_tdb',
            'acl_xattr',
            'aio_fork',
            'aio_pthread',
            'cacheprime',
            'commit',
            'expand_msdfs',
            'linux_xfs_sgid',
            'netatalk',
            'posix_eadb',
            'recycle',
            'shadow_copy',
            'shadow_copy2',
            'streams_depot',
            'syncops',
            'xattr_tdb'
        }

        if os.path.exists(vfs_modules_path):
            vfs_modules.extend(
                filter(lambda m: m not in vfs_exclude,
                       map(lambda f: f.rpartition('.')[0],
                           os.listdir(vfs_modules_path)))
            )
        else:
            vfs_modules.extend(['streams_xattr'])

        return vfs_modules


async def pool_post_import(middleware, pool):
    """
    Makes sure to reload SMB if a pool is imported and there are shares configured for it.
    """
    path = f'/mnt/{pool["name"]}'
    if await middleware.call('sharing.smb.query', [
        ('OR', [
            ('path', '=', path),
            ('path', '^', f'{path}/'),
        ])
    ]):
        asyncio.ensure_future(middleware.call('service.reload', 'cifs'))


async def setup(middleware):
    middleware.register_hook('pool.post_import_pool', pool_post_import, sync=True)
