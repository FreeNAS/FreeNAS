import middlewared.sqlalchemy as sa
import os

from .utils import (
    AUDIT_DATASET_PATH,
    AUDIT_LIFETIME,
    AUDIT_DEFAULT_RESERVATION,
    AUDIT_DEFAULT_QUOTA,
    AUDIT_FILL_CRITICAL,
    AUDIT_FILL_WARNING,
    AUDITED_SERVICES,
)
from middlewared.schema import (
    accepts, Bool, Dict, Int, List, Patch, Ref, returns, Str, UUID
)
from middlewared.service import private, ConfigService
from middlewared.service_exception import ValidationErrors
from middlewared.utils import filter_list
from middlewared.utils.functools import cache
from middlewared.utils.osc import getmntinfo
from middlewared.validators import Range


ALL_AUDITED = [svc[0] for svc in AUDITED_SERVICES]
QUOTA_WARN = 'org.freenas:refquota_warning'
QUOTA_CRIT = 'org.freenas:refquota_critical'


class AuditModel(sa.Model):
    __tablename__ = 'system_audit'

    id = sa.Column(sa.Integer(), primary_key=True)
    retention = sa.Column(sa.Integer(), default=AUDIT_LIFETIME)
    reservation = sa.Column(sa.Integer(), default=AUDIT_DEFAULT_RESERVATION)
    quota = sa.Column(sa.Integer(), default=AUDIT_DEFAULT_QUOTA)
    quota_fill_warning = sa.Column(sa.Integer(), default=AUDIT_FILL_WARNING)
    quota_fill_critical = sa.Column(sa.Integer(), default=AUDIT_FILL_CRITICAL)


class AuditService(ConfigService):
    class Config:
        datastore = 'system.audit'
        cli_namespace = 'system.audit'
        datastore_extend = 'audit.extend'

    ENTRY = Patch(
        'system_audit_update', 'system_audit_config',
        ('add', Int('available')),
        ('add', Dict(
            'space',
            Int('used'),
            Int('used_by_snapshots'),
            Int('available'),
        )),
        ('add', Bool('remote_logging_enabled')),
        ('add', List('enabled_services'))
    )

    @private
    @cache
    def audit_dataset_name(self):
        audit_dev = os.stat(AUDIT_DATASET_PATH).st_dev
        return getmntinfo(audit_dev)[audit_dev]['mount_source']

    @private
    def get_audit_dataset(self):
        ds_name = self.audit_dataset_name()
        ds = self.middleware.call_sync(
            'zfs.dataset.query',
            [['id', '=', ds_name]],
            {'extra': {'retrieve_children': False}, 'get': True}
        )

        for k, default in [(QUOTA_WARN, 80), (QUOTA_CRIT, 95)]:
            try:
                ds[k] = int(ds[k]["rawvalue"])
            except (KeyError, ValueError):
                ds[k] = default

        return ds

    @private
    def extend(self, data):
        sys_adv = self.middleware.call_sync('system.advanced.config')
        data['remote_logging_enabled'] = bool(sys_adv['syslogserver']) and sys_adv['syslog_audit']
        ds_info = self.get_audit_dataset()
        data['space'] = {'used': None, 'used_by_snapshots': None, 'available': None}
        data['space']['used'] = ds_info['properties']['used']['parsed']
        data['space']['used_by_dataset'] = ds_info['properties']['usedbydataset']['parsed']
        data['space']['used_by_reservation'] = ds_info['properties']['usedbyrefreservation']['parsed']
        data['space']['used_by_snapshots'] = ds_info['properties']['usedbysnapshots']['parsed']
        data['space']['available'] = ds_info['properties']['available']['parsed']
        data['enabled_services'] = {'SMB': []}
        audited_smb_shares = self.middleware.call_sync(
            'sharing.smb.query', [['audit.enable', '=', True]]
        )

        for share in audited_smb_shares:
            data['enabled_services']['SMB'].append(share['name'])

        return data

    @private
    async def compress(self, data):
        for key in ['space', 'enabled_services', 'remote_logging_enabled']:
            data.pop(key, None)

        return data

    @accepts(Dict(
        'audit_query',
        List('services', items=[Str('db_name', enum=ALL_AUDITED)], default=ALL_AUDITED),
        Ref('query-filters'),
        Ref('query-options')
    ))
    @returns(List('audit_entries', items=[
        Dict(
            'audit_entry',
            UUID('aid'),
            Int('msg_ts'),
            Dict('time', Int('$date')),
            Str('addr'),
            Str('user'),
            UUID('sess'),
            Str('svc', enum=ALL_AUDITED),
            Dict('svc_data', additional_attrs=True, null=True),
            Str('event'),
            Dict('event_data', additional_attrs=True, null=True),
            Bool('success')
        )
    ]))
    async def query(self, data):
        """
        Query contents of audit databases specified by `services`.

        If the query-option `force_sql_filters` is true, then the query will be
        converted into a more efficient form for better performance. This will
        not be possible if filters use keys within `svc_data` and `event_data`.

        Each audit entry contains the following keys:

        `aid` - GUID for the specific audit event.

        `msg_ts` - Unix timestamp for when the audit event was written to the
        auditing database.

        `time` - converted ISO-8601 timestamp from application recording when event
        occurred.

        `addr` - IP address of client performing action that generated the
        audit message.

        `user` - Username used by client performing action.

        `sess` - GUID uniquely identifying the client session.

        `svc` - Name of the service that generated the message. This will be
        one of the names specified in `services`.

        `svc_data` - JSON object containing variable data depending on the
        particular service. See TrueNAS auditing documentation for the service
        in question.

        `event` - Name of the event type that generated the audit record. Each
        service has its own unique event identifiers.

        `event_data` - JSON object containing variable data depending on the
        particular event type. See TrueNAS auditing documentation for the
        service in question.

        `success` - boolean value indicating whether the action generating the
        event message succeeded.
        """
        results = []
        sql_filters = data['query-options']['force_sql_filters']

        if sql_filters:
            filters = data['query-filters']
            options = data['query-options']
        else:
            filters = []
            options = {}

        for svc in data['services']:
            entries = await self.middleware.call('auditbackend.query', svc, filters, options)
            results.extend(entries)

        if sql_filters:
            return

        return filter_list(results, data['query-filters'], data['query-options'])

    @private
    async def validate_local_storage(self, new, old, verrors):
        new_volsize = new['quota'] * (1024 * 1024 ** 2)
        used = new['space']['used_by_dataset'] + new['space']['used_by_snapshots']
        if old['quota'] != new['quota']:
            if used / new_volsize > new['quota_fill_warning'] / 100:
                verrors.add(
                    'audit_update.quota',
                    'Specified quota would result in the percentage used of the '
                    'audit dataset to exceed the maximum permitted by the configured '
                    'quota_fill_warning.'
                )
        if new['quota'] < new['reservation']:
            verrors.add(
                'audit_update.quota',
                'Quota on auditing dataset must be greater than or equal to '
                'the space reservation for the dataset.'
            )

    @private
    async def update_audit_dataset(self, new):
        ds = await self.middleware.call('audit.get_audit_dataset')
        ds_props = ds['properties']
        old_reservation = ds_props['refreservation']['parsed'] or 0
        old_quota = ds_props['quota']['parsed'] or 0
        old_warn = int(ds_props.get(QUOTA_WARN, {}).get('rawvalue', '0'))
        old_crit = int(ds_props.get(QUOTA_CRIT, {}).get('rawvalue', '0'))

        payload = {}
        if new['quota'] != old_quota / (1024 * 1024 ** 2):
            payload['refquota'] = {'parsed': f'{new["quota"]}G'}

        if new['reservation'] != old_reservation / (1024 * 1024 ** 2):
            payload['refreservation'] = {'parsed': f'{new["reservation"]}G'}

        if new["quota_fill_warning"] != old_warn:
            payload[QUOTA_WARN] = {'parsed': str(new['quota_fill_warning'])}

        if new["quota_fill_critical"] != old_crit:
            payload[QUOTA_CRIT] = {'parsed': str(new['quota_fill_critical'])}

        if not payload:
            return

        await self.middleware.call(
            'zfs.dataset.update', ds['id'], {'properties': payload}
        )

    @accepts(Dict(
        'system_audit_update',
        Int('retention', validators=[Range(1, 30)]),
        Int('reservation', validators=[Range(0, 100)]),
        Int('quota', validators=[Range(0, 100)]),
        Int('quota_fill_warning', validators=[Range(5, 80)]),
        Int('quota_fill_critical', validators=[Range(50, 95)]),
        register=True
    ))
    async def update(self, data):
        """
        Update default audit settings.

        The following fields may be modified:

        `retention` - number of days to retain local audit messages.

        `reservation` - size in GiB of refreservation to set on ZFS dataset
        where the audit databases are stored. The refreservation specifies the
        minimum amount of space guaranteed to the dataset, and counts against
        the space available for other datasets in the zpool where the audit
        dataset is located.

        `quota` - size in GiB of the maximum amount of space that may be
        consumed by the dataset where the audit dabases are stored.

        `quota_fill_warning` - percentage used of dataset quota at which to
        generate a warning alert.

        `quota_fill_critical` - percentage used of dataset quota at which to
        generate a critical alert alert.

        The following fields contain read-only data and are returned in calls
        to `audit.config` and `audit.update`:

        `space` - ZFS dataset properties relating space used and available for
        the dataset where the audit databases are written.

        `remote_logging_enabled` - Boolean indicating whether logging to a
        remote syslog server is enabled on TrueNAS and if audit logs are
        included in what is sent remotely.

        `enabled_services` - JSON object with key denoting service, and value
        containing a JSON array of what aspects of this service are being
        audited. In the case of the SMB audit, the list contains share names
        of shares for which auditing is enabled.
        """
        old = await self.config()
        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()
        await self.validate_local_storage(new, old, verrors)
        verrors.check()

        await self.update_audit_dataset(new)
        await self.compress(new)
        await self.middleware.call('datastore.update', self._config.datastore, old['id'], new)
        return await self.config()
