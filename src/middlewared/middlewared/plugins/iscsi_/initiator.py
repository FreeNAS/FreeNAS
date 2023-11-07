import middlewared.sqlalchemy as sa

from middlewared.schema import accepts, Dict, Int, List, Patch, Str
from middlewared.service import CRUDService, private


class iSCSITargetAuthorizedInitiatorModel(sa.Model):
    __tablename__ = 'services_iscsitargetauthorizedinitiator'

    id = sa.Column(sa.Integer(), primary_key=True)
    iscsi_target_initiator_initiators = sa.Column(sa.Text(), default="ALL")
    iscsi_target_initiator_comment = sa.Column(sa.String(120))


class iSCSITargetAuthorizedInitiator(CRUDService):

    class Config:
        namespace = 'iscsi.initiator'
        datastore = 'services.iscsitargetauthorizedinitiator'
        datastore_prefix = 'iscsi_target_initiator_'
        datastore_extend = 'iscsi.initiator.extend'
        cli_namespace = 'sharing.iscsi.target.authorized_initiator'
        role_prefix = 'SHARING_ISCSI_INITIATOR'

    @accepts(Dict(
        'iscsi_initiator_create',
        List('initiators'),
        Str('comment'),
        register=True
    ))
    async def do_create(self, data):
        """
        Create an iSCSI Initiator.

        `initiators` is a list of initiator hostnames which are authorized to access an iSCSI Target. To allow all
        possible initiators, `initiators` can be left empty.
        """
        await self.compress(data)

        data['id'] = await self.middleware.call(
            'datastore.insert', self._config.datastore, data,
            {'prefix': self._config.datastore_prefix})

        await self._service_change('iscsitarget', 'reload')

        return await self.get_instance(data['id'])

    @accepts(
        Int('id'),
        Patch(
            'iscsi_initiator_create',
            'iscsi_initiator_update',
            ('attr', {'update': True})
        )
    )
    async def do_update(self, id_, data):
        """
        Update iSCSI initiator of `id`.
        """
        old = await self.get_instance(id_)

        new = old.copy()
        new.update(data)

        await self.compress(new)
        await self.middleware.call(
            'datastore.update', self._config.datastore, id_, new,
            {'prefix': self._config.datastore_prefix})

        await self._service_change('iscsitarget', 'reload')

        return await self.get_instance(id_)

    @accepts(Int('id'))
    async def do_delete(self, id_):
        """
        Delete iSCSI initiator of `id`.
        """
        await self.get_instance(id_)
        result = await self.middleware.call(
            'datastore.delete', self._config.datastore, id_
        )

        await self._service_change('iscsitarget', 'reload')

        return result

    @private
    async def compress(self, data):
        initiators = data['initiators']
        initiators = 'ALL' if not initiators else '\n'.join(initiators)
        data['initiators'] = initiators
        return data

    @private
    async def extend(self, data):
        initiators = data['initiators']
        initiators = [] if initiators == 'ALL' else initiators.split()
        data['initiators'] = initiators
        return data
