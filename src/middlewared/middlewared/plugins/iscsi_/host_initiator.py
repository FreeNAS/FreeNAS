from middlewared.schema import accepts, Bool, Int, List
from middlewared.service import CallError, Service, ServiceChangeMixin


class iSCSIHostService(Service, ServiceChangeMixin):

    class Config:
        namespace = "iscsi.host"

    @accepts(Int("id"), roles=['SHARING_ISCSI_HOST_READ'])
    async def get_initiators(self, id_):
        """
        Returns initiator groups associated with host `id`.
        """
        host = await self.middleware.call("iscsi.host.get_instance", id_)

        return [
            initiator
            for initiator in await self.middleware.call("iscsi.initiator.query")
            if set(host["iqns"]) & set(initiator["initiators"])
        ]

    @accepts(Int("id"), List("ids", items=[Int("id")]), Bool("force", default=False), roles=['SHARING_ISCSI_HOST_WRITE'])
    async def set_initiators(self, id_, ids, force):
        """
        Associates initiator groups `ids` with host `id`.
        Use `force` if you want to allow adding first or removing last initiator from initiator groups.
        """
        host = await self.middleware.call("iscsi.host.get_instance", id_)

        update = []
        for initiator in await self.middleware.call("iscsi.initiator.query"):
            initiators = set(initiator["initiators"])
            had_initiators = bool(initiators)
            if initiator["id"] in ids:
                initiators |= set(host["iqns"])
                if not force and not had_initiators and initiators:
                    raise CallError(
                        f"Unable to add initiator to the Initiator Group {initiator['id']} " +
                        (f"({initiator['comment']}) " if initiator["comment"] else "") +
                        "that includes all initiators."
                    )
            else:
                initiators -= set(host["iqns"])
                if not force and had_initiators and not initiators:
                    raise CallError(
                        f"Unable to remove the last remaining initiator from Initiator Group {initiator['id']}" +
                        (f" ({initiator['comment']})" if initiator["comment"] else "")
                    )

            update.append((initiator["id"], list(initiators)))

        for id_, initiators in update:
            await self.middleware.call("iscsi.initiator.update", id_, {"initiators": initiators})

        await self._service_change("iscsitarget", "reload")
