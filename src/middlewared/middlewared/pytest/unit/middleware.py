import asyncio
import logging
from unittest.mock import AsyncMock, Mock

from middlewared.plugins.datastore.read import DatastoreService
from middlewared.utils import filter_list
from middlewared.utils.plugins import SchemasMixin


class Middleware(SchemasMixin, dict):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self['failover.licensed'] = AsyncMock(return_value=False)

        self.call_hook = AsyncMock()
        self.call_hook_inline = Mock()
        self.event_register = Mock()
        self.send_event = Mock()

        self.logger = logging.getLogger("middlewared")

        super().__init__()

        # Resolve core schemas like `query-filters`
        super()._resolve_methods([DatastoreService(self)], [])

    def _resolve_methods(self, services, events):
        try:
            return super()._resolve_methods(services, events)
        except ValueError as e:
            self.logger.warning(str(e))

    async def _call(self, name, serviceobj, method, args, app=None):
        self._resolve_methods([serviceobj], [])
        return await method(*args)

    async def call(self, name, *args):
        result = self[name](*args)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    def call_sync(self, name, *args):
        return self[name](*args)

    async def run_in_executor(self, executor, method, *args, **kwargs):
        return method(*args, **kwargs)

    async def run_in_thread(self, method, *args, **kwargs):
        return method(*args, **kwargs)

    def _query_filter(self, lst):
        def query(filters=None, options=None):
            return filter_list(lst, filters, options)
        return query
