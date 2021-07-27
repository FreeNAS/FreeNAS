import asyncio
import collections
import copy
import functools

from middlewared.schema import Dict, List, Str, returns
from middlewared.service import accepts, private, Service

from .utils import get_chart_release_from_namespace, get_namespace, is_ix_namespace


EVENT_LOCKS = collections.defaultdict(asyncio.Lock)
LOCKS = collections.defaultdict(asyncio.Lock)


class ChartReleaseService(Service):

    CHART_RELEASES = {}

    class Config:
        namespace = 'chart.release'

    @accepts(Str('release_name'))
    @returns(List(
        'events', items=[Dict(
            'event',
            Dict(
                'involved_object',
                Str('kind'),
                Str('name'),
                Str('namespace'),
                additional_attrs=True,
                null=True,
            ),
            Dict(
                'metadata',
                Str('namespace', required=True),
                Str('uid', required=True),
                Str('name', required=True),
                additional_attrs=True,
            ),
            additional_attrs=True,
        )]
    ))
    async def events(self, release_name):
        """
        Returns kubernetes events for `release_name` Chart Release.
        """
        return await self.middleware.call('k8s.event.query', [], {'extra': {'namespace': get_namespace(release_name)}})

    @private
    async def refresh_events_state(self, chart_release_name=None):
        filters = [['id', '=', chart_release_name]] if chart_release_name else []
        for chart_release in await self.middleware.call('chart.release.query', filters):
            async with LOCKS[chart_release['name']]:
                ChartReleaseService.CHART_RELEASES[chart_release['name']] = {
                    'lock': asyncio.Lock(),
                    'data': chart_release,
                    'queue': copy.deepcopy(self.get_queue()),
                    'poll': False,
                }

    @private
    @functools.cache
    def get_queue(self):
        iterable = []
        cur = 2
        while cur <= 300:
            iterable.append(cur)
            cur *= 2
        return collections.deque(iterable)

    @private
    async def remove_chart_release_from_events_state(self, chart_release_name):
        async with LOCKS[chart_release_name]:
            ChartReleaseService.CHART_RELEASES.pop(chart_release_name, None)

    @private
    async def handle_k8s_event(self, k8s_event):
        name = get_chart_release_from_namespace(k8s_event['involved_object']['namespace'])
        async with EVENT_LOCKS[name]:
            if name not in self.CHART_RELEASES:
                # It's possible the chart release got deleted
                return

            status = await self.middleware.call('chart.release.pod_status', name)
            cached_chart_release = self.CHART_RELEASES[name]
            if status['status'] != cached_chart_release['data']['status']:
                # raise event
                async with LOCKS[name]:
                    cached_chart_release['data'].update({
                        'status': status['status'],
                        'pod_status': {
                            'desired': status['desired'],
                            'available': status['available'],
                        }
                    })
                    self.middleware.send_event(
                        'chart.release.query', 'CHANGED', id=name, fields=cached_chart_release['data']
                    )


async def chart_release_event(middleware, event_type, args):
    args = args['fields']
    if args['involved_object']['kind'] != 'Pod' or not is_ix_namespace(args['involved_object']['namespace']):
        return

    await middleware.call('chart.release.handle_k8s_event', args)


async def setup(middleware):
    middleware.event_subscribe('kubernetes.events', chart_release_event)
    if await middleware.call('service.started', 'kubernetes'):
        asyncio.ensure_future(middleware.call('chart.release.refresh_events_state'))
