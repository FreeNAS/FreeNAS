from middlewared.service import Service


class UsageService(Service):

    FAILED_RETRIES = 3

    class Config:
        private = True

    async def firstboot(self):
        _hash = await self.middleware.call('system.host_id')
        version = await self.middleware.call('system.version')
        retries = self.FAILED_RETRIES
        while retries:
            try:
                await self.middleware.call('usage.submit_stats', {
                    'platform': 'TrueNAS-SCALE',
                    'system_hash': _hash,
                    'firstboot': [{'version': version}]
                })
            except Exception as e:
                retries -= 1
                if not retries:
                    self.logger.error('Failed to send firstboot statistics: %s', e)
            else:
                break
