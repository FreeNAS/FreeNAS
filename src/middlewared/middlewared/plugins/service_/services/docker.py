import asyncio

from middlewared.plugins.docker.state_utils import Status

from .base import SimpleService


class DockerService(SimpleService):
    name = 'docker'
    etc = ['app_registry', 'docker']
    systemd_unit = 'docker'

    async def before_start(self):
        await self.middleware.call('docker.state.set_status', Status.INITIALIZING.value)
        await self.middleware.call('docker.state.before_start_check')
        physical_ifaces = await self.middleware.call('interface.query', [['type', '=', 'PHYSICAL']])
        for key, value in (
            ('vm.panic_on_oom', 0),
            ('vm.overcommit_memory', 1),
            *[(f'net.ipv6.conf.{i["name"]}.accept_ra', 2) for i in physical_ifaces],
        ):
            await self.middleware.call('sysctl.set_value', key, value)

    async def start(self):
        try:
            await super().start()
            # We have a timeout for docker to start within 15 minutes of the above call, if that doesn't happen
            # then we get into a failed start that docker failed to start. This has been necessary because
            # HDDs have been notorious and can take quite some time for docker to start on boot.
            timeout = 8 * 60  # We do 8 because we sleep for 2 secs - so in total it is 16 minutes
            while timeout > 0:
                if not await self.middleware.call('service.started', 'docker'):
                    await asyncio.sleep(2)
                    timeout -= 2
                else:
                    break
        finally:
            asyncio.get_event_loop().call_later(
                2,
                lambda: self.middleware.create_task(self.middleware.call('docker.state.after_start_check')),
            )

    async def stop(self):
        await super().stop()
        await self._systemd_unit('docker.socket', 'stop')

    async def after_start(self):
        await self.middleware.call('docker.state.set_status', Status.RUNNING.value)
        self.middleware.create_task(self.middleware.call('docker.events.setup'))
        if (await self.middleware.call('docker.config'))['enable_image_updates']:
            self.middleware.create_task(self.middleware.call('app.image.op.check_update'))

    async def before_stop(self):
        await self.middleware.call('docker.state.set_status', Status.STOPPING.value)

    async def after_stop(self):
        await self.middleware.call('docker.state.set_status', Status.STOPPED.value)
