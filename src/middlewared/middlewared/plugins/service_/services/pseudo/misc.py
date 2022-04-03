import asyncio

from middlewared.utils import osc

from middlewared.plugins.service_.services.base import ServiceState, ServiceInterface, SimpleService
from middlewared.plugins.service_.services.base_freebsd import freebsd_service
from middlewared.plugins.service_.services.base_linux import systemd_unit


class PseudoServiceBase(ServiceInterface):
    async def get_state(self):
        return ServiceState(True, [])


class CronService(PseudoServiceBase):
    name = "cron"

    etc = ["cron"]
    restartable = True

    async def restart(self):
        pass


class DiskService(PseudoServiceBase):
    name = "disk"

    etc = ["fstab"]
    restartable = True
    reloadable = True

    async def restart(self):
        await self.reload()

    async def reload(self):
        if osc.IS_FREEBSD:
            await freebsd_service("mountlate", "start")

        # FIXME: Linux

        asyncio.ensure_future(self.middleware.call("service.restart", "collectd"))


class KmipService(PseudoServiceBase):
    name = "kmip"

    async def start(self):
        await self.middleware.call("service.start", "ssl")
        await self.middleware.call("etc.generate", "kmip")

    async def get_state(self):
        return ServiceState(
            (await self.middleware.call('kmip.config'))['enabled'],
            [],
        )


class LoaderService(PseudoServiceBase):
    name = "loader"

    etc = ["loader"]
    reloadable = True

    async def reload(self):
        pass


class MOTDService(PseudoServiceBase):
    name = "motd"

    etc = ["motd"]

    async def start(self):
        if osc.IS_FREEBSD:
            await freebsd_service("motd", "start")


class HostnameService(PseudoServiceBase):
    name = "hostname"

    reloadable = True

    async def reload(self):
        await self.middleware.call("etc.generate", "hostname")
        await self.middleware.call("service.restart", "mdns")
        await self.middleware.call("service.restart", "collectd")


class HttpService(PseudoServiceBase):
    name = "http"

    etc = ["nginx"]
    restartable = True
    reloadable = True

    async def restart(self):
        if osc.IS_FREEBSD:
            await freebsd_service("nginx", "restart")
        if osc.IS_LINUX:
            await systemd_unit("nginx", "restart")

    async def reload(self):
        if osc.IS_FREEBSD:
            await freebsd_service("nginx", "reload")
        if osc.IS_LINUX:
            await systemd_unit("nginx", "reload")


class NetworkService(PseudoServiceBase):
    name = "network"

    async def start(self):
        await self.middleware.call("interface.sync")
        await self.middleware.call("route.sync")


class NetworkGeneralService(PseudoServiceBase):
    name = "networkgeneral"

    reloadable = True

    async def reload(self):
        await self.middleware.call("service.reload", "resolvconf")
        await self.middleware.call("service.restart", "routing")


class NtpdService(SimpleService):
    name = "ntpd"

    etc = ["ntpd"]
    restartable = True

    freebsd_rc = "ntpd"

    systemd_unit = "ntp"


class OpenVmToolsService(SimpleService):
    name = "open-vm-tools"

    systemd_unit = "open-vm-tools"


class PowerdService(SimpleService):
    name = "powerd"

    etc = ["rc"]

    freebsd_rc = "powerd"

    # FIXME: Linux


class RcService(PseudoServiceBase):
    name = "rc"

    etc = ["rc"]
    reloadable = True

    async def reload(self):
        pass


class ResolvConfService(PseudoServiceBase):
    name = "resolvconf"

    reloadable = True

    async def reload(self):
        await self.middleware.call("service.reload", "hostname")
        await self.middleware.call("dns.sync")


class RoutingService(SimpleService):
    name = "routing"

    etc = ["rc"]

    restartable = True

    freebsd_rc = "routing"

    async def get_state(self):
        return ServiceState(True, [])

    async def _restart_linux(self):
        await self.middleware.call("staticroute.sync")


class SslService(PseudoServiceBase):
    name = "ssl"

    etc = ["ssl"]

    async def start(self):
        pass


class SysctlService(PseudoServiceBase):
    name = "sysctl"

    etc = ["sysctl"]
    reloadable = True

    async def reload(self):
        pass


class SyslogdService(SimpleService):
    name = "syslogd"

    etc = ["syslogd"]
    restartable = True
    reloadable = True

    freebsd_rc = "syslog-ng"

    systemd_unit = "syslog-ng"


class SystemService(PseudoServiceBase):
    name = "system"

    restartable = True

    async def stop(self):
        asyncio.ensure_future(self.middleware.call("system.shutdown", {"delay": 3}))

    async def restart(self):
        asyncio.ensure_future(self.middleware.call("system.reboot", {"delay": 3}))


class TimeservicesService(PseudoServiceBase):
    name = "timeservices"

    etc = ["localtime"]
    reloadable = True

    async def reload(self):
        await self.middleware.call("service.restart", "ntpd")

        settings = await self.middleware.call("datastore.config", "system.settings")
        await self.middleware.call("core.environ_update", {"TZ": settings["stg_timezone"]})


class DSCacheService(PseudoServiceBase):
    name = "dscache"

    async def start(self):
        await self.middleware.call('dscache.refresh')

    async def stop(self):
        await self.middleware.call('idmap.clear_idmap_cache')
        await self.middleware.call('dscache.refresh')


class UserService(PseudoServiceBase):
    name = "user"

    etc = ["user"]
    reloadable = True

    async def reload(self):
        pass
