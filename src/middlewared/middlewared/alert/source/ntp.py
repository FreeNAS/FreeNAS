import time
from datetime import timedelta

from middlewared.alert.base import AlertClass, AlertCategory, Alert, AlertLevel, AlertSource
from middlewared.alert.schedule import IntervalSchedule


class NTPHealthCheckAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.WARNING
    title = "NTP Health Check Failed"
    text = "NTP health check failed - %(reason)s"


class NTPHealthCheckAlertSource(AlertSource):
    schedule = IntervalSchedule(timedelta(hours=12))
    run_on_backup_node = False

    async def check(self):
        uptime_seconds = time.clock_gettime(time.CLOCK_MONOTONIC_RAW)
        if uptime_seconds < 300:
            return

        try:
            peers = await self.middleware.call("system.ntpserver.peers")
        except Exception:
            self.middleware.logger.warning("Failed to retrieve peers.", exc_info=True)
            peers = []

        if not peers:
            return

        active_peer = [x for x in peers if x['status'].endswith('PEER')]
        if not active_peer:
            return Alert(
                NTPHealthCheckAlertClass,
                {'reason': f'No Active NTP peers: {[{x["remote"]: x["status"]} for x in peers]}'}
            )

        peer = active_peer[0]
        if peer['offset'] < 300000:
            return

        return Alert(
            NTPHealthCheckAlertClass,
            {'reason': f'{peer["remote"]} has an offset of {peer["offset"]}, which exceeds permitted value of 5 minutes.'}
        )
