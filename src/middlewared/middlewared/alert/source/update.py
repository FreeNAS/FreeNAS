from datetime import timedelta

from middlewared.alert.base import Alert, AlertClass, AlertCategory, AlertLevel, AlertSource, FilePresenceAlertSource
from middlewared.alert.schedule import IntervalSchedule
from middlewared.plugins.update_.utils import UPDATE_FAILED_SENTINEL


class HasUpdateAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.INFO
    title = "Update Available"
    text = "A system update is available. Go to System Settings → Update to download and apply the update."


class UpdateFailedAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.CRITICAL
    title = "Update Failed"
    text = f"Update failed. See {UPDATE_FAILED_SENTINEL} for details."


class HadUpdateAlertSource(AlertSource):
    schedule = IntervalSchedule(timedelta(hours=1))
    run_on_backup_node = False

    async def check(self):
        if (await self.middleware.call("update.check_available"))["status"] == "AVAILABLE":
            return Alert(HasUpdateAlertClass)


class UpdateFailedAlertSource(FilePresenceAlertSource):
    path = UPDATE_FAILED_SENTINEL
    klass = UpdateFailedAlertClass
