from middlewared.alert.base import AlertClass, AlertCategory, AlertLevel, FilePresenceAlertSource
from middlewared.plugins.disk import GELI_REKEY_FAILED


class VolumeRekeyAlertClass(AlertClass):
    category = AlertCategory.STORAGE
    level = AlertLevel.CRITICAL
    title = "Failed to Rekey One or More Disks of Encrypted Pool"
    text = ("Rekeying one or more disks in an encrypted pool failed. Please make "
            "sure working recovery keys are available, check log files, and "
            "correct the problem immediately to avoid data loss.")


class VolumeRekeyAlertSource(FilePresenceAlertSource):
    path = GELI_REKEY_FAILED
    klass = VolumeRekeyAlertClass
