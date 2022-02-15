import errno
import os
import subprocess

from middlewared.alert.base import AlertClass, AlertCategory, AlertLevel, Alert, ThreadedAlertSource, UnavailableException
from middlewared.service_exception import CallError


class FailoverInterfaceNotFoundAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Failover Internal Interface Not Found"
    text = "Failover internal interface not found. Contact support."

    products = ("ENTERPRISE",)


class TrueNASVersionsMismatchAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "TrueNAS Versions Mismatch In Failover"
    text = "TrueNAS versions mismatch in failover. Update both controllers to the same version."

    products = ("ENTERPRISE",)


class FailoverAccessDeniedAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Failover Access Denied"
    text = "Failover access denied. Please reconfigure it."

    products = ("ENTERPRISE",)


class FailoverStatusCheckFailedAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Failed to Check Failover Status with the Other Controller"
    text = "Failed to check failover status with the other controller: %s."

    products = ("ENTERPRISE",)


class FailoverFailedAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Failover Failed"
    text = "Failover failed: %s."
    products = ("SCALE_ENTERPRISE",)


class ExternalFailoverLinkStatusAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Could not Determine External Failover Link Status"
    text = "Could not determine external failover link status, check cabling."

    products = ("ENTERPRISE",)


class InternalFailoverLinkStatusAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Could not Determine Internal Failover Link Status"
    text = "Could not determine internal failover link status. Automatic failover disabled."

    products = ("ENTERPRISE",)


class VRRPStatesDoNotAgreeAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Controllers VRRP States Do Not Agree"
    text = "Controllers VRRP states do not agree: %(error)s."
    products = ("SCALE_ENTERPRISE",)


class CTLHALinkAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "CTL HA link Is not Connected"
    text = "CTL HA link is not connected."

    products = ("ENTERPRISE",)


class NoFailoverPassphraseKeysAlertClass(AlertClass):
    category = AlertCategory.HA
    level = AlertLevel.CRITICAL
    title = "Passphrase Missing For Legacy-Encrypted Pool"
    text = "Failover is unavailable until a legacy encryption passphrase is added to %(pool)r."

    products = ("ENTERPRISE",)


class FailoverAlertSource(ThreadedAlertSource):
    products = ("ENTERPRISE",)
    failover_related = True
    run_on_backup_node = False

    def check_sync(self):
        if not self.middleware.call_sync('failover.licensed'):
            return []
        elif not self.middleware.call_sync('failover.internal_interfaces'):
            return [Alert(FailoverInterfaceNotFoundAlertClass)]

        alerts = []
        try:
            if not self.middleware.call_sync('failover.call_remote', 'system.ready'):
                raise UnavailableException()

            local_version = self.middleware.call_sync('system.version')
            remote_version = self.middleware.call_sync('failover.call_remote', 'system.version')
            if local_version != remote_version:
                return [Alert(TrueNASVersionsMismatchAlertClass)]

            local = self.middleware.call_sync('failover.vip.get_states')
            remote = self.middleware.call_sync('failover.call_remote', 'failover.vip.get_states')
            if err := self.middleware.call_sync('failover.vip.check_states', local, remote):
                return [Alert(VRRPStatesDoNotAgreeAlertClass, {"error": i}) for i in err]
        except CallError as e:
            if e.errno != errno.ECONNREFUSED:
                return [Alert(FailoverStatusCheckFailedAlertClass, [str(e)])]

        status = self.middleware.call_sync('failover.status')
        if status == 'ERROR':
            return [Alert(FailoverFailedAlertClass, ['Check /root/syslog/failover.log on both controllers.']))
        elif status not in ('MASTER', 'BACKUP', 'SINGLE'):
            alerts.append(Alert(ExternalFailoverLinkStatusAlertClass))

        internal_ifaces = self.middleware.call_sync('failover.internal_interfaces')
        if internal_ifaces:
            p1 = subprocess.Popen(
                "/sbin/ifconfig %s|grep -E 'vhid (10|20) '|grep 'carp:'" % internal_ifaces[0],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
                encoding='utf8',
            )
            stdout = p1.communicate()[0].strip()
            if status != "SINGLE" and stdout.count("\n") != 1:
                alerts.append(Alert(InternalFailoverLinkStatusAlertClass))

        if status == 'BACKUP':
            fobj = self.middleware.call_sync('failover.generate_failover_data')
            try:
                if len(fobj['phrasedvolumes']) > 0:
                    keys = self.middleware.call_sync('failover.encryption_keys')['geli']
                    not_found = False
                    for pool in fobj['phrasedvolumes']:
                        if pool not in keys:
                            not_found = True
                            alerts.append(Alert(NoFailoverPassphraseKeysAlertClass, {'pool': pool}))
                    if not_found:
                        # Kick a syncfrompeer if we don't.
                        self.middleware.call_sync('failover.sync_keys_from_remote_node')
            except Exception:
                pass

        return alerts
