from collections import defaultdict
from datetime import datetime
import errno
import os
import traceback
import uuid

from middlewared.alert.base import (
    AlertCategory,
    alert_category_names,
    AlertClass,
    OneShotAlertClass,
    DismissableAlertClass,
    AlertLevel,
    Alert,
    AlertSource,
    FilePresenceAlertSource,
    ThreadedAlertSource,
    ThreadedAlertService,
    ProThreadedAlertService,
)
from middlewared.alert.base import UnavailableException, AlertService as _AlertService
from middlewared.schema import Any, Bool, Dict, Int, Str, accepts, Patch, Ref
from middlewared.service import (
    ConfigService, CRUDService, Service, ValidationErrors,
    job, periodic, private,
)
from middlewared.service_exception import CallError
from middlewared.utils import bisect, load_modules, load_classes

POLICIES = ["IMMEDIATELY", "HOURLY", "DAILY", "NEVER"]
DEFAULT_POLICY = "IMMEDIATELY"

ALERT_SOURCES = {}
ALERT_SERVICES_FACTORIES = {}


class AlertSourceRunFailedAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.CRITICAL
    title = "Failed to check for alert"
    text = "Failed to check for alert %(source_name)s:\n%(traceback)s"


class AlertSourceRunFailedOnBackupNodeAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.CRITICAL
    title = "Failed to check for alert on backup node"
    text = "Failed to check for alert %(source_name)s on backup node:\n%(traceback)s"


class TestAlertClass(AlertClass):
    category = AlertCategory.SYSTEM
    level = AlertLevel.CRITICAL
    title = "Test alert"

    exclude_from_list = True


class AlertPolicy:
    def __init__(self, key=lambda now: now):
        self.key = key

        self.last_key_value = None
        self.last_key_value_alerts = {}

    def receive_alerts(self, now, alerts):
        alerts = {alert.uuid: alert for alert in alerts}
        gone_alerts = []
        new_alerts = []
        key = self.key(now)
        if key != self.last_key_value:
            gone_alerts = [alert for alert in self.last_key_value_alerts.values() if alert.uuid not in alerts]
            new_alerts = [alert for alert in alerts.values() if alert.uuid not in self.last_key_value_alerts]

            self.last_key_value = key
            self.last_key_value_alerts = alerts

        return gone_alerts, new_alerts


class AlertService(Service):
    def __init__(self, middleware):
        super().__init__(middleware)

        self.node = "A"

        self.alerts = []

        self.alert_source_last_run = defaultdict(lambda: datetime.min)

        self.policies = {
            "IMMEDIATELY": AlertPolicy(),
            "HOURLY": AlertPolicy(lambda d: (d.date(), d.hour)),
            "DAILY": AlertPolicy(lambda d: (d.date())),
            "NEVER": AlertPolicy(lambda d: None),
        }

    @private
    async def initialize(self):
        if not await self.middleware.call("system.is_freenas"):
            if await self.middleware.call("failover.node") == "B":
                self.node = "B"

        main_sources_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir, "alert", "source")
        sources_dirs = [os.path.join(overlay_dir, "alert", "source") for overlay_dir in self.middleware.overlay_dirs]
        sources_dirs.insert(0, main_sources_dir)
        for sources_dir in sources_dirs:
            for module in load_modules(sources_dir):
                for cls in load_classes(module, AlertSource, (FilePresenceAlertSource, ThreadedAlertSource)):
                    source = cls(self.middleware)
                    ALERT_SOURCES[source.name] = source

        main_services_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), os.path.pardir, "alert",
                                         "service")
        services_dirs = [os.path.join(overlay_dir, "alert", "service") for overlay_dir in self.middleware.overlay_dirs]
        services_dirs.insert(0, main_services_dir)
        for services_dir in services_dirs:
            for module in load_modules(services_dir):
                for cls in load_classes(module, _AlertService, (ThreadedAlertService, ProThreadedAlertService)):
                    ALERT_SERVICES_FACTORIES[cls.name()] = cls

        for alert in await self.middleware.call("datastore.query", "system.alert"):
            del alert["id"]

            try:
                alert["klass"] = AlertClass.class_by_name[alert["klass"]]
            except KeyError:
                self.logger.info("Alert class %r is no longer present", alert["klass"])
                continue

            alert["_uuid"] = alert.pop("uuid")
            alert["_source"] = alert.pop("source")
            alert["_key"] = alert.pop("key")
            alert["_text"] = alert.pop("text")

            alert = Alert(**alert)

            self.alerts.append(alert)

        for policy in self.policies.values():
            policy.receive_alerts(datetime.utcnow(), self.alerts)

    @private
    async def terminate(self):
        await self.flush_alerts()

    @accepts()
    async def list_policies(self):
        """
        List all alert policies which indicate the frequency of the alerts.
        """
        return POLICIES

    @accepts()
    async def list_categories(self):
        """
        List all types of alert sources which the system can issue.
        """

        return [
            {
                "id": alert_category.name,
                "title": alert_category_names[alert_category],
                "classes": sorted(
                    [
                        {
                            "id": alert_class.name,
                            "title": alert_class.title,
                        }
                        for alert_class in AlertClass.classes
                        if alert_class.category == alert_category
                    ],
                    key=lambda klass: klass["title"]
                )
            }
            for alert_category in AlertCategory
        ]

    @private
    async def list_sources(self):
        # TODO: this is a deprecated method for backward compatibility

        return [
            {
                "name": klass["id"],
                "title": klass["title"],
            }
            for klass in sum([v["classes"] for v in await self.list_categories()], [])
        ]

    @accepts()
    async def list(self):
        """
        List all types of alerts including active/dismissed currently in the system.
        """

        classes = (await self.middleware.call("alertclasses.config"))["classes"]

        return [
            dict(alert.__dict__,
                 id=alert.uuid,
                 klass=alert.klass.name,
                 level=classes.get(alert.klass.name, {}).get("level", alert.klass.level.name),
                 formatted=alert.formatted,
                 one_shot=issubclass(alert.klass, OneShotAlertClass))
            for alert in sorted(self.alerts, key=lambda alert: (alert.klass.title, alert.datetime))
        ]

    def __alert_by_uuid(self, uuid):
        try:
            return [a for a in self.alerts if a.uuid == uuid][0]
        except IndexError:
            return None

    @accepts(Str("uuid"))
    async def dismiss(self, uuid):
        """
        Dismiss `id` alert.
        """

        alert = self.__alert_by_uuid(uuid)
        if alert is None:
            return

        if issubclass(alert.klass, DismissableAlertClass):
            related_alerts, unrelated_alerts = bisect(lambda a: (a.node, a.klass) == (alert.node, alert.klass),
                                                      self.alerts)
            self.alerts = (
                unrelated_alerts +
                await alert.klass(self.middleware).dismiss(related_alerts, alert)
            )
        elif issubclass(alert.klass, OneShotAlertClass):
            self.alerts = [a for a in self.alerts if a.uuid != uuid]
        else:
            alert.dismissed = True

    @accepts(Str("uuid"))
    def restore(self, uuid):
        """
        Restore `id` alert which had been dismissed.
        """

        alert = self.__alert_by_uuid(uuid)
        if alert is None:
            return

        alert.dismissed = False

    @periodic(60)
    @private
    @job(lock="process_alerts", transient=True)
    async def process_alerts(self, job):
        if not await self.middleware.call("system.ready"):
            return

        if (
            not await self.middleware.call('system.is_freenas') and
            await self.middleware.call('failover.licensed') and
            await self.middleware.call('failover.status') == 'BACKUP'
        ):
            return

        await self.__run_alerts()

        await self.middleware.call("alert.send_alerts")

    @private
    @job(lock="process_alerts", transient=True)
    async def send_alerts(self, job):
        classes = (await self.middleware.call("alertclasses.config"))["classes"]

        now = datetime.now()
        for policy_name, policy in self.policies.items():
            gone_alerts, new_alerts = policy.receive_alerts(now, self.alerts)

            for alert_service_desc in await self.middleware.call("datastore.query", "system.alertservice"):
                service_gone_alerts = [
                    alert for alert in gone_alerts
                    if (
                        AlertLevel[classes.get(alert.klass.name, {}).get("level", alert.klass.level.name)].value >=
                        AlertLevel[alert_service_desc["level"]].value and

                        classes.get(alert.klass.name, {}).get("policy", DEFAULT_POLICY) == policy_name
                    )
                ]
                service_new_alerts = [
                    alert for alert in new_alerts
                    if (
                        AlertLevel[classes.get(alert.klass.name, {}).get("level", alert.klass.level.name)].value >=
                        AlertLevel[alert_service_desc["level"]].value and

                        classes.get(alert.klass.name, {}).get("policy", DEFAULT_POLICY) == policy_name
                    )
                ]

                if not service_gone_alerts and not service_new_alerts:
                    continue

                factory = ALERT_SERVICES_FACTORIES.get(alert_service_desc["type"])
                if factory is None:
                    self.logger.error("Alert service %r does not exist", alert_service_desc["type"])
                    continue

                try:
                    alert_service = factory(self.middleware, alert_service_desc["attributes"])
                except Exception:
                    self.logger.error("Error creating alert service %r with parameters=%r",
                                      alert_service_desc["type"], alert_service_desc["attributes"], exc_info=True)
                    continue

                if self.alerts or service_gone_alerts or service_new_alerts:
                    try:
                        await alert_service.send(self.alerts, service_gone_alerts, service_new_alerts)
                    except Exception:
                        self.logger.error("Error in alert service %r", alert_service_desc["type"], exc_info=True)

            if policy_name == "IMMEDIATELY":
                for alert in new_alerts:
                    if alert.mail:
                        await self.middleware.call("mail.send", alert.mail)

                if not await self.middleware.call("system.is_freenas"):
                    new_hardware_alerts = [alert for alert in new_alerts if alert.klass.hardware]
                    if new_hardware_alerts:
                        if await self.middleware.call("support.is_available_and_enabled"):
                            support = await self.middleware.call("support.config")
                            msg = [f"* {alert.formatted}" for alert in new_hardware_alerts]

                            serial = (await self.middleware.call("system.info"))["system_serial"]

                            for name, verbose_name in await self.middleware.call("support.fields"):
                                value = support[name]
                                if value:
                                    msg += ["", "{}: {}".format(verbose_name, value)]

                            try:
                                await self.middleware.call("support.new_ticket", {
                                    "title": "Automatic alert (%s)" % serial,
                                    "body": "\n".join(msg),
                                    "attach_debug": False,
                                    "category": "Hardware",
                                    "criticality": "Loss of Functionality",
                                    "environment": "Production",
                                    "name": "Automatic Alert",
                                    "email": "auto-support@ixsystems.com",
                                    "phone": "-",
                                })
                            except Exception:
                                self.logger.error(f"Failed to create a support ticket", exc_info=True)

    def __uuid(self):
        return str(uuid.uuid4())

    async def __run_alerts(self):
        master_node = "A"
        backup_node = "B"
        run_on_backup_node = False
        if not await self.middleware.call("system.is_freenas"):
            if await self.middleware.call("failover.licensed"):
                master_node = await self.middleware.call("failover.node")
                try:
                    backup_node = await self.middleware.call("failover.call_remote", "failover.node")
                    remote_version = await self.middleware.call("failover.call_remote", "system.version")
                    remote_failover_status = await self.middleware.call("failover.call_remote",
                                                                        "failover.status")
                except Exception:
                    pass
                else:
                    if remote_version == await self.middleware.call("system.version"):
                        if remote_failover_status == "BACKUP":
                            run_on_backup_node = True

        for alert_source in ALERT_SOURCES.values():
            if not alert_source.schedule.should_run(datetime.utcnow(), self.alert_source_last_run[alert_source.name]):
                continue

            self.alert_source_last_run[alert_source.name] = datetime.utcnow()

            self.logger.trace("Running alert source: %r", alert_source.name)

            try:
                alerts_a = await self.__run_source(alert_source.name)
            except UnavailableException:
                alerts_a = [alert
                            for alert in self.alerts
                            if alert.node == master_node and alert.source == alert_source.name]
            for alert in alerts_a:
                alert.node = master_node

            alerts_b = []
            if run_on_backup_node and alert_source.run_on_backup_node:
                try:
                    try:
                        alerts_b = await self.middleware.call("failover.call_remote", "alert.run_source",
                                                              [alert_source.name])
                    except CallError as e:
                        if e.errno == CallError.EALERTCHECKERUNAVAILABLE:
                            alerts_b = [alert
                                        for alert in self.alerts
                                        if alert.node == backup_node and alert.source == alert_source.name]
                        else:
                            raise
                    else:
                        alerts_b = [Alert(**dict(alert,
                                                 klass=AlertClass.class_by_name[alert["klass"]],
                                                 _uuid=alert.pop("id"),
                                                 _source=alert.pop("source"),
                                                 _key=alert.pop("key"),
                                                 _text=alert.pop("text")))
                                    for alert in alerts_b]
                except Exception:
                    alerts_b = [
                        Alert(AlertSourceRunFailedOnBackupNodeAlertClass,
                              args={
                                  "source_name": alert_source.name,
                                  "traceback": traceback.format_exc(),
                              },
                              _source=alert_source.name)
                    ]
            for alert in alerts_b:
                alert.node = backup_node

            for alert in alerts_a + alerts_b:
                self.__handle_alert(alert)

            self.alerts = (
                [a for a in self.alerts if a.source != alert_source.name] +
                alerts_a +
                alerts_b
            )

    def __handle_alert(self, alert):
        try:
            existing_alert = [
                a for a in self.alerts
                if (a.node, a.source, a.klass, a.key) == (alert.node, alert.source, alert.klass, alert.key)
            ][0]
        except IndexError:
            existing_alert = None

        if existing_alert is None:
            alert.uuid = self.__uuid()
        else:
            alert.uuid = existing_alert.uuid
        if existing_alert is None:
            alert.datetime = alert.datetime or datetime.utcnow()
        else:
            alert.datetime = existing_alert.datetime
        if existing_alert is None:
            alert.dismissed = False
        else:
            alert.dismissed = existing_alert.dismissed

    @private
    async def run_source(self, source_name):
        try:
            return [dict(alert.__dict__, klass=alert.klass.name)
                    for alert in await self.__run_source(source_name)]
        except UnavailableException:
            raise CallError("This alert checker is unavailable", CallError.EALERTCHECKERUNAVAILABLE)

    async def __run_source(self, source_name):
        alert_source = ALERT_SOURCES[source_name]

        try:
            alerts = (await alert_source.check()) or []
        except UnavailableException:
            raise
        except Exception:
            alerts = [
                Alert(AlertSourceRunFailedAlertClass,
                      args={
                          "source_name": alert_source.name,
                          "traceback": traceback.format_exc(),
                      })
            ]
        else:
            if not isinstance(alerts, list):
                alerts = [alerts]

        for alert in alerts:
            alert.source = source_name

        return alerts

    @periodic(3600)
    @private
    async def flush_alerts(self):
        if (
            not await self.middleware.call('system.is_freenas') and
            await self.middleware.call('failover.licensed') and
            await self.middleware.call('failover.status') == 'BACKUP'
        ):
            return

        await self.middleware.call("datastore.delete", "system.alert", [])

        for alert in self.alerts:
            d = alert.__dict__.copy()
            d["klass"] = d["klass"].name
            del d["mail"]
            await self.middleware.call("datastore.insert", "system.alert", d)

    @private
    @accepts(Str("klass"), Any("args", null=True))
    @job(lock="process_alerts", transient=True)
    async def oneshot_create(self, job, klass, args):
        try:
            klass = AlertClass.class_by_name[klass]
        except KeyError:
            raise CallError(f"Invalid alert source: {klass!r}")

        if not issubclass(klass, OneShotAlertClass):
            raise CallError(f"Alert class {klass!r} is not a one-shot alert source")

        alert = await klass(self.middleware).create(args)
        if alert is None:
            return

        alert.source = ""
        alert.klass = alert.klass

        alert.node = self.node

        self.__handle_alert(alert)

        self.alerts = [a for a in self.alerts if a.uuid != alert.uuid] + [alert]

        await self.middleware.call("alert.send_alerts")

    @private
    @accepts(Str("klass"), Any("query", null=True))
    @job(lock="process_alerts", transient=True)
    async def oneshot_delete(self, job, klass, query):
        try:
            klass = AlertClass.class_by_name[klass]
        except KeyError:
            raise CallError(f"Invalid alert source: {klass!r}")

        if not issubclass(klass, OneShotAlertClass):
            raise CallError(f"Alert class {klass!r} is not a one-shot alert source")

        related_alerts, unrelated_alerts = bisect(lambda a: (a.node, a.klass) == (self.node, klass),
                                                  self.alerts)
        self.alerts = (
            unrelated_alerts +
            await klass(self.middleware).delete(related_alerts, query)
        )

        await self.middleware.call("alert.send_alerts")

    @private
    def alert_source_clear_run(self, name):
        alert_source = ALERT_SOURCES.get(name)
        if not alert_source:
            raise CallError("Alert source {name!r} not found.", errno.ENOENT)

        self.alert_source_last_run[alert_source.name] = datetime.min


class AlertServiceService(CRUDService):
    class Config:
        datastore = "system.alertservice"
        datastore_extend = "alertservice._extend"
        datastore_order_by = ["name"]

    @accepts()
    async def list_types(self):
        """
        List all types of supported Alert services which can be configured with the system.
        """
        return [
            {
                "name": name,
                "title": factory.title,
            }
            for name, factory in sorted(ALERT_SERVICES_FACTORIES.items(), key=lambda i: i[1].title.lower())
        ]

    @private
    async def _extend(self, service):
        try:
            service["type__title"] = ALERT_SERVICES_FACTORIES[service["type"]].title
        except KeyError:
            service["type__title"] = "<Unknown>"

        return service

    @private
    async def _compress(self, service):
        return service

    @private
    async def _validate(self, service, schema_name):
        verrors = ValidationErrors()

        factory = ALERT_SERVICES_FACTORIES.get(service["type"])
        if factory is None:
            verrors.add(f"{schema_name}.type", "This field has invalid value")
            raise verrors

        try:
            factory.validate(service.get('attributes', {}))
        except ValidationErrors as e:
            verrors.add_child(f"{schema_name}.attributes", e)

        if verrors:
            raise verrors

    @accepts(Dict(
        "alert_service_create",
        Str("name"),
        Str("type", required=True),
        Dict("attributes", additional_attrs=True),
        Str("level", enum=list(AlertLevel.__members__)),
        Bool("enabled"),
        register=True,
    ))
    async def do_create(self, data):
        """
        Create an Alert Service of specified `type`.

        If `enabled`, it sends alerts to the configured `type` of Alert Service.

        .. examples(websocket)::

          Create an Alert Service of Mail `type`

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "alertservice.create",
                "params": [{
                    "name": "Test Email Alert",
                    "enabled": true,
                    "type": "Mail",
                    "attributes": {
                        "email": "dev@ixsystems.com"
                    },
                    "settings": {
                        "VolumeVersion": "HOURLY"
                    }
                }]
            }
        """
        await self._validate(data, "alert_service_create")

        data["id"] = await self.middleware.call("datastore.insert", self._config.datastore, data)

        await self._extend(data)

        return data

    @accepts(Int("id"), Patch(
        "alert_service_create",
        "alert_service_update",
        ("attr", {"update": True}),
    ))
    async def do_update(self, id, data):
        """
        Update Alert Service of `id`.
        """
        old = await self.middleware.call("datastore.query", self._config.datastore, [("id", "=", id)],
                                         {"extend": self._config.datastore_extend,
                                          "get": True})

        new = old.copy()
        new.update(data)

        await self._validate(data, "alert_service_update")

        await self._compress(data)

        await self.middleware.call("datastore.update", self._config.datastore, id, data)

        await self._extend(new)

        return new

    @accepts(Int("id"))
    async def do_delete(self, id):
        """
        Delete Alert Service of `id`.
        """
        return await self.middleware.call("datastore.delete", self._config.datastore, id)

    @accepts(
        Ref('alert_service_create')
    )
    async def test(self, data):
        """
        Send a test alert using `type` of Alert Service.

        .. examples(websocket)::

          Send a test alert using Alert Service of Mail `type`.

            :::javascript
            {
                "id": "6841f242-840a-11e6-a437-00e04d680384",
                "msg": "method",
                "method": "alertservice.test",
                "params": [{
                    "name": "Test Email Alert",
                    "enabled": true,
                    "type": "Mail",
                    "attributes": {
                        "email": "dev@ixsystems.com"
                    },
                    "settings": {}
                }]
            }
        """
        await self._validate(data, "alert_service_test")

        factory = ALERT_SERVICES_FACTORIES.get(data["type"])
        if factory is None:
            self.logger.error("Alert service %r does not exist", data["type"])
            return False

        try:
            alert_service = factory(self.middleware, data["attributes"])
        except Exception:
            self.logger.error("Error creating alert service %r with parameters=%r",
                              data["type"], data["attributes"], exc_info=True)
            return False

        test_alert = Alert(
            TestAlertClass,
            node="A",
            datetime=datetime.utcnow(),
        )

        try:
            await alert_service.send([test_alert], [], [test_alert])
        except Exception:
            self.logger.error("Error in alert service %r", data["type"], exc_info=True)
            return False

        return True


class AlertClassesService(ConfigService):
    class Config:
        datastore = "system.alertclasses"

    @accepts(Dict(
        "alert_classes_update",
        Dict("classes", additional_attrs=True),
    ))
    async def do_update(self, data):
        """
        Update default Alert settings.
        """
        old = await self.config()

        new = old.copy()
        new.update(data)

        verrors = ValidationErrors()

        for k, v in new["classes"].items():
            if k not in AlertClass.class_by_name:
                verrors.add(f"alert_class_update.classes.{k}", "This alert class does not exist")

            if not isinstance(v, dict):
                verrors.add(f"alert_class_update.classes.{k}", "Not a dictionary")

            if "level" in v:
                if v["level"] not in AlertLevel.__members__:
                    verrors.add(f"alert_class_update.classes.{k}.level", "This alert level does not exist")

            if "policy" in v:
                if v["policy"] not in POLICIES:
                    verrors.add(f"alert_class_update.classes.{k}.policy", "This alert policy does not exist")

        if verrors:
            raise verrors

        await self.middleware.call("datastore.update", self._config.datastore, old["id"], new)

        return new


class AlertDefaultSettingsService(Service):
    class Config:
        private = True

    async def config(self):
        return {
            "settings": {
                k: v["policy"]
                for k, v in (await self.middleware.call("alertclasses.config"))["classes"].items()
                if "policy" in v
            },
        }

    @accepts(Dict(
        "alert_default_settings_update",
        Dict("settings", additional_attrs=True),
    ))
    async def update(self, data):
        await self.middleware.call("alertclasses.update", {
            "classes": {
                k: {"policy": v}
                for k, v in data["settings"].items()
            },
        })

        return await self.config()


async def setup(middleware):
    await middleware.call("alert.initialize")
