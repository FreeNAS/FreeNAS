from subprocess import run, DEVNULL

from middlewared.service import Service
from middlewared.schema import Str, Dict, accepts, returns


class IpmiChassisService(Service):

    class Config:
        namespace = 'ipmi.chassis'
        cli_namespace = 'service.ipmi.chassis'

    @accepts()
    @returns(Dict('chassis_info', additional_attrs=True))
    def info(self):
        """Return looks like:
        {
            "system_power": "on",
            "power_overload": "false",
            "interlock": "inactive",
            "power_fault": "false",
            "power_control_fault": "false",
            "power_restore_policy": "Always off",
            "last_power_event": "unknown",
            "chassis_intrusion": "inactive",
            "front_panel_lockout": "inactive",
            "drive_fault": "false",
            "cooling/fan_fault": "false",
            "chassis_identify_state": "off"
        }
        """
        rv = {}
        if not self.middleware.call_sync('ipmi.is_loaded'):
            return rv

        out = run(['ipmi-chassis', '--get-chassis-status'], capture_output=True)
        for line in filter(lambda x: x, out.stdout.decode().split('\n')):
            ele, status = line.split(':', 1)
            rv[ele.strip().replace(' ', '_').lower()] = status.strip()

        return rv

    @accepts(Str('verb', default='ON', enum=['ON', 'OFF']))
    @returns()
    def identify(self, verb):
        """
        Toggle the chassis identify light.

        `verb`: str if 'ON' turn identify light on. if 'OFF' turn identify light off.
        """
        verb = 'force' if verb == 'ON' else '0'
        run(['ipmi-chassis', f'--chassis-identify={verb}'], stdout=DEVNULL, stderr=DEVNULL)
