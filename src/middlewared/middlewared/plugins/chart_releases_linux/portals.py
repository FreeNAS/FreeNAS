import base64
import os
import threading
import yaml

from catalog_validation.items.questions_utils import CUSTOM_PORTALS_KEY
from catalog_validation.items.ix_values_utils import CUSTOM_PORTALS_JSON_SCHEMA
from jsonschema import validate as json_schema_validate, ValidationError as JsonValidationError

from middlewared.service import private, Service
from middlewared.utils import get

from .utils import normalized_port_value


PORTAL_LOCK = threading.Lock()


class ChartReleaseService(Service):

    class Config:
        namespace = 'chart.release'

    PORTAL_CACHE = {}

    @private
    def clear_portal_cache(self):
        with PORTAL_LOCK:
            self.PORTAL_CACHE = {}

    @private
    def get_portal_cache(self):
        return self.PORTAL_CACHE

    @private
    def clear_chart_release_portal_cache(self, release_name):
        with PORTAL_LOCK:
            self.PORTAL_CACHE.pop(release_name, None)

    @private
    def retrieve_portals_for_chart_release(self, release_data, node_ip):
        with PORTAL_LOCK:
            if release_data['name'] not in self.PORTAL_CACHE:
                self.PORTAL_CACHE[release_data['name']] = self.retrieve_portals_for_chart_release_impl(
                    release_data, node_ip
                )
            return self.PORTAL_CACHE[release_data['name']]

    @private
    def retrieve_portals_for_chart_release_impl(self, release_data, node_ip):
        cleaned_portals = {}
        questions_yaml_path = os.path.join(
            release_data['path'], 'charts', release_data['chart_metadata']['version'], 'questions.yaml'
        )
        if not os.path.exists(questions_yaml_path):
            return cleaned_portals

        if release_data['chart_metadata']['name'] == 'ix-chart':
            cleaned_portals.update(self.get_ix_chart_portal(release_data, node_ip))

        with open(questions_yaml_path, 'r') as f:
            portals = yaml.safe_load(f.read()).get('portals') or {}

        def tag_func(key):
            return self.parse_tag(release_data, key, node_ip)

        for portal_type, schema in portals.items():
            t_portals = []
            path = tag_func(schema.get('path') or '/')
            for protocol in filter(bool, map(tag_func, schema['protocols'])):
                for host in filter(bool, map(tag_func, schema['host'])):
                    for port in filter(bool, map(tag_func, schema['ports'])):
                        t_portals.append(f'{protocol}://{host}{normalized_port_value(protocol, port)}{path}')

            cleaned_portals[portal_type] = t_portals

        cleaned_portals.update(self.get_user_configured_portals(release_data, node_ip))
        return cleaned_portals

    @private
    def get_user_configured_portals(self, release_data, node_ip):
        portals = {}
        custom_portals = release_data['config'].get(CUSTOM_PORTALS_KEY)
        if custom_portals is None:
            return portals
        try:
            json_schema_validate(custom_portals, CUSTOM_PORTALS_JSON_SCHEMA)
        except JsonValidationError:
            return portals

        for portal_config in release_data['config'].get(CUSTOM_PORTALS_KEY) or []:
            path = portal_config.get('path') or ''
            host = node_ip if portal_config['useNodeIP'] else portal_config['host']
            protocol = portal_config['protocol']
            port = portal_config['port']

            portals[portal_config['portalName']] = [
                f'{protocol}://{host}{normalized_port_value(protocol, port)}{path}'
            ]
        return portals

    @private
    def get_ix_chart_portal(self, release_data, node_ip):
        portal_config = release_data['config'].get('portalDetails')
        if not portal_config or not release_data['config'].get('enableUIPortal'):
            return {}
        host = node_ip if portal_config['useNodeIP'] else portal_config['host']
        protocol = portal_config['protocol']
        return {
            portal_config['portalName']: [
                f'{protocol}://{host}{normalized_port_value(protocol, portal_config["port"])}'
            ]
        }

    @private
    def parse_tag(self, release_data, tag, node_ip):
        tag = self.parse_k8s_resource_tag(release_data, tag)
        if not tag:
            return
        if tag == '$node_ip':
            return node_ip
        elif tag.startswith('$variable-'):
            return get(release_data['config'], tag[len('$variable-'):])

        return tag

    @private
    def parse_k8s_resource_tag(self, release_data, tag):
        # Format expected here is "$kubernetes-resource_RESOURCE-TYPE_RESOURCE-NAME_KEY-NAME"
        if not tag.startswith('$kubernetes-resource'):
            return tag

        if tag.count('_') < 3:
            return

        _, resource_type, resource_name, key = tag.split('_', 3)
        if resource_type not in ('configmap', 'secret'):
            return

        resource = self.middleware.call_sync(
            f'k8s.{resource_type}.query', [
                ['metadata.namespace', '=', release_data['namespace']], ['metadata.name', '=', resource_name]
            ]
        )
        if not resource or 'data' not in resource[0] or not isinstance(resource[0]['data'].get(key), (int, str)):
            # Chart creator did not create the resource or we have a malformed
            # secret/configmap, nothing we can do on this end
            return
        else:
            value = resource[0]['data'][key]

        if resource_type == 'secret':
            value = base64.b64decode(value)

        return str(value)
