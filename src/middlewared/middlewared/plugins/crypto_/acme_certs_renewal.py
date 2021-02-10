from middlewared.service import private, Service


class CertificateService(Service):

    class Config:
        cli_namespace = 'system.certificate'

    @private
    async def services_dependent_on_cert(self, id):
        await self.middleware.call('certificate.get_instance', id)
        services = await self.middleware.call('core.get_services')
        dependents = {
            'services': [],
            'chart_releases': [
                c['id'] for c in await self.middleware.call(
                    'chart.release.query', [['resources.truenas_certificates', 'rin', id]], {
                        'extra': {'retrieve_resources': True}
                    }
                )
            ],
        }
        for svc_name in map(
            lambda d: d['service'], filter(
                lambda d: d['service'] in services,
                (await self.middleware.call('certificate.get_dependencies', id)).values()
            )
        ):
            svc = services[svc_name]
            data = {}
            if svc_name == 'system.general':
                data = {'action': 'reload', 'service': 'http'}
            elif svc_name == 'system.advanced':
                data = {'action': 'reload', 'service': 'syslogd'}
            elif svc_name == 'kmip':
                if (await self.middleware.call('kmip.config'))['enabled']:
                    data = {'action': 'start', 'service': 'kmip'}
            elif svc_name == 'ldap':
                if (await self.middleware.call('ldap.config'))['enable']:
                    data = {'action': 'start', 'service': 'ldap'}
            elif svc['config']['service']:
                data = {
                    'action': svc['config']['service_verb'] or 'reload', 'service': svc['config']['service']
                }

            if data:
                dependents['services'].append(data)

        return dependents
