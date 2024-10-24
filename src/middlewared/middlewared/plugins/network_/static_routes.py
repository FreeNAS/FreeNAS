import ipaddress

from middlewared.api import api_method
from middlewared.api.current import (
    StaticRouteEntry,
    StaticRouteUpdateArgs,
    StaticRouteUpdateResult,
    StaticRouteCreateArgs,
    StaticRouteCreateResult,
    StaticRouteDeleteArgs,
    StaticRouteDeleteResult,
)
import middlewared.sqlalchemy as sa
from middlewared.service import CRUDService, private
from middlewared.schema import ValidationErrors
from middlewared.plugins.interface.netif import netif


class StaticRouteModel(sa.Model):
    __tablename__ = 'network_staticroute'

    id = sa.Column(sa.Integer(), primary_key=True)
    sr_destination = sa.Column(sa.String(120))
    sr_gateway = sa.Column(sa.String(42))
    sr_description = sa.Column(sa.String(120))


class StaticRouteService(CRUDService):
    class Config:
        datastore = 'network.staticroute'
        datastore_prefix = 'sr_'
        datastore_extend = 'staticroute.upper'
        cli_namespace = 'network.static_route'
        entry = StaticRouteEntry

    @api_method(StaticRouteCreateArgs, StaticRouteCreateResult)
    async def do_create(self, data):
        """
        Create a Static Route.

        Address families of `gateway` and `destination` should match when creating a static route.

        `description` is an optional attribute for any notes regarding the static route.
        """
        self._validate('staticroute_create', data)

        await self.lower(data)

        id_ = await self.middleware.call(
            'datastore.insert', self._config.datastore, data,
            {'prefix': self._config.datastore_prefix})

        await self.middleware.call('service.restart', 'routing')

        return await self.get_instance(id_)

    @api_method(StaticRouteUpdateArgs, StaticRouteUpdateResult)
    async def do_update(self, id_, data):
        """
        Update Static Route of `id`.
        """
        old = await self.get_instance(id_)
        new = old.copy()
        new.update(data)

        self._validate('staticroute_update', new)

        await self.lower(new)
        await self.middleware.call(
            'datastore.update', self._config.datastore, id_, new,
            {'prefix': self._config.datastore_prefix})

        await self.middleware.call('service.restart', 'routing')

        return await self.get_instance(id_)

    @api_method(StaticRouteDeleteArgs, StaticRouteDeleteResult)
    def do_delete(self, id_):
        """
        Delete Static Route of `id`.
        """
        staticroute = self.middleware.call_sync('staticroute.get_instance', id_)
        rv = self.middleware.call_sync('datastore.delete', self._config.datastore, id_)
        try:
            rt = netif.RoutingTable()
            rt.delete(self._netif_route(staticroute))
        except Exception as e:
            self.logger.warn(
                'Failed to delete static route %s: %s', staticroute['destination'], e,
            )

        return rv

    @private
    def sync(self):
        rt = netif.RoutingTable()
        new_routes = [self._netif_route(route) for route in self.middleware.call_sync('staticroute.query')]

        default_route_ipv4 = rt.default_route_ipv4
        default_route_ipv6 = rt.default_route_ipv6
        for route in rt.routes:
            if route in new_routes:
                new_routes.remove(route)
                continue

            if route not in [default_route_ipv4, default_route_ipv6] and route.gateway is not None:
                self.logger.debug('Removing route %r', route.asdict())
                try:
                    rt.delete(route)
                except Exception as e:
                    self.logger.warning('Failed to remove route: %r', e)

        for route in new_routes:
            self.logger.debug('Adding route %r', route.asdict())
            try:
                rt.add(route)
            except Exception as e:
                self.logger.warning('Failed to add route: %r', e)

    @private
    async def lower(self, data):
        data['description'] = data['description'].lower()
        return data

    @private
    async def upper(self, data):
        data['description'] = data['description'].upper()
        return data

    def _validate(self, schema_name, data):
        verrors = ValidationErrors()

        if (':' in data['destination']) != (':' in data['gateway']):
            verrors.add(f'{schema_name}.destination', 'Destination and gateway address families must match')

        verrors.check()

    def _netif_route(self, staticroute):
        ip_interface = ipaddress.ip_interface(staticroute['destination'])
        return netif.Route(
            str(ip_interface.ip), str(ip_interface.netmask), gateway=staticroute['gateway']
        )
