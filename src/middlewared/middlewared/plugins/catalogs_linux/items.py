import functools
import json
import os

from catalog_validation.items.catalog import get_items_in_trains, retrieve_train_names, retrieve_trains_data
from catalog_validation.items.utils import get_catalog_json_schema
from jsonschema import validate as json_schema_validate, ValidationError as JsonValidationError

from middlewared.schema import Bool, Dict, List, returns, Str
from middlewared.service import accepts, job, private, Service

from .items_util import get_item_version_details
from .utils import CATALOG_JSON_FILE, get_cache_key


class CatalogService(Service):

    class Config:
        cli_namespace = 'app.catalog'

    @private
    def cached(self, label):
        return self.middleware.call_sync('cache.has_key', get_cache_key(label))

    @accepts(
        Str('label'),
        Dict(
            'options',
            Bool('cache', default=True),
            Bool('cache_only', default=False),
            Bool('retrieve_all_trains', default=True),
            List('trains', items=[Str('train_name')]),
        )
    )
    @returns(Dict(
        'trains',
        additional_attrs=True,
        example={
            'charts': {
                'chia': {
                    'name': 'chia',
                    'categories': ['storage', 'crypto'],
                    'app_readme': 'app readme here',
                    'location': '/mnt/evo/ix-applications/catalogs/github_com_truenas_charts_git_master/charts/chia',
                    'healthy': True,
                    'healthy_error': False,
                    'latest_version': '1.2.0',
                    'latest_app_version': '1.1.6',
                    'icon_url': 'https://www.chia.net/img/chia_logo.svg',
                    'title': 'Chia',
                    'description': 'App description here',
                }
            }
        }
    ))
    @job(lock=lambda args: f'catalog_item_retrieval_{json.dumps(args)}', lock_queue_size=1)
    async def items(self, job, label, options):
        """
        Retrieve item details for `label` catalog.

        `options.cache` is a boolean which when set will try to get items details for `label` catalog from cache
        if available.

        `options.cache_only` is a boolean which when set will force usage of cache only for retrieving catalog
        information. If the content for the catalog in question is not cached, no content would be returned. If
        `options.cache` is unset, this attribute has no effect.

        `options.retrieve_all_trains` is a boolean value which when set will retrieve information for all the trains
        present in the catalog ( it is set by default ).

        `options.trains` is a list of train name(s) which will allow selective filtering to retrieve only information
        of desired trains in a catalog. If `options.retrieve_all_trains` is set, it has precedence over `options.train`.
        """
        return await job.wrap(await self.middleware.call('catalog.items_internal', label, options))

    @private
    @accepts(
        Str('label'),
        Dict(
            'options',
            Bool('cache', default=True),
            Bool('cache_only', default=False),
            Bool('retrieve_all_trains', default=True),
            List('trains', items=[Str('train_name')]),
        )
    )
    @job(lock=lambda args: f'catalog_item_retrieval_internal_{json.dumps(args)}', lock_queue_size=1, transient=True)
    def items_internal(self, job, label, options):
        catalog = self.middleware.call_sync('catalog.get_instance', label)
        all_trains = options['retrieve_all_trains']
        cache_key = get_cache_key(label)
        cache_available = self.middleware.call_sync('cache.has_key', cache_key)
        if options['cache'] and options['cache_only'] and not cache_available:
            return {}

        if options['cache'] and cache_available:
            job.set_progress(10, 'Retrieving cached content')
            orig_data = self.middleware.call_sync('cache.get', cache_key)
            job.set_progress(60, 'Normalizing cached content')
            cached_data = {}
            for train in orig_data:
                if not all_trains and train not in options['trains']:
                    continue

                train_data = {}
                for catalog_item in orig_data[train]:
                    train_data[catalog_item] = {k: v for k, v in orig_data[train][catalog_item].items()}

                cached_data[train] = train_data

            job.set_progress(100, 'Retrieved catalog item(s) details successfully')
            self.middleware.loop.call_later(30, functools.partial(job.set_result, None))
            return cached_data
        elif not os.path.exists(catalog['location']):
            job.set_progress(5, f'Cloning {label!r} catalog repository')
            self.middleware.call_sync('catalog.update_git_repository', catalog)

        if all_trains:
            # We can only safely say that the catalog is healthy if we retrieve data for all trains
            self.middleware.call_sync('alert.oneshot_delete', 'CatalogNotHealthy', label)

        trains = self.get_trains(job, catalog, options)

        if all_trains:
            # We will only update cache if we are retrieving data of all trains for a catalog
            # which happens when we sync catalog(s) periodically or manually
            # We cache for 90000 seconds giving system an extra 1 hour to refresh it's cache which
            # happens after 24h - which means that for a small amount of time it's possible that user
            # come with a case where system is trying to access cached data but it has expired and it's
            # reading again from disk hence the extra 1 hour.
            self.middleware.call_sync('cache.put', get_cache_key(label), trains, 90000)

        if label == self.middleware.call_sync('catalog.official_catalog_label'):
            # Update feature map cache whenever official catalog is updated
            self.middleware.call_sync('catalog.get_feature_map', False)

        job.set_progress(100, f'Successfully retrieved {label!r} catalog information')
        self.middleware.loop.call_later(30, functools.partial(job.set_result, None))
        return trains

    @private
    def get_trains(self, job, catalog, options):
        if os.path.exists(os.path.join(catalog['location'], CATALOG_JSON_FILE)):
            # If the data is malformed or something similar, let's read the data then from filesystem
            try:
                return self.retrieve_trains_data_from_json(catalog, options)
            except (json.JSONDecodeError, JsonValidationError):
                self.logger.error('Invalid catalog json file specified for %r catalog', catalog['id'])

        return self.get_trains_impl(job, catalog, options)

    @private
    def retrieve_trains_data_from_json(self, catalog, options):
        trains_to_traverse = retrieve_train_names(
            catalog['location'], options['retrieve_all_trains'], options['trains']
        )
        with open(os.path.join(catalog['location'], CATALOG_JSON_FILE), 'r') as f:
            catalog_data = json.loads(f.read())
            json_schema_validate(catalog_data, get_catalog_json_schema())

            data = {k: v for k, v in catalog_data.items() if k in trains_to_traverse}

        for train in data:
            for item in data[train]:
                data[train][item]['location'] = os.path.join(catalog['location'], train, item)

        return data

    @private
    def get_trains_impl(self, job, catalog, options):
        # We make sure we do not dive into library and docs folders and not consider those a train
        # This allows us to use these folders for placing helm library charts and docs respectively
        location = catalog['location']
        questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')

        trains_to_traverse = retrieve_train_names(location, options['retrieve_all_trains'], options['trains'])
        # In order to calculate job progress, we need to know number of items we would be traversing
        items = get_items_in_trains(trains_to_traverse, location)

        job.set_progress(8, f'Retrieving {", ".join(trains_to_traverse)!r} train(s) information')

        trains, unhealthy_apps = retrieve_trains_data(
            items, location, catalog['preferred_trains'], trains_to_traverse, job, questions_context
        )

        if unhealthy_apps:
            self.middleware.call_sync(
                'alert.oneshot_create', 'CatalogNotHealthy', {
                    'catalog': catalog['id'], 'apps': ', '.join(unhealthy_apps)
                }
            )

        job.set_progress(90, f'Retrieved {", ".join(trains_to_traverse)} train(s) information')
        return trains

    @private
    def item_version_details(self, version_path, questions_context=None):
        if not questions_context:
            questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')
        return get_item_version_details(version_path, questions_context)

    @private
    async def get_normalised_questions_context(self):
        k8s_started = await self.middleware.call('kubernetes.validate_k8s_setup', False)
        return {
            'nic_choices': await self.middleware.call('chart.release.nic_choices'),
            'gpus': await self.middleware.call('k8s.gpu.available_gpus') if k8s_started else {},
            'timezones': await self.middleware.call('system.general.timezone_choices'),
            'node_ip': await self.middleware.call('kubernetes.node_ip'),
            'certificates': await self.middleware.call('chart.release.certificate_choices'),
            'certificate_authorities': await self.middleware.call('chart.release.certificate_authority_choices'),
            'system.general.config': await self.middleware.call('system.general.config'),
        }

    @private
    def retrieve_train_names(self, location, all_trains=True, trains_filter=None):
        return retrieve_train_names(location, all_trains, trains_filter)
