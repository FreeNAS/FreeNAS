import errno
import os

from middlewared.schema import accepts, Bool, Dict, List, returns, Str
from middlewared.service import CallError, Service

from .items_util import get_item_details
from .update import OFFICIAL_LABEL


class CatalogService(Service):

    class Config:
        cli_namespace = 'app.catalog'

    @accepts(
        Str('item_name'),
        Dict(
            'item_version_details',
            Bool('cache'),  # TODO: Remove this once UI adapts
            Str('catalog', required=True),
            Str('train', required=True),
        )
    )
    @returns(Dict(
        'item_details',
        Str('name', required=True),
        List('categories', items=[Str('category')], required=True),
        List('maintainers', required=True),
        List('tags', required=True),
        List('screenshots', required=True, items=[Str('screenshot')]),
        List('sources', required=True, items=[Str('source')]),
        Str('app_readme', null=True, required=True),
        Str('location', required=True),
        Bool('healthy', required=True),
        Bool('recommended', required=True),
        Str('healthy_error', required=True, null=True),
        Str('healthy_error', required=True, null=True),
        Dict('versions', required=True, additional_attrs=True),
        Str('latest_version', required=True, null=True),
        Str('latest_app_version', required=True, null=True),
        Str('latest_human_version', required=True, null=True),
        Str('last_update', required=True, null=True),
        Str('icon_url', required=True, null=True),
        Str('home', required=True),
    ))
    def get_item_details(self, item_name, options):
        """
        Retrieve information of `item_name` `item_version_details.catalog` catalog item.
        """
        catalog = self.middleware.call_sync('catalog.get_instance', options['catalog'])
        item_location = os.path.join(catalog['location'], options['train'], item_name)
        if not os.path.exists(item_location):
            raise CallError(f'Unable to locate {item_name!r} at {item_location!r}', errno=errno.ENOENT)
        elif not os.path.isdir(item_location):
            raise CallError(f'{item_location!r} must be a directory')

        train_data = self.middleware.call_sync('catalog.items', options['catalog'], {
            'retrieve_all_trains': False,
            'trains': [options['train']],
        })
        if options['train'] not in train_data:
            raise CallError(f'Unable to locate {options["train"]!r} train')
        elif item_name not in train_data[options['train']]:
            raise CallError(f'Unable to locate {item_name!r} item in {options["train"]!r} train')

        questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')

        item_details = get_item_details(item_location, train_data[options['train']][item_name], questions_context)
        if options['catalog'] == OFFICIAL_LABEL:
            recommended_apps = self.middleware.call_sync('catalog.retrieve_recommended_apps')
            if options['train'] in recommended_apps and item_name in recommended_apps[options['train']]:
                item_details['recommended'] = True

        return item_details
