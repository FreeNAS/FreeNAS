import errno
import os

from middlewared.schema import accepts, Bool, Dict, List, returns, Str
from middlewared.service import CallError, Service

from .items_util import get_item_details


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
        Str('app_readme', null=True, required=True),
        Str('location', required=True),
        Bool('healthy', required=True),
        Str('healthy_error', required=True, null=True),
        Str('healthy_error', required=True, null=True),
        Dict('versions', required=True, additional_attrs=True),
        Str('latest_version', required=True, null=True),
        Str('latest_app_version', required=True, null=True),
        Str('latest_human_version', required=True, null=True),
        Str('icon_url', required=True, null=True),
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

        questions_context = self.middleware.call_sync('catalog.get_normalised_questions_context')
        return get_item_details(item_location, questions_context, {'retrieve_versions': True})
