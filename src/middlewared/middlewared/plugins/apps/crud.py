import errno
import os
import textwrap

from middlewared.plugins.docker.state_utils import IX_APPS_MOUNT_PATH
from middlewared.schema import accepts, Dict, Str
from middlewared.service import CallError, CRUDService, filterable, job
from middlewared.utils import filter_list
from middlewared.validators import Match, Range

from .version_utils import get_latest_version_from_app_versions


class AppService(CRUDService):
    class Config:
        namespace = 'app'
        datastore_primary_key_type = 'string'
        cli_namespace = 'apps'
        private = True  # FIXME: Remove this once we have schema defined

    @filterable
    def query(self, filters, options):
        if not self.middleware.call_sync('docker.state.validate', False):
            return filter_list([], filters, options)

        apps = []
        return filter_list(apps, filters, options)

    @accepts(
        Dict(
            'app_create',
            Dict('values', additional_attrs=True, private=True),
            Str('catalog_app', required=True),
            Str(
                'app_name', required=True, validators=[Match(
                    r'^[a-z]([-a-z0-9]*[a-z0-9])?$',
                    explanation=textwrap.dedent(
                        '''
                        Application name must have the following:
                        1) Lowercase alphanumeric characters can be specified
                        2) Name must start with an alphabetic character and can end with alphanumeric character
                        3) Hyphen '-' is allowed but not as the first or last character
                        e.g abc123, abc, abcd-1232
                        '''
                    )
                ), Range(min_=1, max_=40)]
            ),
            Str('train', default='stable'),
            Str('version', default='latest'),
        )
    )
    @job(lock=lambda args: f'app_create_{args[0]["app_name"]}')
    def do_create(self, job, data):
        self.middleware.call_sync('docker.state.validate')

        if self.query([['id', '=', data['app_name']]]):
            raise CallError(f'Application with name {data["app_name"]} already exists', errno=errno.EEXIST)

        complete_app_details = self.middleware.call_sync('catalog.get_app_details', data['catalog_app'], {
            'train': data['train'],
        })
        version = data['version']
        if version == 'latest':
            version = get_latest_version_from_app_versions(complete_app_details['versions'])

        if version not in complete_app_details['version']:
            raise CallError(f'Version {version} not found in {data["item"]} app', errno=errno.ENOENT)

        app_details = complete_app_details['versions'][version]
        self.middleware.call_sync('catalog.version_supported_error_check', app_details)

        app_dir = os.path.join(IX_APPS_MOUNT_PATH, 'app_configs', data['app_name'])
        # The idea is to validate the values provided first and if it passes our validation test, we
        # can move forward with setting up the datasets and installing the catalog item
        new_values, context = self.middleware.call_sync(
            'app.schema.normalise_and_validate_values', app_details, data['values'], False, app_dir
        )

        job.set_progress(25, 'Initial Validation completed')

        # Now that we have completed validation for the app in question wrt values provided,
        # we will now perform the following steps
        # 1) Create relevant dir for app
        # 2) Copy app version into app dir
        # 3) Have docker compose deploy the app in question  # FIXME: Let's implement this later please
