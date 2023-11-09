import errno
import json
import jsonschema
import os
import typing

from catalog_validation.items.items_util import (
    get_item_version_details as get_catalog_item_version_details,
    normalise_questions,
)
from catalog_validation.utils import CACHED_VERSION_FILE_NAME, VERSION_VALIDATION_SCHEMA

from middlewared.plugins.chart_releases_linux.schema import construct_schema
from middlewared.plugins.update_.utils import can_update
from middlewared.service import CallError
from middlewared.utils import sw_info


def get_item_default_values(version_details: dict) -> dict:
    return construct_schema(version_details, {}, False)['new_values']


def minimum_scale_version_check_update(version_details: dict) -> dict:
    version_details['supported'] = minimum_scale_version_check_update_impl(version_details)[0]
    return version_details


def minimum_scale_version_check_update_impl(
    version_details: dict, check_supported_key: bool = True
) -> typing.Tuple[bool, bool]:
    # `check_supported_key` is used because when catalog validation returns the data it only checks the
    # missing features and based on that makes the decision. So if something is not already supported
    # we do not want to validate minimum scale version in that case. However, when we want to report to
    # the user as to why exactly the app version is not supported, we need to be able to make that distinction
    if version_details.get('healthy', True) and version_details['chart_metadata'].get('minimum_scale_version') and (
        not check_supported_key or version_details['supported']
    ):
        try:
            if sw_info()['version'] != version_details['chart_metadata']['minimum_scale_version'] and not can_update(
                version_details['chart_metadata']['minimum_scale_version'], sw_info()['version']
            ):
                return False, False
        except Exception:
            # In case invalid version string is specified we don't want a traceback here
            # let's just explicitly not support the app version in question
            return False, True

    return True, False


def get_item_details(item_location: str, item_data: dict, questions_context: dict) -> dict:
    item_name = os.path.basename(item_location)
    item_data['versions'] = retrieve_cached_versions_data(get_cached_item_version_path(item_location), item_name)

    # At this point, we have cached versions and items data - now we want to do the following:
    # 1) Update location in each version entry
    # 2) Make sure default values have been normalised
    # 3) Normalise questions
    for version_name, version_data in item_data['versions'].items():
        minimum_scale_version_check_update(version_data)
        version_data.update({
            'location': os.path.join(item_location, version_name),
            'values': get_item_default_values(version_data),
        })
        normalise_questions(version_data, questions_context)

    return item_data


def get_item_version_details(version_path: str, questions_context: dict) -> dict:
    return minimum_scale_version_check_update(get_catalog_item_version_details(version_path, questions_context, {
        'default_values_callable': get_item_default_values,
    }))


def get_cached_item_version_path(item_path: str) -> str:
    return os.path.join(item_path, CACHED_VERSION_FILE_NAME)


def retrieve_cached_versions_data(version_path: str, item_name: str) -> dict:
    try:
        with open(version_path, 'r') as f:
            data = json.loads(f.read())
            jsonschema.validate(data, VERSION_VALIDATION_SCHEMA)
    except FileNotFoundError:
        raise CallError(f'Unable to locate {item_name!r} versions', errno=errno.ENOENT)
    except IsADirectoryError:
        raise CallError(f'{version_path!r} must be a file')
    except json.JSONDecodeError:
        raise CallError(f'Unable to parse {version_path!r} file')
    except jsonschema.ValidationError as e:
        raise CallError(f'Unable to validate {version_path!r} file: {e}')
    else:
        return data
