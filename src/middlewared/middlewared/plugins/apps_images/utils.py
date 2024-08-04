import re

from collections import defaultdict
from typing import Dict, List, Union

from middlewared.service import CallError


# Default values
DEFAULT_DOCKER_REGISTRY = 'registry-1.docker.io'
DEFAULT_DOCKER_REPO = 'library'
DEFAULT_DOCKER_TAG = 'latest'
DOCKER_CONTENT_DIGEST_HEADER = 'Docker-Content-Digest'

# Taken from OCI: https://github.com/opencontainers/go-digest/blob/master/digest.go#L63
DIGEST_RE = r"[a-z0-9]+(?:[.+_-])*:[a-zA-Z0-9=_-]+"


def normalize_reference(reference: str) -> Dict:
    """
    Parses the reference for image, tag and repository.

    Most of the logic has been used from docker engine to make sure we follow the same rules/practices
    for normalising the image name / tag
    """
    # This needs to be done as containerd automatically adds docker.io as a registery which can't be queried by us
    # when checking for update alerts as registry-1.docker.io is the one used to actually query that information
    reference = reference.removeprefix('docker.io/')
    registry_idx = reference.find('/')
    if registry_idx == -1 or (not any(c in reference[:registry_idx] for c in ('.', ':')) and reference[:registry_idx] != 'localhost'):
        registry, tagged_image = DEFAULT_DOCKER_REGISTRY, reference
    else:
        registry, tagged_image = reference[:registry_idx], reference[registry_idx + 1:]

    if '/' not in tagged_image:
        tagged_image = f'{DEFAULT_DOCKER_REPO}/{tagged_image}'

    # if image is not tagged, use default value.
    if ':' not in tagged_image:
        tagged_image += f':{DEFAULT_DOCKER_TAG}'

    # At this point, tag should be included already – we just need to see whether this
    # tag is named or digested and respond accordingly.
    ref_is_digest = False
    if '@' in tagged_image:
        matches = re.findall(DIGEST_RE, tagged_image)
        if not matches:
            raise CallError(f'Invalid reference format: {tagged_image}')

        tag = matches[-1]
        tag_pos = tagged_image.find(tag)
        image = tagged_image[:tag_pos - 1].rsplit(':', 1)[0]
        sep = '@'
        ref_is_digest = True
    elif ':' in tagged_image:
        image, tag = tagged_image.rsplit(':', 1)
        sep = ':'

    return {
        'reference': reference,
        'image': image,
        'tag': tag,
        'registry': registry,
        'complete_tag': f'{registry}/{image}{sep}{tag}',
        'reference_is_digest': ref_is_digest,
    }


def get_chart_releases_consuming_image(
    image_names: Union[list, set], chart_releases: list, get_mapping: bool = False
) -> Union[dict, list]:
    chart_releases_consuming_image = defaultdict(list) if get_mapping else set()
    images = {i['complete_tag']: i for i in map(normalize_reference, image_names)}
    for chart_release in chart_releases:
        for image in chart_release['resources']['container_images']:
            parsed_image = normalize_reference(image)
            if parsed_image['complete_tag'] in images and images[
                parsed_image['complete_tag']
            ]['tag'] == parsed_image['tag']:
                if get_mapping:
                    chart_releases_consuming_image[chart_release['name']].append(parsed_image['reference'])
                else:
                    chart_releases_consuming_image.add(chart_release['name'])
    return chart_releases_consuming_image if get_mapping else list(chart_releases_consuming_image)


def parse_tags(references: List[str]) -> List[Dict[str, str]]:
    return [normalize_reference(reference=reference) for reference in references]


def normalize_docker_limits_header(headers: dict) -> dict:
    if not all(limit_key in headers for limit_key in ['ratelimit-limit', 'ratelimit-remaining']):
        return {'error': 'Unable to retrieve rate limit information from registry'}

    total_pull_limit, total_time_limit = headers['ratelimit-limit'].split(';w=')
    remaining_pull_limit, remaining_time_limit = headers['ratelimit-remaining'].split(';w=')

    return {
        'total_pull_limit': int(total_pull_limit),
        'total_time_limit_in_secs': int(total_time_limit),
        'remaining_pull_limit': int(remaining_pull_limit),
        'remaining_time_limit_in_secs': int(remaining_time_limit),
        'error': None,
    }
