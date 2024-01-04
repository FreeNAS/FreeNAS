import errno
import pytest

from middlewared.client import ClientException
from middlewared.test.integration.assets.account import unprivileged_user_client
from middlewared.test.integration.utils import call


@pytest.mark.parametrize('role,endpoint,valid_role', (
    ('READONLY', 'webui.crypto.certificate_profiles', True),
    ('READONLY', 'webui.crypto.certificateauthority_profiles', True),
    ('NETWORK_INTERFACE_WRITE', 'webui.crypto.certificate_profiles', False),
    ('NETWORK_INTERFACE_WRITE', 'webui.crypto.certificateauthority_profiles', False),
))
def test_ui_crypto_profiles_readonly_role(role, endpoint, valid_role):
    with unprivileged_user_client(roles=[role]) as c:
        if valid_role:
            c.call(endpoint)
        else:
            with pytest.raises(ClientException) as ve:
                c.call(endpoint)

            assert ve.value.errno == errno.EACCES
            assert ve.value.error == 'Not authorized'


@pytest.mark.parametrize('role,valid_role', (
    ('READONLY', True),
    ('NETWORK_INTERFACE_WRITE', False),
))
def test_ui_crypto_domain_names_readonly_role(role, valid_role):
    default_certificate = call('certificate.query', [('name', '=', 'truenas_default')])
    if not default_certificate:
        pytest.skip('Default certificate does not exist which is required for this test')
    else:
        default_certificate = default_certificate[0]

    with unprivileged_user_client(roles=[role]) as c:
        if valid_role:
            c.call('webui.crypto.get_domain_names', default_certificate['id'])
        else:
            with pytest.raises(ClientException) as ve:
                c.call('webui.crypto.get_domain_names', default_certificate['id'])

            assert ve.value.errno == errno.EACCES
            assert ve.value.error == 'Not authorized'
