import os
import pam

from middlewared.plugins.account import unixhash_is_valid
from middlewared.plugins.account_.constants import ADMIN_UID, MIDDLEWARE_PAM_SERVICE
from middlewared.service import Service, private
from middlewared.utils.crypto import check_unixhash


class AuthService(Service):

    class Config:
        cli_namespace = 'auth'

    @private
    async def authenticate(self, username, password):
        if user_info := (await self.middleware.call(
            'datastore.query', 'account.bsdusers',
            [('username', '=', username)],
            {'prefix': 'bsdusr_', 'select': ['id', 'unixhash', 'uid']},
        )):
            user_info = user_info[0] | {'local': True}
            unixhash = user_info.pop('unixhash')
        else:
            user_info = {'id': None, 'uid': None, 'local': False}
            unixhash = None

        pam_resp = {'code': pam.PAM_AUTH_ERR, 'reason': 'Authentication failure'}

        # The following provides way for root user to avoid getting locked out
        # of webui via due to PAM enforcing password policies on the root
        # account. Specifically, some legacy users have configured the root
        # account so its password has password_disabled = true. We have to
        # maintain the old middleware authentication code (bypassing PAM) to
        # prevent this.
        #
        # In all failure cases libpam_authenticate is called so that timing
        # is consistent with pam_fail_delay
        if username == 'root' and await self.middleware.call('privilege.always_has_root_password_enabled'):
            if not unixhash_is_valid(unixhash):
                await self.middleware.call('auth.libpam_authenticate', username, password)
            elif await self.middleware.run_in_thread(check_unixhash, password, unixhash):
                pam_resp = {'code': pam.PAM_SUCCESS, 'reason': ''}
            else:
                await self.middleware.call('auth.libpam_authenticate', username, password)

        else:
            pam_resp = await self.middleware.call('auth.libpam_authenticate', username, password)

        if pam_resp['code'] != pam.PAM_SUCCESS:
            return None

        return await self.authenticate_user({'username': username}, user_info)

    @private
    def libpam_authenticate(self, username, password):
        """
        Following PAM codes are returned:

        PAM_SUCCESS = 0
        PAM_AUTH_ERR = 7 // Bad username or password
        PAM_NEW_AUTHTOK_REQD = 12 // User must change password

        Potentially other may be returned as well depending on the particulars
        of the PAM modules.
        """
        if not os.path.exists(MIDDLEWARE_PAM_SERVICE):
            self.logger.error('PAM service file is missing. Attempting to regenerate')
            self.middleware.call_sync('etc.generate', 'pam_middleware')
            if not os.path.exists(MIDDLEWARE_PAM_SERVICE):
                self.logger.error(
                    '%s: Unable to generate PAM service file for middleware. Denying '
                    'access to user.', username
                )
                return {'code': pam.PAM_ABORT, 'reason': 'Failed to generate PAM service file'}

        p = pam.pam()
        p.authenticate(username, password, service='middleware')
        return {'code': p.code, 'reason': p.reason}

    @private
    async def authenticate_user(self, query, user_info):
        try:
            user = await self.middleware.call('user.get_user_obj', {
                **query, 'get_groups': True,
                'sid_info': not user_info['local'],
            })
        except KeyError:
            return None

        if user_info['uid'] is not None and user_info['uid'] != user['pw_uid']:
            # For some reason there's a mismatch between the passwd file
            # and what is stored in the TrueNAS configuration.
            self.logger.error(
                '%s: rejecting access for local user due to uid [%d] not '
                'matching expected value [%d]',
                user['pw_name'], user['pw_uid'], user_info['uid']
            )
            return None

        match user['source']:
            case 'LOCAL':
                # Local user
                twofactor_id = user_info['id']
                groups_key = 'local_groups'
                account_flags = ['LOCAL']
            case 'ACTIVEDIRECTORY':
                # Active directory user
                twofactor_id = user['sid']
                groups_key = 'ds_groups'
                account_flags = ['DIRECTORY_SERVICE', 'ACTIVE_DIRECTORY']
            case 'LDAP':
                # This includes both OpenLDAP and IPA domains
                # Since IPA domains may have cross-realm trusts with separate
                # idmap configuration we will preferentially use the SID if it is
                # available (since it should be static and universally unique)
                twofactor_id = user['sid'] or user_info['id']
                groups_key = 'ds_groups'
                account_flags = ['DIRECTORY_SERVICE', 'LDAP']
            case _:
                self.logger.error('[%s]: unknown user source. Rejecting access.', user['source'])
                return None

        if user['local'] != user_info['local']:
            # There is a disagreement between our expectation of user account source
            # based on our database and what NSS _actually_ returned.
            self.logger.error(
                '%d: Rejecting access by user id due to potential collision between '
                'local and directory service user account. TrueNAS configuration '
                'expected a %s user account but received an account provided by %s.',
                user['pw_uid'], 'local' if user_info['local'] else 'non-local', user['source']
            )
            return None

        # Two-factor authentication token is keyed by SID for activedirectory
        # users.
        twofactor_enabled = bool((await self.middleware.call(
            'auth.twofactor.get_user_config',
            twofactor_id, user_info['local']
        ))['secret'])

        groups = set(user['grouplist'])

        if twofactor_enabled:
            account_flags.append('2FA')

        if user['pw_uid'] in (0, ADMIN_UID):
            if not user['local']:
                # Although this should be covered in above check for mismatch in
                # value of `local`, perform an extra explicit check for the case
                # of root / root-equivalent accounts.
                self.logger.error(
                    'Rejecting admin account access due to collision with acccount provided '
                    'by a directory service.'
                )
                return None

            account_flags.append('SYS_ADMIN')

        privileges = await self.middleware.call('privilege.privileges_for_groups', groups_key, groups)
        if not privileges:
            return None

        return {
            'username': user['pw_name'],
            'account_attributes': account_flags,
            'privilege': await self.middleware.call('privilege.compose_privilege', privileges),
        }

    @private
    async def authenticate_root(self):
        return {
            'username': 'root',
            'account_attributes': ['LOCAL', 'SYS_ADMIN'],
            'privilege': await self.middleware.call('privilege.full_privilege'),
        }
