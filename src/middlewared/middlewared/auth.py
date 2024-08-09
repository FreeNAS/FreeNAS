import re

from middlewared.utils.allowlist import Allowlist


class SessionManagerCredentials:
    is_user_session = False
    allowlist = None

    @classmethod
    def class_name(cls):
        return re.sub(
            r"([A-Z])",
            r"_\1",
            cls.__name__.replace("SessionManagerCredentials", "")
        ).lstrip("_").upper()

    def login(self):
        pass

    def is_valid(self):
        return True

    def authorize(self, method, resource):
        return False

    def has_role(self, role):
        return False

    def notify_used(self):
        pass

    def logout(self):
        pass

    def dump(self):
        return {}


class UserSessionManagerCredentials(SessionManagerCredentials):
    def __init__(self, user):
        self.user = user
        self.allowlist = Allowlist(user["privilege"]["allowlist"])
        self.is_user_session = True

    def authorize(self, method, resource):
        return self.allowlist.authorize(method, resource)

    def has_role(self, role):
        return role in self.user["privilege"]["roles"]

    def dump(self):
        return {
            "username": self.user["username"],
        }


class UnixSocketSessionManagerCredentials(UserSessionManagerCredentials):
    pass


class LoginPasswordSessionManagerCredentials(UserSessionManagerCredentials):
    pass


class ApiKeySessionManagerCredentials(SessionManagerCredentials):
    def __init__(self, api_key):
        self.api_key = api_key

    def authorize(self, method, resource):
        return self.api_key.authorize(method, resource)

    def dump(self):
        return {
            "api_key": {
                "id": self.api_key.api_key["id"],
                "name": self.api_key.api_key["name"],
            }
        }


class TokenSessionManagerCredentials(SessionManagerCredentials):
    def __init__(self, token_manager, token):
        self.root_credentials = token.root_credentials()

        self.token_manager = token_manager
        self.token = token
        self.is_user_session = self.root_credentials.is_user_session
        if self.is_user_session:
            self.user = self.root_credentials.user

        self.allowlist = self.root_credentials.allowlist

    def is_valid(self):
        return self.token.is_valid()

    def authorize(self, method, resource):
        return self.token.parent_credentials.authorize(method, resource)

    def has_role(self, role):
        return self.token.parent_credentials.has_role(role)

    def notify_used(self):
        self.token.notify_used()

    def logout(self):
        self.token_manager.destroy(self.token)

    def dump(self):
        data = {
            "parent": dump_credentials(self.token.parent_credentials),
        }
        if self.is_user_session:
            data["username"] = self.user["username"]

        return data


class TrueNasNodeSessionManagerCredentials(SessionManagerCredentials):
    def authorize(self, method, resource):
        return True


def is_ha_connection(remote_addr, remote_port):
    return remote_port <= 1024 and remote_addr in ('169.254.10.1', '169.254.10.2')


class FakeApplication:
    authenticated_credentials = SessionManagerCredentials()


def fake_app():
    return FakeApplication()


def dump_credentials(credentials):
    return {
        "credentials": credentials.class_name(),
        "credentials_data": credentials.dump(),
    }
