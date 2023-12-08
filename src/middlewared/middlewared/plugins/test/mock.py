import errno
from middlewared.service import CallError, Service


class TestService(Service):
    class Config:
        private = True

    async def set_mock(self, name, args, description):
        if await self.middleware.call('system.is_stable'):
            raise CallError("Mocked methods may not be set in stable releases.", errno.EPERM)

        if isinstance(description, str):
            exec(description)
            try:
                method = locals()["mock"]
            except KeyError:
                raise CallError("Your mock declaration must include `def mock` or `async def mock`")
        elif isinstance(description, dict):
            keys = set(description.keys())
            if keys == {"exception"}:
                def method(*args, **kwargs):
                    raise Exception()
            elif keys == {"return_value"}:
                def method(*args, **kwargs):
                    return description["return_value"]
            else:
                raise CallError("Invalid mock declaration")
        else:
            raise CallError("Invalid mock declaration")

        self.middleware.set_mock(name, args, method)

    async def remove_mock(self, name, args):
        self.middleware.remove_mock(name, args)

    # Dummy methods to mock for internal infrastructure testing (i.e. jobs manager)

    async def test1(self):
        pass

    async def test2(self):
        pass
