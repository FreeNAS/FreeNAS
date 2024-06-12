import asyncio
from collections import defaultdict
import errno
import functools
import typing
from uuid import uuid4

from middlewared.event import EventSource
from middlewared.main import Application, Middleware
from middlewared.schema import ValidationErrors
from middlewared.service_exception import CallError, CallException


class IdentData(typing.NamedTuple):
    subscriber: 'Subscriber'
    name: str
    arg: typing.Optional[str]
    

class Subscriber:
    def send_event(self, event_type: str, **kwargs):
        raise NotImplementedError

    def terminate(self, error: typing.Optional[Exception]):
        raise NotImplementedError


class AppSubscriber(Subscriber):
    def __init__(self, app: Application, collection: str):
        self.app = app
        self.collection = collection

    def send_event(self, event_type, **kwargs):
        self.app.send_event(self.collection, event_type, **kwargs)

    def terminate(self, error):
        error_dict: typing.Dict[str, dict[str, typing.Any]] = {}
        if error:
            if isinstance(error, ValidationErrors):
                error_dict['error'] = self.app.get_error_dict(
                    errno.EAGAIN, str(error), etype='VALIDATION', extra=list(error)
                )
            elif isinstance(error, CallError):
                error_dict['error'] = self.app.get_error_dict(
                    error.errno, str(error), extra=error.extra
                )
            else:
                error_dict['error'] = self.app.get_error_dict(errno.EINVAL, str(error))

        self.app._send({'msg': 'nosub', 'collection': self.collection, **error_dict})


class InternalSubscriber(Subscriber):
    def __init__(self):
        self.iterator = InternalSubscriberIterator()

    def send_event(self, event_type, **kwargs):
        self.iterator.queue.put_nowait((False, (event_type, kwargs)))

    def terminate(self, error):
        if error:
            self.iterator.queue.put_nowait((True, error))
        else:
            self.iterator.queue.put_nowait(None)


IteratorItemType = tuple[str, dict[str, typing.Any]]
IteratorQueueItemType = typing.Optional[tuple[bool, typing.Union[IteratorItemType, Exception]]]

class InternalSubscriberIterator:
    def __init__(self):
        self.queue = asyncio.Queue()

    def __aiter__(self):
        return self

    async def __anext__(self) -> typing.Optional[IteratorItemType]:
        item: IteratorQueueItemType = await self.queue.get()

        if item is None:
            raise StopAsyncIteration

        is_error, value = item
        if is_error:
            raise value
        else:
            return value


class EventSourceManager:
    def __init__(self, middleware: Middleware):
        self.middleware = middleware

        self.event_sources: typing.Dict[str, type[EventSource]] = {}
        self.instances: typing.DefaultDict[str, dict[typing.Optional[str], EventSource]] = defaultdict(dict)
        self.idents: typing.Dict[str, IdentData] = {}
        self.subscriptions: typing.DefaultDict[str, defaultdict[typing.Optional[str], set[str]]] = defaultdict(lambda: defaultdict(set))

    def short_name_arg(self, name: str):
        if ':' in name:
            shortname, arg = name.split(':', 1)
        else:
            shortname = name
            arg = None
        return shortname, arg

    def get_full_name(self, name: str, arg: typing.Optional[str]):
        if arg is None:
            return name
        else:
            return f'{name}:{arg}'

    def register(self, name: str, event_source: typing.Type[EventSource], roles: typing.Iterable[str]):
        if not issubclass(event_source, EventSource):
            raise RuntimeError(f"{event_source} is not EventSource subclass")

        self.event_sources[name] = event_source

        self.middleware.role_manager.register_event(name, roles)

    async def subscribe(self, subscriber: Subscriber, ident: str, name: str, arg: typing.Optional[str]):
        if ident in self.idents:
            raise ValueError(f"Ident {ident} is already used")

        self.idents[ident] = IdentData(subscriber, name, arg)
        self.subscriptions[name][arg].add(ident)

        if arg not in self.instances[name]:
            self.middleware.logger.trace("Creating new instance of event source %r:%r", name, arg)
            self.instances[name][arg] = self.event_sources[name](
                self.middleware, name, arg,
                functools.partial(self._send_event, name, arg),
                functools.partial(self._unsubscribe_all, name, arg),
            )
            # Validate that specified `arg` is acceptable wrt event source in question
            try:
                await self.instances[name][arg].validate_arg()
            except ValidationErrors as e:
                await self.unsubscribe(ident, e)
            else:
                self.middleware.create_task(self.instances[name][arg].process())
        else:
            self.middleware.logger.trace("Re-using existing instance of event source %r:%r", name, arg)

    async def unsubscribe(self, ident: str, error: typing.Optional[CallException]=None):
        ident_data = self.idents.pop(ident)
        self.terminate(ident_data, error)

        idents = self.subscriptions[ident_data.name][ident_data.arg]
        idents.remove(ident)
        if not idents:
            self.middleware.logger.trace("Canceling instance of event source %r:%r as the last subscriber "
                                         "unsubscribed", ident_data.name, ident_data.arg)
            instance = self.instances[ident_data.name].pop(ident_data.arg)
            await instance.cancel()

    def terminate(self, ident: IdentData, error: typing.Optional[Exception]=None):
        ident.subscriber.terminate(error)

    async def subscribe_app(self, app: Application, ident: str, name: str, arg: typing.Optional[str]):
        await self.subscribe(AppSubscriber(app, self.get_full_name(name, arg)), ident, name, arg)

    async def unsubscribe_app(self, app: Application):
        for ident, ident_data in list(self.idents.items()):
            if isinstance(ident_data.subscriber, AppSubscriber) and ident_data.subscriber.app == app:
                await self.unsubscribe(ident)

    async def iterate(self, name: str, arg: typing.Optional[str]):
        ident = str(uuid4())
        subscriber = InternalSubscriber()
        await self.subscribe(subscriber, ident, name, arg)
        return subscriber.iterator

    def _send_event(self, name: str, arg: typing.Optional[str], event_type: str, **kwargs):
        for ident in list(self.subscriptions[name][arg]):
            try:
                ident_data = self.idents[ident]
            except KeyError:
                self.middleware.logger.trace("Ident %r is gone", ident)
                continue

            ident_data.subscriber.send_event(event_type, **kwargs)

    async def _unsubscribe_all(self, name: str, arg: typing.Optional[str], error: typing.Optional[Exception]=None):
        for ident in self.subscriptions[name][arg]:
            self.terminate(self.idents.pop(ident), error)

        self.instances[name].pop(arg, None)
        self.subscriptions[name][arg].clear()
