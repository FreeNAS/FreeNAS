import asyncio
import os
import psutil
import pybonjour
import queue
import re
import select
import socket
import threading

from pybonjour import (
    kDNSServiceFlagsMoreComing,
    kDNSServiceFlagsAdd,
    kDNSServiceErr_NoError
)

from middlewared.service import Service


class mDNSDaemonThread(object):
    def __init__(self, *args, **kwargs):
        super(mDNSDaemonThread, self).__init__()
        self.mdnsd_pidfile = "/var/run/mdnsd.pid"
        self.mdnsd_piddir = "/var/run/"

    def pidfile_exists(self):
        return os.access(self.mdnsd_pidfile, os.F_OK)

    def is_alive(self):
        mdnsd_proc = None
        alive = False

        if not self.pidfile_exists():
            return False

        for proc in psutil.process_iter():
            procdict = proc.as_dict(['name'])
            procname = str(procdict['name'])

            match = re.search("([^/]+)$", procname)
            if not match:
                continue

            procname = match.group(0)
            if procname == "mdnsd":
                mdnsd_proc = proc
                break

        if mdnsd_proc and mdnsd_proc.is_running():
            alive = True

        return alive

    def wait(self):
        alive = False

        if self.is_alive():
            return True

        fd = os.open(self.mdnsd_piddir, os.O_RDONLY)
        kq = select.kqueue()

        events = [select.kevent(
            fd, filter=select.KQ_FILTER_VNODE,
            flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
            fflags=select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND
        )]

        events = kq.control(events, 0, 0)
        if not self.is_alive() and self.pidfile_exists():
            os.unlink(self.mdnsd_pidfile)

        while (not alive):
            proc_events = kq.control([], 1)
            for event in proc_events:
                if ((event.fflags & select.KQ_NOTE_WRITE) or
                        (event.fflags & select.KQ_NOTE_EXTEND)):
                    if self.pidfile_exists() and self.is_alive():
                        alive = True
                        break

        kq.close()
        os.close(fd)

        return True


class mDNSObject(object):
    def __init__(self, **kwargs):
        self.sdRef = kwargs.get('sdRef')
        self.flags = kwargs.get('flags')
        self.interface = kwargs.get('interface')
        self.name = kwargs.get('name')

    def to_dict(self):
        return {
            'type': 'mDNSObject',
            'sdRef': memoryview(self.sdRef).tobytes().decode('utf-8'),
            'flags': self.flags,
            'interface': self.interface,
            'name': self.name
        }


class mDNSDiscoverObject(mDNSObject):
    def __init__(self, **kwargs):
        super(mDNSDiscoverObject, self).__init__(**kwargs)
        self.regtype = kwargs.get('regtype')
        self.domain = kwargs.get('domain')

    @property
    def fullname(self):
        return "%s.%s.%s" % (
            self.name.strip('.'),
            self.regtype.strip('.'),
            self.domain.strip('.')
        )

    def to_dict(self):
        bdict = super(mDNSDiscoverObject, self).to_dict()
        bdict.update({
            'type': 'mDNSDiscoverObject',
            'regtype': self.regtype,
            'domain': self.domain
        })
        return bdict


class mDNSServiceObject(mDNSObject):
    def __init__(self, **kwargs):
        super(mDNSServiceObject, self).__init__(**kwargs)
        self.target = kwargs.get('target')
        self.port = kwargs.get('port')
        self.text = kwargs.get('text')

    def to_dict(self):
        bdict = super(mDNSServiceObject, self).to_dict()
        bdict.update({
            'type': 'mDNSServiceObject',
            'target': self.target,
            'port': self.port,
            'text': self.text
        })
        return bdict


class mDNSThread(threading.Thread):
    def __init__(self, **kwargs):
        super(mDNSThread, self).__init__()
        self.setDaemon(True)
        self.logger = kwargs.get('logger')
        self.timeout = kwargs.get('timeout', 30)

        self.mdnsd = mDNSDaemonThread()
        self.mdnsd.wait()

    def active(self, sdRef):
        return (bool(sdRef) and sdRef.fileno() != -1)

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)


class DiscoverThread(mDNSThread):
    def __init__(self, **kwargs):
        super(DiscoverThread, self).__init__(**kwargs)
        self.regtype = "_services._dns-sd._udp"
        self.queue = kwargs.get('queue')
        self.finished = threading.Event()
        self.pipe = os.pipe()

    def on_discover(self, sdRef, flags, interface, error, name, regtype, domain):
        self.debug("DiscoverThread: name=%s flags=0x%08x error=%d", name, flags, error)

        if error != kDNSServiceErr_NoError:
            return

        self.queue.put(
            mDNSDiscoverObject(
                sdRef=sdRef,
                flags=flags,
                interface=interface,
                name=name,
                regtype=regtype,
                domain=domain
            )
        )

    def run(self):
        sdRef = pybonjour.DNSServiceBrowse(
            regtype=self.regtype,
            callBack=self.on_discover
        )

        while True:
            r, w, x = select.select([sdRef, self.pipe[0]], [], [])
            if self.pipe[0] in r:
                break

            for ref in r:
                pybonjour.DNSServiceProcessResult(ref)

            if self.finished.is_set():
                break

        if self.active(sdRef):
            sdRef.close()

    def cancel(self):
        self.finished.set()
        os.write(self.pipe[1], b'42')


class ServicesThread(mDNSThread):
    def __init__(self, **kwargs):
        super(ServicesThread, self).__init__(**kwargs)
        self.queue = kwargs.get('queue')
        self.service_queue = kwargs.get('service_queue')
        self.finished = threading.Event()
        self.pipe = os.pipe()
        self.references = []
        self.cache = {}

    def to_regtype(self, obj):
        regtype = None

        if (obj.flags & (kDNSServiceFlagsAdd | kDNSServiceFlagsMoreComing)) \
           or not (obj.flags & kDNSServiceFlagsAdd):
            service = obj.name
            proto = obj.regtype.split('.')[0]
            regtype = "%s.%s." % (service, proto)

        return regtype

    def on_discover(self, sdRef, flags, interface, error, name, regtype, domain):
        self.debug("ServicesThread: name=%s flags=0x%08x error=%d", name, flags, error)

        if error != kDNSServiceErr_NoError:
            return

        obj = mDNSDiscoverObject(
            sdRef=sdRef,
            flags=flags,
            interface=interface,
            name=name,
            regtype=regtype,
            domain=domain
        )

        if not (obj.flags & kDNSServiceFlagsAdd):
            self.debug("ServicesThread: remove %s", name)
            cobj = self.cache.get(obj.fullname)
            if cobj:
                if cobj.sdRef in self.references:
                    self.references.remove(cobj.sdRef)
                if self.active(cobj.sdRef):
                    cobj.sdRef.close()
                del self.cache[obj.fullname]
        else:
            self.cache[obj.fullname] = obj
            self.service_queue.put(obj)

    def run(self):
        while True:
            try:
                obj = self.queue.get(block=True, timeout=self.timeout)
            except queue.Empty:
                if self.finished.is_set():
                    break
                continue

            regtype = self.to_regtype(obj)
            if not regtype:
                continue

            sdRef = pybonjour.DNSServiceBrowse(
                regtype=regtype,
                callBack=self.on_discover
            )

            self.references.append(sdRef)
            _references = list(filter(self.active, self.references))

            r, w, x = select.select(_references + [self.pipe[0]], [], [])
            if self.pipe[0] in r:
                break
            for ref in r:
                pybonjour.DNSServiceProcessResult(ref)
            if not (obj.flags & kDNSServiceFlagsAdd):
                self.references.remove(sdRef)
                if self.active(sdRef):
                    sdRef.close()

            if self.finished.is_set():
                break

        for ref in self.references:
            self.references.remove(ref)
            if self.active(ref):
                ref.close()

    def cancel(self):
        self.finished.set()
        os.write(self.pipe[1], b'42')


class ResolveThread(mDNSThread):
    def __init__(self, **kwargs):
        super(ResolveThread, self).__init__(**kwargs)
        self.queue = kwargs.get('queue')
        self.finished = threading.Event()
        self.references = []
        self.services = []

    def on_resolve(self, sdRef, flags, interface, error, name, target, port, text):
        self.debug("ResolveThread: name=%s flags=0x%08x error=%d", name, flags, error)

        if error != kDNSServiceErr_NoError:
            return

        self.services.append(
            mDNSServiceObject(
                sdRef=sdRef,
                flags=flags,
                interface=interface,
                name=name,
                target=target,
                port=port,
                text=text
            )
        )

        self.references.remove(sdRef)
        sdRef.close()

    def run(self):
        while True:
            try:
                obj = self.queue.get(block=True, timeout=self.timeout)
            except queue.Empty:
                if self.finished.is_set():
                    break
                continue

            sdRef = pybonjour.DNSServiceResolve(
                flags=obj.flags,
                interfaceIndex=obj.interface,
                name=obj.name,
                regtype=obj.regtype,
                domain=obj.domain,
                callBack=self.on_resolve
            )

            self.references.append(sdRef)
            _references = list(filter(self.active, self.references))

            r, w, x = select.select(_references, [], [])
            for ref in r:
                pybonjour.DNSServiceProcessResult(ref)

            if self.finished.is_set():
                break

        for ref in self.references:
            self.references.remove(ref)
            if self.active(ref):
                ref.close()

    def cancel(self):
        self.finished.set()

    async def remove_by_host(self, host, service=None):
        ret = False

        if not host:
            return ret

        for s in self.services:
            parts = s.name.split('.')
            if len(parts) < 3:
                continue

            _host = parts[0]
            _service = "%s.%s" % (parts[1], parts[2])

            if _host == host:
                if (service and _service == service) or \
                   (service and _service == service[:-1]) or \
                   (not service):
                    self.services.remove(s)
                    ret = True
        return ret

    async def get_by_host(self, host, service=None):
        if not host:
            return None

        services = []
        for s in self.services:
            parts = s.name.split('.')
            if len(parts) < 3:
                continue

            _host = parts[0]
            _service = "%s.%s" % (parts[1], parts[2])

            if _host == host:
                if (service and _service == service) or \
                   (service and _service == service[:-1]) or \
                   (not service):
                    services.append(s)

        return services

    async def get_by_service(self, service, host=None):
        if not service:
            return None

        services = []
        for s in self.services:
            parts = s.name.split('.')
            if len(parts) < 3:
                continue

            _host = parts[0]
            _service = "%s.%s" % (parts[1], parts[2])

            if (_service == service) or (_service == service[:-1]):
                if (host and _host == host) or (not host):
                    services.append(s)

        return services

    async def get_services(self):
        json_serialized = []
        for s in self.services:
            json_serialized.append(s.to_dict())
        return json_serialized


class mDNSBrowserService(Service):
    def __init__(self, *args):
        super(mDNSBrowserService, self).__init__(*args)
        self.threads = {}
        self.dq = None
        self.sq = None
        self.dthread = None
        self.sthread = None
        self.rthread = None
        self.initialized = False
        self.lock = threading.Lock()

    async def remove_by_host(self, host, service=None):
        return await self.rthread.remove_by_host(host, service)

    async def get_by_host(self, host, service=None):
        return await self.rthread.get_by_host(host, service)

    async def get_by_service(self, service, host=None):
        return await self.rthread.get_by_service(service, host)

    async def get_services(self):
        return await self.rthread.get_services()

    def start(self):
        self.logger.debug("mDNSBrowserService: start()")

        self.lock.acquire()
        if self.initialized:
            self.lock.release()
            return
        self.lock.release()

        self.dq = queue.Queue()
        self.sq = queue.Queue()

        self.dthread = DiscoverThread(queue=self.dq, logger=self.middleware.logger, timeout=5)
        self.sthread = ServicesThread(queue=self.dq, service_queue=self.sq, logger=self.middleware.logger, timeout=5)
        self.rthread = ResolveThread(queue=self.sq, logger=self.middleware.logger, timeout=5)

        self.dthread.start()
        self.sthread.start()
        self.rthread.start()

        self.lock.acquire()
        self.initialized = True
        self.lock.release()

    def stop(self):
        self.logger.debug("mDNSBrowserService: stop()")

        self.rthread.cancel()
        self.sthread.cancel()
        self.dthread.cancel()

        self.lock.acquire()
        self.initialized = False
        self.lock.release()

    def restart(self):
        self.logger.debug("mDNSBrowserService: restart()")

        self.stop()
        self.start()


class mDNSServiceThread(threading.Thread):
    def __init__(self, **kwargs):
        super(mDNSServiceThread, self).__init__()
        self.setDaemon(True)
        self.service = kwargs.get('service')
        self.middleware = kwargs.get('middleware')
        self.logger = kwargs.get('logger')
        self.hostname = kwargs.get('hostname')
        self.service = kwargs.get('service')
        self.regtype = kwargs.get('regtype')
        self.port = kwargs.get('port')
        self.pipe = os.pipe()
        self.finished = threading.Event()

    def debug(self, msg, *args, **kwargs):
        self.logger.debug(msg, *args, **kwargs)

    def _register(self, name, regtype, port):
        if not (name and regtype and port):
            return

        sdRef = pybonjour.DNSServiceRegister(name=name, regtype=regtype, port=port, callBack=None)

        while True:
            r, w, x = select.select([sdRef, self.pipe[0]], [], [])
            if self.pipe[0] in r:
                break

            for ref in r:
                pybonjour.DNSServiceProcessResult(ref)

            if self.finished.is_set():
                break

        # This deregisters service
        sdRef.close()

    def register(self):
        if self.hostname and self.regtype and self.port:
            self._register(self.hostname, self.regtype, self.port)

    def run(self):
        self.register()

    def setup(self):
        pass

    def cancel(self):
        self.finished.set()
        os.write(self.pipe[1], b'42')


class mDNSServiceSSHThread(mDNSServiceThread):
    def __init__(self, **kwargs):
        if 'service' not in kwargs:
            kwargs['service'] = 'ssh'
        super(mDNSServiceSSHThread, self).__init__(**kwargs)

    def setup(self):
        ssh_service = self.middleware.call_sync(
            'datastore.query',
            'services.services', [('srv_service', '=', 'ssh'), ('srv_enable', '=', True)])
        if ssh_service:
            response = self.middleware.call_sync('datastore.query', 'services.ssh', [], {'get': True})
            if response:
                self.port = response['ssh_tcpport']
                self.regtype = "_ssh._tcp."


class mDNSServiceSFTPThread(mDNSServiceThread):
    def __init__(self, **kwargs):
        kwargs['service'] = 'sftp'
        super(mDNSServiceSFTPThread, self).__init__(**kwargs)

    def setup(self):
        ssh_service = self.middleware.call_sync(
            'datastore.query',
            'services.services', [('srv_service', '=', 'ssh'), ('srv_enable', '=', True)])
        if ssh_service:
            response = self.middleware.call_sync('datastore.query', 'services.ssh', [], {'get': True})
            if response:
                self.port = response['ssh_tcpport']
                self.regtype = "_sftp._tcp."


class mDNSServiceHTTPThread(mDNSServiceThread):
    def __init__(self, **kwargs):
        kwargs['service'] = 'http'
        super(mDNSServiceHTTPThread, self).__init__(**kwargs)

    def setup(self):
        webui = self.middleware.call_sync('datastore.query', 'system.settings')
        if (webui[0]['stg_guiprotocol'] == 'http' or
           webui[0]['stg_guiprotocol'] == 'httphttps'):
            self.port = int(webui[0]['stg_guiport'] or 80)
            self.regtype = "_http._tcp."


class mDNSServiceHTTPSThread(mDNSServiceThread):
    def __init__(self, **kwargs):
        kwargs['service'] = 'https'
        super(mDNSServiceHTTPSThread, self).__init__(**kwargs)

    def setup(self):
        webui = self.middleware.call_sync('datastore.query', 'system.settings')
        if (webui[0]['stg_guiprotocol'] == 'https' or
           webui[0]['stg_guiprotocol'] == 'httphttps'):
            self.port = int(webui[0]['stg_guihttpsport'] or 443)
            self.regtype = "_https._tcp."


class mDNSServiceMiddlewareThread(mDNSServiceThread):
    def __init__(self, **kwargs):
        kwargs['service'] = 'middleware'
        super(mDNSServiceMiddlewareThread, self).__init__(**kwargs)

    def setup(self):
        webui = self.middleware.call_sync('datastore.query', 'system.settings')
        if (webui[0]['stg_guiprotocol'] == 'http' or
           webui[0]['stg_guiprotocol'] == 'httphttps'):
            self.port = int(webui[0]['stg_guiport'] or 80)
            self.regtype = "_middleware._tcp."


class mDNSServiceMiddlewareSSLThread(mDNSServiceThread):
    def __init__(self, **kwargs):
        kwargs['service'] = 'middleware-ssl'
        super(mDNSServiceMiddlewareSSLThread, self).__init__(**kwargs)

    def setup(self):
        webui = self.middleware.call_sync('datastore.query', 'system.settings')
        if (webui[0]['stg_guiprotocol'] == 'https' or
           webui[0]['stg_guiprotocol'] == 'httphttps'):
            self.port = int(webui[0]['stg_guihttpsport'] or 443)
            self.regtype = "_middleware-ssl._tcp."


class mDNSAdvertiseService(Service):
    def __init__(self, *args):
        super(mDNSAdvertiseService, self).__init__(*args)
        self.threads = {}
        self.initialized = False
        self.lock = threading.Lock()
        self.mdnsd = mDNSDaemonThread()

    def start(self):
        self.lock.acquire()
        if self.initialized:
            self.lock.release()
            return
        self.lock.release()

        self.mdnsd.wait()

        try:
            hostname = socket.gethostname().split('.')[0]
        except IndexError:
            hostname = socket.gethostname()

        mdns_advertise_services = [
            mDNSServiceSSHThread,
            mDNSServiceSFTPThread,
            mDNSServiceHTTPThread,
            mDNSServiceHTTPSThread,
            mDNSServiceMiddlewareThread,
            mDNSServiceMiddlewareSSLThread
        ]

        for service in mdns_advertise_services:
            thread = service(middleware=self.middleware, logger=self.logger, hostname=hostname)
            thread.setup()
            thread_name = thread.service
            self.threads[thread_name] = thread
            thread.start()

        self.lock.acquire()
        self.initialized = True
        self.lock.release()

    def stop(self):
        for thread in self.threads.copy():
            thread = self.threads.get(thread)
            thread.cancel()
            del self.threads[thread.service]
        self.threads = {}

        self.lock.acquire()
        self.initialized = False
        self.lock.release()

    def restart(self):
        self.stop()
        self.start()


class mDNSService(Service):
    pass


def setup(middleware):
    asyncio.ensure_future(middleware.call('mdnsadvertise.start'))
    asyncio.ensure_future(middleware.call('mdnsbrowser.start'))
