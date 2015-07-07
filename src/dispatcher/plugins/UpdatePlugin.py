# +
# Copyright 2014 iXsystems, Inc.
# All rights reserved
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted providing that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
#####################################################################

import errno
import sys
import re
import logging
from resources import Resource
from cache import CacheStore
from task import (Provider, Task, ProgressTask, TaskException, VerifyException)
from dispatcher.rpc import (RpcException, description, accepts,
                            returns, SchemaHelper as h)
from lib.system import system

sys.path.append('/usr/local/lib')
from freenasOS import Configuration
from freenasOS.Exceptions import (UpdateManifestNotFound,
                                  ManifestInvalidSignature,
                                  UpdateBootEnvironmentException,
                                  UpdatePackageException)
from freenasOS.Update import (
    ActivateClone, CheckForUpdates, DeleteClone, PendingUpdates,
    PendingUpdatesChanges, DownloadUpdate, ApplyUpdate
)

# Keep this even if currently unused as it helps when there is a
# need for debugging
logger = logging.getLogger('UpdatePlugin')
update_cache = CacheStore()
update_resource_string = 'update:operations'


def parse_changelog(changelog, start='', end=''):
    "Utility function to parse an available changelog"
    regexp = r'### START (\S+)(.+?)### END \1'
    reg = re.findall(regexp, changelog, re.S | re.M)

    if not reg:
        return None

    changelog = None
    for seq, changes in reg:
        if not changes.strip('\n'):
            continue
        if seq == start:
            # Once we found the right one, we start accumulating
            changelog = []
        elif changelog is not None:
            changelog.append(changes.strip('\n'))
        if seq == end:
            break
    return changelog


def get_changelog(train, cache_dir='/var/tmp/update', start='', end=''):
    "Utility to get and eventually parse a changelog if available"
    conf = Configuration.Configuration()
    changelog = conf.GetChangeLog(train=train, save_dir=cache_dir)
    if not changelog:
        return None

    return parse_changelog(changelog.read(), start, end)


# The handler(s) below is/are taken from the freenas 9.3 code
# specifically from gui/system/utils.py
class CheckUpdateHandler(object):
    "A handler for the CheckUpdate call"

    def __init__(self):
        self.changes = []

    def call(self, op, newpkg, oldpkg):
        self.changes.append({
            'operation': op,
            'old': oldpkg,
            'new': newpkg,
        })

    def output(self):
        output = []
        for c in self.changes:
            opdict = {
                'operation': c['operation'],
                'previous_name': c['old'].Name(),
                'previous_version': c['old'].Version(),
                'new_name': c['new'].Name(),
                'new_version': c['new'].Version()
            }
            output.append(opdict)
        return output


def check_updates(dispatcher, cache_dir=None, check_now=False):
    "Utility function to just check for Updates"
    update_cache.invalidate('updateAvailable')
    update_cache.invalidate('updateOperations')
    update_cache.invalidate('changelog')
    conf = Configuration.Configuration()
    update_ops = None
    handler = CheckUpdateHandler()
    train = dispatcher.configstore.get('update.train')
    try:
        update = CheckForUpdates(
            handler=handler.call,
            train=train,
            cache_dir=None if check_now else cache_dir,
        )
    except Exception:
        update_cache.put('updateAvailable', False)
        update_cache.put('updateOperations', update_ops)
        update_cache.put('changelog', '')
        raise

    if update:
        update_ops = handler.output()
        sys_mani = conf.SystemManifest()
        if sys_mani:
            sequence = sys_mani.Sequence()
        else:
            sequence = ''
        changelog = get_changelog(train,
                                  cache_dir=cache_dir,
                                  start=sequence,
                                  end=update.Sequence())
    else:
        changelog = None
    update_cache.put('updateAvailable', True if update else False)
    update_cache.put('updateOperations', update_ops)
    update_cache.put('changelog', changelog)


class UpdateHandler(object):
    "A handler for Downloading and Applying Updates calls"

    def __init__(self, dispatcher, update_progress=None):
        self.progress = 0
        self.details = ''
        self.finished = False
        self.error = False
        self.indeterminate = False
        self.reboot = False
        self.pkgname = ''
        self.pkgversion = ''
        self.operation = ''
        self.filename = ''
        self.filesize = 0
        self.numfilestotal = 0
        self.numfilesdone = 0
        self._baseprogress = 0
        self.master_progress = 0
        self.dispatcher = dispatcher
        # Below is the function handle passed to this by the Task so that
        # its status and progress can be updated accordingly
        self.update_progress = update_progress

    def check_handler(self, index, pkg, pkgList):
        self.pkgname = pkg.Name()
        self.pkgversion = pkg.Version()
        self.operation = 'Downloading'
        self.details = '%s %s' % (
            'Downloading',
            '%s-%s' % (self.pkgname, self.pkgversion),
        )
        stepprogress = int((1.0 / float(len(pkgList))) * 100)
        self._baseprogress = index * stepprogress
        self.progress = (index - 1) * stepprogress
        self.emit_update_details()

    def get_handler(self, method, filename, size=None,
                    progress=None, download_rate=None):
        filename = filename.rsplit('/', 1)[-1]
        if progress is not None:
            self.progress = (progress * self._baseprogress) / 100
            if self.progress == 0:
                self.progress = 1
            self.details = '%s %s(%d%%)%s' % (
                filename,
                '%s ' % size
                if size else '',
                progress,
                '  %s/s' % download_rate
                if download_rate else '',
            )
        self.emit_update_details()

    def install_handler(self, index, name, packages):
        self.indeterminate = False
        total = len(packages)
        self.numfilesdone = index
        self.numfilesdone = total
        self.progress = int((float(index) / float(total)) * 100.0)
        self.operation = 'Installing'
        self.details = '%s %s (%d/%d)' % (
            'Installing',
            name,
            index,
            total,
        )

    def emit_update_details(self):
        # Doing the drill below as there is a small window when
        # step*progress logic does not catch up with the new value of step
        if self.progress >= self.master_progress:
            self.master_progress = self.progress
        data = {
            'indeterminate': self.indeterminate,
            'percent': self.master_progress,
            'reboot': self.reboot,
            'pkg_name': self.pkgname,
            'pkg_version': self.pkgversion,
            'filename': self.filename,
            'filesize': self.filesize,
            'num_files_one': self.numfilesdone,
            'num_files_total': self.numfilestotal,
            'error': self.error,
            'finished': self.finished,
            'details': self.details,
        }
        if self.update_progress is not None:
            self.update_progress(self.master_progress, self.details)
        self.dispatcher.dispatch_event('update.in_progress', {
            'operation': self.operation,
            'data': data,
        })


def generate_update_cache(dispatcher, cache_dir=None):
    if cache_dir is None:
        try:
            cache_dir = dispatcher.rpc.call_sync(
                            'system-dataset.request_directory',
                            'update')
        except RpcException:
            cache_dir = '/var/tmp/update'
    update_cache.put('cache_dir', cache_dir)
    try:
        check_updates(dispatcher, cache_dir=cache_dir)
    except Exception as e:
        # What to do now?
        logger.debug('generate_update_cache (UpdatePlugin) falied' +
                     'because of: {0}'.format(str(e)))


@description("Provides System Updater Configuration")
class UpdateProvider(Provider):

    @accepts()
    @returns(str)
    def is_update_available(self):
        temp_updateAvailable = update_cache.get('updateAvailable',
                                                timeout=1)
        if temp_updateAvailable is not None:
            return temp_updateAvailable
        elif update_cache.is_valid('updateAvailable'):
            return temp_updateAvailable
        else:
            raise RpcException(
                errno.EBUSY,
                'Update Availability flag is invalidated, an Update Check' +
                ' might be underway. Try again in some time.')

    @accepts()
    @returns(h.array(str))
    def obtain_changelog(self):
        temp_changelog = update_cache.get('changelog', timeout=1)
        if temp_changelog is not None:
            return temp_changelog
        elif update_cache.is_valid('changelog'):
            return temp_changelog
        else:
            raise RpcException(
                errno.EBUSY,
                'Changelog list is invalidated, an Update Check' +
                ' might be underway. Try again in some time.')

    @accepts()
    @returns(h.array(h.ref('update.ops')))
    def get_update_ops(self):
        temp_updateOperations = update_cache.get('updateOperations', timeout=1)
        if temp_updateOperations is not None:
            return temp_updateOperations
        elif update_cache.is_valid('updateOperations'):
            return temp_updateOperations
        else:
            raise RpcException(
                errno.EBUSY,
                'Update Operations Dict is invalidated, an Update Check' +
                ' might be underway. Try again in some time.')

    @accepts()
    @returns(str)
    def get_current_train(self):
        return self.dispatcher.configstore.get('update.train')

    @accepts()
    @returns(h.ref('update'))
    def get_config(self):
        return {
            'train': self.dispatcher.configstore.get('update.train'),
            'check_auto': self.dispatcher.configstore.get(
                'update.check_auto'),
        }


@description("Set the System Updater Cofiguration Settings")
@accepts(h.ref('update'))
class UpdateConfigureTask(Task):

    def describe(self):
        return "System Updater Configure Settings"

    def verify(self, props):
        # TODO: Fix this verify's resource allocation as unique task
        train_to_set = props.get('train')
        conf = Configuration.Configuration()
        conf.LoadTrainsConfig()
        trains = conf.AvailableTrains() or []
        if trains:
            trains = trains.keys()
        if train_to_set not in trains:
            raise VerifyException(
                errno.ENOENT,
                '{0} is not a valid train'.format(train_to_set))
        block = self.dispatcher.resource_graph.get_resource(
                    update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(
                errno.EBUSY,
                'An Update Operation (Configuration/ Download/ Applying ' +
                'the Updates) is already in the queue, please retry later')

        return [update_resource_string]

    def run(self, props):

        self.dispatcher.configstore.set(
            'update.train',
            props.get('train'),
        )
        self.dispatcher.configstore.set(
            'update.check_auto',
            props.get('check_auto'),
        )
        self.dispatcher.dispatch_event('update.changed', {
            'operation': 'update',
        })


@description("Checks for Available Updates and returns if update is availabe" +
             " and if yes returns information on operations that will be" +
             " performed during the update")
@accepts()
class CheckUpdateTask(Task):
    def describe(self):
        return "Checks for Updates and Reports Operations to be performed"

    def verify(self):
        # TODO: Fix this verify's resource allocation as unique task
        block = self.dispatcher.resource_graph.get_resource(
                    update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(
                errno.EBUSY,
                'An Update Operation (Configuration/ Download/ Applying' +
                'the Updates) is already in the queue, please retry later')

        return [update_resource_string]

    def run(self):
        try:
            check_updates(self.dispatcher,
                          cache_dir=update_cache.get('cache_dir', timeout=1),
                          check_now=True)
        except UpdateManifestNotFound:
            TaskException(errno.ENETUNREACH,
                          'Update server could not be reached')
        except Exception as e:
            TaskException(errno.EAGAIN,
                          '{0}'.format(str(e)))


@description("Downloads Updates for the current system update train")
@accepts()
class DownloadUpdateTask(ProgressTask):
    def describe(self):
        return "Downloads the Updates and caches them to apply when needed"

    def verify(self):
        if not update_cache.get('updateAvailable', timeout=1):
            raise VerifyException(
                errno.ENOENT,
                'No updates currently available for download, try running ' +
                'the `update.check` task')

        block = self.dispatcher.resource_graph.get_resource(
                    update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(
                errno.EBUSY,
                'An Update Operation (Configuration/ Download/ Applying' +
                'the Updates) is already in the queue, please retry later')

        return [update_resource_string]

    def update_progress(self, progress, message):
        if message:
            self.message = message
        self.set_progress(progress)

    def run(self):
        self.message = 'Downloading Updates...'
        self.set_progress(0)
        handler = UpdateHandler(self.dispatcher,
                                update_progress=self.update_progress)
        train = self.dispatcher.configstore.get('update.train')
        cache_dir = update_cache.get('cache_dir')
        if cache_dir is None:
            try:
                cache_dir = self.dispatcher.rpc.call_sync(
                                'system-dataset.request_directory',
                                'update')
            except RpcException:
                cache_dir = '/var/tmp/update'
        try:
            download_successful = DownloadUpdate(
                                  train, cache_dir,
                                  get_handler=handler.get_handler,
                                  check_handler=handler.check_handler)
        except Exception as e:
            raise TaskException(
                      errno.EAGAIN,
                      'Got exception {0} while trying to '.format(str(e)) +
                      ' Download Updates')
        if not download_successful:
            handler.error = True
            handler.emit_update_details()
            raise TaskException(
                      errno.EAGAIN,
                      'Downloading Updates Failed for some reason, check logs')
        handler.finished = True
        handler.emit_update_details()
        self.message = "Updates Finished Downloading"
        self.set_progress(100)


# Fix this when the fn10 freenas-pkg tools is updated by sef
@accepts()
@description("Applies cached updates")
class UpdateApplyTask(ProgressTask):
    def describe(self):
        return "Applies cached updates to the system and reboots if necessary"

    def verify(self):
        block = self.dispatcher.resource_graph.get_resource(
                    update_resource_string)
        if block is not None and block.busy:
            raise VerifyException(
                errno.EBUSY,
                'An Update Operation (Configuration/ Download/ Applying' +
                'the Updates) is already in the queue, please retry later')

        return ['root', update_resource_string]

    def update_progress(self, progress, message):
        if message:
            self.message = message
        self.set_progress(progress)

    def run(self):
        self.message = 'Applying Updates...'
        self.set_progress(0)
        handler = UpdateHandler(self.dispatcher,
                                update_progress=self.update_progress)
        cache_dir = update_cache.get('cache_dir')
        if cache_dir is None:
            try:
                cache_dir = self.dispatcher.rpc.call_sync(
                                'system-dataset.request_directory',
                                'update')
            except RpcException:
                cache_dir = '/var/tmp/update'
        # Note: for now we force reboots always, TODO: Fix in M3-M4
        try:
            ApplyUpdate(cache_dir, install_handler=handler.install_handler,
                        force_reboot=True)
        except ManifestInvalidSignature as e:
            logger.debug('UpdateApplyTask Error: Cached manifest has ' +
                         'invalid signature: {0}'.format(str(e)))
            TaskException(
                errno.EINVAL,
                'Cached manifest has invalid signature: {0}'.format(str(e)))
        except UpdateBootEnvironmentException as e:
            logger.debug(
                'UpdateApplyTask Boot Environment Error: {0}'.format(str(e)))
            TaskException(errno.EAGAIN, str(e))
        except UpdatePackageException as e:
            logger.debug('UpdateApplyTask Package Error: {0}'.format(str(e)))
            TaskException(errno.EAGAIN, str(e))
        except Exception as e:
            raise TaskException(
                      errno.EAGAIN,
                      'Got exception {0} while trying to '.format(str(e)) +
                      ' Apply Updates')
        handler.finished = True
        handler.emit_update_details()
        self.run_subtask('system.reboot')
        self.message = "Updates Finished Installing Successfully"
        self.set_progress(100)


def _depends():
    return ['SystemDatasetPlugin']


def _init(dispatcher, plugin):
    # Register Schemas
    plugin.register_schema_definition('update', {
        'type': 'object',
        'properties': {
            'train': {'type': 'string'},
            'check_auto': {'type': 'boolean'},
        },
    })
    update_in_progress_schema = h.object(properties={
            'operation': h.enum(str, ['Downloading', 'Installing']),
            'details': str,
            'indeterminate': bool,
            'percent': int,
            'reboot': bool,
            'pkg_name': str,
            'pkg_version': str,
            'filename': str,
            'filesize': int,
            'num_files_done': int,
            'num_files_total': int,
            'error': bool,
            'finished': bool,
        })
    plugin.register_schema_definition('update.in_progress',
                                      update_in_progress_schema)

    plugin.register_schema_definition('update.ops', {
        'type': 'object',
        'properties': {
            'new_name': {'type': 'string'},
            'previous_version': {'type': 'string'},
            'operation': {
                'type': 'string',
                'enum': ['upgrade', 'install']
            },
            'new_version': {'type': 'string'},
            'previous_name': {'type': 'string'},
        }
    })

    # Register providers
    plugin.register_provider("update", UpdateProvider)

    # Register task handlers
    plugin.register_task_handler("update.configure", UpdateConfigureTask)
    plugin.register_task_handler("update.check", CheckUpdateTask)
    plugin.register_task_handler("update.download", DownloadUpdateTask)
    plugin.register_task_handler("update.update", UpdateApplyTask)

    # Register Event Types
    plugin.register_event_type('update.in_progress', None,
                               update_in_progress_schema)
    plugin.register_event_type('update.changed')

    # Register reources
    plugin.register_resource(Resource(update_resource_string), ['system'])

    # Get the Update Cache (if any) at system boot (and hence in init here)
    generate_update_cache(dispatcher)
