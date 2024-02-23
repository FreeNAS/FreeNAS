import asyncio
import logging
import operator
import re
import signal
import subprocess
import json
from datetime import datetime, timedelta
from functools import wraps, cache
from threading import Lock

from middlewared.service_exception import MatchNotFound

MID_PID = None
MIDDLEWARE_RUN_DIR = '/var/run/middleware'
BOOTREADY = f'{MIDDLEWARE_RUN_DIR}/.bootready'
MANIFEST_FILE = '/data/manifest.json'
BRAND = 'TrueNAS'
PRODUCT = 'SCALE'
BRAND_PRODUCT = f'{BRAND}-{PRODUCT}'
NULLS_FIRST = 'nulls_first:'
NULLS_LAST = 'nulls_last:'
REVERSE_CHAR = '-'
MAX_FILTERS_DEPTH = 3
TIMESTAMP_DESIGNATOR = '.$date'

logger = logging.getLogger(__name__)


class UnexpectedFailure(Exception):
    pass


def bisect(condition, iterable):
    a = []
    b = []
    for val in iterable:
        if condition(val):
            a.append(val)
        else:
            b.append(val)

    return a, b


def Popen(args, **kwargs):
    shell = kwargs.pop('shell', None)
    if shell:
        return asyncio.create_subprocess_shell(args, **kwargs)
    else:
        return asyncio.create_subprocess_exec(*args, **kwargs)


async def run(*args, **kwargs):
    if isinstance(args[0], list):
        args = tuple(args[0])
    kwargs.setdefault('stdout', subprocess.PIPE)
    kwargs.setdefault('stderr', subprocess.PIPE)
    check = kwargs.pop('check', True)
    encoding = kwargs.pop('encoding', None)
    errors = kwargs.pop('errors', None) or 'strict'
    input_ = kwargs.pop('input', None)
    if input_ is not None:
        kwargs['stdin'] = subprocess.PIPE
    abort_signal = kwargs.pop('abort_signal', signal.SIGKILL)
    proc = await asyncio.create_subprocess_exec(*args, **kwargs)
    try:
        stdout, stderr = await proc.communicate(input_)
    except asyncio.CancelledError:
        if abort_signal is not None:
            proc.send_signal(abort_signal)
        raise
    if encoding:
        if stdout is not None:
            stdout = stdout.decode(encoding, errors)
        if stderr is not None:
            stderr = stderr.decode(encoding, errors)
    cp = subprocess.CompletedProcess(args, proc.returncode, stdout=stdout, stderr=stderr)
    if check:
        cp.check_returncode()
    return cp


def partition(s):
    rv = ''
    while True:
        left, sep, right = s.partition('.')
        if not sep:
            return rv + left, right
        if left[-1] == '\\':
            rv += left[:-1] + sep
            s = right
        else:
            return rv + left, right


def get(obj, path):
    """
    Get a path in obj using dot notation

    e.g.
        obj = {'foo': {'bar': '1'}, 'foo.bar': '2', 'foobar': ['first', 'second', 'third']}

        path = 'foo.bar' returns '1'
        path = 'foo\\.bar' returns '2'
        path = 'foobar.0' returns 'first'
    """
    right = path
    cur = obj
    while right:
        left, right = partition(right)
        if isinstance(cur, dict):
            cur = cur.get(left)
        elif isinstance(cur, (list, tuple)):
            left = int(left)
            cur = cur[left] if left < len(cur) else None
    return cur


def select_path(obj, path):
    keys = []
    right = path
    cur = obj
    while right:
        left, right = partition(right)
        if isinstance(cur, dict):
            cur = cur.get(left, MatchNotFound)
            keys.append(left)
        elif isinstance(cur, (list, tuple)):
            raise ValueError('Selecting by list index is not supported')

    return (keys, cur)


def casefold(obj):
    if obj is None:
        return None

    if isinstance(obj, str):
        return obj.casefold()

    if isinstance(obj, (list, tuple)):
        return [x.casefold() for x in obj]

    raise ValueError(f'{type(obj)}: support for casefolding object type not implemented.')


class filters(object):
    def op_in(x, y):
        return operator.contains(y, x)

    def op_rin(x, y):
        if x is None:
            return False

        return operator.contains(x, y)

    def op_nin(x, y):
        if x is None:
            return False

        return not operator.contains(y, x)

    def op_rnin(x, y):
        if x is None:
            return False

        return not operator.contains(x, y)

    def op_re(x, y):
        return re.match(y, x)

    def op_startswith(x, y):
        if x is None:
            return False

        return x.startswith(y)

    def op_notstartswith(x, y):
        if x is None:
            return False

        return not x.startswith(y)

    def op_endswith(x, y):
        if x is None:
            return False

        return x.endswith(y)

    def op_notendswith(x, y):
        if x is None:
            return False

        return not x.endswith(y)

    opmap = {
        '=': operator.eq,
        '!=': operator.ne,
        '>': operator.gt,
        '>=': operator.ge,
        '<': operator.lt,
        '<=': operator.le,
        '~': op_re,
        'in': op_in,
        'nin': op_nin,
        'rin': op_rin,
        'rnin': op_rnin,
        '^': op_startswith,
        '!^': op_notstartswith,
        '$': op_endswith,
        '!$': op_notendswith,
    }

    def validate_filters(self, filters, recursion_depth=0, value_maps=None):
        """
        This method gets called when `query-filters` gets validated in
        the accepts() decorator of public API endpoints. It is generally
        a good idea to improve validation here, but not at significant
        expense of performance as this is called every time `filter_list`
        is called.
        """
        if recursion_depth > MAX_FILTERS_DEPTH:
            raise ValueError('query-filters max recursion depth exceeded')

        for f in filters:
            if len(f) == 2:
                op, value = f
                if op != 'OR':
                    raise ValueError(f'Invalid operation: {op}')

                if not value:
                    raise ValueError('OR filter requires at least one branch.')

                for branch in value:
                    if isinstance(branch[0], list):
                        self.validate_filters(branch, recursion_depth + 1, value_maps)
                    else:
                        self.validate_filters([branch], recursion_depth + 1, value_maps)

                continue

            elif len(f) != 3:
                raise ValueError(f'Invalid filter {f}')

            op = f[1]
            if op[0] == 'C':
                op = op[1:]
                if op == '~':
                    raise ValueError('Invalid case-insensitive operation: {}'.format(f[1]))

            if op not in self.opmap:
                raise ValueError('Invalid operation: {}'.format(f[1]))

            # special handling for datetime objects
            for operand in (f[0], f[2]):
                if not isinstance(operand, str) or not operand.endswith(TIMESTAMP_DESIGNATOR):
                    continue

                if op not in ['=', '!=', '>', '>=', '<', '<=']:
                    raise ValueError(f'{op}: invalid timestamp operation.')

                other = f[2] if operand == f[0] else f[0]
                # At this point we're just validating that it's an ISO8601 string.
                try:
                    ts = datetime.fromisoformat(other)
                except (TypeError, ValueError):
                    raise ValueError(f'{other}: must be an ISO-8601 formatted timestamp string')

                if value_maps is not None:
                    value_maps[other] = ts

    def validate_select(self, select):
        for s in select:
            if isinstance(s, str):
                continue

            if isinstance(s, list):
                if len(s) != 2:
                    raise ValueError(
                        f'{s}: A select as list may only contain two parameters: the name '
                        'of the parameter being selected, and the name to which to assign it '
                        'in resulting data.'
                    )

                for idx, selector in enumerate(s):
                    if isinstance(selector, str):
                        continue

                    raise ValueError(
                        f'{s}: {"first" if idx == 0 else "second"} item must be a string.'
                    )

                continue

            raise ValueError(
                f'{s}: selectors must be either a parameter name as a string or '
                'a list containing two items [<parameter name>, <as name>] to emulate '
                'SELECT <parameter name> AS <as name>.'
            )

    def validate_order_by(self, order_by):
        for idx, o in enumerate(order_by):
            if isinstance(o, str):
                continue

            raise ValueError(
                f'{order_by}: parameter at index {idx} [{o}] is not a string.'
            )

    def validate_options(self, options):
        if options is None:
            return ({}, [], [])

        if options.get('get') and options.get('limit', 0) > 1:
            raise ValueError(
                'Invalid options combination. `get` implies a single result.'
            )

        if options.get('get') and options.get('offset'):
            raise ValueError(
                'Invalid options combination. `get` implies a single result.'
            )

        select = options.get('select', [])
        self.validate_select(select)
        order_by = options.get('order_by', [])
        self.validate_order_by(order_by)

        return (options, select, order_by)

    def filterop(self, i, f, source_getter):
        name, op, value = f
        source = source_getter(i, name)

        if op[0] == 'C':
            fn = self.opmap[op[1:]]
            source = casefold(source)
            value = casefold(value)
        else:
            fn = self.opmap[op]

        if fn(source, value):
            return True

        return False

    def getter_fn(self, _list):
        if not _list:
            return None

        if isinstance(_list[0], dict):
            return get

        return getattr

    def eval_filter(self, list_item, the_filter, getter, value_maps):
        """
        `the_filter` in this case will be a single condition of either the form
        [<a>, <opcode>, <b>] or ["OR", [<condition>, <condition>, ...]

        This allows us to do a simple check of list length to determine whether
        we have a conjunction or disjunction.

        value_maps is dict supplied in which to store operands that need to
        be converted into a different type.

        Recursion depth is checked when validate_filters is called above.
        """
        if len(the_filter) == 2:
            # OR check
            op, value = the_filter
            for branch in value:
                if isinstance(branch[0], list):
                    # This branch of OR is a conjunction of
                    # multiple conditions. All of them must be
                    # True in order for branch to be True.
                    hit = True
                    for i in branch:
                        if not self.eval_filter(list_item, i, getter, value_maps):
                            hit = False
                            break
                else:
                    hit = self.eval_filter(list_item, branch, getter, value_maps)

                if hit is True:
                    return True

            # None of conditions in disjunction are True.
            return False

        # Normal condition check
        if not value_maps:
            return self.filterop(list_item, the_filter, getter)

        if (operand_1 := value_maps.get(the_filter[0])):
            operand_2.rstrip(TIMESTAMP_DESIGNATOR)
        else:
            operand_1 = the_filter[0]

        if (operand_2 := value_maps.get(the_filter[2])):
            operand_1.rstrip(TIMESTAMP_DESIGNATOR)
        else:
            operand_2 = the_filter[2]

        return self.filterop(list_item, (operand_1, the_filter[1], operand_2), getter)


    def do_filters(self, _list, filters, select, shortcircuit, value_maps):
        rv = []

        getter = self.getter_fn(_list)
        for i in _list:
            valid = True
            for f in filters:
                if not self.eval_filter(i, f, getter, value_maps):
                    valid = False
                    break

            if not valid:
                continue

            if select:
                entry = self.do_select([i], select)[0]
            else:
                entry = i

            rv.append(entry)
            if shortcircuit:
                break

        return rv

    def do_select(self, _list, select):
        rv = []
        for i in _list:
            entry = {}
            for s in select:
                if isinstance(s, list):
                    target, new_name = s
                else:
                    target = s
                    new_name = None

                keys, value = select_path(i, target)
                if value is MatchNotFound:
                    continue

                if new_name is not None:
                    entry[new_name] = value
                    continue

                last = keys.pop(-1)
                obj = entry
                for k in keys:
                    obj = obj.setdefault(k, {})

                obj[last] = value

            rv.append(entry)

        return rv

    def do_count(self, rv):
        return len(rv)

    def order_nulls(self, _list, order):
        if order.startswith(REVERSE_CHAR):
            order = order[1:]
            reverse = True
        else:
            reverse = False

        nulls = []
        non_nulls = []
        for entry in _list:
            if entry[order] is None:
                nulls.append(entry)
            else:
                non_nulls.append(entry)

        non_nulls = sorted(non_nulls, key=lambda x: get(x, order), reverse=reverse)
        return (nulls, non_nulls)

    def order_no_null(self, _list, order):
        if order.startswith(REVERSE_CHAR):
            order = order[1:]
            reverse = True
        else:
            reverse = False

        return sorted(_list, key=lambda x: get(x, order), reverse=reverse)

    def do_order(self, rv, order_by):
        for o in order_by:
            if o.startswith(NULLS_FIRST):
                nulls, non_nulls = self.order_nulls(rv, o[len(NULLS_FIRST):])
                rv = nulls + non_nulls
            elif o.startswith(NULLS_LAST):
                nulls, non_nulls = self.order_nulls(rv, o[len(NULLS_LAST):])
                rv = non_nulls + nulls
            else:
                rv = self.order_no_null(rv, o)

        return rv

    def do_get(self, rv):
        try:
            return rv[0]
        except IndexError:
            raise MatchNotFound() from None

    def filter_list(self, _list, filters=None, options=None):
        options, select, order_by = self.validate_options(options)

        do_shortcircuit = options.get('get') and not order_by
        if filters:
            maps = {}
            self.validate_filters(filters, value_maps=maps)
            rv = self.do_filters(_list, filters, select, do_shortcircuit, value_maps=maps)
            if do_shortcircuit:
                return self.do_get(rv)

        elif select:
            rv = self.do_select(_list, select)
        else:
            rv = _list

        if options.get('count') is True:
            return self.do_count(rv)

        rv = self.do_order(rv, order_by)

        if options.get('get') is True:
            return self.do_get(rv)

        if options.get('offset'):
            rv = rv[options['offset']:]

        if options.get('limit'):
            return rv[:options['limit']]

        return rv


filter_list = filters().filter_list


def filter_getattrs(filters):
    """
    Get a set of attributes in a filter list.
    """
    attrs = set()
    if not filters:
        return attrs

    f = filters.copy()
    while f:
        filter_ = f.pop()
        if len(filter_) == 2:
            f.append(filter_[1])
        elif len(filter_) == 3:
            attrs.add(filter_[0])
        else:
            raise ValueError('Invalid filter.')
    return attrs


@cache
def sw_info():
    """Returns the various software information from the manifest file."""
    with open(MANIFEST_FILE) as f:
        manifest = json.load(f)
        version = manifest['version']
        return {
            'stable': 'MASTER' not in manifest['version'],
            'codename': manifest['codename'],
            'version': version,
            'fullname': f'{BRAND_PRODUCT}-{version}',
            'buildtime': manifest['buildtime'],
        }

def sw_codename():
    return sw_info()['codename']


def sw_buildtime():
    return sw_info()['buildtime']


def sw_version():
    return sw_info()['fullname']


def sw_version_is_stable():
    return sw_info()['stable']


def is_empty(val):
    """
    A small utility function that check if the provided string is either None, '',
    or just a string containing only spaces
    """
    return val in [None, ''] or val.isspace()


class Nid(object):

    def __init__(self, _id):
        self._id = _id

    def __call__(self):
        num = self._id
        self._id += 1
        return num


class cache_with_autorefresh(object):
    """
    A decorator which caches the result of a function (with no arguments as yet)
    and returns the cache untill the autorefresh timeout is hit, upon which it
    call the function again and caches the result for future calls.
    """

    def __init__(self, seconds=0, minutes=0, hours=0):
        self.refresh_period = timedelta(
            seconds=seconds, minutes=minutes, hours=hours
        )
        self.cached_return = None
        self.first = True
        self.time_of_last_call = datetime.min
        self.lock = Lock()

    def __call__(self, fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            now = datetime.now()
            time_since_last_call = now - self.time_of_last_call

            with self.lock:
                if time_since_last_call > self.refresh_period or self.first:
                    self.first = False
                    self.time_of_last_call = now
                    self.cached_return = fn(*args, **kwargs)

            return self.cached_return

        return wrapper
