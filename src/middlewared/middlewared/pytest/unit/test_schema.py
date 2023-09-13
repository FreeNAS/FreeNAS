import pytest
from unittest.mock import Mock

from middlewared.service import job
from middlewared.service_exception import ValidationErrors
from middlewared.schema import (
    accepts, Bool, Cron, Dict, Dir, File, Float, Int, IPAddr, List, Str, URI, UnixPerm, LocalUsername
)


def test__nonhidden_after_hidden():
    with pytest.raises(ValueError):
        @accepts(Int('id'), Bool('fake', hidden=True), List('flags'))
        def f(self, id, fake, flags):
            pass


def test__schema_str_empty():

    @accepts(Str('data', empty=False))
    def strempty(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        strempty(self, '')


def test__schema_str_non_empty():

    @accepts(Str('data', empty=True))
    def strempty(self, data):
        return data

    self = Mock()

    assert strempty(self, '') == ''


def test__schema_str_null():

    @accepts(Str('data', null=True))
    def strnull(self, data):
        return data

    self = Mock()

    assert strnull(self, None) is None


def test__schema_str_not_null():

    @accepts(Str('data', null=False))
    def strnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        assert strnotnull(self, None) is not None


@pytest.mark.parametrize("value,expected", [
    ('foo', 'foo'),
    (3, '3'),
    (False, ValidationErrors),
    (3.3, ValidationErrors),
    (["foo"], ValidationErrors),
])
def test__schema_str_values(value, expected):

    @accepts(Str('data'))
    def strv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            strv(self, value)
        assert ei.value.errors[0].errmsg == 'Not a string'
    else:
        assert strv(self, value) == expected


@pytest.mark.parametrize("value,expected", [
    ('FOO', 'FOO'),
    ('BAR', 'BAR'),
    ('FOOBAR', ValidationErrors),
])
def test__schema_str_num(value, expected):

    @accepts(Str('data', enum=['FOO', 'BAR']))
    def strv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            strv(self, value)
        assert ei.value.errors[0].errmsg.startswith('Invalid choice')
    else:
        assert strv(self, value) == expected


def test__schema_bool_null():

    @accepts(Bool('data', null=True))
    def boolnull(self, data):
        return data

    self = Mock()

    assert boolnull(self, None) is None


def test__schema_bool_not_null():

    @accepts(Bool('data', null=False))
    def boolnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        assert boolnotnull(self, None) is not None


def test__schema_float_null():

    @accepts(Float('data', null=True))
    def floatnull(self, data):
        return data

    self = Mock()

    assert floatnull(self, None) is None


def test__schema_float_not_null():

    @accepts(Float('data', null=False))
    def floatnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        assert floatnotnull(self, None) is not None


@pytest.mark.parametrize("value,expected", [
    (5, 5.0),
    ('5', 5.0),
    ('5.0', 5.0),
    (5.0, 5.0),
    ('FOO', ValidationErrors),
    (False, ValidationErrors),
    ([4], ValidationErrors),
])
def test__schema_float_values(value, expected):

    @accepts(Float('data', null=False))
    def floatv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            floatv(self, value)
        assert ei.value.errors[0].errmsg == 'Not a floating point number'
    else:
        assert floatv(self, value) == expected


def test__schema_int_null():

    @accepts(Int('data', null=True))
    def intnull(self, data):
        return data

    self = Mock()

    assert intnull(self, None) is None


def test__schema_int_not_null():

    @accepts(Int('data', null=False))
    def intnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        assert intnotnull(self, None) is not None


@pytest.mark.parametrize("value,expected", [
    (3, 3),
    ('3', 3),
    ('-3', -3),
    (-3, -3),
    (3.0, ValidationErrors),
    ('FOO', ValidationErrors),
    (False, ValidationErrors),
    ([4], ValidationErrors),
])
def test__schema_int_values(value, expected):

    @accepts(Int('data'))
    def intv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            intv(self, False)
        assert ei.value.errors[0].errmsg == 'Not an integer'
    else:
        assert intv(self, value) == expected


def test__schema_dict_null():

    @accepts(Dict('data', null=True))
    def dictnull(self, data):
        return data

    self = Mock()

    assert dictnull(self, None) is None


def test__schema_dict_not_null():

    @accepts(Str('data', null=False))
    def dictnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        assert dictnotnull(self, None) != {}


@pytest.mark.parametrize("value,expected", [
    ({'foo': 'foo'}, {'foo': 'foo'}),
    ({}, {}),
    ({'foo': None}, ValidationErrors),
    ({'bar': None}, ValidationErrors),
])
def test__schema_dict_not_null_args(value, expected):

    @accepts(Dict(
        'data',
        Str('foo'),
        Bool('bar'),
    ))
    def dictargs(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            dictargs(self, value)
        assert ei.value.errors[0].errmsg == 'null not allowed'
    else:
        assert dictargs(self, value) == expected


@pytest.mark.parametrize("value,expected", [
    ({'foo': 'foo', 'bar': False, 'list': []}, {'foo': 'foo', 'bar': False, 'list': []}),
    ({'foo': 'foo'}, ValidationErrors),
    ({'bar': False}, ValidationErrors),
    ({'foo': 'foo', 'bar': False}, {'foo': 'foo', 'bar': False, 'list': []}),
])
def test__schema_dict_required_args(value, expected):

    @accepts(Dict(
        'data',
        Str('foo', required=True),
        Bool('bar', required=True),
        List('list', required=True),
    ))
    def dictargs(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            dictargs(self, value)
        assert ei.value.errors[0].errmsg == 'attribute required'
    else:
        assert dictargs(self, value) == expected


@pytest.mark.parametrize("value,expected,msg", [
    ({'foo': 'foo', 'bar': False}, {'foo': 'foo', 'bar': False, 'list': []}, None),
    ({'foo': 'foo', 'bar': False, 'num': 5}, {'foo': 'foo', 'bar': False, 'num': 5, 'list': []}, None),
    ({'foo': 'foo'}, {'foo': 'foo', 'list': []}, None),
    ({'foo': 'foo', 'list': ['listitem']}, {'foo': 'foo', 'list': ['listitem']}, None),
    ({'foo': 'foo', 'list': 5}, ValidationErrors, 'Not a list'),
    ({'foo': 'foo', 'bar': False, 'num': None}, ValidationErrors, 'null not allowed'),
    ({'foo': None}, ValidationErrors, 'null not allowed'),
    ({'bar': None}, ValidationErrors, 'attribute required'),
])
def test__schema_dict_mixed_args(value, expected, msg):

    @accepts(Dict(
        'data',
        Str('foo', required=True),
        Bool('bar', null=True),
        Int('num'),
        List('list', items=[Str('listitem')]),
    ))
    def dictargs(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors) as ei:
            dictargs(self, value)
        assert ei.value.errors[0].errmsg == msg
    else:
        assert dictargs(self, value) == expected


@pytest.mark.parametrize("schema,attribute", [
    (
        Dict(
            'create',
            Dict(
                'image',
                Str('repository', required=True),
            ),
        ),
        'create.image.repository',
    ),
    (
        Dict(
            'create',
            Str('repository', required=True),
        ),
        'create.repository',
    ),
])
def test__schema_dict_error_handler_attribute_name(schema, attribute):

    @accepts(schema)
    def meth(self, data):
        return data

    with pytest.raises(ValidationErrors) as ei:
        meth({})

    assert ei.value.errors[0].attribute == attribute


def test__schema_dict_error_handler():

    @accepts(Dict(
        'create',
        Str('repository', required=True),
    ))
    def meth(self, data):
        return data

    with pytest.raises(ValidationErrors) as ei:
        meth({})

    assert ei.value.errors[0].attribute == 'create.repository'


@pytest.mark.parametrize('items,value,expected', [
    ([List('b', items=[List('c', private=True)])], [[['a']]], [['********']]),
    ([Dict('b', Str('c', private=True))], [{'c': 'secret'}], [{'c': '********'}]),
    ([Dict('b', Str('c', private=True)), Dict('d', Str('e'))], [{'c': 'secret'}], [{'c': '********'}]),
    ([Dict('b', Str('c')), Dict('d', Str('c', private=True))], [{'c': 'secret'}], ['********']),
])
def test__schema_list_private_items(items, value, expected):
    assert List('a', items=items).dump(value) == expected


def test__schema_list_empty():

    @accepts(List('data', empty=False))
    def listempty(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        listempty(self, [])


def test__schema_list_non_empty():

    @accepts(List('data', empty=True))
    def listempty(self, data):
        return data

    self = Mock()

    assert listempty(self, []) == []


def test__schema_list_null():

    @accepts(List('data', null=True, default=None))
    def listnull(self, data):
        return data

    self = Mock()

    assert listnull(self, None) is None


def test__schema_list_not_null():

    @accepts(List('data', null=False))
    def listnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors):
        assert listnotnull(self, None) != []


def test__schema_list_noarg_not_null():

    @accepts(List('data', null=False))
    def listnotnull(self, data):
        return data

    self = Mock()

    with pytest.raises(ValidationErrors) as ei:
        listnotnull(self, None)
    assert ei.value.errors[0].errmsg == 'null not allowed'


@pytest.mark.parametrize("value,expected", [
    (["foo"], ["foo"]),
    ([2], ["2"]),
    ([2, "foo"], ["2", "foo"]),
    ([False], ValidationErrors),
    ("foo", ValidationErrors),
    ({"foo": "bar"}, ValidationErrors),
])
def test__schema_list_items(value, expected):

    @accepts(List('data', items=[Str('foo')]))
    def listnotnull(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            listnotnull(self, value)
    else:
        assert listnotnull(self, value) == expected


@pytest.mark.parametrize('value,expected', [
    (['foo'], ['foo']),
    ([True, True, 'foo'], [True, True, 'foo']),
    ([2, {'bool': True}], ['2', {'bool': True}]),
    ([2, {'bool': True, 'str': False}], ValidationErrors),
    ({'foo': False}, ValidationErrors),
    ({'unexpected': False}, ValidationErrors),
    ('foo', ValidationErrors),
    ({'foo': 'foo'}, ValidationErrors),
])
def test__schema_list_multiple_items(value, expected):

    @accepts(List('data', items=[Str('foo'), Bool('bool'), Dict('dict', Bool('bool'), Str('str'))]))
    def listnotnull(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            listnotnull(self, value)
    else:
        assert listnotnull(self, value) == expected


def test__schema_list_null_items():

    @accepts(List('data', null=True, items=[Str('item')]))
    def listnull(self, data):
        return data

    self = Mock()

    # FIXME: Why does this return `[]`? It should return `None`
    # We are only checking that there is no crash here
    listnull(self, None)


def test__schema_unixperm_null():

    @accepts(UnixPerm('data', null=True))
    def unixpermnull(self, data):
        return data

    self = Mock()

    assert unixpermnull(self, None) is None


def test__schema_dir_null():

    @accepts(Dir('data', null=True))
    def dirnull(self, data):
        return data

    self = Mock()

    assert dirnull(self, None) is None


def test__schema_file_null():

    @accepts(File('data', null=True))
    def filenull(self, data):
        return data

    self = Mock()

    assert filenull(self, None) is None


@pytest.mark.parametrize("value,expected", [
    ({'minute': '55'}, {'minute': '55'}),
    ({'dow': '2'}, {'dow': '2'}),
    ({'hour': '*'}, {'hour': '*'}),
    ({'minute': '66'}, ValidationErrors),
    ({'hour': '-25'}, ValidationErrors),
    ({'dom': '33'}, ValidationErrors),
])
def test__schema_cron_values(value, expected):

    @accepts(Cron('data'))
    def cronv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            cronv(self, value)
    else:
        result = {k: v for k, v in cronv(self, value).items() if k in expected}
        assert result == expected


@pytest.mark.parametrize("data_dict,begin_end,result", [
    (
        {"cron_minute": "00", "cron_hour": "01", "cron_daymonth": "02", "cron_month": "03", "cron_dayweek": "04"},
        False,
        {"schedule": {"minute": "00", "hour": "01", "dom": "02", "month": "03", "dow": "04"}},
    ),
    (
        {"cron_minute": "00", "cron_hour": None, "cron_daymonth": "02", "cron_month": "03", "cron_dayweek": "04"},
        False,
        {"schedule": None},
    ),
    (
        {"cron_minute": "00", "cron_hour": "01", "cron_daymonth": "02", "cron_month": "03", "cron_dayweek": "04",
         "cron_begin": "05:00:00", "cron_end": "06:00:00"},
        True,
        {"schedule": {"minute": "00", "hour": "01", "dom": "02", "month": "03", "dow": "04",
                      "begin": "05:00", "end": "06:00"}},
    ),
    (
        {"cron_minute": "00", "cron_hour": None, "cron_daymonth": "02", "cron_month": "03", "cron_dayweek": "04",
         "cron_begin": "05:00:00", "cron_end": "06:00:00"},
        True,
        {"schedule": None},
    ),
    (
        {"cron_minute": "00", "cron_hour": "01", "cron_daymonth": "02", "cron_month": "03", "cron_dayweek": "04",
         "cron_begin": "05:00:00", "cron_end": None},
        True,
        {"schedule": None},
    ),
])
def test__cron__convert_db_format_to_schedule(data_dict, begin_end, result):
    Cron.convert_db_format_to_schedule(data_dict, "schedule", "cron_", begin_end)
    assert data_dict == result


@pytest.mark.parametrize("value,error", [
    ({'hour': '0', 'minute': '0', 'begin': '09:00', 'end': '18:00'}, True),
    ({'hour': '9', 'minute': '0', 'begin': '09:00', 'end': '18:00'}, False),
    ({'hour': '9', 'minute': '0', 'begin': '09:10', 'end': '18:00'}, True),
    ({'hour': '9', 'minute': '15', 'begin': '09:10', 'end': '18:00'}, False),
])
def test__cron__begin_end_validate(value, error):

    @accepts(Cron('data', begin_end=True))
    def cronv(self, data):
        return data

    self = Mock()

    if error:
        with pytest.raises(ValidationErrors):
            cronv(self, value)
    else:
        cronv(self, value)


@pytest.mark.parametrize("value,expected", [
    ('127.0.0.1', '127.0.0.1'),
    ('22::56', '22::56'),
    ('192.', ValidationErrors),
    ('5:5', ValidationErrors),
    ('ff:ff:ee:aa', ValidationErrors),
])
def test__schema_ipaddr(value, expected):

    @accepts(IPAddr('data'))
    def ipaddrv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            ipaddrv(self, value)
    else:
        assert ipaddrv(self, value) == expected


@pytest.mark.parametrize("value,expected", [
    ('127.0.0.1/32', '127.0.0.1/32'),
    ('22::56/64', '22::56/64'),
    ('192.', ValidationErrors),
    ('5:5', ValidationErrors),
    ('ff:ff:ee:aa', ValidationErrors),
    ('192.168.3.1/33', ValidationErrors),
    ('ff::4/129', ValidationErrors),
])
def test__schema_ipaddr_cidr(value, expected):

    @accepts(IPAddr('data', cidr=True))
    def ipaddrv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            ipaddrv(self, value)
    else:
        assert ipaddrv(self, value) == expected


@pytest.mark.parametrize("value,expected", [
    ('192.168.0.0%enp0s3', ValidationErrors),
    ('22::56%enp0s3', '22::56%enp0s3'),
])
def test__schema_ipaddr_cidr_allow_zone_index(value, expected):

    @accepts(IPAddr('data', allow_zone_index=True))
    def ipaddrv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            ipaddrv(self, value)
    else:
        assert ipaddrv(self, value) == expected


@pytest.mark.parametrize("value,expected", [
    ('192.168.0.0/24', '192.168.0.0/24'),
    ('192.168.0.0/255.255.255.0', '192.168.0.0/24'),
    ('192.168.0.1', '192.168.0.1/32'),
    ('192.168.0.999', ValidationErrors),
    ('BOGUS.NAME', ValidationErrors),
])
def test__schema_ipaddr_network(value, expected):

    @accepts(IPAddr('data', network=True))
    def ipaddrv(self, data):
        return data

    self = Mock()

    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            ipaddrv(self, value)
    else:
        assert ipaddrv(self, value) == expected


@pytest.mark.parametrize("value,expected", [
    ('192.168.0.0/24', None),
    ('192.168.0.0/255.255.255.0', None),
    ('192.168.0.1', None),
    ('192.168.0.999', ValidationErrors),
    ('BOGUS.NAME', ValidationErrors),
])
def test__schema_ipaddr_validate(value, expected):
    network = value.find('/') != -1
    ipaddr = IPAddr(network=network)
    if expected is ValidationErrors:
        with pytest.raises(ValidationErrors):
            ipaddr.validate(value)
    else:
        assert ipaddr.validate(value) == expected


def test__schema_str_default():

    @accepts(Str('foo'), Str('bar', default='BAR'))
    def strdef(self, foo, bar):
        return bar

    self = Mock()

    assert strdef(self, 'foo') == 'BAR'


def test__schema_str_job_default():
    """
    Job changes the order of the parameters in schema\
    """

    @accepts(Str('foo'), Str('bar', default='BAR'))
    @job()
    def strdef(self, job, foo, bar):
        return bar

    self = Mock()
    jobm = Mock()

    assert strdef(self, jobm, 'foo') == 'BAR'


@pytest.mark.parametrize("schema,attribute", [
    (
        Dict(
            'create',
            Dict(
                'image',
                Str('repository', required=True),
            ),
        ),
        'create.image.repository',
    ),
    (
        Dict(
            'create',
            Str('repository', required=True),
        ),
        'create.repository',
    ),
])
def test__schema_or_error_handler_attribute_name(schema, attribute):

    @accepts(schema)
    def meth(self, data):
        return data

    with pytest.raises(ValidationErrors) as ei:
        meth({})

    assert ei.value.errors[0].attribute == attribute


@pytest.mark.parametrize('test_value,expected_error', [
    ('https://google.com', False),
    ('https:google.com', True),
    ('https:/google', True),
    ('https://www.google.com/search?q=truenas', False),
])
def test__uri_schema(test_value, expected_error):
    @accepts(URI('uri'))
    def strv(self, uri):
        return uri

    self = Mock()

    if expected_error:
        with pytest.raises(ValidationErrors) as ei:
            strv(self, test_value)
        assert ei.value.errors[0].errmsg == 'Not a valid URI'
    else:
        assert strv(self, test_value) == test_value


@pytest.mark.parametrize('value,expected_to_fail', [
    ('', True),
    (f'{"a" * 33}', True),
    (' bad', True),
    ('a$a', True),
    ('a!', True),
    ('a$', False),
    ('aaa', False),
    ('aAA', False),
    ('Aaa', False),
    ('A.a', False),
])
def test__localusername_schema(value, expected_to_fail):
    @accepts(LocalUsername('username', required=True))
    def user(self, data):
        return data

    self = Mock()
    if expected_to_fail:
        with pytest.raises(ValidationErrors):
            user(self, value)
    else:
        assert user(self, value) == value
