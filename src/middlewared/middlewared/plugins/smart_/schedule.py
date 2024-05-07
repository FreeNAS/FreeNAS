# -*- coding=utf-8 -*-
from collections import namedtuple
import re

__all__ = ["smartd_schedule_piece", "smartd_schedule_piece_values"]

ALL_VALUES = object()
RE_RANGE_WITH_DIVISOR = re.compile(r"((?P<min>[0-9]+)-(?P<max>[0-9]+)|\*)/(?P<divisor>[0-9]+)")
RE_RANGE = re.compile(r"((?P<min>[0-9]+)-(?P<max>[0-9]+)|\*)")

SchedulePiece = namedtuple("SchedulePiece", ["key", "min", "max", "enum", "map"])
SMARTD_SCHEDULE_PIECES = [
    SchedulePiece("month", 1, 12, dict(zip([
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"
    ], range(1, 13))), None),
    SchedulePiece("dom", 1, 31, None, None),
    SchedulePiece("dow", 1, 7, dict(zip([
        "mon", "tue", "wed", "thu", "fri", "sat", "sun"
    ], range(1, 8))), {0: 7}),
    SchedulePiece("hour", 0, 23, None, None),
]


def smartd_schedule_piece(value, min_, max_, enum=None, map_=None):
    width = len(str(max_))

    values = smartd_schedule_piece_values_template(value, min_, max_, enum, map_)

    if values == ALL_VALUES:
        return "." * width
    else:
        return "(" + "|".join([f"%0{width}d" % v for v in values]) + ")"


def smartd_schedule_piece_values_template(value, min_, max_, enum=None, map_=None):
    enum = enum or {}
    map_ = map_ or {}

    if value == "*":
        return ALL_VALUES
    elif m := RE_RANGE_WITH_DIVISOR.match(value):
        d = int(m.group("divisor"))
        if m.group("min") is None:
            if d == 1:
                return ALL_VALUES
        else:
            min_ = int(m.group("min"))
            max_ = int(m.group("max"))
        values = [v for v in range(min_, max_ + 1) if v % d == 0]
    elif m := RE_RANGE.match(value):
        start = int(m.group("min"))
        end = int(m.group("max"))
        if end <= start:
            values = [start]
        else:
            values = [i for i in range(start, end + 1)]
    else:
        values = list(filter(lambda v: v is not None,
                             map(lambda s: enum.get(s.lower(), int(s) if s.isdigit() else None),
                                 value.split(","))))
        values = [map_.get(v, v) for v in values]
        if values == list(range(min_, max_ + 1)):
            return ALL_VALUES

    return values


def smartd_schedule_piece_values(value, min_, max_, enum=None, map_=None):
    values = smartd_schedule_piece_values_template(value, min_, max_, enum, map_)

    if values == ALL_VALUES:
        return list(range(min_, max_ + 1))
    else:
        return values
