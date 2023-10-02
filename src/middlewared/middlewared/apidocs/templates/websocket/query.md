${'##'} Query Methods

TrueNAS API has multiple query methods including `pool.query`, `disk.query`, `vm.query`, and many more.

The arguments for these methods support multiple options and filters that are similar to SQL queries.

${'###'} Query Filters

${'####'} Basic Usage

Query Filters are primarily an array of conditions, with each condition also represented as an array.

Each condition in the filter list should compare a field with a value.

eg. Filter Syntax: `["field", "operator", value]` 

For example, to filter the data returned by `disk.query`, we provide a list of conditions:

Javascript:
    :::javascript
    [
      ["name","=","ada1"] 
    ]


${'####'} Supported Operators
| Operator       | Description     |
| :------------- | :----------: |
| '=' |  x == y |
| '!=' |  x != y |
| '>' |  x > y |
| '>=' |  x >= y |
| '<' |  x < y |
| '<=' |  x <= y |
| '~' |  re.match(y, x) |
| 'in' |  x in y |
| 'nin' |  x not in y |
| 'rin' |  x is not None and y in x |
| 'rnin' |  x is not None and y not in x |
| '^' |  x is not None and x.startswith(y) |
| '!^' |  x is not None and not x.startswith(y) |
| '$' |  x is not None and x.endswith(y) |
| '!$' |  x is not None and not x.endswith(y) |

Specifing the prefix 'C' will perform a case-insensitive version of the filter, e.g. `C=`.

${'####'} Multiple Filters

We can use `disk.query` with the "type" and "rotationrate" filters to find hard drives with a rotation rate higher than 5400 RPM:

Javascript:
    :::javascript
    [
      ["type","=","HDD"],
      ["rotationrate",">",5400] // Note that the value should be the correct type
    ]


${'####'} Connectives

Queries with no explicitly defined logical connectives assume conjunction `AND`. The disjunction `OR` is also supported by using the syntax illustrated below. We can use `chart.release.query` with `OR` to filter chart releases by name. Note that the operand for the disjunction contains an array of conditions.

The following is a valid example.
Javascript:
    :::javascript
    ["OR", 
      [
        ["name","=", "firstchart"],
        ["name","=", "secondchart"],
      ]
    ]

The following is also a valid example that returns users that are unlocked and either have password-based authentication for SSH enabled or are SMB users.
Javascript:
    :::javascript
    [
      ["OR",
        [
          ["ssh_password_enabled", "=", true],
          ["smb", "=", true]
        ]
      ],
      ["locked", "=", false]
    ]

The following is an invalid example because the first array member is a conjunction of multiple conditions rather than a single condition.
Javascript:
    :::javascript
    ["OR",
      [
        [["ssh_password_enabled", "=", true], ["twofactor_auth_configured", "=", false]],
        ["enabled","=", true],
      ]
    ]

Some additional examples of connective use are as follows.

These filters when used with `user.query` finds unlocked users with password authentication enabled and two-factor authentication disabled.

Javascript:
    :::javascript
    [
      ["ssh_password_enabled", "=", true],
      ["twofactor_auth_configured", "=", false],
      ["locked", "=", false]
    ]


Sub-keys in complex JSON objects may be specified by using dot (".") to indicate the key. For example the following query-filters if passed to `user.query` endpoint will return entries with a primary group ID of 3000.

Javascript:
    :::javascript
    [
      ["group.bsdgrp_gid", "=", 3000],
    ]

If a key contains a literal dot (".") in its name, then it must be escaped via a double backlash.
Javascript:
    :::javascript
    [
      ["foo\\.bar", "=", 42],
    ]



${'###'} Query Options

Query Options are objects that can further customize the results returned by a Query Method.

Properties of a Query Option include `extend | extend_context | prefix | extra | order_by | select | count | get | limit | offset`

${'####'} Count

Use the `count` option to get the number of results returned.

Javascript:
    :::javascript
    {
      "count": true
    }


${'####'} Limit

Use the `limit` option to limit the number of results returned.

Javascript:
    :::javascript
    {
      "limit": 5
    }


${'####'} Offset

Use the `offset` option to remove the first items from a returned list.

Javascript:
    :::javascript
    {
      "offset": 1 // Omits the first item from the query result
    }


${'####'} Select

Use the `select` option to specify the exact fields to return. Fields must be provided in an array of strings. The dot character (".") may be used to explicitly select only subkeys of the query result.

Javascript:
    :::javascript
    {
      "select": ["devname","size","rotationrate"]
    }


Javascript:
    :::javascript
    {
      "select": [
        "Authentication.status",
        "Authentication.localAddress",
        "Authentication.clientAccount"
      ]
    }



${'####'} Order By

Use the `order_by` option to specify which field determines the sort order. Fields must be provided in an
array of strings.

The following prefixes may be applied to the field name:

`-` reverse sort direction.

`nulls_first:` place any NULL values at head of results list.

`nulls_last:` place any NULL values at tail of results list.

Javascript:
    :::javascript
    {
      "order_by": ["size", "-devname", "nulls_first:-expiretime"]
    }



    




