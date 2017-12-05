# grainy

[![PyPI](https://img.shields.io/pypi/v/grainy.svg?maxAge=60)](https://pypi.python.org/pypi/grainy)
[![Travis CI](https://img.shields.io/travis/20c/grainy.svg?maxAge=60)](https://travis-ci.org/20c/grainy)
[![Code Health](https://landscape.io/github/20c/grainy/master/landscape.svg?style=flat)](https://landscape.io/github/20c/grainy/master)
[![Codecov](https://img.shields.io/codecov/c/github/20c/grainy/master.svg?maxAge=60)](https://codecov.io/github/20c/grainy)
[![Requires.io](https://img.shields.io/requires/github/20c/grainy.svg?maxAge=60)](https://requires.io/github/20c/grainy/requirements)

granular permissions utility

# Quickstart

    from grainy.core import PermissionSet
    from grainy.const import *

    pset = PermissionSet(
      {
        "a" : PERM_READ,
        "a.b" : PERM_RW,
        "a.b.c" : PERM_DENY,
        "b" : PERM_READ,
        "b.*.a" : PERM_RW
      }
    )

    pset.check("a", PERM_READ) # True
    pset.check("a.b", PERM_READ) # True
    pset.check("a.b", PERM_WRITE) # True
    pset.check("a.b.c", PERM_READ) # False
    pset.check("a.b.c", PERM_WRITE) # False
    pset.check("a.x", PERM_READ) # True
    pset.check("b.a.a", PERM_RW) # True
    pset.check("b.b.a", PERM_RW) # True
    pset.check("b.b.b", PERM_RW) # False

    pset.check("a", PERM_READ, explicit=True) # True
    pset.check("a.b", PERM_READ, explicit=True) # True
    pset.check("a.c", PERM_READ, explicit=True) # False

# Setting and Deleting

    pset["a.b"] = const.PERM_READ

    del pset["a.b"]

    pset.update(
      {
        "a.b" : const.PERM_READ
      }
    )

    assert "a.b" in pset

# Applying to data

You can apply the permissions stored in the permission set to any data dict and data that the permission set does not have READ access to will be removed.

grainy was created out of a need to apply granular permissions on potentially large dict objects and perform well.

    # init
    pset = core.PermissionSet(
      {
        "a" : const.PERM_READ,
        "a.b.c" : const.PERM_RW,
        "a.b.e" : const.PERM_DENY,
        "a.b.*.d" : const.PERM_DENY,
        "f.g" : const.PERM_READ
      }
    )

    # original data
    data = {
      "a" : {
        "b" : {
          "c" : {
            "A" : True
          },
          "d" : {
            "A" : True
          },
          "e" : {
            "A" : False
          }
        }
      },
      "f": {
        "a" : False,
        "g" : True
      }
    }

    # expected data after permissions are appied
    expected = {
      "a" : {
        "b" : {
          "c" : {
            "A" : True
          },
          "d" : {
            "A" : True
          }
        }
      },
      "f": {
        "g" : True
      }
    }

    rv = pset.apply(data)
    assert rv == expected

As of version 1.2 it is also possible to apply permissions to lists using namespace handlers

    pset = core.PermissionSet({
        "a.b" : const.PERM_READ,
        "x" : const.PERM_READ,
        "x.z" : const.PERM_DENY,
        "nested.*.data.public" : const.PERM_READ
    })

    data= {
        "a" : [
            { "id" : "b" },
            { "id" : "c" }
        ],
        "x" : [
            { "custom" : "y" },
            { "custom" : "z" }
        ],
        "nested" : [
            {
                "data" : [
                    {
                        "level" : "public",
                        "some" : "data"
                    },
                    {
                        "level" : "private",
                        "sekret" : "data"
                    }
                ]
            }
        ]
    }

    expected = {
        "a" : [
            { "id" : "b" }
        ],
        "nested" : [
            {
                "data" : [
                    { "level" : "public", "some" : "data" }
                ]
            }
        ],
        "x" : [
            { "custom" : "y" }
        ]
    }

    applicator = core.Applicator()
    applicator.handle("x", key=lambda row,idx: row["custom"])
    applicator.handle("nested.*.data", key=lambda row,idx: row["level"])

    rv = pset.apply(data, applicator=applicator)
    self.assertEqual(rv, expected)


