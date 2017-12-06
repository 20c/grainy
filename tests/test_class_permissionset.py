from grainy import core, const
import pytest
import sys
import unittest
import json

performance_test = pytest.mark.skipif(
    not pytest.config.getoption("--performance"),
    reason="need --performance option to run"
)

p1 = core.Permission("a", const.PERM_READ)
p2 = core.Permission("a.b.c", const.PERM_RW)

pdict = {
    "a" : const.PERM_READ,
    "a.b.c" : const.PERM_RW,
    "a.b.*.d" : const.PERM_DENY,
    "a.c" : const.PERM_WRITE,
    "b.c" : const.PERM_READ,
    "k" : const.PERM_READ,
    "k.x.y" : const.PERM_DENY,
    "l" : const.PERM_READ,
    "l.*.y" : const.PERM_DENY
}


pdict2 = {
    "a" : const.PERM_READ,
    "a.b.c" : const.PERM_RW,
    "a.b.e" : const.PERM_DENY,
    "a.b.*.d" : const.PERM_DENY,
    "e.f" : const.PERM_READ,
    "e.*.g" : const.PERM_WRITE,
    "e.*.g.a" : const.PERM_READ,
    "e.*.g.b" : const.PERM_RW,
    "e.h.g" : const.PERM_DENY,
    "f.g" : const.PERM_READ
}

pdict3 = {
    "a.100" : const.PERM_READ,
    "a.b.c" : const.PERM_RW,
    "a.b.e" : const.PERM_DENY,
    "a.b.*.d" : const.PERM_DENY,
    "e.f" : const.PERM_READ,
    "e.*.g" : const.PERM_WRITE,
    "e.*.g.a" : const.PERM_READ,
    "e.*.g.b" : const.PERM_RW,
    "e.h.g" : const.PERM_DENY
}

pdict4 = {
    "a.b" : const.PERM_READ,
    "x" : const.PERM_READ,
    "x.z" : const.PERM_DENY,
    "nested.*.data.public" : const.PERM_READ
}


class TestPermissionSet(unittest.TestCase):

    def test_init(self):
        pset = core.PermissionSet([p1,p2])
        self.assertEqual(pset.permissions["a"], p1)
        self.assertEqual(pset.permissions["a.b.c"], p2)

        pset = core.PermissionSet(pdict)
        self.assertEqual(pset.permissions["a"], p1)
        self.assertEqual(pset.permissions["a.b.c"], p2)

    def test_update_index(self):
        pset = core.PermissionSet(pdict)
        expected = {
            'a': {
                '__': 1,
                '__implicit' : False,
                'c': {
                    '__implicit' : False,
                    '__': 14
                },
                'b': {
                    '__': 1,
                    '__implicit' : True,
                    'c': {
                        '__': 15,
                        '__implicit' : False
                    },
                    '*': {
                        '__implicit' : True,
                        '__': 1,
                        'd': {
                            '__implicit' : False,
                            '__': 0
                        }
                    }
                }
            },
            'b': {
                '__implicit' : True,
                '__': 0,
                'c': {
                    '__implicit' : False,
                    '__': 1
                }
            },
            'k' :{
                "__" : 1,
                "__implicit" : False,
                'x' : {
                    "__": 1,
                    "__implicit" : True,
                    "y" : {
                        "__": 0,
                        "__implicit": False
                    }
                }
            },
            'l' :{
                "__" : 1,
                "__implicit" : False,
                '*' : {
                    "__": 1,
                    "__implicit" : True,
                    "y" : {
                        "__": 0,
                        "__implicit": False
                    }
                }
            }
        }

        self.maxDiff = None

        self.assertEqual(pset.index, expected)

    def test_contains(self):
        pset = core.PermissionSet(pdict)
        self.assertIn("a", pset)
        self.assertIn("a.b.c", pset)
        self.assertNotIn("x", pset)

    def test_update(self):

        pset = core.PermissionSet(pdict)

        pset.update({"x":const.PERM_READ, "z":core.Permission("z", const.PERM_READ)})
        self.assertIn("a", pset)
        self.assertIn("a.b.c", pset)
        self.assertIn("x", pset)
        self.assertIn("z", pset)

        self.assertEqual(pset.check("x", const.PERM_READ), True)
        self.assertEqual(pset.check("z", const.PERM_READ), True)


    def test_setitem_delitem(self):
        pset = core.PermissionSet()
        pset["a"] = const.PERM_READ
        pset["a.b"] = const.PERM_RW
        pset["b"] = const.PERM_READ

        self.assertEqual(pset.permissions["a"].check(const.PERM_READ), True)
        self.assertEqual(pset.permissions["a.b"].check(const.PERM_WRITE), True)
        self.assertEqual(pset.permissions["b"].check(const.PERM_READ), True)

        pset["a.b"] = const.PERM_READ

        self.assertEqual(pset.permissions["a.b"].check(const.PERM_WRITE), False)

        del pset["b"]

        self.assertNotIn("b", pset)


    def test_check(self):
        pset = core.PermissionSet(pdict2)

        self.assertEqual(pset.check("a.b", const.PERM_READ), True)
        self.assertEqual(pset.check("a.b.c", const.PERM_WRITE), True)
        self.assertEqual(pset.check("a.b.d", const.PERM_READ), True)
        self.assertEqual(pset.check("a.b.c.d", const.PERM_READ), False)
        self.assertEqual(pset.check("e.f", const.PERM_READ), True)
        self.assertEqual(pset.check("e", const.PERM_READ), False )
        self.assertEqual(pset.check("e.j.g", const.PERM_WRITE), True)
        self.assertEqual(pset.check("e.k.g.a", const.PERM_WRITE), False)
        self.assertEqual(pset.check("e.h.g", const.PERM_READ), False)
        self.assertEqual(pset.check("e.h.g.a", const.PERM_WRITE), False)
        self.assertEqual(pset.check("e.m.g.a", const.PERM_WRITE), False)
        self.assertEqual(pset.check("e.m.g.b", const.PERM_RW), True)
        self.assertEqual(pset.check("f", const.PERM_WRITE), False)
        self.assertEqual(pset.check("f.g", const.PERM_READ), True)

    def test_check_explicit(self):
        pset = core.PermissionSet(pdict)
        self.assertEqual(pset.check("a.b", const.PERM_READ, explicit=True), False)
        self.assertEqual(pset.check("a", const.PERM_READ, explicit=True), True )
        self.assertEqual(pset.check("a", const.PERM_WRITE, explicit=True), False)
        self.assertEqual(pset.check("a.b.c", const.PERM_WRITE, explicit=True), True)
        self.assertEqual(pset.check("a.b.c", const.PERM_READ, explicit=True), True)

    def test_apply(self):
        pset = core.PermissionSet(pdict2)
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
                "g" : True
            }
        }

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
        self.assertEqual(rv, expected)

    def test_apply_explicit(self):
        pset = core.PermissionSet(pdict)

        data = {
            "a" : {
                "b": {
                    "c": True,
                    "d": False,
                    "e": True,
                    "f" : { "something" : "else"},
                    "g" : {
                        "nested" : {
                            "something" : "else"
                        },
                        "test" : True
                    }
                }
            },
            "k" : {
                "a" : {
                    "nested" : {
                        "something" : "else"
                    },
                    "test": True
                }
            }
        }

        expected = {
            "a" : {
                "b" : {
                    "c": True,
                    "e": True,
                    "g": {
                        "test" : True
                    }
                }
            },
            "k" : {
                "a" : {
                    "test": True
                }
            }
        }

        applicator = core.Applicator(pset)
        applicator.handler("a.b.d", explicit=True)
        applicator.handler("a.b.f", explicit=True)
        applicator.handler("k.a.nested", explicit=True)
        applicator.handler("a.b.*.nested", explicit=True)
        rv = pset.apply(data, applicator=applicator)
        self.assertEqual(rv, expected)

        expected = {
            "a" : {
                "b" : {
                    "c": True,
                    "d": False,
                    "e": True,
                    "f" : { "something" : "else" },
                    "g" : {
                        "nested" : {
                            "something" : "else"
                        },
                        "test" : True
                    }
                }
            },
            "k" : {
                "a" : {
                    "nested" : {
                        "something" : "else"
                    },
                    "test" : True
                }
            }
        }

        pset["a.b.d"] = const.PERM_READ
        pset["a.b.f"] = const.PERM_READ
        pset["k.a.nested"] = const.PERM_READ
        pset["a.b.g.nested"] = const.PERM_READ
        rv = pset.apply(data, applicator=applicator)
        self.assertEqual(rv, expected)



    def test_apply_nested_lists(self):
        pset = core.PermissionSet(pdict4)
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
                            "some" : "data",
                            "explicit" : {
                                "sekret" : "data"
                            }
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

        applicator = core.Applicator(pset)
        applicator.handler("x", key=lambda row,idx: row["custom"])
        applicator.handler("nested.*.data", key=lambda row,idx: row["level"])
        applicator.handler("nested.*.data.public.explicit", explicit=True)
        rv = pset.apply(data, applicator=applicator)
        self.assertEqual(rv, expected)



    @performance_test
    def test_performance(self):

        def mkdataset(depth=3):
            depth = depth - 1
            if depth <= 0:
                return
            return dict([(str(k),mkdataset(depth=depth)) for k in range(1,1000)])
        data = {
            "a" : mkdataset(3),
            "b" : mkdataset(3)
        }

        pset = core.PermissionSet(pdict3)

        import time

        t= time.time()
        cleaned = pset.apply(data)
        diff = time.time() - t

        self.assertLess(diff, 0.002)

