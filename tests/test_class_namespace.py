from grainy import core, const
import unittest

class TestNamespace(unittest.TestCase):

    def test_init(self):
        ns = core.Namespace("a.b.c")
        self.assertEqual(ns.value, "a.b.c")

        ns = core.Namespace("a.b.*")
        self.assertEqual(ns.value, "a.b")

        ns = core.Namespace(["a","b","c"])
        self.assertEqual(ns.value, "a.b.c")

        ns = core.Namespace(["a","b",1])
        self.assertEqual(ns.value, "a.b.1")

    def test_append(self):
        a = core.Namespace("a.b")
        b = core.Namespace("c.d")
        c = core.Namespace("x.y")

        self.assertEqual( (a+b).keys, ["a","b","c","d"])

        c += b

        self.assertEqual( c.keys, ["x","y","c","d"])


    def test_iter(self):
        ns = core.Namespace("a.b.c")
        self.assertEqual([k for k in ns], ["a","b","c"])

    def test_container(self):
        ns = core.Namespace("a.b.c")
        container, tail = ns.container()
        self.assertEqual(container, {"a":{"b":{"c":{}}}})
        self.assertEqual(tail, {})

        container, tail = ns.container({"d":123})
        self.assertEqual(container, {"a":{"b":{"c":{"d":123}}}})
        self.assertEqual(tail, {"d":123})

    def test_match(self):
        ns = core.Namespace("a.b.c")
        self.assertEqual(ns.match(["a","b"]), True)
        self.assertEqual(ns.match(["a"]), True)
        self.assertEqual(ns.match(["a","*"]), True)
        self.assertEqual(ns.match(["a","*","c"]), True)
        self.assertEqual(ns.match(["a","b","c"]), True)
        self.assertEqual(ns.match(["a","*","c","d"]), False)
        self.assertEqual(ns.match(["a","b","c","d"]), False)
        self.assertEqual(ns.match(["b"]), False)
        self.assertEqual(ns.match(["a","c"]), False)
