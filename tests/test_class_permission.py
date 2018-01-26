from grainy import core, const
import unittest

test_ns = core.Namespace("a.b.c")

class TestPermission(unittest.TestCase):

    def test_init(self):
        perm = core.Permission(test_ns, const.PERM_RW)
        self.assertEqual(perm.value, const.PERM_RW)
        self.assertEqual(perm.namespace, test_ns)

        perm = core.Permission("a.b.c", const.PERM_RW)
        self.assertEqual(isinstance(perm.namespace, core.Namespace), True)

    def test_has_value(self):
        perm = core.Permission(test_ns, const.PERM_RW)
        self.assertEqual(perm.has_value(), True)

        perm = core.Permission(test_ns, const.PERM_DENY)
        self.assertEqual(perm.has_value(), True)

        perm = core.Permission(test_ns, None)
        self.assertEqual(perm.has_value(), False)

    def test_check(self):
        perm = core.Permission(test_ns, const.PERM_RW)
        self.assertEqual(perm.check(const.PERM_READ), True)
        self.assertEqual(perm.check(const.PERM_WRITE), True)

        perm = core.Permission(test_ns, const.PERM_READ)
        self.assertEqual(perm.check(const.PERM_READ), True)
        self.assertEqual(perm.check(const.PERM_WRITE), False)

        perm = core.Permission(test_ns, const.PERM_DENY)
        self.assertEqual(perm.check(const.PERM_READ), False)
        self.assertEqual(perm.check(const.PERM_WRITE), False)
