import unittest
from grainy import core, const


class TestUtils(unittest.TestCase):

    def test_int_flags(self):
        self.assertEqual(core.int_flags("c"), const.PERM_CREATE)
        self.assertEqual(core.int_flags("cr"), const.PERM_CREATE | const.PERM_READ)
        self.assertEqual(core.int_flags("cru"), const.PERM_CREATE | const.PERM_READ | const.PERM_UPDATE)
        self.assertEqual(core.int_flags("crud"), const.PERM_CREATE | const.PERM_READ | const.PERM_UPDATE | const.PERM_DELETE)

