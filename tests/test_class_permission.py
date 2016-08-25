from grainy import core, const

test_ns = core.Namespace("a.b.c")

class TestPermission(object):
  
  def test_init(self):
    perm = core.Permission(test_ns, const.PERM_RW)
    assert perm.value == const.PERM_RW
    assert perm.namespace == test_ns

    perm = core.Permission("a.b.c", const.PERM_RW)
    assert isinstance(perm.namespace, core.Namespace)

  def test_has_value(self):
    perm = core.Permission(test_ns, const.PERM_RW)
    assert perm.has_value() == True

    perm = core.Permission(test_ns, const.PERM_DENY)
    assert perm.has_value() == True

    perm = core.Permission(test_ns, None)
    assert perm.has_value() == False

  def test_check(self):
    perm = core.Permission(test_ns, const.PERM_RW)
    assert perm.check(const.PERM_READ) == True
    assert perm.check(const.PERM_WRITE) == True

    perm = core.Permission(test_ns, const.PERM_READ)
    assert perm.check(const.PERM_READ) == True
    assert perm.check(const.PERM_WRITE) == False

    perm = core.Permission(test_ns, const.PERM_DENY)
    assert perm.check(const.PERM_READ) == False
    assert perm.check(const.PERM_WRITE) == False
