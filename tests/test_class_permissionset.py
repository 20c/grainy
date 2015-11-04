from twentyc.perms import core, const

p1 = core.Permission("a", const.PERM_READ)
p2 = core.Permission("a.b.c", const.PERM_RW)

pdict = {
  "a" : const.PERM_READ,
  "a.b.c" : const.PERM_RW,
  "a.b.*.d" : const.PERM_DENY,
  "a.c" : const.PERM_WRITE
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
  "e.h.g" : const.PERM_DENY
}


class TestPermissionSet(object):

  def test_init(self):
    pset = core.PermissionSet([p1,p2])
    assert pset.permissions["a"] == p1
    assert pset.permissions["a.b.c"] == p2

    pset = core.PermissionSet(pdict)
    assert pset.permissions["a"] == p1
    assert pset.permissions["a.b.c"] == p2

  def test_update_index(self):
    pset = core.PermissionSet(pdict)
    expected = {'a': {'__': 1, 'c': {'__': 14}, 'b': {'__': 1, 'c': {'__': 15}, '*': {'__': None, 'd': {'__': 0}}}}}
    assert pset.index == expected

  def test_check(self):
    pset = core.PermissionSet(pdict2)

    assert pset.check("a.b", const.PERM_READ) == True
    assert pset.check("a.b.c", const.PERM_WRITE) == True
    assert pset.check("a.b.d", const.PERM_READ) == True
    assert pset.check("a.b.c.d", const.PERM_READ) == False
    assert pset.check("e.f", const.PERM_READ) == True
    assert pset.check("e", const.PERM_READ) == False 
    assert pset.check("e.j.g", const.PERM_WRITE) == True
    assert pset.check("e.k.g.a", const.PERM_WRITE) == False
    assert pset.check("e.h.g", const.PERM_READ) == False
    assert pset.check("e.h.g.a", const.PERM_WRITE) == False
    assert pset.check("e.m.g.a", const.PERM_WRITE) == False
    assert pset.check("e.m.g.b", const.PERM_RW) == True
    assert pset.check("f", const.PERM_WRITE) == False

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
      }
    }

    rv = pset.apply(data)
    assert rv == expected




