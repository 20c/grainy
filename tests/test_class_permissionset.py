from twentyc.perms import core, const
import pytest
import sys

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
  "b.c" : const.PERM_READ
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
            '__': None, 
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
      }
    }

    print pset.index
    assert pset.index == expected

  def test_contains(self):
    pset = core.PermissionSet(pdict)
    assert "a" in pset
    assert "a.b.c" in pset
    assert "x" not in pset

  def test_update(self):

    pset = core.PermissionSet(pdict)

    pset.update({"x":const.PERM_READ, "z":core.Permission("z", const.PERM_READ)})
    assert "a" in pset
    assert "a.b.c" in pset
    assert "x" in pset
    assert "z" in pset
    
    assert pset.check("x", const.PERM_READ) == True
    assert pset.check("z", const.PERM_READ) == True
    

  def test_setitem_delitem(self):
    pset = core.PermissionSet()
    pset["a"] = const.PERM_READ
    pset["a.b"] = const.PERM_RW
    pset["b"] = const.PERM_READ

    assert pset.permissions["a"].check(const.PERM_READ) == True
    assert pset.permissions["a.b"].check(const.PERM_WRITE) == True
    assert pset.permissions["b"].check(const.PERM_READ) == True

    pset["a.b"] = const.PERM_READ

    assert pset.permissions["a.b"].check(const.PERM_WRITE) == False 

    del pset["b"]

    assert "b" not in pset
    

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
    assert pset.check("f.g", const.PERM_READ) == True

  def test_check_explicit(self):
    pset = core.PermissionSet(pdict)

    assert pset.check("a.b", const.PERM_READ, explicit=True) == False
    assert pset.check("a", const.PERM_READ, explicit=True) == True 
    assert pset.check("a", const.PERM_WRITE, explicit=True) == False
    assert pset.check("a.b.c", const.PERM_WRITE, explicit=True) == True
    assert pset.check("a.b.c", const.PERM_READ, explicit=True) == True
    

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
    print pset.read_access_map
    assert rv == expected

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

    print "test_performance took %.5f seconds" % diff

    assert diff < 0.002

