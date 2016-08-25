from grainy import core, const

class TestNamespace(object):
  
  def test_init(self):
    ns = core.Namespace("a.b.c")
    assert ns.value == "a.b.c"

    ns = core.Namespace("a.b.*")
    assert ns.value == "a.b"

  def test_str_unicode(self):
    ns = core.Namespace("a.b.c")
    assert str(ns) == "a.b.c"
    assert unicode(ns) == u"a.b.c"

  def test_iter(self):
    ns = core.Namespace("a.b.c")
    assert [k for k in ns] == ["a","b","c"]

  def test_container(self):
    ns = core.Namespace("a.b.c")
    container, tail = ns.container()
    assert container == {"a":{"b":{"c":{}}}}
    assert tail == {}
  
    container, tail = ns.container({"d":123})
    assert container == {"a":{"b":{"c":{"d":123}}}}
    assert tail == {"d":123}

  def test_match(self):
    ns = core.Namespace("a.b.c")
    assert ns.match(["a","b"]) == True
    assert ns.match(["a"]) == True
    assert ns.match(["a","*"]) == True
    assert ns.match(["a","*","c"]) == True 
    assert ns.match(["a","b","c"]) == True
    assert ns.match(["a","*","c","d"]) == False
    assert ns.match(["a","b","c","d"]) == False
    assert ns.match(["b"]) == False
    assert ns.match(["a","c"]) == False
