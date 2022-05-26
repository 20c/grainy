pdict2 = {
    "a": GRAINY_CONST.PERM_READ,
    "a.b.c": GRAINY_CONST.PERM_RW,
    "a.b.e": GRAINY_CONST.PERM_DENY,
    "a.b.*.d": GRAINY_CONST.PERM_DENY,
    "e.f": GRAINY_CONST.PERM_READ,
    "e.*.g": GRAINY_CONST.PERM_WRITE,
    "e.*.g.a": GRAINY_CONST.PERM_READ,
    "e.*.g.b": GRAINY_CONST.PERM_RW,
    "e.h.g": GRAINY_CONST.PERM_DENY,
    "f.g": GRAINY_CONST.PERM_READ,
}

pdict3 = {
    "a.100": GRAINY_CONST.PERM_READ,
    "a.b.c": GRAINY_CONST.PERM_RW,
    "a.b.e": GRAINY_CONST.PERM_DENY,
    "a.b.*.d": GRAINY_CONST.PERM_DENY,
    "e.f": GRAINY_CONST.PERM_READ,
    "e.*.g": GRAINY_CONST.PERM_WRITE,
    "e.*.g.a": GRAINY_CONST.PERM_READ,
    "e.*.g.b": GRAINY_CONST.PERM_RW,
    "e.h.g": GRAINY_CONST.PERM_DENY,
}

pdict4 = {
    "a.b": GRAINY_CONST.PERM_READ,
    "x": GRAINY_CONST.PERM_READ,
    "x.z": GRAINY_CONST.PERM_DENY,
    "nested.*.data.public": GRAINY_CONST.PERM_READ,
}

pdict5 = {
    "a.b.c": GRAINY_CONST.PERM_READ,
    "a.b.d": GRAINY_CONST.PERM_READ | GRAINY_CONST.PERM_WRITE,
    "a.b.e": GRAINY_CONST.PERM_READ,
    "r.s": GRAINY_CONST.PERM_READ,
    "x.*.z": GRAINY_CONST.PERM_READ,
    "x.*.x": GRAINY_CONST.PERM_READ | GRAINY_CONST.PERM_WRITE,
}

pdict6 = {
    "a.b.c": GRAINY_CONST.PERM_WRITE,
    "a.b.c.d.e": GRAINY_CONST.PERM_READ,
}

pdict7 = {
    "a.b.c": GRAINY_CONST.PERM_WRITE,
    "a.b.c.d": GRAINY_CONST.PERM_WRITE,
    "a.b.*.d.e": GRAINY_CONST.PERM_READ,
}

pdict8 = {
    "a.b": GRAINY_CONST.PERM_READ,
    "a.b.*.d.*.f.g": GRAINY_CONST.PERM_READ,
    "a.b.20525": GRAINY_CONST.PERM_READ | GRAINY_CONST.PERM_CREATE,
}

pdict9 = {
    "a.b": GRAINY_CONST.PERM_READ,
    "a.b.*.d.*.e.public": GRAINY_CONST.PERM_READ,
    "a.b.*.x.*.f.public": GRAINY_CONST.PERM_READ,
}

pdict10 = {
    "a.b": GRAINY_CONST.PERM_READ,
    "a.b.*.x.*.f.public": GRAINY_CONST.PERM_READ,
}

pdict11 = {
    "a.b.10356.x": 15,
    "a.b": 1,
    "a.b.*.y.*.h.users": 1,
    "a.b.20525": 5,
    "a.b.*.x.*.i.public": 1,
    "a.b.*.x.*.i.users": 1,
    "a.b.10356": 1,
    "a.b.10356.y.*.h.private": 1,
    "a.b.10356.x.*.i.private": 1,
}

pdict12 = {"*.5": 15, "a.6": 1, "b.6": 1}

pdict13 = {"*": 15}


QUnit.test('Test permision set check', function(assert) {

    grainy.setup(pdict2)

    assert.true(grainy.check("a.b", GRAINY_CONST.PERM_READ))
    assert.true(grainy.check("a.b.c", GRAINY_CONST.PERM_WRITE))
    assert.true(grainy.check("a.b.d", GRAINY_CONST.PERM_READ))
    assert.false(grainy.check("a.b.c.d", GRAINY_CONST.PERM_READ))
    assert.true(grainy.check("e.f", GRAINY_CONST.PERM_READ))
    assert.false(grainy.check("e", GRAINY_CONST.PERM_READ))
    assert.true(grainy.check("e.j.g", GRAINY_CONST.PERM_WRITE))
    assert.false(grainy.check("e.k.g.a", GRAINY_CONST.PERM_WRITE))
    assert.false(grainy.check("e.h.g", GRAINY_CONST.PERM_READ))
    assert.false(grainy.check("e.h.g.a", GRAINY_CONST.PERM_WRITE))
    assert.false(grainy.check("e.m.g.a", GRAINY_CONST.PERM_WRITE))
    assert.true(grainy.check("e.m.g.b", GRAINY_CONST.PERM_RW))
    assert.false(grainy.check("f", GRAINY_CONST.PERM_WRITE))
    assert.true(grainy.check("f.g", GRAINY_CONST.PERM_READ))

    grainy.setup(pdict6)
    assert.true(grainy.check("a.b.c", GRAINY_CONST.PERM_WRITE))
    assert.true(grainy.check("a.b.c.d", GRAINY_CONST.PERM_WRITE))

    grainy.setup(pdict7)
    assert.true(grainy.check("a.b.c", GRAINY_CONST.PERM_WRITE))
    //assert.true(grainy.check("a.b.c.d", GRAINY_CONST.PERM_WRITE)) // TODO: fix failing

    grainy.setup(pdict8)
    //assert.true(grainy.check("a.b.20525.d", GRAINY_CONST.PERM_CREATE)) // TODO: fix failing
    //assert.true(grainy.check("a.b.20525.d.*", GRAINY_CONST.PERM_CREATE)) // TODO: fix failing
    assert.true(grainy.check("a.b.20525.d.1234.f.g", GRAINY_CONST.PERM_READ))

    grainy.setup(pdict9)
    //assert.false(grainy.check("a.b.10356.d.20.e.private", GRAINY_CONST.PERM_READ, explicit=true)) // TODO: fix failing

    grainy.setup(pdict10)
    //assert.false(grainy.check("a.b.10356.d.20.e.private", GRAINY_CONST.PERM_READ, explicit=true)) // TODO: fix failing

    grainy.setup(pdict11)
    assert.true(grainy.check("a.b.10356.x.2966", GRAINY_CONST.PERM_CREATE))
    assert.true(grainy.check("a.b.10356.x.2966.i.private", GRAINY_CONST.PERM_READ, explicit=true))

    grainy.setup(pdict12)
    assert.true(grainy.check("a.5", GRAINY_CONST.PERM_CREATE))

    grainy.setup(pdict13)
    grainy.debug = true
    assert.true(grainy.check("a.5", GRAINY_CONST.PERM_CREATE))
});