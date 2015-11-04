# twentyc.perms
granular permissions utility framework

# Purpose
Utility functions to permission out namespaces at various access levels. 

# Quickstart

    from twentyc.perms.core import PermissionSet
    from twentyc.perms.const import *

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
