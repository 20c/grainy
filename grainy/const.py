"""
grainy constants

## Permission Flags

### Main

- `PERM_READ`: read permissions (0x01)
- `PERM_UPDATE`: update permissions (0x02)
- `PERM_CREATE`: create permissions (0x04)
- `PERM_DELETE`: delete permissions (0x08)

### Special

- `PERM_DENY`: deny all access (0x00)

### Combined

- `PERM_WRITE`: write permissions (`PERM_UPDATE|PERM_CREATE|PERM_DELETE`)
- `PERM_RW`: read and write permissions (`PERM_WRITE|PERM_READ`)

## Maps

- `PERM_STRING_MAP`: mapping of int flag to str flag

```py
dict(PERM_STRING_MAP).get(PERM_CREATE) #c
dict(PERM_STRING_MAP).get(PERM_READ) #r
dict(PERM_STRING_MAP).get(PERM_UPDATE) #u
dict(PERM_STRING_MAP).get(PERM_DELETE) #d
```
"""

PERM_READ = 0x01
PERM_UPDATE = 0x02
PERM_CREATE = 0x04
PERM_DELETE = 0x08
PERM_WRITE = PERM_UPDATE | PERM_CREATE | PERM_DELETE
PERM_DENY = 0
PERM_RW = PERM_READ | PERM_WRITE

PERM_STRING_MAP = [
    (PERM_CREATE, "c"),
    (PERM_READ, "r"),
    (PERM_UPDATE, "u"),
    (PERM_DELETE, "d"),
]

MATCH_NO = 0
MATCH_YES = 1
MATCH_PARTIAL = 2
