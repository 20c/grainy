"""
core functionality
"""

import grainy.const as const


def list_key_handler(row, idx):
    if isinstance(row, dict):
        return row.get("id", row.get("name", f"{idx}"))
    return idx


def int_flags(flags, mapper=const.PERM_STRING_MAP):
    """
    Converts string permission flags into integer permission flags as
    specified in const.PERM_STRING_MAP

    **Arguments**

    - flags (`str`): one or more flags
      For example: "crud" or "ru" or "r"
    - mapper (`list=const.PERM_STRING_MAP`): a list containing tuples mapping
      int permission flag to string permission flag. If not specified will
      default to const.PERM_STRING_MAP.

    **Returns**

    `int`
    """

    r = 0
    if not flags:
        return r

    if isinstance(flags, int):
        return flags

    if not isinstance(flags, str):
        raise TypeError("`flags` needs to be a string or integer type")

    for f in flags:
        for f_i, f_s in mapper:
            if f_s == f:
                r = r | f_i
    return r


class Namespace:
    """
    Object representing a permissioning namespace

    # Instanced Attributes

    - length (`int`): namespace key length, number of keys in the namespace
    - value (`str`): namespace
    - keys (`list<str>`): namespace keys
    """

    def __init__(self, value, strip=True):
        """
        **Arguments**

        - value (`list<str>`|`str`): can either be a list containing
        namespace keys or a str with keys delimited by the `.` character
        """
        self.set(value, strip=strip)

    def __unicode__(self):
        return self.value

    def __str__(self):
        return self.value

    def __hash__(self):
        return self.value.__hash__()

    def __iter__(self):
        yield from self.value.split(".")


    def __setitem__(self, index, value):
        self.keys[index] = value
        self.set(".".join(self.keys), strip=self.strip)

    def __getitem__(self, index):
        return self.keys[index]

    def __eq__(self, other):
        return str(self) == str(other)

    def __add__(self, other):
        if not isinstance(other, Namespace):
            raise NotImplemented()

        return Namespace(self.keys + other.keys)

    def __iadd__(self, other):
        return self.__add__(other)

    def set(self, value, strip=True):
        """
        Set the namespace value

        This is called *automatically* during __init__

        **Arguments**

        - value (`list<str>`|`str`): can either be a list containing
        namespace keys or a str with keys delimited by the `.` character
        """

        if isinstance(value, list):
            value = ".".join([str(v) for v in value])
        if strip:
            value = value.rstrip(".*")
        self.value = value
        self.keys = [k for k in self]
        self.length = len(self.keys)

    def match(self, keys, partial=True):
        """
        Check if the value of this namespace is matched by
        keys

        !!! note "Wildcards"
            You can use the `*` character as a wildcard match for
            keys

        ??? note "Examples"
            ```py
            ns = Namespace("a.b.c")
            ns.match(["a"]) #True
            ns.match(["a","b"]) #True
            ns.match(["a","b","c"]) #True
            ns.match(["a","*","c"]) #True
            ns.match(["b","b","c"]) #False
            ```

        **Arguments**

        - keys (`list`): list of keys

        **Keyword Arguments**

        - partial (`bool=True`): allow partial matching


        **Returns**

        `bool`: `True` if matched, `False` if not

        """
        if not partial and len(keys) != self.length:
            return False
        c = 0
        for k in keys:
            if c >= self.length:
                return False
            a = self.keys[c]
            if a != "*" and k != "*" and k != a:
                return False
            c += 1

        return True

    def container(self, data=None):
        """
        Creates a dict built from the keys of this namespace

        ??? note "Example"

            ```py
            self.value = "a.b.c"

            container, tail = self.container()
            #{"a":{"b":{"c":{}}}, {}

            container, tail = self.container({"d":123})
            #{"a":{"b":{"c":{"d":123}}}, {"d":123}
            ```

        **Keyword Arguments**

        - data (`dict`): use this as root dict

        **Returns**

        `tuple(<dict>,<dict>)`: a tuple containing the root of the
        generated `dict` as the first element and the tail of the
        generated `dict` as the second element

        """

        if data is None:
            data = {}

        root = p = d = {}
        j = 0
        k = None
        for k in self:
            d[k] = {}
            p = d
            d = d[k]
        if k is not None:
            p[k] = data
        return (root, p[k])


class Permission:
    """
    Permission object defined by a namespace and a permission bitmask

    # Instanced Attributes

    - namespace (`Namespace`)
    - value (`int`): permission mask
    """

    def __init__(self, namespace, value):
        """
        **Arguments**

        - namespace (`str`|`Namespace`)
        - value (`int`): permission mask
        """
        if isinstance(namespace, str):
            namespace = Namespace(namespace)

        self.namespace = namespace
        self.value = value

    def __eq__(self, other):
        r = other.namespace == self.namespace and other.value == self.value
        return r

    def has_value(self):
        """
        Check that value has been set

        **Returns**

        `bool`: `True` if value has been set, `False` if not
        """
        return self.value is not None

    def check(self, level):
        """
        Check if permission mask contains the specified
        permission level

        **Arguments**

        - level (`int`): permission flag

        **Returns**

        `bool`: `True` if flag is contained in mask, `False` if not
        """
        if not self.has_value():
            return False
        return (self.value & level) != 0


class PermissionSet:
    """
    Holds a set of Namespaces and permissions to run permission checks
    on

    Can also be applied to a data dict to remove keys that are not
    accessible according the permissions in the set

    # Instanced Attributes

    - permissions (`dict`): permissions in this set
    - index (`dict`): permission index
    - read_access_map (`dict`)
    """

    def __init__(self, rules=None):
        """
        **Keyword Arguments**

        - rules (`list<Permission>`|`dict<str,int>`): list of `Permission` objects
        or `dict` of `namspace(str)`:`permission(int)` pairs
        """

        if rules is None:
            rules = []

        self.permissions = {}
        self.index = {}
        self.read_access_map = {}

        if type(rules) == list:
            for permission in rules:
                self.__add__(permission)
        elif type(rules) == dict:
            for ns, p in list(rules.items()):
                self.__add__(Permission(ns, p))

    @property
    def namespaces(self):
        """
        `list` of all namespaces registered in this permission set
        """
        return list(self.permissions.keys())

    def __iter__(self):
        yield from list(self.permissions.values())

    def __contains__(self, item):
        return item in self.permissions

    def __radd__(self, other):
        self.__add__(other)

    def __add__(self, other):
        if isinstance(other, Permission):
            self.permissions[str(other.namespace)] = other
        self.update_index()

    def __setitem__(self, key, other, reindex=True):
        if isinstance(other, Permission):
            self.permissions[key] = other
        elif isinstance(other, int):
            self.permissions[key] = Permission(key, other)
        else:
            raise TypeError(
                "Value needs to be a Permission instance or a permission flag"
            )
        if reindex:
            self.update_index()

    def __delitem__(self, namespace):
        if namespace in self.permissions:
            del self.permissions[namespace]
        else:
            raise KeyError("No permission registered under namespace '%s'" % namespace)
        self.update_index()

    def update(self, permissions, override=True):
        """
        Update the permissionset with a dict of namespace<str>:permission<Permission|int|long>
        pairs

        ??? note "Examples"
            ```py
            pset.update(
              {
                "a" : const.PERM_READ,
                "b" : Permission("b", const.PERM_RW)
              }
            )
            ```

        **Arguments**

        - permissions (`dict`): dict mapping namespaces (`str`) to permission (`Permission` or `int`)
        - override (`bool`=True): if True will override existing namespaces if they exist
        """
        for k, v in list(permissions.items()):
            if not override and k in self.permissions:
                continue
            self.__setitem__(k, v, reindex=False)
        self.update_index()

    def update_index(self):
        """
        Regenerates the permission index for this set

        Called everytime a rule is added / removed / modified in
        the set
        """

        # update index

        idx = {}
        for _, p in sorted(list(self.permissions.items()), key=lambda x: str(x[0])):
            branch = idx
            parent_p = None
            for k in p.namespace.keys:
                if not k in branch:
                    branch[k] = {"__": parent_p}
                    branch[k].update(__implicit=True)

                branch = branch[k]
                parent_p = branch["__"]
            branch["__"] = p.value
            branch["__implicit"] = False

        self.index = idx

        # update read access map

        ramap = {}

        def update_ramap(branch_idx):
            r = {"__": False}
            for k, v in list(branch_idx.items()):
                if k != "__" and k != "__implicit":
                    r[k] = update_ramap(v)

            if (
                branch_idx["__"] is not None
                and (branch_idx["__"] & const.PERM_READ) != 0
            ):
                r["__"] = True
            return r

        for k, v in list(idx.items()):
            ramap[k] = update_ramap(v)

        self.read_access_map = ramap

        return self.index

    def _check(self, keys, branch, flags=None, i=0, explicit=False, l=0):

        implicit = branch.get("__implicit")


        if not l:
            l = len(keys)

        #debug = getattr(self, "debug", False)

        try:
            key = keys[i]
        except IndexError:
            return flags, i, implicit

        key_flag = None
        key_implicit = True
        key_pos = 0
        wc_flag = None
        wc_implicit = True
        wc_pos = 0


        if key in branch:
            if explicit and branch[key].get("__implicit") and i + 1 >= l:
                key_flag, key_pos = None, 0
            else:
                key_flag, key_pos, key_implicit = self._check(
                    keys,
                    branch[key],
                    flags=branch[key].get("__", flags),
                    i=i + 1,
                    explicit=explicit,
                    l=l,
                )
        if "*" in branch:
            if explicit and branch["*"].get("__implicit") and i + 1 >= l:
                wc_flag, wc_pos = None, 0
            else:
                wc_flag, wc_pos, wc_implicit = self._check(
                    keys,
                    branch["*"],
                    flags=branch["*"].get("__", flags),
                    i=i + 1,
                    explicit=explicit,
                    l=l,
                )
        #if debug:
        #    print("")
        #    print("KEYS (inner)", keys[:i], "pos", i, "flags", flags, "length", l, "expl", explicit, "impl", implicit)
        #    print("key", key, "flag", key_flag, "implicit", key_implicit, "pos", key_pos, "wc flag", wc_flag, "wc implicit", wc_implicit, "wc pos",  wc_pos)


        if explicit and key_pos == 0 and wc_pos == 0:
            return None, i, implicit


        if wc_flag is not None and (not explicit or not wc_implicit):
            if key_pos < wc_pos:
                if (not wc_implicit or key_implicit) and (implicit or explicit):
                    return wc_flag, wc_pos, wc_implicit
            if key_flag is None and (implicit or explicit):
                return wc_flag, wc_pos, wc_implicit
        if key_flag is not None and (not explicit or not key_implicit):
            if i < key_pos:
                if not key_implicit or implicit:
                    return key_flag, key_pos, key_implicit
                if flags is None:
                    return key_flag, key_pos, key_implicit

        return flags, i, implicit

    def get_permissions(self, namespace, explicit=False):
        """
        Returns the permissions level for the specified namespace

        **Arguments**

        - namespace (`str`): permissioning namespace

        **Keyword Arguments**

        - explicit (`bool=False`): require explicitly set permissions to the provided namespace

        **Returns**

        `int`: permission mask
        """

        if not isinstance(namespace, Namespace):
            namespace = Namespace(namespace)
        keys = namespace.keys

        p, pos, implicit = self._check(keys, self.index, explicit=explicit)
        if not p or (explicit and implicit) or (explicit and pos != len(keys)):
            p = 0
        return p

    def expandable(self, namespace):
        """
        Returns whether or not the submitted namespace is expandable.

        An expandable namespace is any namespace that contains "?"
        keys.

        **Arguments**

        - namespace (`str`): permissioning namespace

        **Returns**

        - `bool`
        """

        if not isinstance(namespace, Namespace):
            namespace = Namespace(namespace)
        return "?" in namespace.keys

    def expand(self, namespace, explicit=False, index=None, path=None, length=0, exact=False):

        """
        Expands "?" parts of a namespace into a list of namespaces

        **Arguments**

        - namespace (`str`): permissioning namespace

        **Returns**

        - `list`: list of namespaces
        """

        if not isinstance(namespace, Namespace):
            namespace = Namespace(namespace)
        keys = namespace.keys

        if not index:
            index = self.index

        if not path:
            path = []

        if not length:
            length = len(keys)

        token = keys[0]
        result = []

        for k in list(index.keys()):
            if k[0] == "_":
                continue
            if token == k or token == "?" or k == "*":
                if k == "*" and token != "?":
                    _path = path + [token]
                else:
                    _path = path + [k]
                if (len(_path) == length or not exact) and (index[k]["__"] or not explicit):
                    _namespace = Namespace(_path)
                    if _namespace.value:
                        result.append(_namespace)

                result += [
                    ns
                    for ns in self.expand(
                        keys[1:], index=index[k], path=_path, length=length,
                        explicit=explicit, exact=exact
                    )
                ]

        return list(set(result))

    def check(self, namespace, level, explicit=False):
        """
        Checks if the permset has permission to the specified namespace
        at the specified level

        **Arguments**

        - namespace (`str`): permissioning namespace
        - level (`int`): permission flag, `PERM_READ` for example

        **Keyword Arguments**

        - explicit (`bool=False`): require explicitly set permissions to the provided namespace

        **Returns**

        `bool`: `True` if permissioned `False` if not

        """


        if self.expandable(namespace):
            for _namespace in self.expand(namespace):
                if self.get_permissions(_namespace, explicit=explicit) & level != 0:
                    return True
            return False

        return (self.get_permissions(namespace, explicit=explicit) & level) != 0

    def apply(self, data, path=None, applicator=None):
        """
        Apply permissions in this set to the provided data, effectively
        removing all keys from it are not permissioned to be viewed

        **Arguments**

        - data (`dict`)

        **Keyword Arguments**

        - applicator (`Applicator=None`): allows you to specify the
        applicator instance to use. If none is specified an instance
        of `Applicator` will be used.

        **Returns**

        `dict`: cleaned data
        """

        if applicator:
            applicator.pset = self
        else:
            applicator = Applicator(self)

        return applicator.apply(data, path=path)


class Applicator:

    """
    Handles application of permissions to a dataset contained
    in a dict

    Any data that is not permissioned to be read will be removed
    during application of permissions.
    """

    def __init__(self, pset):
        self.pset = pset
        self.handlers = {}

    def handler(self, path, key=None, explicit=False, **kwargs):
        if not isinstance(path, Namespace):
            path = Namespace(path, strip=False)
        handler = {"namespace": path, "key": key, "explicit": explicit}
        handler.update(**kwargs)
        self.handlers[str(path)] = handler

    def find_handler(self, path):
        handler = None
        if path and self.handlers:
            namespace = Namespace(path, strip=False)
            for _handler in list(self.handlers.values()):
                if namespace.match(_handler.get("namespace").keys, partial=False):
                    handler = _handler
                    break
        return handler

    def apply(self, data, path=None):
        """
        Apply permissions in this set to the provided data, effectively
        removing all keys from it are not permissioned to be viewed

        **Arguments**

        - data (`dict`)

        **Returns**

        `dict`: cleaned data
        """

        if path is None:
            path = []

        if not isinstance(data, dict):
            return data

        def _enumerate(value):
            if isinstance(value, list):
                yield from enumerate(value)
            elif isinstance(value, dict):
                yield from list(value.items())

        def _set(container, key, value):
            if isinstance(container, list):
                container.append(value)
            else:
                container[key] = value

        def _apply(ramap, value, status=False, wc=False, path=[]):

            if not isinstance(value, dict) and not isinstance(value, list):
                if status:
                    return value
                else:
                    return None

            if not wc:
                status = ramap.get("__", status)

            handler = None
            key_handler = None
            if path and self.handlers:
                namespace = Namespace(path)
                for _handler in list(self.handlers.values()):
                    if namespace.match(_handler.get("namespace").keys, partial=False):
                        handler = _handler
                        key_handler = handler.get("key")
                        break

            if isinstance(value, list):
                if not key_handler:
                    key_handler = list_key_handler
                rv = []
            else:
                rv = {}

            for k, v in _enumerate(value):
                if key_handler:
                    k = key_handler(v, k)
                k = str(k)
                if isinstance(v, dict) or isinstance(v, list):
                    if k in ramap:
                        r = _apply(ramap[k], v, status=status, path=path + [k])
                        if r:
                            _set(rv, k, r)
                    elif "*" in ramap:
                        r = _apply(
                            ramap["*"], v, status=status, wc=True, path=path + [k]
                        )
                        if r:
                            _set(rv, k, r)
                    elif status:
                        _set(rv, k, v)
                else:
                    if k in ramap:
                        if ramap[k].get("__", True):
                            _set(rv, k, v)
                    elif "*" in ramap and ramap["*"].get("__", True):
                        _set(rv, k, v)
                    elif status:
                        _set(rv, k, v)

            return rv

        # loop through all the handlers that specify the `explicit` arguments
        # and temprorarily add deny rules for those to the targeted permissionset
        tmpns = {}
        for ns, handler in list(self.handlers.items()):
            if handler.get("explicit"):
                p = self.pset.get_permissions(ns)
                if p & const.PERM_READ:
                    exists = False
                    for _ns in self.pset.namespaces:
                        if Namespace(_ns).match(Namespace(ns).keys, partial=False):
                            exists = True
                            break
                    if exists:
                        continue
                    tmpns[ns] = p
                    self.pset[ns] = const.PERM_DENY

        # apply permissions
        rv = _apply(self.pset.read_access_map, data)

        # remove temporarily added deny rules
        for ns, p in list(tmpns.items()):
            if p is None:
                del self.pset[ns]
            else:
                self.pset[ns] = p

        return rv


class NamespaceKeyApplicator(Applicator):

    """
    Applicator that looks for permission namespaces from
    a specified field in the dict it is scanning
    """

    # field name that holds permission namespace
    namespace_key = "_grainy"

    # remove the permission namespace field from the
    # data during application
    remove_namespace_key = True

    denied = object()

    def apply(self, data, **kwargs):

        if isinstance(data, list):
            return self.apply_list(data)
        elif isinstance(data, dict):
            namespace = data.get(self.namespace_key)

            explicit = False
            fn = False
            handler = self.find_handler(namespace)
            if handler:
                explicit = handler.get("explicit", False)
                fn = handler.get("fn", None)

            if fn:
                fn(namespace, data)

            if namespace and not self.pset.check(namespace, 0x01, explicit=explicit):
                return self.denied
            elif namespace and self.remove_namespace_key:
                del data[self.namespace_key]

            return self.apply_dict(data)
        return data

    def apply_list(self, data, **kwargs):
        _data = []
        for row in data:
            _row = self.apply(row)
            if _row != self.denied:
                _data.append(_row)
        return _data

    def apply_dict(self, data, **kwargs):
        _data = {}
        for key, item in data.items():
            _item = self.apply(item)
            if _item != self.denied:
                _data[key] = _item
        return _data

