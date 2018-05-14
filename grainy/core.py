import six
from builtins import str
from past.builtins import basestring
from builtins import object
import grainy.const as const

def list_key_handler(row, idx):
    if isinstance(row, dict):
        return row.get("id", row.get("name", str(idx)))
    return idx

def int_flags(flags, mapper=const.PERM_STRING_MAP):
    """
    Converts string permission flags into integer permission flags as
    specified in const.PERM_STRING_MAP
    Arguments:
        - flags <str>: one or more flags
            For example: "crud" or "ru" or "r"
        - mapper <list=const.PERM_STRING_MAP>: a list containing tuples mapping
            int permission flag to string permission flag. If not specified will
            default to const.PERM_STRING_MAP.
    Returns:
        - int
    """

    r = 0
    if not flags:
        return r

    if isinstance(flags, six.integer_types):
        return flags

    if not isinstance(flags, six.string_types):
        raise TypeError("`flags` needs to be a string or integer type")

    for f in flags:
        for f_i, f_s in mapper:
            if f_s == f:
                r = r | f_i
    return r

class Namespace(object):
    """
    Object representing a permissioning namespace
    """

    def __init__(self, value):
        self.set(value)

    def __unicode__(self):
        return self.value

    def __str__(self):
        return self.value

    def __iter__(self):
        for k in self.value.split("."):
            yield k

    def __eq__(self, other):
        return str(self) == str(other)

    def __add__(self, other):
        if not isinstance(other, Namespace):
            raise NotImplemented()

        return Namespace(self.keys + other.keys)

    def __iadd__(self, other):
        return self.__add__(other)

    def set(self, value):
        if isinstance(value, list):
            value = ".".join([str(v) for v in value])
        if len(value) > 2 and value[-2:] == ".*":
            value = value[:-2]
        self.value = value
        self.keys = [k for k in self]
        self.length = len(self.keys)

    def match(self, keys, partial=True):
        """
        Check if the value of this namespace is matched by
        keys

        '*' is treated as wildcard

        Arguments:

        keys -- list of keys

        Examples:

            ns = Namespace("a.b.c")
            ns.match(["a"]) #True
            ns.match(["a","b"]) #True
            ns.match(["a","b","c"]) #True
            ns.match(["a","*","c"]) #True
            ns.match(["b","b","c"]) #False

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

        Returns the dict created as well as the tail in a tuple

        Example:

            self.value = "a.b.c"

            container, tail = self.container()
            #{"a":{"b":{"c":{}}}, {}

            container, tail = self.container({"d":123})
            #{"a":{"b":{"c":{"d":123}}}, {"d":123}
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


class Permission(object):
    """
    Permission object defined by a namespace and a permission bitmask

    Arguments:

    namespace -- string or Namespace instance defining the namespace
    value -- permission bitmask
    """

    def __init__(self, namespace, value):
        if isinstance(namespace, basestring):
            namespace = Namespace(namespace)

        self.namespace = namespace
        self.value = value

    def __eq__(self, other):
        r = (
            other.namespace == self.namespace and
            other.value == self.value
        )
        return r

    def has_value(self):
        """
        Check that value has been set
        """
        return (self.value is not None)

    def check(self, level):
        """
        Check if permission flagset contains the specified
        permission level
        """
        if not self.has_value():
            return False
        return (self.value & level) != 0


class PermissionSet(object):
    """
    Holds a set of Namespaces and permissions to run permission checks
    on

    Can also be applied to a data dict to remove keys that are not
    accessible according the permissions in the set

    Keyword arguments:
    rules -- list of Permission objects or dict of namespace(str) : permission(int) pairs
    """

    def __init__(self, rules=None):

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
        Returns list of all namespaces registered in this permission set
        """
        return list(self.permissions.keys())

    def __iter__(self):
        for v in list(self.permissions.values()):
            yield v

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
        elif isinstance(other, six.integer_types):
            self.permissions[key] = Permission(key, other)
        else:
            raise TypeError(
                "Value needs to be a Permission instance or a permission flag")
        if reindex:
            self.update_index()

    def __delitem__(self, namespace):
        if namespace in self.permissions:
            del self.permissions[namespace]
        else:
            raise KeyError(
                "No permission registered under namespace '%s'" % namespace)
        self.update_index()

    def update(self, permissions):
        """
        Update the permissionset with a dict of namespace<str>:permission<Permission|int|long>
        pairs

        Example:

            pset.update(
              {
                "a" : const.PERM_READ,
                "b" : Permission("b", const.PERM_RW)
              }
            )
        """
        for k, v in list(permissions.items()):
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
        for _, p in sorted(self.permissions.items(), key=lambda x: str(x[0])):
            branch = idx
            parent_p = const.PERM_DENY
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

            if branch_idx["__"] is not None and (branch_idx["__"] & const.PERM_READ) != 0:
                r["__"] = True
            return r

        for k, v in list(idx.items()):
            ramap[k] = update_ramap(v)

        self.read_access_map = ramap

        return self.index

    def _check(self, keys, branch, flags=None, i=0, explicit=False, l=0):

        try:
            key = keys[i]
        except IndexError:
            return flags, i

        p = 0
        r = 0
        j = 0
        a = 0

        if not l:
            l = len(keys)

        if key in branch:
            if explicit and branch[key].get("__implicit") and i + 1 >= l:
                p, r = 0, 0
            else:
                p, r = self._check(keys, branch[key], flags=branch[key].get(
                    "__", flags), i=i + 1, explicit=explicit, l=l)
        if "*" in branch:
            if explicit and branch["*"].get("__implicit") and i + 1 >= l:
                j, a = 0, 0
            else:
                j, a = self._check(keys, branch[
                                   "*"], flags=branch["*"].get("__", flags), i=i + 1, explicit=explicit, l=l)

        if explicit and r == 0 and a == 0:
            return 0, i

        if j is not None:
            if r < a or p is None:
                return j, a
        if p is not None:
            if r > i or flags is None:
                return p, r
        return flags, i

    def get_permissions(self, namespace, explicit=False):
        """
        Returns the permissions level for the specified namespace

        Arguments:

        namespace -- permissioning namespace (str)
        explicit -- require explicitly set permissions to the provided namespace

        Returns:

        int -- permissioning flags
        """

        if not isinstance(namespace, Namespace):
            namespace = Namespace(namespace)
        keys = namespace.keys
        p, _ = self._check(keys, self.index, explicit=explicit)
        return p


    def check(self, namespace, level, explicit=False):
        """
        Checks if the permset has permission to the specified namespace
        at the specified level

        Arguments:

        namespace -- permissioning namespace (str)
        level -- permissioning level (int) (PERM_READ for example)
        explicit -- require explicitly set permissions to the provided namespace

        Returns:

        bool
        """

        return (self.get_permissions(namespace, explicit=explicit) & level) != 0

    def apply(self, data, path=None, applicator=None):
        """
        Apply permissions in this set to the provided data, effectively
        removing all keys from it are not permissioned to be viewed

        Arguments:

        data -- dict of data

        Returns:

        Cleaned data
        """

        if applicator:
            applicator.pset = self
        else:
            applicator = Applicator(self)

        return applicator.apply(data, path=path)


class Applicator(object):

    def __init__(self, pset):
        self.pset = pset
        self.handlers = {}

    def handler(self, path, key=None, explicit=False):
        if not isinstance(path, Namespace):
            path = Namespace(path)
        self.handlers[str(path)] = {
            "namespace" : path,
            "key" : key,
            "explicit" : explicit
        }

    def apply(self, data, path=None):
        """
        Apply permissions in this set to the provided data, effectively
        removing all keys from it are not permissioned to be viewed

        Arguments:

        data -- dict of data

        Returns:

        Cleaned data
        """

        if path is None:
            path = []

        if not isinstance(data, dict):
            return data

        def _enumerate(value):
            if isinstance(value, list):
                for k, v in enumerate(value):
                    yield k, v
            elif isinstance(value, dict):
                for k, v in value.items():
                    yield k, v

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
                for _handler in self.handlers.values():
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
                        r = _apply(ramap[k], v, status=status, path=path+[k])
                        if r:
                            _set(rv, k, r)
                    elif "*" in ramap:
                        r = _apply(ramap["*"], v, status=status, wc=True, path=path+[k])
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
        for ns, handler in self.handlers.items():
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
        for ns, p in tmpns.items():
            if p is None:
                del self.pset[ns]
            else:
                self.pset[ns] = p

        return rv


