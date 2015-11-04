import const
class Namespace(object):
  """
  Object representing a permissioning namespace
  """

  def __init__(self, value):
    self.set(value);

  def __unicode__(self):
    return self.value

  def __str__(self):
    return self.value
  
  def __iter__(self):
    for k in self.value.split("."):
      yield k

  def __eq__(self, other):
    return str(self) == str(other)

  def set(self, value):
    if isinstance(value, list):
      value = ".".join(value)
    if len(value) > 2 and value[-2:] == ".*":
      value = value[:-2]
    self.value = value
    self.keys = [k for k in self]
    self.length = len(self.keys)

  def match(self, keys):
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
    c = 0
    for k in keys:
      if c >= self.length:
        return False
      a = self.keys[c]
      if a != "*" and k != "*" and k != a:
        return False
      c += 1
    return True

  def container(self, data={}):
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

    root = p = d = {}
    j = 0
    for k in self:
      d[k] = {}
      p = d
      d = d[k]
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

  def __init__(self, rules=[]):
    
    self.permissions = {}
    self.index = {} 
    self.read_access_map = {}

    if type(rules) == list:
      for permission in rules:
        self.__add__(permission)
    elif type(rules) == dict:
      for ns, p in rules.items():
        self.__add__(Permission(ns, p))

  def __radd__(self, other):
    self.__add__(other)
  
  def __add__(self, other):
    if isinstance(other, Permission):
      self.permissions[str(other.namespace)] = other

    self.update_index()

  def update_index(self):
    """
    Regenerates the permission index for this set

    Called everytime a rule is added / removed / modified in
    the set
    """

    # update index
    
    idx = {}
    for ns, p in self.permissions.items():
      branch = idx
      parent_p = const.PERM_DENY
      for k in p.namespace.keys:
        if not k in branch:
          if k != "*":
            branch[k] = { "__" : parent_p }
          else:
            branch[k] = { "__" : None }

        branch = branch[k]
        parent_p = branch["__"]
      branch["__"] = p.value

    self.index = idx
    return self.index

  def _check(self, keys, branch, flags=None, i=0):
    
    try:
      key = keys[i]
    except IndexError:
      return flags, i

    p = 0
    r = 0
    j = 0
    a = 0
    if key in branch:
      p, r = self._check(keys, branch[key], flags=branch[key].get("__", flags), i=i+1)
    if "*" in branch:
      j, a = self._check(keys, branch["*"], flags=branch["*"].get("__", flags), i=i+1)
    
    #print "_check", key, flags, i, ":", p, r, ":", j, a

    if j is not None:
      if r < a or p is None:
        return j, a
    if p is not None:
      if r > i or flags is None:
        return p, r
    return flags, i
      
      

  def check(self, namespace, level):
    """
    Checks if the permset has permission to the specified namespace
    at the specified level

    Arguments:

    namespace -- permissioning namespace (str) 
    level -- permissioning level (int) (PERM_READ for example)
    """
    
    if not isinstance(namespace, Namespace):
      namespace = Namespace(namespace)
    keys = namespace.keys
    p,g = self._check(keys, self.index) 
    return (p & level) != 0
      

  def apply(self, data, path=[]):
    """
    Apply permissions in this set to the provided data, effectively
    removing all keys from it are not permissioned to be viewed

    Arguments:

    data -- dict of data 

    Returns:

    Cleaned data
    """
    
    if not isinstance(data, dict):
      return data

    rv = {}

    for k,v in data.items():
      p = path+[k]
      if self.check(path+[k], const.PERM_READ):
        rv[k] = self.apply(v, path=p)

    return rv

