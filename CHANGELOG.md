# Changelog


## Unreleased
### Changed
- move to ctl
- update requirements


## 1.4.0
### Added
- `const.PERM_STRING_MAP` to allow mapping string flags to integer flags
- `int_flags` function to allow converting string flags to integer flags


## 1.3.7
### Fixed
- allow passing of `long` values for permissions in PermissionSet.__setitem__


## 1.3.6
### Added
- Namespace.__add__
- Namespace.__iadd__


## 1.3.5
### Fixed
- Issue in Applicator.apply with explicitly required namespaces and wildcard permissions


## 1.3.4
### Fixed
- Applicator.handlers made instanced property


## 1.3.3
### Fixed
- Issue where wildcard permissions would not correctly inherit from parent permission
- Issue with numeric namespace elements during Applicator.apply


## 1.3.2
### Fixed
- Passing a number as one of the path components during Namespace.__init__ will no longer fail with a TypeError


## 1.3.1
### Added
- Applicator class
- Way to require explicit namespaces when applying permissions to datasets
### Changed
- PermissionSet.apply now uses the new Applicator class
- Renamed core.list_namespace_handler to core.list_key_handler
### Removed
- PermissionSet.handle_namespace (Replaced by Applicator class)


## 1.2.0
### Added
- namespace handlers
- Support applying permissions to nested lists


## 1.1.0
### Added
- Implemented PermissionSet.get_permissions()