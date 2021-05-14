# Changelog


## Unreleased


## 1.8.0
### Fixed
- fix issue with * and *.* namespacing
### Changed
- switch to poetry for package management (#11)
- switch to github actions (#9)


## 1.7.2
### Fixed
- fix issue with permission checks against namespaces starting with a wildcard


## 1.7.1
### Fixed
- bugs with permission checking (#10)


## 1.7.0
### Added
- `PermissionSet.update`: add `override` argument


## 1.6.0
### Added
- python3.9 support
- const.PERM_CRUD
- strip argument to Namespace.set and Namespace.__init__ (defaults to True)
- NamespaceKeyApplicator
### Fixed
- several bugs with implicit and explicit permission checking


## 1.5.0
### Added
- Expandable namespaces
- javascript implementation (experimental)
- Python3.8 support
### Removed
- Python2.7 support
- Python3.4 support
- Python3.5 support


## 1.4.1
### Added
- api docs
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