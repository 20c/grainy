
# Change Log

## [Unreleased]
### Added

- Applicator class
- Way to require explicit namespaces when applying permissions to datasets

### Fixed
### Changed

- PermissionSet.apply now uses the new Applicator class
- Renamed core.list_namespace_handler to core.list_key_handler

### Deprecated
### Removed

- PermissionSet.handle_namespace (Replaced by Applicator class)

### Security

## 1.2.0

### Added

- namespace handlers
- Support applying permissions to nested lists

## 1.1.0

### Added

- Implemented PermissionSet.get_permissions()

