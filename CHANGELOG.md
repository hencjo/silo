# Changelog

## X.Y.Z (unreleased)

### Bug Fixes

### Improvements

- Renamed niloo to Silo across the binary, package metadata, docs, and user-facing text.

### Breaking Changes

- **Rename**: Changed the CLI binary/package name from `niloo` to `silo`, updated the default issuer path from `/Niloo` to `/Silo`, and switched examples and metadata to the new name.

## 0.1.0

### Improvements

- Added explicit support for disabling the browser flow with `authorization_code: {}` while keeping `client_credentials` available.

### Breaking Changes

- **Config format**: Replaced the separate browser-flow and machine-client client configuration with a shared `clients` section. Any configured client can now use either flow, and `authorization_code` now only contains browser-flow `subs`.
