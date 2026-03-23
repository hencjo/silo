# Changelog

## X.Y.Z (unreleased)

### Bug Fixes

### Improvements

- Added explicit support for disabling the browser flow with `authorization_code: {}` while keeping `client_credentials` available.

### Breaking Changes

- **Config format**: Replaced the separate browser-flow and machine-client client configuration with a shared `clients` section. Any configured client can now use either flow, and `authorization_code` now only contains browser-flow `subs`.
