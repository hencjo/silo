# Changelog

## Unreleased

### Bug Fixes

### Improvements

### Breaking Changes

## 3.0.0




### Bug Fixes

- Improve remote HTTP error output.



### Improvements

- Add scoped client credentials **Upgrade:** Move machine clients to client_credentials.clients, nest claims under scopes.<scope>.claims, and pass scopes with --scope..



### Bug Fixes

### Improvements

### Breaking Changes

- **Client credentials configuration**: Added repeatable scope requests and moved serve-mode machine clients from `clients` to scope-gated entries under `client_credentials.clients`. Legacy `givenName`, `defaultName`, and `claims` fields under `clients` are now ignored. **Upgrade:** Move every machine client to `client_credentials.clients`, move its former `claims` under `scopes.<scope>.claims`, remove `givenName` and `defaultName`, and pass the required scope with `--scope`. Keep a copy under `clients` only when the same ID is also an authorization-code relying party.

## 2.0.0




### Bug Fixes

- Fix for building packages on release.

- Hide sub when preferred_username is available **Upgrade:** No config change is required; users with claims.preferred_username now see only preferred_username in the picker.



### Improvements

- Release v1.0.2.

- Support reusable signing keys.

- Improve authorization-code fidelity.

- Prefer preferred_username in user picker **Upgrade:** No config change is required; users with claims.preferred_username will now see preferred_username followed by the muted sub value.


## 1.0.2




### Bug Fixes

- Improve remote token error diagnostics.



### Improvements

- Gh in pkgs.

- Release v1.0.2.



## 1.0.2




### Bug Fixes

- Improve remote token error diagnostics.



### Improvements

- Gh in pkgs.



## 1.0.0

### Bug Fixes

### Improvements

### Breaking Changes

## 1.0.1

### Bug Fixes

- Kept the browser user picker in the same order as `authorization_code.subs` in the config file.

### Improvements

- Preserved arbitrary claim values from config in issued JWTs, so `authorization_code` users can now emit scalar claims like `email` as well as arrays, booleans, numbers, and objects.

### Breaking Changes

## 1.0.0

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
