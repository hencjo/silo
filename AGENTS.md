# AGENTS.md

This file provides guidance to AI Code Agents when working with code in this repository.

## Build & Development Commands

Use `devenv shell` to get a shell with Rust and all dependencies installed.
Prefix commands with `devenv shell --` to run them directly.

- **Build**: `cargo build`
- **Run CLI**: `cargo run -- [args]`
- **Build with Nix**: `nix build`
- **Format**: `cargo fmt`
- **Lint**: `cargo clippy`
- **Run all tests**: `devenv-run-tests run tests`
- **Run single test**: `devenv-run-tests run tests --only <test_name>`

## Architecture Overview

niloo is a local OpenID mock backend.

It is aimed at local development and test scenarios where you need:

- a browser-based OpenID authorization code flow
- a JWKS endpoint for JWT validation
- a simple `client_credentials` client for fetching tokens from Niloo or a real issuer

It's built and consumed as a nix flake (`flake.nix`, `flake.lock`).

## Changelog


`CHANGELOG.md` follows this structure:

```
## <version> (unreleased)

### Bug Fixes

- Fixed <description> ([#<issue>](https://github.com/hencjo/niloo/issues/<issue>)).

### Improvements

- <Description of improvement>.

### Breaking Changes

- **<Name>**: <Description>.
```

