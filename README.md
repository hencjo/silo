# niloo

`niloo` is a local OpenID mock backend.

It is aimed at local development and test scenarios where you need:

- a browser-based OpenID authorization code flow
- a JWKS endpoint for JWT validation
- a simple `client_credentials` client for fetching tokens from Niloo or a real issuer

The name stands for:

> NILOO: niloo is local only openid

## Features

- OpenID discovery at `/Niloo/.well-known/openid-configuration`
- authorization endpoint at `/Niloo/oauth2/authorize`
- token endpoint at `/Niloo/oauth2/token`
- JWKS at `/Niloo/jwks.json`
- configurable mock users from YAML
- interactive user chooser for browser flow
- optional `--sub` to preselect one mock user
- `client_credentials` mode for fetching remote access tokens and printing them to stdout

Run with Nix:

```bash
nix build .#niloo
nix run .#niloo -- --help
```

## Quick Start

Generate a starter config:

```bash
cargo run -- example-config > config.yaml
```

```bash
niloo serve --port 9799 --config-file config.yaml
```

Fetch a local `client_credentials` token from the running server:

```bash
CLIENT_ID=sub1 CLIENT_SECRET=client_secret \
  niloo client_credentials --issuer-url http://localhost:9799/Niloo
```

## Config

The server reads a YAML file with a `subs` map. Each entry is both:

- a selectable browser-flow user
- a valid `client_id` for the local `client_credentials` flow

Example:

```yaml
subs:
  sub1:
    givenName: Mock
    defaultName: Mock User
    claims:
      groups:
        - admin
  sub2:
    givenName: Admin
    defaultName: Admin User
    claims:
      groups:
        - auditor
```

Notes:

- `givenName` and `defaultName` are emitted in the ID token.
- Each key under `claims` becomes a claim in issued JWTs.
- For local `client_credentials`, the Basic auth `client_id` must match one of the configured sub keys.

## Commands

Top-level help:

```bash
niloo --help
```

