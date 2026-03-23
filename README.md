# niloo

> NILOO: niloo is local only openid

`niloo` is a local OpenID mock backend.

It is aimed at local development and test scenarios where you need:

- a browser-based OpenID authorization code flow
- a JWKS endpoint for JWT validation
- a simple `client_credentials` client for fetching tokens from Niloo or a real issuer

## Features

- OpenID discovery at `/Niloo/.well-known/openid-configuration`
- authorization endpoint at `/Niloo/oauth2/authorize`
- token endpoint at `/Niloo/oauth2/token`
- JWKS at `/Niloo/jwks.json`
- configurable mock users from YAML
- interactive user chooser for browser flow
- optional `--sub` to preselect one mock user
- `client_credentials` mode for fetching remote access tokens and printing them to stdout

## Install or run with nix

```bash
nix profile add github:hencjo/niloo
```

Run niloo directly from the flake without installing it:

```bash
nix run github:hencjo/niloo -- example-config > config.yaml
nix run github:hencjo/niloo -- serve --port 9799 --config-file config.yaml &
```

In another shell:
```bash
CLIENT_ID=system-api CLIENT_SECRET=client_secret \
  nix run github:hencjo/niloo -- client_credentials --issuer-url http://localhost:9799/Niloo
```

## Quick Start

Generate a starter config:

```bash
niloo example-config > config.yaml
```

```bash
niloo serve --port 9799 --config-file config.yaml
```

Fetch a local `client_credentials` token from the running server:

```bash
CLIENT_ID=system-api CLIENT_SECRET=client_secret \
  niloo client_credentials --issuer-url http://localhost:9799/Niloo
```

## Config

The server reads a YAML file with:

- `clients` for OAuth clients and optional `client_credentials` token claims
- `authorization_code.subs` for selectable browser-flow users
- `authorization_code: {}` to disable the browser flow entirely

Example:

```yaml
clients:
  relying-party:
    client_secret: client_secret
  system-api:
    client_secret: client_secret
    givenName: System
    defaultName: System API
    claims:
      groups:
        - admin
authorization_code:
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
- All entries under `clients` are OAuth clients, and any configured client can use either flow.
- For `client_credentials`, `givenName`, `defaultName`, and `claims` are optional per client. If omitted, Niloo still mints a valid token with `sub=<client_id>`.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
