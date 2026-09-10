# silo

> SILO: Silo is local OpenID

`silo` is a local OpenID mock backend.

It is aimed at local development and test scenarios where you need:

- a browser-based OpenID authorization code flow
- a JWKS endpoint for JWT validation
- an interactive `authorization_code` client for browser login against a real issuer
- a simple `client_credentials` client for fetching tokens from Silo or a real issuer

## Browser flow

The browser-based authorization flow includes a built-in user picker:

![Silo user picker](./docs/screenshots/user-picker.png)

The code exchange returns signed ID and access tokens. Silo does not issue refresh tokens.

## Features

- OpenID discovery at `/Silo/.well-known/openid-configuration`
- authorization endpoint at `/Silo/oauth2/authorize`
- token endpoint at `/Silo/oauth2/token`
- JWKS at `/Silo/jwks.json`
- RS256 ID tokens and access tokens for the authorization-code flow
- standard OAuth error redirects for valid clients and redirect URLs
- configurable mock users from YAML
- interactive user chooser for browser flow
- optional `--sub` to preselect one mock user
- `authorization_code` mode for fetching a remote access token through browser login
- `client_credentials` mode with repeatable scope requests for fetching remote access tokens
- scope-gated mock claims for serve-mode `client_credentials` tokens

## Install or run with nix

```bash
nix profile add github:hencjo/silo
```

Run silo directly from the flake without installing it:

```bash
nix run github:hencjo/silo -- example-config > config.yaml
nix run github:hencjo/silo -- serve --port 9799 --config-file config.yaml &
```

In another shell:
```bash
CLIENT_ID=system-api CLIENT_SECRET=client_secret \
  nix run github:hencjo/silo -- client_credentials --issuer-url http://localhost:9799/Silo --scope api.read
```

## Quick Start

Generate a starter config:

```bash
silo example-config > config.yaml
```

```bash
silo serve --port 9799 --config-file config.yaml
```

Fetch a local `client_credentials` token from the running server:

```bash
CLIENT_ID=system-api CLIENT_SECRET=client_secret \
  silo client_credentials --issuer-url http://localhost:9799/Silo --scope api.read
```

## Remote authorization-code login

Use `authorization_code` to log in through a real issuer and print its access token:

```bash
CLIENT_ID=relying-party CLIENT_SECRET=client_secret \
  silo authorization_code \
  --issuer-url https://idp.example \
  --scope openid --scope profile
```

Silo uses the first free port from `8787` through `8887` and prints the resulting
`http://localhost:<port>/callback` redirect URI to stderr on startup so it can be whitelisted with
the issuer. It listens for one callback, opens the authorization URL in the default browser,
exchanges the code using `client_secret_post`, and prints only the access token to stdout. The URL
is also printed to stderr; pass `--no-browser` to open it yourself.

If no scopes are supplied, Silo requests `openid`. `CLIENT_SECRET` is accepted from the environment
only. Use `--insecure` only for a development issuer with an untrusted TLS certificate.

For headless tests against a locally running Silo, select a configured user directly:

```bash
CLIENT_ID=relying-party CLIENT_SECRET=client_secret \
  silo authorization_code \
  --issuer-url http://localhost:9799/Silo \
  --non-interactive --sub sub1
```

Headless mode accepts loopback issuers only. `--sub` is optional when the server was already
started with `silo serve --sub`; otherwise Silo returns the user chooser and the command fails.

## Config

The server reads a YAML file with:

- `clients` for authorization-code relying parties
- `client_credentials.clients` for machine clients and their scope-gated token claims
- `authorization_code.subs` for selectable browser-flow users
- `authorization_code: {}` to disable the browser flow entirely
- an omitted or empty `client_credentials` section to disable that flow
- optional `key_file` for sharing one signing key across restarts or Silo instances

Example:

```yaml
# Optional; relative paths resolve from this config file.
# key_file: ./silo-private-key.pem
clients:
  relying-party:
    client_secret: client_secret
client_credentials:
  clients:
    system-api:
      client_secret: client_secret
      scopes:
        api.read:
          claims:
            groups:
              - admin
authorization_code:
  subs:
    sub1:
      givenName: Mock
      defaultName: Mock User
      claims:
        preferred_username: mock
        groups:
          - admin
    sub2:
      givenName: Admin
      defaultName: Admin User
      claims:
        groups:
          - auditor
        email: admin@example.com
```

Notes:

- `givenName` and `defaultName` are emitted in the ID token.
- The user picker shows a non-empty string `claims.preferred_username`; otherwise it shows `sub`.
- Each key under an authorization-code user's `claims` becomes an unconditional JWT claim.
- For `client_credentials`, claims are emitted only when their containing scope is requested. Repeat `--scope` to request multiple scopes.
- Unknown machine-client scopes and conflicting values for the same claim return `invalid_scope`.
- A machine token requested without scopes remains valid and contains only protocol claims.
- Without `key_file`, Silo creates a fresh temporary signing key for each run.
- A missing configured `key_file` is generated once and then reused. Its `kid` is derived from the public key.
- Authorization-code and machine-client registries are separate; configure an ID in both places if it must use both flows.

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
