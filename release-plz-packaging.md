# Packaging and releases

This repo ships `silo` as a GitHub release with a static Linux binary tarball.

There are three moving parts:

- `release-plz.toml` decides versions, changelog entries, Git tags, and GitHub releases.
- `.github/workflows/release-plz.yml` runs release-plz on pushes to `master`.
- `.github/workflows/release-plz.yml` calls `.github/workflows/release-artifacts.yml` after a release.
- `.github/workflows/release-artifacts.yml` builds and uploads the binary tarball, and can also be run manually.

`Cargo.toml` is the version source of truth. `flake.nix` reads the same version from `Cargo.toml`.

## Version and changelog flow

Every meaningful change should use a release-plz-compatible Conventional Commit title, for example:

```text
fix: remove tar command dependency from archive handling
docs: document deployment verification and rollback cycle
ci: improve release artifact naming and contents
```

On push to `master`, the `Release-plz` workflow runs three jobs:

1. **Release-plz release**
   - publishes a GitHub release when a release PR has already been merged
   - creates the Git tag
   - does not publish to crates.io
2. **Release artifacts**
   - runs only when the release tag points at the current commit
   - builds the static Linux tarball
   - uploads the tarball and checksum to the release
3. **Release-plz PR**
   - opens or updates the release PR
   - bumps `Cargo.toml`
   - updates `CHANGELOG.md`

The release PR is the gate. Pushing ordinary work to `master` should create or update that PR; the actual release happens after the release PR is merged.

## release-plz configuration

Important settings in `release-plz.toml`:

```toml
git_only = true
git_release_enable = true
git_release_name = "{{ package }}-v{{ version }}"
git_tag_enable = true
git_tag_name = "{{ package }}-v{{ version }}"
publish = false
```

Meaning:

- `git_only = true`: use Git tags/releases as the release backend.
- `git_tag_name`: tags are named like `silo-v1.0.2`.
- `git_release_name`: GitHub releases use the same name.
- `publish = false`: never try to publish to crates.io.

That last line is important. Without it, release-plz may still ask Cargo to publish and fail with `no token found`.

## GitHub Action permissions

Repository settings must allow Actions to write:

1. **Settings → Actions → General**
2. **Workflow permissions**: `Read and write permissions`
3. Enable **Allow GitHub Actions to create and approve pull requests**

No crates.io token is required.

## Binary build

The artifact workflow builds this Rust target:

```text
x86_64-unknown-linux-musl
```

The public package name intentionally hides the Rust target triple and uses:

```text
linux-x86_64-static
```

The workflow installs:

- stable Rust
- Rust target `x86_64-unknown-linux-musl`
- Ubuntu package `musl-tools`

It also sets:

```text
CC_x86_64_unknown_linux_musl=musl-gcc
```

That C compiler is needed by native dependencies such as `ring` while building for musl.

The build command is:

```bash
cargo build --release --locked --target x86_64-unknown-linux-musl
```

## Release artifact shape

For version `1.0.2`, the expected files are:

```text
silo-1.0.2-linux-x86_64-static.tar.gz
silo-1.0.2-linux-x86_64-static.tar.gz.sha256
```

The tarball contains one top-level directory:

```text
silo-1.0.2-linux-x86_64-static/
├── LICENSE
├── README.md
└── silo
```

The archive is created with numeric root ownership:

```bash
tar --owner=0 --group=0 --numeric-owner ...
```

The checksum file is generated from inside `dist/`, so it contains the archive basename only:

```text
<sha256>  silo-1.0.2-linux-x86_64-static.tar.gz
```

## Artifact upload

The artifact workflow uploads the tarball and checksum in two places:

1. As a GitHub Actions workflow artifact.
2. As assets on the matching GitHub release with `gh release upload --clobber`.

Manual rebuild for an existing release:

```bash
devenv shell gh workflow run release-artifacts.yml \
  --repo hencjo/silo \
  -f tag=silo-v1.0.2
```

## Known GitHub Actions trap

GitHub releases created by `GITHUB_TOKEN` may not trigger separate workflows that listen for `release: published`.

So `release-plz.yml` invokes the artifact workflow directly after release creation. The artifact workflow also supports:

- automatic `release: published`
- manual `workflow_dispatch` with a `tag` input

If a release exists but assets are missing, manually dispatch `release-artifacts.yml` for that tag.

## Local checks

Before changing packaging or release logic, run:

```bash
cargo test
git diff --check
nix eval .#packages.x86_64-linux.silo.version --raw
```

After a release, verify assets:

```bash
devenv shell gh release view silo-v1.0.2 \
  --repo hencjo/silo \
  --json tagName,name,assets,url
```
