# Release process

Releases are handled by `release-plz` through GitHub Actions.

## One-time GitHub setup

Do this before trusting the release workflow:

1. Go to **Settings → Actions → General**.
2. Under **Workflow permissions**, choose **Read and write permissions**.
3. Enable **Allow GitHub Actions to create and approve pull requests**.
4. Go to **Settings → Actions → Workflow permissions** if GitHub shows the setting there instead; GitHub likes moving things around.
5. No crates.io token is needed. If a workflow asks for one, the config is wrong.

## Normal release

1. Merge feature/fix PRs into `master`.
2. Wait for the **Release-plz PR** workflow to open or update a PR named like:

   ```text
   chore: release
   ```

3. Review that PR. It should update:
   - `Cargo.toml`
   - `Cargo.lock`
   - `CHANGELOG.md`

4. If the changelog wording is bad, edit the release PR. Do not hand-edit release files on `master`.
5. Merge the release PR into `master`.
6. Wait for the **Release-plz release** workflow.
7. Confirm GitHub now has:
   - a tag named `silo-vX.Y.Z`
   - a GitHub Release named `silo-vX.Y.Z`
   - release notes copied from that version's changelog section
8. Wait for the **Release artifacts** job in the same workflow.
9. Confirm the release has:
   - `silo-X.Y.Z-linux-x86_64-static.tar.gz`
   - `silo-X.Y.Z-linux-x86_64-static.tar.gz.sha256`

That's it.

## How version bumps are chosen

Use conventional-ish commit prefixes:

- `fix: ...` -> patch release
- `feat: ...` -> minor release
- `BREAKING CHANGE:` in the commit body -> major release

The config also accepts older project-style messages like `Improvement: ...` and `Bug ...`, but prefer `fix:` and `feat:` from now on. Random commit messages make ugly changelogs; don't do that.

## Local dry run

To see what release-plz would do locally:

```sh
devenv shell -- release-plz update --allow-dirty
```

This edits files in your working tree. If you were only testing, throw the changes away before continuing.

## Manual release check

After a release PR is merged, check:

```sh
git fetch --tags origin
git tag --list 'silo-v*' | sort -V | tail
gh release view silo-vX.Y.Z
```

If `gh` is not installed, check the Releases page on GitHub instead.

## Important details

- Silo is **not** published to crates.io. `release-plz` runs in `git_only` mode.
- New release tags use `silo-vX.Y.Z`.
- Old bare tags like `1.0.1` exist, but release-plz intentionally ignores them because the old tags were made before `Cargo.toml` versions were kept in sync.
- `CHANGELOG.md` should always keep an empty `Unreleased` section at the top for the next cycle.
- Binary artifacts are built by the `Release artifacts` job in `.github/workflows/release-plz.yml`.
- `.github/workflows/release-artifacts.yml` also exists as a manual fallback. Use it if assets are missing:

  ```sh
  gh workflow run release-artifacts.yml -f tag=silo-vX.Y.Z
  ```

## If something goes wrong

Do not create a random manual tag unless you know exactly why release-plz failed. Fix the release PR/workflow and rerun it; manual tags are how release automation gets cursed.
