# Contributing to mykey

## Workflow (PR-flow discipline)

1. Work on a topic branch off `main`. **Never push directly to `main`.**
2. Open a **draft** PR against `main`.
3. Tests/verification: for code changes, state how you verified (e.g.
   `python mykey_cli.py gen --service test` smoke test). Docs-only PRs need no
   test run but must have every documented command verified against the repo.
4. The repository owner reviews and merges. **Only the owner merges.**

## Changelog & versioning

- Every PR adds an entry under `## [Unreleased]` in `CHANGELOG.md`.
- Patch = fix, minor = feature, major = breaking change (semver).
- Merge commits reference the PR number (e.g. `Merge pull request #12`).
- Releases are tagged `vX.Y.Z` after merge.

## Security

- Never commit vault data (`*.mykey`), `salt.bin`, export CSVs, or secrets.
- Report vulnerabilities privately to the maintainer (see SECURITY.md) — do
  not open public issues for them.
