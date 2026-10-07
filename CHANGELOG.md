# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MIT license headers on all Python source files, matching the repo's
  existing MIT license (`MIT License`, Copyright (c) 2026 Nrupal Akolkar).
- CONTRIBUTING.md: PR-flow discipline (draft PR → verified → owner merges;
  no direct pushes to `main`; CHANGELOG entry per PR; semver; tagged releases).
- CHANGELOG.md (this file).
- NOTICE.md: project attribution.

### Fixed
- README installation block referenced truncated/broken clone URLs
  (`https://g`, `https://github.com`) — now points at the real repo with a
  working `pip install -r requirements.txt` step.
- `requirements.txt` was in `pip install <pkg>` command form (not parseable
  by pip) — rewritten as a plain requirement list.

### Notes
- No version file exists in the repo; no semver bump applied.
- No deploy target found (desktop/local app; no CI, no Worker/Pages deploy)
  — Track 2 skipped.
- `vault.json` is committed (145 bytes). Owner to confirm whether this
  belongs in the repo or under `.gitignore`.
