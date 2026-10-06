# cmnp

moon + proto adapter for ccid. Not an official moonrepo product.

## Role

ccid is the stable layer. cmnp is the active execution layer behind it: ccid
hands it the checks to run, cmnp runs them with [moon](https://moonrepo.dev)
(task graph, input-hash caching, remote cache) and pins toolchains with
[proto](https://moonrepo.dev/proto). Repositories never call moon directly;
they declare their checks in the repo manifest, and ccid policy decides which
run where. Checks are defined once, there and in that policy, never in cmnp.

cdgr is the dormant sibling adapter built on Dagger.

## Crate

`cmnp` is a Rust library (this repo). `ccid cached` calls
`cmnp::executor::execute` with its validated check declarations; ccid owns the
manifest and check definitions, cmnp owns how moon runs them:

- `executor::Check` — check declaration, field-for-field compatible with ccid's
  manifest check (the tool identity hashes the whole declaration).
- `executor::Request` — validated run: repository, moon project, checks,
  selection, tool name/revision and environment.
- `executor::execute` — probe tool identities, generate `.moon/workspace.yml`
  and `moon.yml`, run moon, return results and receipts.
- `executor::validate_selection`, `project_id`, `remote_cache` — shared by
  ccid's `cached` command so validation lives in exactly one place.

There is no `cmnp` binary: repositories keep calling `ccid cached`.

## Layout

| Path | Content |
|---|---|
| `templates/.moon/workspace.yml` | Workspace config with the remote cache placeholder `grpc://<bazel-remote>:9092` |
| `templates/go/moon.yml` | Go project tasks: test, vet, build, with inputs and declared outputs |
| `templates/rust/moon.yml` | Rust project tasks: test, clippy, build, with inputs and declared outputs |
| `templates/.prototools` | Toolchain pins (proto) |

## Status

| Item | State |
|---|---|
| Stage | pilot |
| Org | `corbet-foss`, mirrored on Forgejo, GitHub, GitLab, Bitbucket |
| Remote cache | bazel-remote on `solid/apps/cache/bazel-remote` (planned); the address in the template is a placeholder |
| Toolchain pins | Placeholders; policy "current stable Rust without exact pins" is still to be reconciled with proto lockfiles |

## Licence

LGPL-3.0-or-later. The full text is in `LICENSE.md`.

## Runner notes (from the dotkeeper pilot, 2026-10-05)

- Persist only `.moon/cache/hashes` and `.moon/cache/outputs` between runs; the rest of `.moon/cache` holds absolute checkout paths and breaks the next run.
- Put `$PROTO_HOME/bin` on PATH (not the proto shims); `git` must be on PATH for `proto install`.
- Prune `.moon/cache/outputs` periodically (`moon clean --lifetime`).
- An unreachable remote cache costs a 30 s connect timeout per task, then moon continues without it.
