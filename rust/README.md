# OpsGate Rust port

A Rust port of both long-running OpsGate processes (`python -m opsgate serve`
and `python -m opsgate runner`) as one binary, `opsgate`. The contract, the
intentional divergences and the slices are in [`PLAN.md`](PLAN.md); the
mapping of every Python test to its Rust test is in [`TESTMAP.md`](TESTMAP.md).

**Status:** foundations only (slice S1). The workspace, CI, the fixture
generator and the command-line skeleton exist; every command is still a stub
that exits 2. The Python package in `src/opsgate` is the production
implementation and the oracle for the contract. Nothing deploys or runs this
code yet.

## Layout

```
rust/
  Cargo.toml            workspace (version 0.3.0; Python is 0.2.0)
  Cargo.lock            committed; every build uses --locked
  rust-toolchain.toml   pinned toolchain 1.99.0 (also the MSRV)
  deny.toml             cargo-deny policy (licenses, advisories, sources)
  crates/
    opsgate-core/       pure logic: settings, JSON canon/checksum, time, validation, log preview, path containment (S2a-S2c)
    opsgate-store/      SQLite store, check-db (S3a, S3b)
    opsgate-web/        HTTP API and web UI (S4a, S4b, S5)
    opsgate-runner/     runner (S6a, S6b)
    opsgate/            the binary: command line, build.rs (embeds the git commit)
  fixtures/
    generate.py         writes the fixtures from the Python implementation
    schema.sql          sqlite_master of a Python-initialised database (4.10)
```

The library crates are empty until their slices land. Every crate forbids
`unsafe` code (workspace lint).

## Toolchain

Install [rustup](https://rustup.rs); `rust-toolchain.toml` selects 1.99.0
with rustfmt and clippy (`rustup toolchain install` inside `rust/`). A `cargo`
that is not the rustup proxy (for example Homebrew's) ignores the pin, so put
`~/.cargo/bin` first on `PATH`. `just rs-deny` needs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) 0.20.2 on `PATH`.

## Recipes

Run from the repository root:

| Recipe | What it does |
| --- | --- |
| `just rs-check` | `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test --locked` |
| `just rs-test` | `cargo test --workspace --locked` |
| `just rs-deny` | `cargo deny --locked check` against `deny.toml` |
| `just rs-fmt` | `cargo fmt --all` |
| `just rs-fixtures` | regenerate `rust/fixtures` from the Python implementation |
| `just rs-build` | release build for this host (`rust/target/release/opsgate`) |

The parity harnesses get their recipes (`rs-parity-api`, `rs-parity-runner`)
with slices S7a and S7b. `just check` stays the Python check.

## CI

The `rust` job of `.github/workflows/ci.yml` runs on `ubuntu-latest` and
`macos-15`: rustfmt, clippy, `cargo deny --locked check` (pinned, sha256
verified cargo-deny release), `cargo test --locked`, a release build, a
`--version` smoke test (version and the checked-out commit) and the release
binary size in the job summary. The fixture drift test runs in the Python job
as part of pytest.

## Fixtures

`fixtures/generate.py` imports `opsgate` and calls the real Python code on a
fixed corpus (PLAN.md 7.2). Fixtures are never edited by hand:

```bash
just rs-fixtures                                     # rewrite every fixture
uv run python rust/fixtures/generate.py --check      # exit 1 on drift
```

`tests/test_rust_fixtures.py` (pytest, so `just test` and the Python CI job)
regenerates every fixture in memory and fails when a committed file differs,
also on whitespace. A Python change that alters a fixture must regenerate it
in the same change; the Rust tests then show what to port. Each slice adds its
builders to `GENERATORS` in `generate.py`.

| Fixture | Content | Used by |
| --- | --- | --- |
| `schema.sql` | `sqlite_master` of a database initialised by `OpsGateService.init_db`, tables then indexes; runs as one script | schema contract test (S3a) |

## Command line

```
opsgate [serve] [--db PATH] [--bind-host HOST] [--bind-port PORT]
opsgate runner [--once]
opsgate check-config api|runner
opsgate check-db --db PATH
opsgate --version
```

No command means `serve`, as with `python -m opsgate`. Until their slices
land, the commands print `opsgate <command>: not implemented yet` on stderr and
exit 2; usage errors also exit 2. `opsgate --version` prints
`opsgate <version> (<full commit>)`. `build.rs` takes the commit from
`OPSGATE_GIT_COMMIT` (40 or 64 lowercase hex digits; the release workflow sets
it), else from `git rev-parse HEAD`, else `unknown`.
