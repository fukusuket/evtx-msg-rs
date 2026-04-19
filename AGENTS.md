# AGENTS.md

## Project Overview

`evtx-msg-rs` is a Rust (edition 2024) CLI / library prototype for **full message resolution of Windows Event Log (.evtx) records** — reconstructing the human-readable message text that Event Viewer displays, including message resource lookup and parameter substitution.

### Why message resolution is non-trivial

`.evtx` records store only:
- Event metadata (Provider, EventID, Level, …)
- Substitution parameters (`%1`, `%2`, … placeholders)

The **message template** lives in external resources (provider DLLs / `.mui` files) registered in the registry (`HKLM\SYSTEM\CurrentControlSet\Services\EventLog\…` or the manifest-based `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}`).

Full reconstruction requires:
1. Parse `.evtx` → extract `ProviderGuid`/`ProviderName` + `EventID` + parameter values.
2. Locate the provider's message DLL (registry lookup or offline DB).
3. Load the PE resource section → extract the message template for the given `EventID`.
4. Substitute parameters into the template → produce the final message text.

## Key Dependency

- **`evtx = "0.11.2"`** – parses `.evtx` binary format. Exposes records as XML or JSON.

```rust
use evtx::EvtxParser;

let mut parser = EvtxParser::from_path(path)?;
for record in parser.records_json() {
    let r = record?;
    // r.data: JSON string containing System / EventData fields
    println!("{}", r.data);
}
```

## Build & Run

```bash
cargo build                  # debug build
cargo build --release        # release build (always use this for performance measurement)
cargo run -- <args>          # run (debug)
cargo clippy -- -D warnings  # lint (treat warnings as errors)
cargo test                   # run tests
cargo bench                  # benchmarks (after adding criterion)
rustup update stable         # keep Rust 2024 edition toolchain current
```

## Development Style & Conventions

### General Principles

- **Single binary crate** (a `lib` target may be added later); entry point is `src/main.rs`.
- No workspace, feature flags, or build scripts unless strictly necessary.
- **Minimize dependencies.** Do not add heavy GUI frameworks or async runtimes (e.g., Tokio).

### Error Handling

| Context | Crate |
|---------|-------|
| Application-level (main / CLI) | `anyhow` |
| Library-facing public error types | `thiserror` |

Both crates are already in the dependency tree via `evtx` — no extra `Cargo.toml` entries needed.

### Performance Guidelines

- **Avoid unnecessary heap allocations**: prefer `&str` / `Cow<str>` over `String` where possible.
- **Zero-copy**: minimize buffer copies. Consider `memmap2` or `bytes` for PE resource loading and message substitution.
- **Prefer iterator chains**: only `collect()` when truly necessary.
- **Profile on release builds**: use `cargo build --release` + `samply` / `perf` / Instruments to identify hot paths before optimizing.
- **Apply `#[inline]` after measurement**: do not add it speculatively.
- **Custom allocator**: consider swapping in `mimalloc` or `jemalloc` if benchmarks justify it.
- **Parallelism**: `evtx` already uses `rayon` internally — record-level parallel parsing is handled. Evaluate the dependency cost before adding more parallelism.
- **String formatting**: avoid excessive `format!` calls; use `write!` / `BufWriter` to buffer output.

### Test-Driven Development

Follow the **Red → Green → Refactor** cycle strictly:

1. **Red** — write a failing test that captures the intended behaviour before writing any implementation.
2. **Green** — write the minimal production code required to make the test pass.
3. **Refactor** — clean up duplication and improve clarity without changing observable behaviour; keep all tests green.

Additional TDD rules:
- Never write production code without a corresponding failing test first.
- Keep each test focused on a single behaviour; avoid over-specifying internals.
- Prefer fast, deterministic unit tests. Mock or stub I/O-heavy paths (registry access, file reads) in unit tests; exercise them in integration tests under `tests/`.
- Run `cargo test` after every Green and Refactor step.

### Coding Conventions

- No `unsafe` code (if unavoidable for PE parsing, a `// SAFETY:` comment is mandatory).
- All public APIs must have `///` doc comments.
- All `clippy` warnings must be resolved (`-D warnings`).
- Unit tests go in `#[cfg(test)]` modules; integration tests go in `tests/`.

## Planned Architecture

```
src/
  main.rs          # CLI: argument parsing and orchestration
  parser.rs        # thin wrapper around the evtx crate; yields structured records
  resolver.rs      # message template lookup & parameter substitution
  registry.rs      # provider DLL path resolution via Windows registry or offline DB
  pe_resource.rs   # PE message-resource extraction (FormatMessage equivalent)
```

## Key Files

| Path | Purpose |
|------|---------|
| `src/main.rs` | CLI entry point (stub) |
| `Cargo.toml` | Package metadata & dependencies |
