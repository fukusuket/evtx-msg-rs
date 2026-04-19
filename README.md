# evtx-msg-rs

A Rust CLI tool for **full message resolution of Windows Event Log (`.evtx`) records** —
reconstructing the human-readable message text that Event Viewer displays, including
message resource lookup and parameter substitution.

## Why this exists

`.evtx` files store only event metadata (`ProviderName`, `EventID`, …) and raw
substitution parameters (`%1`, `%2`, …).  The **message template** lives inside Windows
DLL / MUI files registered in the registry.  Existing Rust tools (Hayabusa, Chainsaw,
`evtx_dump`) parse the binary format but do **not** perform full template resolution.
`evtx-msg-rs` fills that gap.

## Features

- Parses `.evtx` files using the [`evtx`](https://crates.io/crates/evtx) crate.
- **Online resolution** (Windows): looks up provider DLLs via the Windows registry, parses
  the PE `RT_MESSAGETABLE` resource with [`pelite`](https://crates.io/crates/pelite), and
  performs FormatMessage-compatible `%N` / `%%` / `%n` / `%r` / `%t` / `%b` / `%0`
  substitution.
- **Extensible architecture**: a `MessageResolver` trait allows future offline / SQLite-DB
  backends without changing existing code.
- Outputs one JSON object per record to stdout.

## Usage

```bash
# Single file
evtx-msg-rs <path/to/file.evtx>

# Directory (all *.evtx files are processed recursively)
evtx-msg-rs <path/to/dir/>
```

Each line of output is a JSON object:

```json
{"event_id":4624,"provider":"Microsoft-Windows-Security-Auditing","file":"Security.evtx","message":"An account was successfully logged on.\r\n..."}
```

`"message"` is `null` when the template cannot be resolved (provider not registered, or
running on a non-Windows platform).

## Architecture

```
src/
  main.rs          # CLI entry point — BufWriter JSON output
  error.rs         # ResolveError (thiserror)
  parser.rs        # evtx wrapper → EvtxRecord {provider_name, provider_guid, event_id, params}
  resolver.rs      # MessageResolver trait + ChainedResolver + NullResolver
  registry.rs      # cfg(windows): registry lookup → DLL path → pe_resource + substitution
  pe_resource.rs   # pelite pe64: RT_MESSAGETABLE → message template string
  substitution.rs  # FormatMessage-compatible %N / special-sequence substitution
```

### Registry lookup order (Windows)

1. **Manifest-based** (preferred):
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}` → `MessageFileName`
2. **Classic**:
   `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\{ProviderName}` → `EventMessageFile`
3. **MUI fallback**: if the DLL itself is absent, tries `{dll_dir}\en-US\{dll}.mui`.

### Substitution sequences

| Sequence | Result |
|----------|--------|
| `%1`–`%99` | Parameter value (1-indexed); left as-is if out of range |
| `%%` | Literal `%` |
| `%n` | `\r\n` |
| `%r` | `\r` |
| `%t` | `\t` |
| `%b` | Space |
| `%0` | Truncate output here |

### Future offline extension

Add `src/sqlite_resolver.rs` implementing `MessageResolver` and push it onto
`ChainedResolver` — no other changes required.  On non-Windows, the registry resolver is
excluded at compile time; only the SQLite resolver is used.

## Build & Run

```bash
cargo build --release
cargo run -- path/to/Security.evtx
```

## Development

```bash
cargo test                  # run all unit tests (26 tests, no Windows required)
cargo clippy -- -D warnings # lint
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `evtx = "0.11.2"` | `.evtx` binary format parser |
| `pelite = "0.10"` | PE resource extraction (RT_MESSAGETABLE) |
| `winreg = "0.56"` | Windows registry access (`cfg(windows)` only) |
| `anyhow = "1"` | Application-level error handling |
| `thiserror = "2"` | Library-facing `ResolveError` type |
| `serde_json = "1"` | JSON parsing of evtx record data |

## License

MIT
