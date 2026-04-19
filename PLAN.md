# Implementation Plan: Online Message Resolution (Windows-only)

## Overview

Implement full Windows Event Log message resolution for `.evtx` records on Windows,
with an architecture that allows future offline/cross-platform resolution via a DB backend.

### Design Decisions

- **Out-of-range substitution params** (`%N` where N > params.len()): leave the placeholder as-is (do not error).
- **CLI options**: minimal — just `<evtx_file>` positional argument for now.
- **Dependency versions**: use latest stable at time of implementation.

---

## Module Layout

```
src/
  main.rs          # CLI entry point
  error.rs         # ResolveError (thiserror)
  parser.rs        # evtx wrapper → EvtxRecord
  resolver.rs      # MessageResolver trait + ChainedResolver + NullResolver
  registry.rs      # cfg(windows): registry → DLL path resolution
  pe_resource.rs   # pelite: RT_MESSAGETABLE → message template
  substitution.rs  # FormatMessage-compatible %N / %b / %n / %r / %t / %% substitution
```

---

## Cargo.toml Dependencies

```toml
[dependencies]
evtx       = "0.11.2"
anyhow     = "1"         # explicit direct dep (already in tree via evtx)
thiserror  = "2"         # explicit direct dep (already in tree via evtx)
serde_json = "1"         # explicit direct dep (already in tree via evtx)
pelite     = "0.10"      # PE/MUI resource parsing — Pure Rust, zero unsafe surface

[target.'cfg(windows)'.dependencies]
winreg = "0.56"          # Windows registry access — Windows-only
```

---

## Phase 1 — `error.rs`: Shared Error Type

### Test first (Red)
- `ResolveError::ProviderNotFound("foo")` displays `"provider not found: foo"`.
- `ResolveError` implements `std::error::Error` (can be converted to `anyhow::Error` via `?`).

### Implementation (Green)

```rust
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    #[error("message ID {0:#010x} not found in resource")]
    MessageIdNotFound(u32),

    #[error("PE resource error: {0}")]
    PeResource(String),

    #[error("registry error: {0}")]
    Registry(String),

    #[error(transparent)]
    EvtxParse(#[from] evtx::err::EvtxError),
}
```

---

## Phase 2 — `parser.rs`: EvtxRecord Parser

### Test first (Red)
- `parse_record(json)` on a valid JSON string extracts `provider_name`, `provider_guid`, `event_id`, `params` correctly.
- Missing required fields return an appropriate error.

### Implementation (Green)

```rust
/// Structured representation of a single .evtx record.
pub struct EvtxRecord {
    pub provider_name: String,
    pub provider_guid: Option<String>, // "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"
    pub event_id: u32,
    pub params: Vec<String>,           // ordered list for %1, %2, ...
}

/// Parse a single record from its JSON representation (from evtx crate).
pub fn parse_record(json: &str) -> Result<EvtxRecord, ResolveError>;

/// Iterate over all records in an .evtx file.
pub fn records_from_path(path: &Path)
    -> impl Iterator<Item = Result<EvtxRecord, ResolveError>>;
```

JSON field mapping:
- `Event.System.Provider["#attributes"]["Name"]` → `provider_name`
- `Event.System.Provider["#attributes"]["Guid"]` → `provider_guid`
- `Event.System.EventID` → `event_id`
- `Event.EventData.Data[]` (array) or `Event.EventData.Data` (single) → `params`

---

## Phase 3 — `resolver.rs`: MessageResolver Trait

### Test first (Red)
- `NullResolver::resolve(record)` always returns `Ok(None)`.
- `ChainedResolver` with all `NullResolver`s returns `Ok(None)`.
- `ChainedResolver` returns the first `Ok(Some(_))` result from the chain.
- An `Err` from one resolver causes `ChainedResolver` to propagate the error (do **not** silently skip errors).

### Implementation (Green)

```rust
/// Common interface for online and offline message resolution.
/// Future offline implementations (e.g., SqliteResolver) implement this trait.
pub trait MessageResolver {
    fn resolve(&self, record: &EvtxRecord) -> Result<Option<String>, ResolveError>;
}

/// Test stub — always returns Ok(None).
pub struct NullResolver;

/// Tries resolvers in order; returns the first Ok(Some(_)) or Ok(None) if all miss.
/// Propagates the first Err encountered.
pub struct ChainedResolver {
    resolvers: Vec<Box<dyn MessageResolver>>,
}

impl ChainedResolver {
    pub fn new(resolvers: Vec<Box<dyn MessageResolver>>) -> Self;
    pub fn push(&mut self, resolver: Box<dyn MessageResolver>);
}
```

> **Future extension point**: add `OfflineDbResolver` (SQLite) to `ChainedResolver` without
> changing any existing code. On non-Windows, omit `RegistryResolver` and use only
> `SqliteResolver`.

---

## Phase 4 — `substitution.rs`: FormatMessage-Compatible Substitution

### Test first (Red) — table-driven

| Template                   | Params              | Expected                  |
|----------------------------|---------------------|---------------------------|
| `"Service %1 started."`    | `["Spooler"]`       | `"Service Spooler started."` |
| `"Error %1: %2"`           | `["5", "Access denied"]` | `"Error 5: Access denied"` |
| `"100%%"`                  | `[]`                | `"100%"`                  |
| `"Line1%nLine2"`           | `[]`                | `"Line1\r\nLine2"`        |
| `"Col1%tCol2"`             | `[]`                | `"Col1\tCol2"`            |
| `"%b"`                     | `[]`                | `" "`                     |
| `"%r"`                     | `[]`                | `"\r"`                    |
| `"msg%0trailing"`          | `[]`                | `"msg"`                   |
| `"%3"` (only 1 param)      | `["a"]`             | `"%3"` (left as-is)       |

### Implementation (Green)

```rust
/// Perform FormatMessage-compatible parameter substitution.
///
/// Substitution sequences:
/// - `%1`–`%99` : replaced with `params[N-1]`; left as-is if index out of range.
/// - `%%`       : literal `%`
/// - `%n`       : `\r\n`
/// - `%r`       : `\r`
/// - `%t`       : `\t`
/// - `%b`       : ` ` (space)
/// - `%0`       : truncate output at this point (suppress trailing newline)
pub fn substitute(template: &str, params: &[&str]) -> String;
```

- Single-pass character scan using `write!` into a `String` buffer.
- `%N` matching is greedy up to 2 digits (e.g., `%12` → param 12, not param 1 + "2").

---

## Phase 5 — `pe_resource.rs`: PE Resource Extraction

### Test first (Red)
- Minimal hand-crafted `RT_MESSAGETABLE` byte fixture → `extract_message(bytes, event_id)` returns the correct template string.
- UTF-16LE entry is decoded correctly.
- ANSI entry is decoded correctly.
- Non-existent `event_id` returns `Err(ResolveError::MessageIdNotFound(_))`.

### Implementation (Green)

```rust
/// Extract the message template for `event_id` from a PE binary (DLL/EXE/MUI).
///
/// Returns `Err(ResolveError::MessageIdNotFound)` if the ID is absent.
pub fn extract_message(pe_bytes: &[u8], event_id: u32) -> Result<String, ResolveError>;
```

Algorithm:
1. `pelite::PeFile::from_bytes(pe_bytes)` → navigate to resource directory.
2. Find `RT_MESSAGETABLE` (type ID = 11).
3. Parse `MESSAGE_RESOURCE_DATA` → iterate blocks (`LowId`..`HighId`).
4. Locate the block containing `event_id & 0x0000_FFFF`, compute entry offset.
5. Read `MESSAGE_RESOURCE_ENTRY`: `Flags == 0x0001` → UTF-16LE, `0x0000` → ANSI.
6. Decode and return the text (strip trailing `\0`, `\r\n`).

Notes:
- If `unsafe` is required for raw byte casting, add `// SAFETY:` comment.
- MUI fallback is handled in `registry.rs`, not here; this function is pure PE parsing.

---

## Phase 6 — `registry.rs`: Registry DLL Path Resolution (Windows-only)

### Test first (Red)
- Abstract registry access behind a `RegistryProvider` trait to enable unit-test mocking.
- Mock: GUID key present → `resolve_dll_path` returns the mocked path.
- Mock: GUID key absent, classic key present → falls back to classic path.
- `%SystemRoot%` in path value is expanded correctly.
- MUI fallback: if DLL path does not exist, `{dir}\en-US\{dll}.mui` is tried.

### Implementation (Green)

```rust
#[cfg(windows)]
pub struct RegistryResolver;

#[cfg(windows)]
impl RegistryResolver {
    pub fn new() -> Self;
}

#[cfg(windows)]
impl MessageResolver for RegistryResolver {
    fn resolve(&self, record: &EvtxRecord) -> Result<Option<String>, ResolveError> {
        // 1. Locate DLL via registry (manifest-based GUID key preferred, classic fallback)
        // 2. Expand %SystemRoot% / %WinDir% in path
        // 3. Try DLL path; if not found, try MUI fallback ({dir}\en-US\{dll}.mui)
        // 4. Read DLL bytes → pe_resource::extract_message(bytes, record.event_id)
        // 5. substitution::substitute(template, &record.params)
        // 6. Return Ok(Some(resolved_message))
    }
}
```

Registry lookup order:
1. **Manifest-based** (preferred):
   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{GUID}` → `MessageFileName`
2. **Classic**:
   `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\{ProviderName}` → `EventMessageFile`

MUI fallback path: `{dll_dir}\en-US\{dll_filename}.mui`

---

## Phase 7 — CLI Integration (`main.rs`)

### Test first (Red)
- Integration test (`tests/`): `cfg(windows)` only — feed a real `.evtx` file, assert non-empty output.
- `cfg(not(windows))`: running with `NullResolver` does not panic; unresolved records are output with a placeholder message.

### Implementation (Green)

```
USAGE: evtx-msg-rs <evtx_file>
```

Orchestration:
```
records_from_path(path)
  → ChainedResolver::resolve(record)
      Windows:     RegistryResolver → pe_resource → substitution
      non-Windows: NullResolver
  → print to BufWriter<Stdout>
```

Output format (minimal, one JSON object per line):
```json
{"record_id": 1, "event_id": 4624, "provider": "...", "message": "..."}
```
If message resolution returns `None` or fails, `"message"` is `null`.

---

## Future Offline Extension Points

| Addition | How |
|---|---|
| SQLite offline DB | Add `src/sqlite_resolver.rs` implementing `MessageResolver`; no other changes needed |
| Online → Offline fallback | `ChainedResolver::new(vec![Box::new(RegistryResolver::new()), Box::new(SqliteResolver::open(db_path)?)])` |
| DB-builder tool | Subcommand or separate binary: walk registry + DLLs on Windows → export to SQLite |
| Cross-platform analysis | `cfg(windows)` excludes `RegistryResolver`; only `SqliteResolver` is used |

---

## TDD Checklist (per phase)

- [ ] Write failing test (`cargo test` shows red)
- [ ] Write minimal implementation (`cargo test` shows green)
- [ ] Refactor; confirm `cargo test` still green
- [ ] `cargo clippy -- -D warnings` passes
- [ ] All public items have `///` doc comments

