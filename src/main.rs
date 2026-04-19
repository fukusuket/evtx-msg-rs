// On non-Windows, several items exist solely for the Windows resolver path and
// are intentionally unused on the current platform.
#![cfg_attr(not(windows), allow(dead_code))]

mod error;
mod parser;
mod pe_resource;
mod resolver;
mod substitution;

#[cfg(windows)]
mod registry;

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use anyhow::Context;

use parser::records_from_path;
use resolver::{ChainedResolver, MessageResolver, NullResolver};

fn main() -> anyhow::Result<()> {
    let path: PathBuf = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .context("Usage: evtx-msg-rs <evtx_file_or_dir>")?;

    let resolver = build_resolver();

    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for evtx_path in collect_evtx_paths(&path)? {
        process_file(&evtx_path, &resolver, &mut out)?;
    }

    Ok(())
}

/// Collect `.evtx` file paths to process.
///
/// - If `path` is a file, returns that single path.
/// - If `path` is a directory, returns all `*.evtx` files found recursively.
fn collect_evtx_paths(path: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if path.is_file() {
        return Ok(vec![path.to_path_buf()]);
    }

    if path.is_dir() {
        let mut paths = Vec::new();
        collect_evtx_recursive(path, &mut paths)?;
        paths.sort();
        return Ok(paths);
    }

    anyhow::bail!("path does not exist: {}", path.display());
}

/// Recursively walk `dir` and collect files with a `.evtx` extension.
fn collect_evtx_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("cannot read directory: {}", dir.display()))?
    {
        let entry = entry.with_context(|| format!("cannot read entry in: {}", dir.display()))?;
        let p = entry.path();
        if p.is_dir() {
            collect_evtx_recursive(&p, out)?;
        } else if p.extension().and_then(|e| e.to_str()) == Some("evtx") {
            out.push(p);
        }
    }
    Ok(())
}

/// Parse all records in `path` and write resolved JSON lines to `out`.
fn process_file(
    path: &Path,
    resolver: &ChainedResolver,
    out: &mut impl Write,
) -> anyhow::Result<()> {
    let file_str = path.display().to_string();

    for result in records_from_path(path) {
        let record = match result {
            Ok(r) => r,
            Err(e) => {
                eprintln!("warn: {file_str}: skipping record: {e}");
                continue;
            }
        };

        let message = match resolver.resolve(&record) {
            Ok(Some(msg)) => format!("{msg:?}"),
            Ok(None) => "null".to_string(),
            Err(e) => {
                eprintln!(
                    "warn: {file_str}: resolve failed for event {}: {e}",
                    record.event_id
                );
                "null".to_string()
            }
        };

        writeln!(
            out,
            r#"{{"event_id":{id},"provider":{prov:?},"file":{file_str:?},"message":{message}}}"#,
            id = record.event_id,
            prov = record.provider_name,
        )?;
    }

    Ok(())
}

/// Build the resolver chain appropriate for the current platform.
fn build_resolver() -> ChainedResolver {
    #[cfg(windows)]
    {
        ChainedResolver::new(vec![
            Box::new(registry::RegistryResolver::new()),
        ])
    }
    #[cfg(not(windows))]
    {
        ChainedResolver::new(vec![Box::new(NullResolver) as Box<dyn MessageResolver>])
    }
}
