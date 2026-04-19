//! Integration tests for Windows online message resolution.
//!
//! These tests require a live Windows environment and are compiled only on Windows.
//! They exercise the full pipeline:
//!   evtx file → parse → registry lookup → PE resource → substitution → resolved message

#![cfg(windows)]

use std::process::Command;

/// Path to a Windows system log that always exists on any Windows Server / Desktop install.
const SYSTEM_LOG: &str = r"C:\Windows\System32\winevt\Logs\System.evtx";
const APPLICATION_LOG: &str = r"C:\Windows\System32\winevt\Logs\Application.evtx";

/// Run the binary against an evtx file and return stdout lines.
fn run_binary(evtx_path: &str) -> Vec<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_evtx-msg-rs"))
        .arg(evtx_path)
        .output()
        .expect("failed to execute binary");

    assert!(
        output.status.success() || !output.stdout.is_empty(),
        "binary exited with status {} and empty stdout\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_string)
        .filter(|l| !l.is_empty())
        .collect()
}

/// Verify that every output line is valid JSON with the expected keys.
fn assert_valid_json_lines(lines: &[String]) {
    assert!(!lines.is_empty(), "expected at least one output line");

    for line in lines {
        let v: serde_json::Value =
            serde_json::from_str(line).unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"));

        assert!(v.get("event_id").is_some(), "missing event_id in: {line}");
        assert!(v.get("provider").is_some(), "missing provider in: {line}");
        assert!(v.get("file").is_some(), "missing file in: {line}");
        assert!(v.get("message").is_some(), "missing message key in: {line}");
    }
}

/// At least one record in the output must have a non-null resolved message.
fn assert_some_resolved(lines: &[String]) {
    let resolved: Vec<&String> = lines
        .iter()
        .filter(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v.get("message").cloned())
                .map(|m| !m.is_null())
                .unwrap_or(false)
        })
        .collect();

    assert!(
        !resolved.is_empty(),
        "expected at least one resolved (non-null) message in output"
    );
}

/// Print a summary: total records, resolved count, and up to `n` resolved samples.
fn print_summary(label: &str, lines: &[String], n: usize) {
    let total = lines.len();
    let resolved: Vec<serde_json::Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|v: &serde_json::Value| {
            v.get("message").map(|m| !m.is_null()).unwrap_or(false)
        })
        .collect();

    println!(
        "\n=== {label} ===\n  total records : {total}\n  resolved      : {}",
        resolved.len()
    );

    println!("  --- first {n} resolved messages ---");
    for v in resolved.iter().take(n) {
        let event_id = v["event_id"].as_u64().unwrap_or(0);
        let provider = v["provider"].as_str().unwrap_or("");
        let message = v["message"].as_str().unwrap_or("").replace('\n', "↵").replace('\r', "");
        // Truncate long messages for readability.
        let preview: String = message.chars().take(120).collect();
        let ellipsis = if message.chars().count() > 120 { "…" } else { "" };
        println!("  [{event_id}] {provider}\n    {preview}{ellipsis}");
    }
}

#[test]
fn system_log_produces_valid_json() {
    let lines = run_binary(SYSTEM_LOG);
    print_summary("System.evtx — JSON validity", &lines, 3);
    assert_valid_json_lines(&lines);
}

#[test]
fn system_log_has_resolved_messages() {
    let lines = run_binary(SYSTEM_LOG);
    print_summary("System.evtx — resolved messages", &lines, 5);
    assert_some_resolved(&lines);
}

#[test]
fn application_log_produces_valid_json() {
    let lines = run_binary(APPLICATION_LOG);
    print_summary("Application.evtx — JSON validity", &lines, 3);
    assert_valid_json_lines(&lines);
}

#[test]
fn directory_input_processes_multiple_files() {
    let dir = r"C:\Windows\System32\winevt\Logs";
    let output = Command::new(env!("CARGO_BIN_EXE_evtx-msg-rs"))
        .arg(dir)
        .output()
        .expect("failed to execute binary");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();

    assert!(!lines.is_empty(), "expected output when given a logs directory");

    let files: std::collections::HashSet<String> = lines
        .iter()
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v.get("file").and_then(|f| f.as_str()).map(str::to_string))
        })
        .collect();

    println!("\n=== Directory input ===");
    println!("  total records : {}", lines.len());
    println!("  distinct files: {}", files.len());
    let mut sorted_files: Vec<&String> = files.iter().collect();
    sorted_files.sort();
    for f in &sorted_files {
        println!("    {f}");
    }

    assert!(
        files.len() > 1,
        "expected records from multiple .evtx files, got: {files:?}"
    );
}
