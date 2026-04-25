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
        let v: serde_json::Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"));

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
/// Also warns about records whose message still contains unresolved `%N` placeholders.
fn print_summary(label: &str, lines: &[String], n: usize) {
    let total = lines.len();
    let resolved: Vec<serde_json::Value> = lines
        .iter()
        .filter_map(|l| serde_json::from_str(l).ok())
        .filter(|v: &serde_json::Value| v.get("message").map(|m| !m.is_null()).unwrap_or(false))
        .collect();

    // Detect messages that still contain %1..%99 placeholders.
    let placeholder_re = |s: &str| -> bool {
        let b = s.as_bytes();
        let mut i = 0;
        while i + 1 < b.len() {
            if b[i] == b'%' && b[i + 1].is_ascii_digit() && b[i + 1] != b'0' {
                return true;
            }
            i += 1;
        }
        false
    };
    let unresolved_placeholders: Vec<&serde_json::Value> = resolved
        .iter()
        .filter(|v| v["message"].as_str().map(placeholder_re).unwrap_or(false))
        .collect();

    println!(
        "\n=== {label} ===\n  total records       : {total}\n  resolved            : {}\n  still has %N        : {}",
        resolved.len(),
        unresolved_placeholders.len(),
    );

    if !unresolved_placeholders.is_empty() {
        println!("  --- records with unresolved placeholders (first 3) ---");
        println!("  NOTE: unresolved %N indicates the provider's message template");
        println!("        references a parameter index that was not present in EventData.");
        println!("        e.g. docker EventID 11 has template '[%2]' but only supplies");
        println!("        one string param → %2 stays unresolved.  This is a provider");
        println!("        behaviour, not a parser bug.");
        for v in unresolved_placeholders.iter().take(3) {
            let event_id = v["event_id"].as_u64().unwrap_or(0);
            let provider = v["provider"].as_str().unwrap_or("");
            let message = v["message"].as_str().unwrap_or("");
            let params = v["params"].as_array().map(|a| a.len()).unwrap_or(0);
            let preview: String = message.chars().take(200).collect();
            println!("  [{event_id}] {provider}  (extracted params: {params})\n    {preview}");
        }
    }

    println!("  --- first {n} resolved messages ---");
    for v in resolved.iter().take(n) {
        let event_id = v["event_id"].as_u64().unwrap_or(0);
        let provider = v["provider"].as_str().unwrap_or("");
        let message = v["message"]
            .as_str()
            .unwrap_or("")
            .replace('\n', "↵")
            .replace('\r', "");
        let preview: String = message.chars().take(120).collect();
        let ellipsis = if message.chars().count() > 120 {
            "…"
        } else {
            ""
        };
        println!("  [{event_id}] {provider}\n    {preview}{ellipsis}");
    }
}

/// Dump raw evtx JSON for the first few records to diagnose EventData structure.
#[test]
fn dump_raw_eventdata_structure() {
    use evtx::EvtxParser;

    for (label, path) in [
        (SYSTEM_LOG, "System.evtx"),
        (APPLICATION_LOG, "Application.evtx"),
    ] {
        let mut parser = EvtxParser::from_path(label).expect("open evtx");
        println!("\n=== Raw EventData JSON — {path} (first 10 records) ===");
        let mut count = 0;
        for record in parser.records_json() {
            if count >= 10 {
                break;
            }
            if let Ok(r) = record {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.data) {
                    let event = v.get("Event");
                    let event_data =
                        event.and_then(|e| e.get("EventData").or_else(|| e.get("UserData")));
                    let event_id = event
                        .and_then(|e| e.get("System"))
                        .and_then(|s| s.get("EventID"))
                        .and_then(|id| {
                            id.as_u64()
                                .or_else(|| id.get("#text").and_then(|t| t.as_u64()))
                        })
                        .unwrap_or(0);
                    println!(
                        "  EventID={event_id}  EventData={}",
                        serde_json::to_string(&event_data).unwrap_or_default()
                    );
                }
                count += 1;
            }
        }
    }

    // Also dump docker events specifically (they have unresolved %2)
    println!("\n=== Application.evtx — docker event 11 (first 2) ===");
    let mut parser = evtx::EvtxParser::from_path(APPLICATION_LOG).expect("open Application.evtx");
    let mut count = 0;
    for record in parser.records_json() {
        if count >= 2 {
            break;
        }
        if let Ok(r) = record {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&r.data) {
                let is_docker_11 = v
                    .get("Event")
                    .and_then(|e| e.get("System"))
                    .and_then(|s| s.get("EventID"))
                    .and_then(|id| {
                        id.as_u64()
                            .or_else(|| id.get("#text").and_then(|t| t.as_u64()))
                    })
                    == Some(11)
                    && v.get("Event")
                        .and_then(|e| e.get("System"))
                        .and_then(|s| s.get("Provider"))
                        .and_then(|p| p.get("#attributes"))
                        .and_then(|a| a.get("Name"))
                        .and_then(|n| n.as_str())
                        == Some("docker");
                if is_docker_11 {
                    println!(
                        "  full JSON: {}",
                        serde_json::to_string(&v).unwrap_or_default()
                    );
                    count += 1;
                }
            }
        }
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

    assert!(
        !lines.is_empty(),
        "expected output when given a logs directory"
    );

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
