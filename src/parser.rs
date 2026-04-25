use std::path::Path;

use evtx::EvtxParser;
use serde_json::Value;

use crate::error::ResolveError;

/// Structured representation of a single `.evtx` record.
#[derive(Debug, Clone)]
pub struct EvtxRecord {
    /// The name of the event provider (e.g. `"Microsoft-Windows-Security-Auditing"`).
    pub provider_name: String,
    /// The provider GUID, if present (e.g. `"{54849625-5478-4994-A5BA-3E3B0328C30D}"`).
    pub provider_guid: Option<String>,
    /// The numeric Event ID.
    pub event_id: u32,
    /// Ordered substitution parameters: `params[0]` → `%1`, `params[1]` → `%2`, …
    pub params: Vec<String>,
}

/// Parse a single record from its JSON representation produced by the `evtx` crate.
///
/// # Errors
/// Returns [`ResolveError::JsonParse`] if required fields are missing or malformed.
pub fn parse_record(json: &str) -> Result<EvtxRecord, ResolveError> {
    let root: Value =
        serde_json::from_str(json).map_err(|e| ResolveError::JsonParse(e.to_string()))?;

    let system = root
        .get("Event")
        .and_then(|e| e.get("System"))
        .ok_or_else(|| ResolveError::JsonParse("missing Event.System".to_string()))?;

    let provider_attrs = system
        .get("Provider")
        .and_then(|p| p.get("#attributes"))
        .ok_or_else(|| ResolveError::JsonParse("missing Provider #attributes".to_string()))?;

    let provider_name = provider_attrs
        .get("Name")
        .and_then(Value::as_str)
        .ok_or_else(|| ResolveError::JsonParse("missing Provider Name".to_string()))?
        .to_string();

    let provider_guid = provider_attrs
        .get("Guid")
        .and_then(Value::as_str)
        .map(str::to_string);

    // EventID may be a plain integer or `{"#text": N, "#attributes": {...}}`.
    let event_id_val = system
        .get("EventID")
        .ok_or_else(|| ResolveError::JsonParse("missing EventID".to_string()))?;

    let event_id: u32 = if let Some(n) = event_id_val.as_u64() {
        n as u32
    } else if let Some(n) = event_id_val.get("#text").and_then(Value::as_u64) {
        n as u32
    } else {
        return Err(ResolveError::JsonParse("invalid EventID".to_string()));
    };

    let params = extract_params(&root);

    Ok(EvtxRecord {
        provider_name,
        provider_guid,
        event_id,
        params,
    })
}

/// Extract substitution parameters from `Event.EventData` or `Event.UserData`.
///
/// evtx produces three distinct `EventData` shapes (plus `UserData`):
///
/// 1. **`Data` key present** – whenever `EventData.Data` exists (even `null`) it is the
///    authoritative source for substitution parameters and is returned directly.
///    Named entries: `{"Data": [{"#attributes":{"Name":"p1"}, "#text":"v1"}, ...]}`
///    Unnamed entries: `{"Data": ["v1", "v2"]}` or `{"Data": "v1"}`
///    No strings logged: `{"Data": null}` → returns `[]`.
///
/// 2. **Flat EventData** – manifested / ETW events where named fields are direct children
///    (no `Data` sub-key): `{"param1":"v1", "param2":"v2", ...}`
///    Metadata-only keys (`#attributes`) and raw binary blobs (`Binary`) are excluded;
///    `Binary` corresponds to `lpRawData` in `ReportEvent` and is **not** a FormatMessage
///    substitution parameter.
///
/// 3. **UserData** – Task Scheduler and similar providers:
///    `{"ElementName": {"#attributes":{...}, "Field1":"v1", "Field2":"v2"}}`
///
/// Parameters are collected in JSON document order, which the evtx crate preserves
/// (it enables serde_json's `preserve_order` feature).
fn extract_params(root: &Value) -> Vec<String> {
    let event = root.get("Event");

    // ── Shape 1: EventData.Data key present ─────────────────────────────────
    // If the `Data` key exists at all (even null/empty), treat it as the sole
    // source of substitution parameters.  Do NOT fall through to flat extraction
    // when Data is null — other sibling keys (e.g. `Binary`) are not params.
    if let Some(event_data) = event.and_then(|e| e.get("EventData")) {
        if let Some(data) = event_data.get("Data") {
            return collect_data_params(data);
        }

        // ── Shape 2: Flat EventData (no `Data` sub-key) ──────────────────────
        // `Binary` = lpRawData from ReportEvent; excluded intentionally.
        if let Value::Object(map) = event_data {
            let params: Vec<String> = map
                .iter()
                .filter(|(k, _)| {
                    let k = k.as_str();
                    k != "#attributes" && k != "Binary"
                })
                .map(|(_, v)| scalar_to_param(v))
                .collect();
            if !params.is_empty() {
                return params;
            }
        }
    }

    // ── Shape 3: UserData ────────────────────────────────────────────────────
    // UserData has one named child whose direct (non-`#attributes`) children are params.
    if let Some(Value::Object(ud_map)) = event.and_then(|e| e.get("UserData")) {
        for (_, child) in ud_map.iter() {
            if let Value::Object(child_map) = child {
                let params: Vec<String> = child_map
                    .iter()
                    .filter(|(k, _)| k.as_str() != "#attributes")
                    .map(|(_, v)| scalar_to_param(v))
                    .collect();
                if !params.is_empty() {
                    return params;
                }
            }
        }
    }

    vec![]
}

/// Convert a scalar (or `{"#text":...}` object) JSON value to a substitution parameter string.
///
/// - String / Number / Bool → their string representation
/// - Null → empty string (preserves positional slot)
/// - Object with `"#text"` → the `#text` value converted to string
/// - Other → empty string
fn scalar_to_param(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => String::new(),
        Value::Object(_) => {
            // {"#attributes":{...}, "#text": "value"} pattern
            if let Some(text) = v.get("#text") {
                match text {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => String::new(),
                }
            } else {
                String::new()
            }
        }
        Value::Array(_) => v.to_string(),
    }
}

/// Collect params from an `EventData.Data` value (named `{"#text":...}` objects or plain strings).
fn collect_data_params(data: &Value) -> Vec<String> {
    match data {
        Value::Null => vec![],
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr.iter().map(scalar_to_param).collect(),
        other => vec![scalar_to_param(other)],
    }
}

/// Iterate over every record in an `.evtx` file, yielding structured [`EvtxRecord`]s.
///
/// # Errors
/// Each item is a `Result`; individual record parse failures are surfaced per-item.
pub fn records_from_path(path: &Path) -> impl Iterator<Item = Result<EvtxRecord, ResolveError>> {
    // Build the parser eagerly; propagate open errors as the first item.
    let parser_result = EvtxParser::from_path(path).map_err(ResolveError::EvtxParse);

    let records: Box<dyn Iterator<Item = Result<EvtxRecord, ResolveError>>> = match parser_result {
        Err(e) => Box::new(std::iter::once(Err(e))),
        Ok(mut parser) => {
            let items: Vec<_> = parser
                .records_json()
                .map(|r| {
                    r.map_err(ResolveError::EvtxParse)
                        .and_then(|rec| parse_record(&rec.data))
                })
                .collect();
            Box::new(items.into_iter())
        }
    };

    records
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_json(name: &str, guid: Option<&str>, event_id: u64, data: &str) -> String {
        let guid_field = match guid {
            Some(g) => format!(r#","Guid":"{g}""#),
            None => String::new(),
        };
        // Use r##"..."## so that interior `"#` sequences don't terminate the literal.
        format!(
            r##"{{
  "Event": {{
    "System": {{
      "Provider": {{"#attributes": {{"Name": "{name}"{guid_field}}}}},
      "EventID": {event_id}
    }},
    "EventData": {{"Data": {data}}}
  }}
}}"##
        )
    }

    #[test]
    fn parse_basic_fields() {
        let json = make_json(
            "Microsoft-Windows-Security-Auditing",
            Some("{54849625-5478-4994-A5BA-3E3B0328C30D}"),
            4624,
            r#"["alice","WORKSTATION"]"#,
        );
        let rec = parse_record(&json).unwrap();
        assert_eq!(rec.provider_name, "Microsoft-Windows-Security-Auditing");
        assert_eq!(
            rec.provider_guid.as_deref(),
            Some("{54849625-5478-4994-A5BA-3E3B0328C30D}")
        );
        assert_eq!(rec.event_id, 4624);
        assert_eq!(rec.params, vec!["alice", "WORKSTATION"]);
    }

    #[test]
    fn parse_no_guid() {
        let json = make_json("MyProvider", None, 1000, r#""single""#);
        let rec = parse_record(&json).unwrap();
        assert!(rec.provider_guid.is_none());
        assert_eq!(rec.params, vec!["single"]);
    }

    #[test]
    fn parse_no_event_data() {
        // Build JSON string without raw-string literals to avoid "#" termination issues.
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":1}}}";
        let rec = parse_record(json).unwrap();
        assert!(rec.params.is_empty());
    }

    #[test]
    fn parse_data_numeric_text() {
        // evtx produces #text as a JSON number (e.g. LogonType: 3).
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":4624},\"EventData\":{\"Data\":[{\"#attributes\":{\"Name\":\"LogonType\"},\"#text\":3}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["3"]);
    }

    #[test]
    fn parse_data_object_with_text_string() {
        // Named Data entries where #text is a string.
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":7036},\"EventData\":{\"Data\":[{\"#attributes\":{\"Name\":\"param1\"},\"#text\":\"Spooler\"},{\"#attributes\":{\"Name\":\"param2\"},\"#text\":\"running\"}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["Spooler", "running"]);
    }

    #[test]
    fn parse_data_object_no_text_returns_empty_string() {
        // Object with only #attributes and no #text → empty param string.
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":1},\"EventData\":{\"Data\":[{\"#attributes\":{\"Name\":\"x\"}}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec![""]);
    }

    // ── Binary field exclusion ───────────────────────────────────────────────

    /// `Binary` in EventData is raw lpRawData from ReportEvent — NOT a FormatMessage
    /// substitution parameter.  It must not appear in `params`.
    #[test]
    fn binary_field_excluded_from_flat_params() {
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":1},\"EventData\":{\"param1\":\"hello\",\"Binary\":\"DEADBEEF\"}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["hello"]);
    }

    /// When EventData contains only a `Binary` key (no string params), params should be empty.
    #[test]
    fn binary_only_eventdata_gives_empty_params() {
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":1},\"EventData\":{\"Binary\":\"DEADBEEF\"}}}";
        let rec = parse_record(json).unwrap();
        assert!(
            rec.params.is_empty(),
            "expected empty params, got: {:?}",
            rec.params
        );
    }

    /// When `Data` is null alongside a `Binary` key, the Binary must not bleed into params.
    /// This covers the classic-event pattern: no string args + binary data only.
    #[test]
    fn data_null_with_binary_gives_empty_params() {
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":11},\"EventData\":{\"Data\":null,\"Binary\":\"DEADBEEF\"}}}";
        let rec = parse_record(json).unwrap();
        assert!(
            rec.params.is_empty(),
            "expected empty params, got: {:?}",
            rec.params
        );
    }

    #[test]
    fn parse_missing_system_returns_error() {
        let json = r#"{"Event": {}}"#;
        assert!(parse_record(json).is_err());
    }

    #[test]
    fn parse_event_id_with_attributes() {
        // Some providers wrap EventID: {"#text": 4625, "#attributes": {"Qualifiers": "0"}}
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":{\"#text\":4625,\"#attributes\":{\"Qualifiers\":\"0\"}}}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.event_id, 4625);
    }
}
