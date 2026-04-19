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
    let root: Value = serde_json::from_str(json)
        .map_err(|e| ResolveError::JsonParse(e.to_string()))?;

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
    } else if let Some(n) = event_id_val
        .get("#text")
        .and_then(Value::as_u64)
    {
        n as u32
    } else {
        return Err(ResolveError::JsonParse("invalid EventID".to_string()));
    };

    let params = extract_params(&root);

    Ok(EvtxRecord { provider_name, provider_guid, event_id, params })
}

/// Extract substitution parameters from `Event.EventData.Data`.
///
/// Handles three shapes:
/// - missing / null → empty list
/// - single string → one-element list
/// - array of strings or objects with `"#text"` → ordered list
fn extract_params(root: &Value) -> Vec<String> {
    let data = root
        .get("Event")
        .and_then(|e| e.get("EventData"))
        .and_then(|ed| ed.get("Data"));

    match data {
        None => vec![],
        Some(Value::Null) => vec![],
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone(),
                Value::Object(_) => v
                    .get("#text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                _ => v.to_string(),
            })
            .collect(),
        Some(other) => vec![other.to_string()],
    }
}

/// Iterate over every record in an `.evtx` file, yielding structured [`EvtxRecord`]s.
///
/// # Errors
/// Each item is a `Result`; individual record parse failures are surfaced per-item.
pub fn records_from_path(
    path: &Path,
) -> impl Iterator<Item = Result<EvtxRecord, ResolveError>> {
    // Build the parser eagerly; propagate open errors as the first item.
    let parser_result = EvtxParser::from_path(path).map_err(ResolveError::EvtxParse);

    let records: Box<dyn Iterator<Item = Result<EvtxRecord, ResolveError>>> =
        match parser_result {
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






