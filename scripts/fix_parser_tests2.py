import pathlib, re

path = pathlib.Path('/Users/fukusuke/Scripts/Rust/evtx-msg-rs/src/parser.rs')
src = path.read_text()

# Replace everything from the first new test to the end of mod tests
# with a clean version.
start_marker = '    #[test]\n    fn parse_data_numeric_text() {'
end_marker = '}\n'  # closing brace of mod tests

start_idx = src.find(start_marker)
# Find the closing } of mod tests after start_idx
# The mod tests block ends at the last top-level } after #[cfg(test)]
# Simple approach: find '}\n' after the parse_event_id_with_attributes test
after_event_id = src.find('    fn parse_event_id_with_attributes()', start_idx)
end_idx = src.find('\n}', after_event_id) + 2  # include the \n}

new_tests = '''    #[test]
    fn parse_data_numeric_text() {
        // evtx produces #text as a JSON number (e.g. LogonType: 3).
        let json = "{\\"Event\\":{\\"System\\":{\\"Provider\\":{\\"#attributes\\":{\\"Name\\":\\"P\\"}},\\"EventID\\":4624},\\"EventData\\":{\\"Data\\":[{\\"#attributes\\":{\\"Name\\":\\"LogonType\\"},\\"#text\\":3}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["3"]);
    }

    #[test]
    fn parse_data_object_with_text_string() {
        // Named Data entries where #text is a string.
        let json = "{\\"Event\\":{\\"System\\":{\\"Provider\\":{\\"#attributes\\":{\\"Name\\":\\"P\\"}},\\"EventID\\":7036},\\"EventData\\":{\\"Data\\":[{\\"#attributes\\":{\\"Name\\":\\"param1\\"},\\"#text\\":\\"Spooler\\"},{\\"#attributes\\":{\\"Name\\":\\"param2\\"},\\"#text\\":\\"running\\"}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["Spooler", "running"]);
    }

    #[test]
    fn parse_data_object_no_text_returns_empty_string() {
        // Object with only #attributes and no #text → empty param string.
        let json = "{\\"Event\\":{\\"System\\":{\\"Provider\\":{\\"#attributes\\":{\\"Name\\":\\"P\\"}},\\"EventID\\":1},\\"EventData\\":{\\"Data\\":[{\\"#attributes\\":{\\"Name\\":\\"x\\"}}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec![""]);
    }

    #[test]
    fn parse_missing_system_returns_error() {
        let json = r#"{"Event": {}}"#;
        assert!(parse_record(json).is_err());
    }

    #[test]
    fn parse_event_id_with_attributes() {
        // Some providers wrap EventID: {"#text": 4625, "#attributes": {"Qualifiers": "0"}}
        let json = "{\\"Event\\":{\\"System\\":{\\"Provider\\":{\\"#attributes\\":{\\"Name\\":\\"P\\"}},\\"EventID\\":{\\"#text\\":4625,\\"#attributes\\":{\\"Qualifiers\\":\\"0\\"}}}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.event_id, 4625);
    }
}
'''

new_src = src[:start_idx] + new_tests
path.write_text(new_src)
print(f"Replaced from offset {start_idx} to {end_idx}, new file length {len(new_src)}")

