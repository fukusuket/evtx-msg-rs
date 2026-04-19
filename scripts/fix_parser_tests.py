import pathlib

path = pathlib.Path('/Users/fukusuke/Scripts/Rust/evtx-msg-rs/src/parser.rs')
src = path.read_text()

# Remove the broken new tests (inserted earlier) and replace with escaped-string versions
old_block = '''    #[test]
    fn parse_data_numeric_text() {
        // evtx sometimes produces #text as a JSON number (e.g. LogonType: 3)
        let json = make_json(
            "P",
            None,
            4624,
            r#"[{"#attributes":{"Name":"LogonType"},"#text":3}]"#,
        );
        let rec = parse_record(&json).unwrap();
        assert_eq!(rec.params, vec!["3"]);
    }

    #[test]
    fn parse_data_object_with_text_string() {
        // Named Data entries: #text is a string
        let json = make_json(
            "P",
            None,
            7036,
            r#"[{"#attributes":{"Name":"param1"},"#text":"Spooler"},{"#attributes":{"Name":"param2"},"#text":"running"}]"#,
        );
        let rec = parse_record(&json).unwrap();
        assert_eq!(rec.params, vec!["Spooler", "running"]);
    }

    #[test]
    fn parse_data_object_no_text_returns_empty_string() {
        // Object with only #attributes and no #text
        let json = make_json(
            "P",
            None,
            1,
            r#"[{"#attributes":{"Name":"x"}}]"#,
        );
        let rec = parse_record(&json).unwrap();
        assert_eq!(rec.params, vec![""]);
    }
'''

# Build JSON strings using regular escaped strings to avoid r#"..."# "#" termination issues.
# {"#attributes":{"Name":"LogonType"},"#text":3}
j_numeric  = '{"Event":{"System":{"Provider":{"\\\"#attributes\\\"":{"Name":"P"}},"EventID":4624},"EventData":{"Data":[{"\\\"#attributes\\\"":{"Name":"LogonType"},"\\\"#text\\\"":\xa33}]}}}'

# We use plain escaped string literals instead.
new_block = r'''    #[test]
    fn parse_data_numeric_text() {
        // evtx produces #text as a JSON number (e.g. LogonType: 3)
        // Use plain escaped strings to avoid r#"..."# termination on "#text".
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":4624},\"EventData\":{\"Data\":[{\"#attributes\":{\"Name\":\"LogonType\"},\"#text\":3}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["3"]);
    }

    #[test]
    fn parse_data_object_with_text_string() {
        // Named Data entries: #text is a string
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":7036},\"EventData\":{\"Data\":[{\"#attributes\":{\"Name\":\"param1\"},\"#text\":\"Spooler\"},{\"#attributes\":{\"Name\":\"param2\"},\"#text\":\"running\"}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec!["Spooler", "running"]);
    }

    #[test]
    fn parse_data_object_no_text_returns_empty_string() {
        // Object with only #attributes and no #text -> empty param string
        let json = "{\"Event\":{\"System\":{\"Provider\":{\"#attributes\":{\"Name\":\"P\"}},\"EventID\":1},\"EventData\":{\"Data\":[{\"#attributes\":{\"Name\":\"x\"}}]}}}";
        let rec = parse_record(json).unwrap();
        assert_eq!(rec.params, vec![""]);
    }
'''

if old_block in src:
    src = src.replace(old_block, new_block)
    path.write_text(src)
    print("replaced ok")
else:
    print("OLD BLOCK NOT FOUND — printing first occurrence of parse_data_numeric:")
    idx = src.find("parse_data_numeric")
    print(repr(src[max(0,idx-20):idx+400]))

