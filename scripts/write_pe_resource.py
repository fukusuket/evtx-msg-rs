import textwrap, pathlib

src = textwrap.dedent(r'''
    use pelite::pe::{Pe, PeFile};
    use pelite::resources::FindError;

    use crate::error::ResolveError;

    // RT_MESSAGETABLE resource type ID.
    const RT_MESSAGETABLE: u32 = 11;

    /// Extract the message template for `event_id` from a PE binary (DLL / EXE / MUI).
    ///
    /// Returns `Err(ResolveError::MessageIdNotFound)` when the ID is absent from the
    /// resource table.  Returns `Err(ResolveError::PeResource(_))` for structural
    /// parse failures.
    pub fn extract_message(pe_bytes: &[u8], event_id: u32) -> Result<String, ResolveError> {
        let pe = PeFile::from_bytes(pe_bytes)
            .map_err(|e| ResolveError::PeResource(format!("PE parse: {e}")))?;

        let resources = pe
            .resources()
            .map_err(|e| ResolveError::PeResource(format!("resources: {e}")))?;

        // Locate RT_MESSAGETABLE (type 11), first language variant.
        let data_entry = resources
            .find_resource(&[
                pelite::resources::Name::Id(RT_MESSAGETABLE),
                pelite::resources::Name::Id(1), // resource name ID (always 1 for msg tables)
            ])
            .map_err(|e| match e {
                FindError::NotFound => {
                    ResolveError::PeResource("RT_MESSAGETABLE not found".to_string())
                }
                other => ResolveError::PeResource(format!("find_resource: {other}")),
            })?;

        let raw = data_entry
            .data()
            .map_err(|e| ResolveError::PeResource(format!("data: {e}")))?;

        parse_message_table(raw, event_id)
    }

    /// Parse a raw `MESSAGE_RESOURCE_DATA` blob and return the text for `event_id`.
    fn parse_message_table(data: &[u8], event_id: u32) -> Result<String, ResolveError> {
        if data.len() < 4 {
            return Err(ResolveError::PeResource("truncated MESSAGE_RESOURCE_DATA".to_string()));
        }

        let num_blocks = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        // Each MESSAGE_RESOURCE_BLOCK is 12 bytes: LowId(4) + HighId(4) + Offset(4)
        let blocks_end = 4 + num_blocks * 12;
        if data.len() < blocks_end {
            return Err(ResolveError::PeResource("truncated block list".to_string()));
        }

        for b in 0..num_blocks {
            let base = 4 + b * 12;
            let low = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
            let high = u32::from_le_bytes(data[base + 4..base + 8].try_into().unwrap());
            let offset = u32::from_le_bytes(data[base + 8..base + 12].try_into().unwrap()) as usize;

            if event_id < low || event_id > high {
                continue;
            }

            // Walk entries from `offset` until we reach the one for `event_id`.
            let mut pos = offset;
            for id in low..=event_id {
                if pos + 4 > data.len() {
                    return Err(ResolveError::PeResource("entry out of bounds".to_string()));
                }
                let length = u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap()) as usize;
                let flags = u16::from_le_bytes(data[pos + 2..pos + 4].try_into().unwrap());

                if length < 4 || pos + length > data.len() {
                    return Err(ResolveError::PeResource("invalid entry length".to_string()));
                }

                if id == event_id {
                    let text_bytes = &data[pos + 4..pos + length];
                    let text = decode_entry(text_bytes, flags)?;
                    return Ok(text);
                }
                pos += length;
            }
        }

        Err(ResolveError::MessageIdNotFound(event_id))
    }

    /// Decode a `MESSAGE_RESOURCE_ENTRY` text payload.
    ///
    /// `flags == 0x0001` → UTF-16LE; `flags == 0x0000` → ANSI (Latin-1).
    fn decode_entry(text_bytes: &[u8], flags: u16) -> Result<String, ResolveError> {
        let raw = if flags & 0x0001 != 0 {
            // UTF-16LE
            if text_bytes.len() % 2 != 0 {
                return Err(ResolveError::PeResource("odd byte count for UTF-16LE".to_string()));
            }
            let units: Vec<u16> = text_bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units)
                .map_err(|e| ResolveError::PeResource(format!("UTF-16 decode: {e}")))?
        } else {
            // ANSI — treat as Latin-1 (each byte is its Unicode code point).
            text_bytes.iter().map(|&b| b as char).collect()
        };

        // Strip trailing NUL, CR, LF.
        Ok(raw.trim_end_matches(|c| c == '\0' || c == '\r' || c == '\n').to_string())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Build a minimal MESSAGE_RESOURCE_DATA blob with a single ANSI entry.
        fn make_msg_table(event_id: u32, text: &str) -> Vec<u8> {
            let text_bytes: Vec<u8> = text.bytes().chain(std::iter::once(0u8)).collect();
            // Align to 4 bytes.
            let pad = (4 - text_bytes.len() % 4) % 4;
            let entry_len = (4 + text_bytes.len() + pad) as u16;

            let mut data: Vec<u8> = Vec::new();
            // num_blocks = 1
            data.extend_from_slice(&1u32.to_le_bytes());
            // block: LowId, HighId, Offset
            data.extend_from_slice(&event_id.to_le_bytes());
            data.extend_from_slice(&event_id.to_le_bytes());
            let offset = (4 + 12) as u32; // after header + 1 block descriptor
            data.extend_from_slice(&offset.to_le_bytes());
            // entry: Length(2) + Flags(2) + text
            data.extend_from_slice(&entry_len.to_le_bytes());
            data.extend_from_slice(&0u16.to_le_bytes()); // ANSI
            data.extend_from_slice(&text_bytes);
            data.extend(std::iter::repeat(0u8).take(pad));
            data
        }

        /// Build a minimal MESSAGE_RESOURCE_DATA blob with a single UTF-16LE entry.
        fn make_msg_table_utf16(event_id: u32, text: &str) -> Vec<u8> {
            let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0u16)).collect();
            let text_bytes: Vec<u8> = utf16.iter().flat_map(|u| u.to_le_bytes()).collect();
            let pad = (4 - text_bytes.len() % 4) % 4;
            let entry_len = (4 + text_bytes.len() + pad) as u16;

            let mut data: Vec<u8> = Vec::new();
            data.extend_from_slice(&1u32.to_le_bytes());
            data.extend_from_slice(&event_id.to_le_bytes());
            data.extend_from_slice(&event_id.to_le_bytes());
            let offset = (4 + 12) as u32;
            data.extend_from_slice(&offset.to_le_bytes());
            data.extend_from_slice(&entry_len.to_le_bytes());
            data.extend_from_slice(&1u16.to_le_bytes()); // UTF-16LE
            data.extend_from_slice(&text_bytes);
            data.extend(std::iter::repeat(0u8).take(pad));
            data
        }

        #[test]
        fn ansi_entry_parsed() {
            let raw = make_msg_table(42, "Hello ANSI\r\n");
            let result = parse_message_table(&raw, 42).unwrap();
            assert_eq!(result, "Hello ANSI");
        }

        #[test]
        fn utf16_entry_parsed() {
            let raw = make_msg_table_utf16(100, "Hello UTF-16\r\n");
            let result = parse_message_table(&raw, 100).unwrap();
            assert_eq!(result, "Hello UTF-16");
        }

        #[test]
        fn missing_event_id_returns_error() {
            let raw = make_msg_table(1, "some message");
            let err = parse_message_table(&raw, 999).unwrap_err();
            assert!(matches!(err, ResolveError::MessageIdNotFound(999)));
        }
    }
''').lstrip('\n')

pathlib.Path('/Users/fukusuke/Scripts/Rust/evtx-msg-rs/src/pe_resource.rs').write_text(src)
print('ok')

