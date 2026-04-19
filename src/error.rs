/// Errors that can occur during message resolution.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    /// The requested provider was not found in any lookup source.
    #[error("provider not found: {0}")]
    ProviderNotFound(String),

    /// The given message ID does not exist in the resource table.
    #[error("message ID {0:#010x} not found in resource")]
    MessageIdNotFound(u32),

    /// An error occurred while parsing the PE resource section.
    #[error("PE resource error: {0}")]
    PeResource(String),

    /// An error occurred while accessing the Windows registry.
    #[error("registry error: {0}")]
    Registry(String),

    /// An error originated from the `evtx` crate during record parsing.
    #[error(transparent)]
    EvtxParse(#[from] evtx::err::EvtxError),

    /// An error occurred while parsing the JSON representation of a record.
    #[error("JSON parse error: {0}")]
    JsonParse(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_not_found_display() {
        let e = ResolveError::ProviderNotFound("foo".to_string());
        assert_eq!(e.to_string(), "provider not found: foo");
    }

    #[test]
    fn message_id_not_found_display() {
        let e = ResolveError::MessageIdNotFound(0x0000_0005);
        assert_eq!(e.to_string(), "message ID 0x00000005 not found in resource");
    }

    #[test]
    fn error_is_std_error() {
        let e = ResolveError::ProviderNotFound("x".to_string());
        // Verify it converts to anyhow::Error without issue.
        let _: anyhow::Error = e.into();
    }
}

