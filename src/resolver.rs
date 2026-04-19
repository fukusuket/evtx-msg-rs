use crate::error::ResolveError;
use crate::parser::EvtxRecord;

/// Common interface for message resolution.
///
/// Implement this trait to add new resolution backends (online registry,
/// offline SQLite DB, …).  A [`ChainedResolver`] can combine multiple
/// implementations with fallback semantics.
pub trait MessageResolver {
    /// Attempt to resolve the human-readable message for `record`.
    ///
    /// Returns:
    /// - `Ok(Some(msg))` – successfully resolved message.
    /// - `Ok(None)`      – this resolver does not know about the provider/event.
    /// - `Err(_)`        – a hard error occurred; callers should propagate it.
    fn resolve(&self, record: &EvtxRecord) -> Result<Option<String>, ResolveError>;
}

/// A no-op resolver used as a test stub.
///
/// Test stub — always returns Ok(None).
#[cfg_attr(windows, allow(dead_code))]
pub struct NullResolver;

impl MessageResolver for NullResolver {
    fn resolve(&self, _record: &EvtxRecord) -> Result<Option<String>, ResolveError> {
        Ok(None)
    }
}

/// Tries a sequence of [`MessageResolver`]s in order.
///
/// Returns the first `Ok(Some(_))` encountered.  If all resolvers return
/// `Ok(None)` the result is `Ok(None)`.  The first `Err` is propagated
/// immediately without trying further resolvers.
pub struct ChainedResolver {
    resolvers: Vec<Box<dyn MessageResolver>>,
}

impl ChainedResolver {
    /// Create a new chain from the given resolvers.
    pub fn new(resolvers: Vec<Box<dyn MessageResolver>>) -> Self {
        Self { resolvers }
    }

    /// Append a resolver to the end of the chain.
    #[allow(dead_code)]
    pub fn push(&mut self, resolver: Box<dyn MessageResolver>) {
        self.resolvers.push(resolver);
    }
}

impl MessageResolver for ChainedResolver {
    fn resolve(&self, record: &EvtxRecord) -> Result<Option<String>, ResolveError> {
        for resolver in &self.resolvers {
            match resolver.resolve(record)? {
                Some(msg) => return Ok(Some(msg)),
                None => continue,
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_record() -> EvtxRecord {
        EvtxRecord {
            provider_name: "Test".to_string(),
            provider_guid: None,
            event_id: 1,
            params: vec![],
        }
    }

    #[test]
    fn null_resolver_returns_none() {
        let r = NullResolver;
        assert_eq!(r.resolve(&dummy_record()).unwrap(), None);
    }

    #[test]
    fn chained_all_null_returns_none() {
        let chain = ChainedResolver::new(vec![
            Box::new(NullResolver),
            Box::new(NullResolver),
        ]);
        assert_eq!(chain.resolve(&dummy_record()).unwrap(), None);
    }

    #[test]
    fn chained_returns_first_some() {
        struct AlwaysSome(&'static str);
        impl MessageResolver for AlwaysSome {
            fn resolve(&self, _: &EvtxRecord) -> Result<Option<String>, ResolveError> {
                Ok(Some(self.0.to_string()))
            }
        }

        let chain = ChainedResolver::new(vec![
            Box::new(NullResolver),
            Box::new(AlwaysSome("hello")),
            Box::new(AlwaysSome("world")), // should not be reached
        ]);
        assert_eq!(
            chain.resolve(&dummy_record()).unwrap(),
            Some("hello".to_string())
        );
    }

    #[test]
    fn chained_propagates_error() {
        struct ErrResolver;
        impl MessageResolver for ErrResolver {
            fn resolve(&self, _: &EvtxRecord) -> Result<Option<String>, ResolveError> {
                Err(ResolveError::ProviderNotFound("boom".to_string()))
            }
        }

        let chain = ChainedResolver::new(vec![
            Box::new(NullResolver),
            Box::new(ErrResolver),
        ]);
        assert!(chain.resolve(&dummy_record()).is_err());
    }
}

