//! Windows registry-based DLL path resolution.
//!
//! This module is compiled **only on Windows** (`#[cfg(windows)]`).

use std::path::{Path, PathBuf};

use crate::error::ResolveError;
use crate::parser::EvtxRecord;
use crate::pe_resource;
use crate::resolver::MessageResolver;
use crate::substitution;

// ── Registry key paths ───────────────────────────────────────────────────────

const WINEVT_PUBLISHERS: &str =
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers";

const EVENTLOG_ROOT: &str =
    r"SYSTEM\CurrentControlSet\Services\EventLog";

// ── RegistryProvider trait (enables unit-test mocking) ───────────────────────

/// Abstraction over Windows registry reads, enabling mock injection in tests.
pub trait RegistryProvider {
    /// Read a `REG_SZ` / `REG_EXPAND_SZ` value from `HKLM\{subkey}\{value}`.
    fn get_local_machine_sz(
        &self,
        subkey: &str,
        value: &str,
    ) -> Result<Option<String>, ResolveError>;

    /// Enumerate the names of all sub-keys under `HKLM\{subkey}`.
    fn enum_subkeys(&self, subkey: &str) -> Result<Vec<String>, ResolveError>;
}

// ── Live implementation using winreg ─────────────────────────────────────────

/// Live registry provider backed by the Windows registry.
pub struct WinRegistryProvider;

impl RegistryProvider for WinRegistryProvider {
    fn get_local_machine_sz(
        &self,
        subkey: &str,
        value: &str,
    ) -> Result<Option<String>, ResolveError> {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        match hklm.open_subkey(subkey) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(ResolveError::Registry(e.to_string())),
            Ok(key) => match key.get_value::<String, _>(value) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(ResolveError::Registry(e.to_string())),
                Ok(v) => Ok(Some(v)),
            },
        }
    }

    fn enum_subkeys(&self, subkey: &str) -> Result<Vec<String>, ResolveError> {
        use winreg::{enums::HKEY_LOCAL_MACHINE, RegKey};

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        match hklm.open_subkey(subkey) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
            Err(e) => Err(ResolveError::Registry(e.to_string())),
            Ok(key) => {
                let names = key
                    .enum_keys()
                    .filter_map(|r| r.ok())
                    .collect();
                Ok(names)
            }
        }
    }
}

// ── Path resolution helpers ──────────────────────────────────────────────────

/// Expand `%SystemRoot%` / `%WinDir%` environment variables in a registry path.
pub fn expand_env(path: &str) -> PathBuf {
    let expanded = path
        .replace(
            "%SystemRoot%",
            &std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string()),
        )
        .replace(
            "%WinDir%",
            &std::env::var("WinDir").unwrap_or_else(|_| r"C:\Windows".to_string()),
        )
        .replace(
            "%ProgramFiles%",
            &std::env::var("ProgramFiles")
                .unwrap_or_else(|_| r"C:\Program Files".to_string()),
        );
    PathBuf::from(expanded)
}

/// If `dll_path` does not exist, try `{dir}\en-US\{filename}.mui`.
pub fn try_mui_fallback(dll_path: &Path) -> Option<PathBuf> {
    if dll_path.exists() {
        return None; // no fallback needed
    }
    let dir = dll_path.parent()?;
    let filename = dll_path.file_name()?;
    let mut mui_name = filename.to_os_string();
    mui_name.push(".mui");
    let candidate = dir.join("en-US").join(&mui_name);
    if candidate.exists() { Some(candidate) } else { None }
}

/// Resolve the DLL path for a provider using the manifest-based registry key.
fn resolve_manifest(
    registry: &dyn RegistryProvider,
    guid: &str,
) -> Result<Option<PathBuf>, ResolveError> {
    let subkey = format!(r"{WINEVT_PUBLISHERS}\{guid}");
    match registry.get_local_machine_sz(&subkey, "MessageFileName")? {
        None => Ok(None),
        Some(raw) => {
            // MessageFileName may contain multiple semicolon-separated paths.
            let first = raw.split(';').next().unwrap_or(&raw).trim().to_string();
            Ok(Some(expand_env(&first)))
        }
    }
}

/// Resolve the DLL path for a provider using the classic EventLog registry key.
fn resolve_classic(
    registry: &dyn RegistryProvider,
    provider_name: &str,
) -> Result<Option<PathBuf>, ResolveError> {
    // Walk every log channel under EventLog (Application, System, Security, …).
    let channels = registry.enum_subkeys(EVENTLOG_ROOT)?;
    for channel in &channels {
        let subkey = format!(r"{EVENTLOG_ROOT}\{channel}\{provider_name}");
        if let Some(raw) =
            registry.get_local_machine_sz(&subkey, "EventMessageFile")?
        {
            let first = raw.split(';').next().unwrap_or(&raw).trim().to_string();
            return Ok(Some(expand_env(&first)));
        }
    }
    Ok(None)
}

// ── RegistryResolver ─────────────────────────────────────────────────────────

/// Resolves event messages by looking up provider DLLs in the Windows registry.
///
/// Lookup order:
/// 1. Manifest-based: `HKLM\SOFTWARE\…\WINEVT\Publishers\{GUID}`
/// 2. Classic: `HKLM\SYSTEM\…\Services\EventLog\*\{ProviderName}`
/// 3. MUI fallback: `{dll_dir}\en-US\{dll}.mui` when the DLL itself is absent.
pub struct RegistryResolver {
    registry: Box<dyn RegistryProvider>,
}

impl RegistryResolver {
    /// Create a resolver backed by the live Windows registry.
    pub fn new() -> Self {
        Self { registry: Box::new(WinRegistryProvider) }
    }

    /// Create a resolver with a custom registry provider (useful for testing).
    #[cfg(test)]
    pub fn with_provider(registry: Box<dyn RegistryProvider>) -> Self {
        Self { registry }
    }
}

impl Default for RegistryResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageResolver for RegistryResolver {
    fn resolve(&self, record: &EvtxRecord) -> Result<Option<String>, ResolveError> {
        // 1. Locate the DLL.
        let dll_path_opt = if let Some(guid) = &record.provider_guid {
            resolve_manifest(self.registry.as_ref(), guid)?
                .or(resolve_classic(self.registry.as_ref(), &record.provider_name)
                    .ok()
                    .flatten())
        } else {
            resolve_classic(self.registry.as_ref(), &record.provider_name)?
        };

        let dll_path = match dll_path_opt {
            None => {
                return Err(ResolveError::ProviderNotFound(
                    record.provider_name.clone(),
                ))
            }
            Some(p) => p,
        };

        // 2. Apply MUI fallback if needed.
        let effective_path = try_mui_fallback(&dll_path)
            .unwrap_or(dll_path);

        // 3. Read DLL bytes.
        let pe_bytes = std::fs::read(&effective_path).map_err(|e| {
            ResolveError::PeResource(format!(
                "cannot read {}: {e}",
                effective_path.display()
            ))
        })?;

        // 4. Extract message template.
        let template = match pe_resource::extract_message(&pe_bytes, record.event_id) {
            Ok(t) => t,
            Err(ResolveError::MessageIdNotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };

        // 5. Substitute parameters.
        let params: Vec<&str> = record.params.iter().map(String::as_str).collect();
        let message = substitution::substitute(&template, &params);
        Ok(Some(message))
    }
}

// ── Unit tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Simple in-memory mock registry provider.
    struct MockRegistry {
        values: HashMap<(String, String), String>,
        subkeys: HashMap<String, Vec<String>>,
    }

    impl MockRegistry {
        fn new() -> Self {
            Self {
                values: HashMap::new(),
                subkeys: HashMap::new(),
            }
        }

        fn insert_value(&mut self, subkey: &str, value: &str, data: &str) {
            self.values
                .insert((subkey.to_string(), value.to_string()), data.to_string());
        }

        fn insert_subkeys(&mut self, parent: &str, children: Vec<&str>) {
            self.subkeys.insert(
                parent.to_string(),
                children.into_iter().map(str::to_string).collect(),
            );
        }
    }

    impl RegistryProvider for MockRegistry {
        fn get_local_machine_sz(
            &self,
            subkey: &str,
            value: &str,
        ) -> Result<Option<String>, ResolveError> {
            Ok(self
                .values
                .get(&(subkey.to_string(), value.to_string()))
                .cloned())
        }

        fn enum_subkeys(&self, subkey: &str) -> Result<Vec<String>, ResolveError> {
            Ok(self
                .subkeys
                .get(subkey)
                .cloned()
                .unwrap_or_default())
        }
    }

    fn dummy_record(name: &str, guid: Option<&str>) -> EvtxRecord {
        EvtxRecord {
            provider_name: name.to_string(),
            provider_guid: guid.map(str::to_string),
            event_id: 1,
            params: vec![],
        }
    }

    #[test]
    fn manifest_based_path_resolved() {
        let guid = "{54849625-5478-4994-A5BA-3E3B0328C30D}";
        let mut mock = MockRegistry::new();
        mock.insert_value(
            &format!(r"{WINEVT_PUBLISHERS}\{guid}"),
            "MessageFileName",
            r"C:\Windows\System32\test.dll",
        );

        let result = resolve_manifest(&mock, guid).unwrap();
        assert_eq!(
            result,
            Some(PathBuf::from(r"C:\Windows\System32\test.dll"))
        );
    }

    #[test]
    fn classic_fallback_when_no_guid_key() {
        let mut mock = MockRegistry::new();
        mock.insert_subkeys(EVENTLOG_ROOT, vec!["Application"]);
        mock.insert_value(
            &format!(r"{EVENTLOG_ROOT}\Application\MyProvider"),
            "EventMessageFile",
            r"C:\Windows\System32\myevt.dll",
        );

        let result =
            resolve_classic(&mock, "MyProvider").unwrap();
        assert_eq!(
            result,
            Some(PathBuf::from(r"C:\Windows\System32\myevt.dll"))
        );
    }

    #[test]
    fn env_var_expanded() {
        let expanded = expand_env(r"%SystemRoot%\System32\test.dll");
        assert!(
            expanded.to_string_lossy().contains("System32"),
            "expected expansion, got: {expanded:?}"
        );
    }

    #[test]
    fn no_provider_returns_none_from_classic() {
        let mock = MockRegistry::new();
        let result = resolve_classic(&mock, "UnknownProvider").unwrap();
        assert_eq!(result, None);
    }
}
