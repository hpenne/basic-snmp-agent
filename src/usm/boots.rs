//! Engine-boots counter persistence for USM.
//!
//! # Requirements
//! Implements: REQ-0094, REQ-0095, REQ-0096, REQ-0097

/// RFC 3414 §2.2 ceiling — once reached, no further authenticated communication
/// is possible without engine reconfiguration.
///
/// # Requirements
/// Implements: REQ-0097
pub const MAX_ENGINE_BOOTS: u32 = 2_147_483_647;

// RFC 3411 §3.3 caps snmpEngineID at 32 bytes; used in FileEngineBootsStore::load
// to reject absurd lengths from corrupted files before any arithmetic on the value.
const MAX_ENGINE_ID_LEN: usize = 32;

/// The persisted state pair returned by [`EngineBootsStore::load`].
///
/// # Requirements
/// Implements: REQ-0095
pub struct StoredBootsState {
    pub engine_id: Vec<u8>,
    pub boots: u32,
}

/// Application-provided storage abstraction for engine-boots persistence.
///
/// The trait is a pure storage primitive — all counter logic (engine-ID comparison,
/// reset on mismatch, increment, ceiling check) is the library's responsibility via
/// [`initialise_engine_boots`].
///
/// The trait uses `std::io::Error` because persistence is inherently I/O; embedders
/// with other backends can wrap via `io::Error::other`.
///
/// # Requirements
/// Implements: REQ-0095
pub trait EngineBootsStore {
    /// Load the previously persisted engine ID and boots counter.
    ///
    /// Returns `Ok(None)` if no state has been persisted yet.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the backing store fails to read or parse the persisted state.
    fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error>;

    /// Persist the given engine ID and boots counter.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the backing store fails to persist the state.
    fn save(&mut self, engine_id: &[u8], boots: u32) -> Result<(), std::io::Error>;
}

/// # Requirements
/// Implements: REQ-0095
impl<T: EngineBootsStore + ?Sized> EngineBootsStore for &mut T {
    fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
        (*self).load()
    }

    fn save(&mut self, engine_id: &[u8], boots: u32) -> Result<(), std::io::Error> {
        (*self).save(engine_id, boots)
    }
}

/// Error returned by [`initialise_engine_boots`].
///
/// # Requirements
/// Implements: REQ-0095, REQ-0097
pub enum InitBootsError {
    /// `snmpEngineBoots` has reached [`MAX_ENGINE_BOOTS`] and cannot be incremented.
    /// The engine must be reconfigured per RFC 3414 §2.2.
    BootsAtCeiling,

    /// The backing store failed to load or save state.
    Store(std::io::Error),
}

impl std::fmt::Display for InitBootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BootsAtCeiling => write!(
                f,
                "snmpEngineBoots has reached its maximum value (2147483647); \
                 engine must be reconfigured per RFC 3414 §2.2"
            ),
            Self::Store(e) => write!(f, "engine-boots store error: {e}"),
        }
    }
}

impl std::fmt::Debug for InitBootsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BootsAtCeiling => write!(f, "BootsAtCeiling"),
            Self::Store(e) => write!(f, "Store({e:?})"),
        }
    }
}

impl std::error::Error for InitBootsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BootsAtCeiling => None,
            Self::Store(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for InitBootsError {
    fn from(e: std::io::Error) -> Self {
        Self::Store(e)
    }
}

/// Initialise the `snmpEngineBoots` counter for this engine.
///
/// Loads the previously persisted state, applies RFC 3414 §2.2 counter logic,
/// persists the new state, and returns the new boots value.
///
/// The caller MUST invoke this function exactly once at agent start-up, before
/// accepting any inbound messages.
///
/// # Errors
///
/// Returns [`InitBootsError::BootsAtCeiling`] if the counter has reached
/// [`MAX_ENGINE_BOOTS`]. Returns [`InitBootsError::Store`] if the backing store
/// fails.
///
/// # Requirements
/// Implements: REQ-0094, REQ-0095, REQ-0097
pub fn initialise_engine_boots(
    store: &mut (impl EngineBootsStore + ?Sized),
    engine_id: &[u8],
) -> Result<u32, InitBootsError> {
    let stored = store.load()?;
    match stored {
        None => {
            store.save(engine_id, 1)?;
            Ok(1)
        }
        Some(state) if state.engine_id == engine_id => {
            // Same engine: increment, check ceiling
            if state.boots >= MAX_ENGINE_BOOTS {
                return Err(InitBootsError::BootsAtCeiling);
            }
            let new_boots = state.boots + 1;
            store.save(engine_id, new_boots)?;
            Ok(new_boots)
        }
        Some(_) => {
            // Engine ID changed: reset to 1 per RFC 3414 §2.2
            store.save(engine_id, 1)?;
            Ok(1)
        }
    }
}

/// File-backed implementation of [`EngineBootsStore`].
///
/// Reads and writes the engine ID and boots counter as a length-prefixed binary
/// record. Writes are atomic: the new state is written to a temporary file
/// alongside the target, then renamed into place, preventing corruption if the
/// process is interrupted mid-write.
///
/// # Requirements
/// Implements: REQ-0096
pub struct FileEngineBootsStore {
    path: std::path::PathBuf,
}

impl FileEngineBootsStore {
    /// Create a new `FileEngineBootsStore` that persists state to `path`.
    ///
    /// # Requirements
    /// Implements: REQ-0096
    ///
    /// # Examples
    ///
    /// ```
    /// use basic_snmp_agent::usm::boots::FileEngineBootsStore;
    ///
    /// let store = FileEngineBootsStore::new("/var/lib/snmp/engine-boots");
    /// ```
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl EngineBootsStore for FileEngineBootsStore {
    fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
        let file_data = match std::fs::read(&self.path) {
            Ok(file_data) => file_data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        // Parse: 4 bytes engine_id length, N bytes engine_id, 4 bytes boots.
        // split_first_chunk handles both the too-short case and the slice-to-array
        // conversion without unwrap, propagating a uniform "unexpected length" error.
        let (engine_id_len_bytes, rest) = file_data.split_first_chunk::<4>().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "engine-boots file has unexpected length",
            )
        })?;
        let engine_id_len =
            usize::try_from(u32::from_be_bytes(*engine_id_len_bytes)).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "engine-boots file contains implausible engine ID length",
                )
            })?;
        if engine_id_len > MAX_ENGINE_ID_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "engine-boots file contains implausible engine ID length",
            ));
        }
        let expected_remaining = engine_id_len + 4;
        if rest.len() != expected_remaining {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "engine-boots file has unexpected length",
            ));
        }
        let (engine_id_bytes, boots_tail) = rest.split_at(engine_id_len);
        let engine_id = engine_id_bytes.to_vec();
        let boots = u32::from_be_bytes(boots_tail.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "engine-boots file has unexpected length",
            )
        })?);
        Ok(Some(StoredBootsState { engine_id, boots }))
    }

    fn save(&mut self, engine_id: &[u8], boots: u32) -> Result<(), std::io::Error> {
        let tmp_path = self.path.with_extension("tmp");
        {
            use std::io::Write as _;
            let file = std::fs::File::create(&tmp_path)?;
            let mut writer = std::io::BufWriter::new(file);
            let engine_id_len = u32::try_from(engine_id.len()).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "engine ID too long")
            })?;
            writer.write_all(&engine_id_len.to_be_bytes())?;
            writer.write_all(engine_id)?;
            writer.write_all(&boots.to_be_bytes())?;
            writer.flush()?;
            // After explicit flush, into_inner cannot fail (buffer is empty).
            // map_err converts the IntoInnerError, which wraps the underlying I/O error.
            let file = writer
                .into_inner()
                .map_err(std::io::IntoInnerError::into_error)?;
            file.sync_all()?;
        }
        std::fs::rename(&tmp_path, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemStore {
        state: Option<StoredBootsState>,
        fail_load: bool,
        fail_save: bool,
    }

    impl MemStore {
        fn new(state: Option<StoredBootsState>) -> Self {
            Self {
                state,
                fail_load: false,
                fail_save: false,
            }
        }

        fn failing_load() -> Self {
            Self {
                state: None,
                fail_load: true,
                fail_save: false,
            }
        }

        fn failing_save(state: Option<StoredBootsState>) -> Self {
            Self {
                state,
                fail_load: false,
                fail_save: true,
            }
        }
    }

    impl EngineBootsStore for MemStore {
        fn load(&mut self) -> Result<Option<StoredBootsState>, std::io::Error> {
            if self.fail_load {
                return Err(std::io::Error::other("simulated load failure"));
            }
            Ok(self.state.take())
        }

        fn save(&mut self, engine_id: &[u8], boots: u32) -> Result<(), std::io::Error> {
            if self.fail_save {
                return Err(std::io::Error::other("simulated save failure"));
            }
            self.state = Some(StoredBootsState {
                engine_id: engine_id.to_vec(),
                boots,
            });
            Ok(())
        }
    }

    #[test]
    fn given_no_prior_state_when_initialise_then_boots_is_one() {
        // Verifies: REQ-0094, REQ-0095
        let engine_id = b"test-engine";
        let mut store = MemStore::new(None);
        let boots = initialise_engine_boots(&mut store, engine_id).unwrap();
        assert_eq!(boots, 1);
    }

    #[test]
    fn given_no_prior_state_when_initialise_then_state_is_saved() {
        // Verifies: REQ-0095
        let engine_id = b"test-engine";
        let mut store = MemStore::new(None);
        initialise_engine_boots(&mut store, engine_id).unwrap();
        let saved = store.state.as_ref().unwrap();
        assert_eq!(saved.engine_id, engine_id);
        assert_eq!(saved.boots, 1);
    }

    #[test]
    fn given_same_engine_id_when_initialise_then_boots_incremented() {
        // Verifies: REQ-0094, REQ-0095
        let engine_id = b"my-engine";
        let prior = StoredBootsState {
            engine_id: engine_id.to_vec(),
            boots: 5,
        };
        let mut store = MemStore::new(Some(prior));
        let boots = initialise_engine_boots(&mut store, engine_id).unwrap();
        assert_eq!(boots, 6);
    }

    #[test]
    fn given_different_engine_id_when_initialise_then_boots_reset_to_one() {
        // Verifies: REQ-0094, REQ-0095
        let old_engine = b"old-engine";
        let new_engine = b"new-engine";
        let prior = StoredBootsState {
            engine_id: old_engine.to_vec(),
            boots: 42,
        };
        let mut store = MemStore::new(Some(prior));
        let boots = initialise_engine_boots(&mut store, new_engine).unwrap();
        assert_eq!(boots, 1);
        let saved = store.state.as_ref().unwrap();
        assert_eq!(saved.engine_id, new_engine);
    }

    #[test]
    fn given_boots_at_ceiling_when_initialise_then_error() {
        // Verifies: REQ-0097
        let engine_id = b"ceiling-engine";
        let prior = StoredBootsState {
            engine_id: engine_id.to_vec(),
            boots: MAX_ENGINE_BOOTS,
        };
        let mut store = MemStore::new(Some(prior));
        let result = initialise_engine_boots(&mut store, engine_id);
        assert!(matches!(result, Err(InitBootsError::BootsAtCeiling)));
        // The store state was taken by load; save must NOT have been called
        assert!(
            store.state.is_none(),
            "save must not be called when boots are at ceiling"
        );
    }

    #[test]
    fn given_boots_below_ceiling_when_initialise_then_ok() {
        // Verifies: REQ-0097
        let engine_id = b"near-ceiling-engine";
        let prior = StoredBootsState {
            engine_id: engine_id.to_vec(),
            boots: MAX_ENGINE_BOOTS - 1,
        };
        let mut store = MemStore::new(Some(prior));
        let boots = initialise_engine_boots(&mut store, engine_id).unwrap();
        assert_eq!(boots, MAX_ENGINE_BOOTS);
    }

    #[test]
    fn given_store_load_fails_when_initialise_then_store_error() {
        // Verifies: REQ-0095
        let mut store = MemStore::failing_load();
        let result = initialise_engine_boots(&mut store, b"engine");
        assert!(matches!(result, Err(InitBootsError::Store(_))));
    }

    #[test]
    fn given_store_save_fails_when_initialise_then_store_error() {
        // Verifies: REQ-0095
        let mut store = MemStore::failing_save(None);
        let result = initialise_engine_boots(&mut store, b"engine");
        assert!(matches!(result, Err(InitBootsError::Store(_))));
    }

    #[test]
    fn given_boots_at_ceiling_error_when_display_then_mentions_ceiling() {
        // Verifies: REQ-0097
        let e = InitBootsError::BootsAtCeiling;
        assert_eq!(
            e.to_string(),
            "snmpEngineBoots has reached its maximum value (2147483647); \
             engine must be reconfigured per RFC 3414 §2.2"
        );
    }

    #[test]
    fn given_store_error_when_display_then_includes_inner_message() {
        // Verifies: REQ-0095
        let io_err = std::io::Error::other("disk full");
        let e = InitBootsError::Store(io_err);
        assert!(e.to_string().contains("engine-boots store error"));
        assert!(e.to_string().contains("disk full"));
    }

    #[test]
    fn given_store_error_when_source_then_returns_io_error() {
        // Verifies: REQ-0095
        use std::error::Error as _;
        let io_err = std::io::Error::other("disk full");
        let e = InitBootsError::Store(io_err);
        let source = e.source().unwrap();
        let io_source = source.downcast_ref::<std::io::Error>().unwrap();
        assert_eq!(io_source.kind(), std::io::ErrorKind::Other);
    }

    #[test]
    fn given_boots_at_ceiling_error_when_source_then_returns_none() {
        // Verifies: REQ-0097
        use std::error::Error as _;
        let e = InitBootsError::BootsAtCeiling;
        assert!(e.source().is_none());
    }
}
