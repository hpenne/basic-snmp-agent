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
#[derive(Debug, PartialEq)]
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
/// record. Writes use the full durable-write pattern: write to a temporary file
/// alongside the target, fsync the temporary file, rename it into place, then
/// fdatasync the parent directory to ensure the directory entry update (rename) is
/// also flushed to disk. This prevents corruption if the process or system is
/// interrupted mid-write.
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
        // Resolve the parent directory before the rename so we can fdatasync it
        // afterwards. Fall back to "." when the path has no explicit parent
        // component (i.e. the file lives in the current working directory).
        let parent_path = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
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
        std::fs::rename(&tmp_path, &self.path)?;
        // Fdatasync the parent directory to ensure the rename (directory entry
        // update) is durable. `sync_data` (fdatasync) is sufficient here because
        // we only need the directory entries flushed, not directory metadata like
        // mtime/ctime. Without this step the rename may be lost on a crash even
        // though the file data itself was synced.
        let parent_dir = std::fs::File::open(parent_path)?;
        parent_dir.sync_data()?;
        Ok(())
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

    #[test]
    fn given_boots_at_ceiling_error_when_debug_formatted_then_shows_variant_name() {
        // Verifies: REQ-0097
        let e = InitBootsError::BootsAtCeiling;
        assert_eq!(format!("{e:?}"), "BootsAtCeiling");
    }

    #[test]
    fn given_store_error_when_debug_formatted_then_includes_inner_error() {
        // Verifies: REQ-0095
        let io_err = std::io::Error::other("store failure");
        let e = InitBootsError::Store(io_err);
        let debug_str = format!("{e:?}");
        assert!(
            debug_str.starts_with("Store("),
            "Debug output must start with Store(, got: {debug_str}"
        );
        assert!(
            debug_str.contains("store failure"),
            "Debug output must contain the inner error message, got: {debug_str}"
        );
    }

    #[test]
    fn given_mut_ref_to_store_when_initialise_via_ref_then_delegates_to_inner() {
        // Verifies: REQ-0095
        // The &mut T blanket impl delegates load/save to the inner store.
        // This calls initialise_engine_boots with a &mut &mut MemStore, exercising
        // the blanket impl with T = &mut MemStore.
        let engine_id = b"myengine";
        let mut store = MemStore::new(Some(StoredBootsState {
            engine_id: engine_id.to_vec(),
            boots: 7,
        }));
        let mut store_ref: &mut MemStore = &mut store;
        // Passing &mut store_ref (&mut (&mut MemStore)) uses the blanket impl.
        let boots = initialise_engine_boots(&mut store_ref, engine_id)
            .expect("initialise via &mut ref must succeed");
        assert_eq!(
            boots, 8,
            "boots must be incremented via &mut T blanket impl"
        );
    }

    #[test]
    fn given_mut_ref_to_store_when_save_via_ref_then_state_is_persisted() {
        // Verifies: REQ-0095
        // The &mut T blanket impl save delegation persists to the inner store.
        let mut store = MemStore::new(None);
        let mut store_ref: &mut MemStore = &mut store;
        // Calling save through &mut store_ref exercises the blanket impl.
        EngineBootsStore::save(&mut store_ref, b"engine", 42)
            .expect("save via &mut ref must succeed");
        let saved = store.state.as_ref().expect("state must be saved");
        assert_eq!(saved.engine_id, b"engine");
        assert_eq!(saved.boots, 42);
    }

    // ── FileEngineBootsStore tests ─────────────────────────────────────────

    #[test]
    fn given_file_store_when_no_file_then_load_returns_none() {
        // Verifies: REQ-0096
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join(format!("boots_test_none_{}.bin", std::process::id()));
        // Ensure file does not exist.
        let _cleanup = std::fs::remove_file(&tmp_path);
        let mut store = FileEngineBootsStore::new(&tmp_path);
        let result = store.load().expect("load from absent file must return Ok");
        assert_eq!(result, None, "absent file must return None");
    }

    #[test]
    fn given_file_store_when_save_then_load_round_trips_correctly() {
        // Verifies: REQ-0096
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join(format!("boots_test_rt_{}.bin", std::process::id()));
        // Ensure file does not exist from a previous run.
        let _cleanup = std::fs::remove_file(&tmp_path);
        let engine_id = b"\x80\x00\x1f\x88\x04myengine";
        let boots_value = 99_u32;

        let mut store = FileEngineBootsStore::new(&tmp_path);
        store
            .save(engine_id, boots_value)
            .expect("save must succeed");

        let loaded = store
            .load()
            .expect("load must succeed")
            .expect("must be Some");
        assert_eq!(loaded.engine_id, engine_id);
        assert_eq!(loaded.boots, boots_value);

        std::fs::remove_file(&tmp_path).expect("test cleanup");
    }

    #[test]
    fn given_file_store_when_file_has_oversized_engine_id_len_then_load_returns_error() {
        // Verifies: REQ-0096
        // engine_id_len field set to MAX_ENGINE_ID_LEN + 1 = 33 (too large).
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join(format!("boots_test_oversize_{}.bin", std::process::id()));
        let oversized_len: u32 =
            u32::try_from(MAX_ENGINE_ID_LEN).expect("MAX_ENGINE_ID_LEN fits in u32") + 1;
        let mut data = oversized_len.to_be_bytes().to_vec();
        // Pad with enough bytes so the file has the oversized_len + 4 structure.
        data.extend(vec![0u8; usize::try_from(oversized_len).unwrap() + 4]);
        std::fs::write(&tmp_path, &data).unwrap();

        let mut store = FileEngineBootsStore::new(&tmp_path);
        let result = store.load();
        let err = result.expect_err("oversized engine_id_len must produce an error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(&tmp_path).expect("test cleanup");
    }

    #[test]
    fn given_file_store_when_file_has_wrong_total_length_then_load_returns_error() {
        // Verifies: REQ-0096
        // engine_id_len = 4 but total remaining bytes != 4 + 4 = 8.
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join(format!("boots_test_wronglen_{}.bin", std::process::id()));
        let engine_id_len: u32 = 4;
        let mut data = engine_id_len.to_be_bytes().to_vec();
        // Add only 3 bytes of engine_id (should be 4) + 4 bytes boots = 7, but expected 8.
        data.extend(vec![0u8; 3]);
        std::fs::write(&tmp_path, &data).unwrap();

        let mut store = FileEngineBootsStore::new(&tmp_path);
        let result = store.load();
        let err = result.expect_err("wrong total length must produce an error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

        std::fs::remove_file(&tmp_path).expect("test cleanup");
    }

    #[test]
    fn given_file_store_when_file_has_exact_max_engine_id_len_then_load_succeeds() {
        // Verifies: REQ-0096
        // engine_id_len == MAX_ENGINE_ID_LEN (32) must be accepted. The mutant
        // "> with >=" would incorrectly reject this boundary value.
        let tmp_dir = std::env::temp_dir();
        let tmp_path = tmp_dir.join(format!("boots_test_maxlen_{}.bin", std::process::id()));
        let engine_id = vec![0xAAu8; MAX_ENGINE_ID_LEN];
        let boots_value: u32 = 1;
        let mut store = FileEngineBootsStore::new(&tmp_path);
        store
            .save(&engine_id, boots_value)
            .expect("save of max-length engine ID must succeed");

        let loaded = store
            .load()
            .expect("load must succeed")
            .expect("must be Some");
        assert_eq!(loaded.engine_id, engine_id);
        assert_eq!(loaded.boots, boots_value);

        std::fs::remove_file(&tmp_path).expect("test cleanup");
    }

    #[test]
    fn given_file_store_when_path_is_directory_then_load_returns_io_error() {
        // Verifies: REQ-0096
        // The match guard in load() must only swallow NotFound errors.
        // When the path exists but is a directory, the read fails with a
        // non-NotFound error that must be propagated, not silently returned
        // as Ok(None).
        let tmp_dir = std::env::temp_dir().join(format!("boots_test_dir_{}", std::process::id()));
        std::fs::create_dir_all(&tmp_dir).expect("must create temp dir");
        let mut store = FileEngineBootsStore::new(&tmp_dir);
        let result = store.load();
        let err = result.expect_err("reading a directory must produce an I/O error, not Ok(None)");
        // The error should NOT be NotFound.
        assert_ne!(err.kind(), std::io::ErrorKind::NotFound);
        std::fs::remove_dir(&tmp_dir).expect("test cleanup");
    }

    #[test]
    fn given_bare_filename_when_parent_resolved_then_falls_back_to_current_dir() {
        // Verifies: REQ-0096
        // Exercises the parent-path resolution logic used in FileEngineBootsStore::save
        // for the edge case where the path has no directory component. Path::parent()
        // returns Some("") for a bare filename, which must be treated as ".".
        let path = std::path::Path::new("engine.dat");
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        assert_eq!(
            parent,
            std::path::Path::new("."),
            "bare filename must resolve parent to '.'"
        );
    }
}
