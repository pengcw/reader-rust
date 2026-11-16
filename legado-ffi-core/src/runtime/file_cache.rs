//! Native per-source text storage; Lua supplies only the trusted cache root.
//! Keep the source-js on-disk layout and LuaFileSystem lock_dir protocol unchanged.
use crate::parser::js::InfoMapState;
use ring::digest::{digest, SHA256};
use serde_json::{json, Value};
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_VALUE: usize = 256 * 1024;
const MAX_FILE: u64 = 2 * 1024 * 1024;
const MAX_ENTRIES: usize = 64;
const MAX_TOTAL: u64 = 16 * 1024 * 1024;
const LOCK_STALE: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheError {
    pub kind: &'static str,
    pub message: &'static str,
}

impl CacheError {
    fn new(kind: &'static str, message: &'static str) -> Self {
        Self { kind, message }
    }

    pub(crate) fn envelope(&self) -> serde_json::Value {
        serde_json::json!({"ok":false,"error":{"kind":self.kind,"message":self.message}})
    }
}

type Result<T> = std::result::Result<T, CacheError>;
fn error(kind: &'static str, message: &'static str) -> CacheError {
    CacheError::new(kind, message)
}

#[derive(Serialize, Deserialize)]
struct Entry {
    version: u8,
    value: String,
    expires: u64,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

fn sha256(text: &str) -> String {
    hex::encode(digest(&SHA256, text.as_bytes()).as_ref())
}

fn directory(path: &Path, create: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(attr) => return if attr.file_type().is_dir() {
            Ok(true)
        } else {
            Err(error("permission_denied", "invalid cache directory"))
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(_) => return Err(error("permission_denied", "invalid cache directory")),
    }
    if !create {
        return Ok(false);
    }
    // Another worker may create the same cache folder between lstat and mkdir.
    let _ = fs::create_dir(path);
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir()) {
        Ok(true)
    } else {
        Err(error("permission_denied", "invalid cache directory"))
    }
}

fn entry_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() == 69 && bytes[..64].iter().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        && &bytes[64..] == b".json"
}

fn temporary_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() > 74 && bytes[..64].iter().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        && bytes[64..].starts_with(b".json.tmp-")
}

fn regular_file(path: &Path) -> Result<Option<u64>> {
    match fs::symlink_metadata(path) {
        Ok(attr) if attr.file_type().is_file() => Ok(Some(attr.len())),
        Ok(_) => Err(error("permission_denied", "cache entry must be a regular file")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(error("operation_failed", "cache read failed")),
    }
}

fn read(path: &Path) -> Result<Option<String>> {
    let Some(size) = regular_file(path)? else { return Ok(None) };
    if size > MAX_FILE {
        return Err(error("limit_exceeded", "cache entry too large"));
    }
    let bytes = crate::crawler::script_cache::read_limited(path, MAX_FILE)
        .ok_or_else(|| error("operation_failed", "cache read failed"))?;
    let entry: Entry = serde_json::from_slice(&bytes)
        .map_err(|_| error("operation_failed", "invalid cache entry"))?;
    if entry.version != 1 || entry.value.len() > MAX_VALUE {
        return Err(error("operation_failed", "invalid cache entry"));
    }
    if entry.expires > 0 && entry.expires <= now() {
        return Ok(None);
    }
    Ok(Some(entry.value))
}

// Matches LuaFileSystem's POSIX lfs.lock_dir(dir, 300): symlink "lock" at
// dir/lockfile.lfs, with stale symlink replacement and RAII unlink on release.
// Do not use the unrelated JS bootstrap cache's ".write.lock" directory.
struct WriterLock(PathBuf);
impl WriterLock {
    fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join("lockfile.lfs");
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            if symlink("lock", &path).is_ok() {
                return Ok(Self(path));
            }
            let stale = fs::symlink_metadata(&path).ok().is_some_and(|attr| {
                attr.file_type().is_symlink() && attr.modified().ok().is_some_and(|time| {
                    SystemTime::now().duration_since(time).unwrap_or_default() > LOCK_STALE
                })
            });
            if !stale || fs::remove_file(&path).is_err() || symlink("lock", &path).is_err() {
                return Err(error("cache_busy", "cache directory is busy"));
            }
            Ok(Self(path))
        }
        #[cfg(not(unix))]
        {
            let file = OpenOptions::new().write(true).create_new(true).open(&path);
            if file.is_err() {
                return Err(error("cache_busy", "cache directory is busy"));
            }
            Ok(Self(path))
        }
    }
}
impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

// Only unit tests can fail directory sync and count attempts; no runtime switch.
#[cfg(test)]
thread_local! {
    static SYNC_FAILURES: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

fn sync_directory(dir: &Path) -> Result<()> {
    #[cfg(test)]
    if SYNC_FAILURES.with(|calls| match calls.get() {
        Some(count) => { calls.set(Some(count + 1)); true }
        None => false,
    }) {
        return Err(error("operation_failed", "cache directory sync failed"));
    }
    File::open(dir).and_then(|file| file.sync_all())
        .map_err(|_| error("operation_failed", "cache directory sync failed"))
}

fn atomic_write(dir: &Path, path: &Path, data: &[u8]) -> Result<()> {
    for _ in 0..4 {
        let temp = path.with_file_name(format!(
            "{}.tmp-{:016x}",
            path.file_name().unwrap_or_default().to_string_lossy(),
            rand::random::<u64>()
        ));
        let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(&temp) else {
            continue;
        };
        let result = file.write_all(data).and_then(|_| file.sync_all());
        drop(file);
        if result.is_ok() && fs::rename(&temp, path).is_ok() {
            // Publication is already committed. Never retry if directory fsync fails.
            return sync_directory(dir);
        }
        let _ = fs::remove_file(temp);
        return Err(error("operation_failed", "cache write failed"));
    }
    Err(error("operation_failed", "cache write failed"))
}

#[derive(Clone)]
pub(crate) struct FileCache {
    root: PathBuf,
}

thread_local! {
    static REQUEST_CACHE: RefCell<Option<Result<FileCache>>> = const { RefCell::new(None) };
}

pub(crate) fn with_request<T>(run: impl FnOnce() -> T) -> T {
    REQUEST_CACHE.with(|cell| crate::util::scoped::with_scoped_value(cell, None, run))
}

impl FileCache {
    pub(crate) fn current() -> Result<Self> {
        REQUEST_CACHE.with(|cell| {
            if let Some(cached) = cell.borrow().as_ref() {
                return cached.clone();
            }
            let resolved = Self::from_host();
            *cell.borrow_mut() = Some(resolved.clone());
            resolved
        })
    }

    pub(crate) fn from_host() -> Result<Self> {
        let response = crate::host_services::call("resource.cache.config", &serde_json::json!({}));
        let root = response.get("data").and_then(|v| v.as_str())
            .filter(|_| response["ok"] == true)
            .ok_or_else(|| error("unavailable", "cache root unavailable"))?;
        let path = PathBuf::from(root);
        if !path.is_absolute()
            || path.components().any(|part| matches!(part, std::path::Component::ParentDir))
            || !directory(&path, false)? {
            return Err(error("unavailable", "cache root unavailable"));
        }
        Ok(Self { root: path.join("source-js") })
    }

    #[cfg(test)]
    pub(crate) fn at(root: PathBuf) -> Self {
        Self { root }
    }

    fn folder(&self, namespace: &str, create: bool) -> Result<Option<PathBuf>> {
        if namespace.is_empty() || namespace.len() > 8192 {
            return Err(error("invalid_argument", "invalid cache key or namespace"));
        }
        if !directory(&self.root, create)? {
            return Ok(None);
        }
        let folder = self.root.join(sha256(namespace));
        if directory(&folder, create)? {
            Ok(Some(folder))
        } else {
            Ok(None)
        }
    }

    fn path(&self, namespace: &str, key: &str, create: bool) -> Result<Option<(PathBuf, PathBuf)>> {
        if key.len() > 1024 {
            return Err(error("invalid_argument", "invalid cache key or namespace"));
        }
        Ok(self.folder(namespace, create)?
            .map(|dir| { let path = dir.join(format!("{}.json", sha256(key))); (dir, path) }))
    }

    pub(crate) fn invoke(&self, namespace: &str, action: &str, args: &serde_json::Value) -> serde_json::Value {
        let call = || -> Result<serde_json::Value> {
            let key = args.get("key").and_then(serde_json::Value::as_str)
                .ok_or_else(|| error("invalid_argument", "invalid cache key or namespace"))?;
            match action {
                "get" => self.get(namespace, key).map(|value| serde_json::json!(value)),
                "delete" => self.delete(namespace, key).map(|_| serde_json::json!(true)),
                "put" => {
                    let value = args.get("value").and_then(serde_json::Value::as_str)
                        .ok_or_else(|| error("invalid_argument", "invalid cache write request"))?;
                    let ttl = args.get("saveTime").and_then(serde_json::Value::as_i64)
                        .and_then(|ttl| i32::try_from(ttl).ok())
                        .ok_or_else(|| error("invalid_argument", "invalid cache write request"))?;
                    self.put(namespace, key, value, ttl).map(|_| serde_json::json!(true))
                }
                _ => Err(error("invalid_argument", "invalid cache operation")),
            }
        };
        match call() {
            Ok(data) => serde_json::json!({"ok":true,"data":data}),
            Err(error) => error.envelope(),
        }
    }

    pub(crate) fn get(&self, namespace: &str, key: &str) -> Result<Option<String>> {
        let Some((_, file)) = self.path(namespace, key, false)? else { return Ok(None) };
        read(&file)
    }

    pub(crate) fn put(&self, namespace: &str, key: &str, value: &str, save_time: i32) -> Result<()> {
        if value.len() > MAX_VALUE {
            return Err(error("limit_exceeded", "cache value too large"));
        }
        let Some((dir, path)) = self.path(namespace, key, true)? else {
            return Err(error("permission_denied", "invalid cache directory"));
        };
        let _guard = WriterLock::acquire(&dir)?;
        let expires = if save_time > 0 { now().saturating_add(save_time as u64) } else { 0 };
        let encoded = serde_json::to_vec(&Entry { version: 1, value: value.to_owned(), expires })
            .map_err(|_| error("invalid_argument", "cache text encoding failed"))?;
        if encoded.len() as u64 > MAX_FILE {
            return Err(error("limit_exceeded", "cache payload too large"));
        }
        // Match Lua's cleanup and quota accounting under the same writer lock.
        let mut count = 0;
        let mut total = 0_u64;
        for entry in fs::read_dir(&dir).map_err(|_| error("operation_failed", "cache operation failed"))? {
            let entry = entry.map_err(|_| error("operation_failed", "cache operation failed"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = entry.path();
            if entry_name(&name) {
                let Some(len) = regular_file(&child)? else { continue };
                // Corrupt regular files still occupy quota, but must not block other keys.
                if matches!(read(&child), Ok(None)) {
                    fs::remove_file(&child).map_err(|_| error("operation_failed", "cache cleanup failed"))?;
                } else {
                    count += 1;
                    total += len;
                }
            } else if temporary_name(&name)
                && fs::symlink_metadata(&child).is_ok_and(|attr| attr.file_type().is_file()) {
                fs::remove_file(&child).map_err(|_| error("operation_failed", "cache cleanup failed"))?;
            }
        }
        let existing = regular_file(&path)?;
        let old = existing.unwrap_or(0);
        let exists = existing.is_some();
        if count + usize::from(!exists) > MAX_ENTRIES
            || total.saturating_sub(old) + encoded.len() as u64 > MAX_TOTAL {
            return Err(error("limit_exceeded", "cache namespace quota exceeded"));
        }
        atomic_write(&dir, &path, &encoded)
    }

    pub(crate) fn delete(&self, namespace: &str, key: &str) -> Result<()> {
        let Some((dir, path)) = self.path(namespace, key, false)? else { return Ok(()) };
        let _guard = WriterLock::acquire(&dir)?;
        if regular_file(&path)?.is_none() {
            return Ok(());
        }
        fs::remove_file(&path).map_err(|_| error("operation_failed", "cache delete failed"))?;
        sync_directory(&dir).map_err(|_| error("operation_failed", "cache delete sync failed"))
    }

    // Menu clear affects only the ordinary URL namespace, not infoMap's prefix.
    pub(crate) fn clear(&self, namespace: &str) -> Result<()> {
        if namespace.is_empty() {
            return Err(error("invalid_argument", "invalid cache namespace"));
        }
        let Some(dir) = self.folder(namespace, false)? else { return Ok(()) };
        let _guard = WriterLock::acquire(&dir)?;
        for entry in fs::read_dir(&dir).map_err(|_| error("operation_failed", "cache clear failed"))? {
            let entry = entry.map_err(|_| error("operation_failed", "cache clear failed"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry_name(&name) || temporary_name(&name) {
                if regular_file(&entry.path())?.is_some() {
                    fs::remove_file(entry.path()).map_err(|_| error("operation_failed", "cache delete failed"))?;
                }
            }
        }
        sync_directory(&dir).map_err(|_| error("operation_failed", "cache delete sync failed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> PathBuf {
        let path = std::env::temp_dir().join(format!("reader-cache-test-{:016x}", rand::random::<u64>()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn disk_format_quota_ttl_namespace_and_symlink() {
        let dir = root();
        let cache = FileCache::at(dir.clone());
        assert_eq!(cache.get("a", "missing").unwrap(), None);
        assert!(cache.get("a", "missing").unwrap().is_none());
        cache.put("a", "key", "你好\0text", 0).unwrap();
        assert_eq!(cache.get("a", "key").unwrap().as_deref(), Some("你好\0text"));
        assert_eq!(cache.get("b", "key").unwrap(), None);
        assert_eq!(cache.get("a", "bad"), Ok(None));
        let file = dir.join(sha256("a")).join(format!("{}.json", sha256("key")));
        let contents: serde_json::Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(contents, serde_json::json!({"version":1,"value":"你好\0text","expires":0}));
        assert!(cache.put("a", "oversize", &"x".repeat(MAX_VALUE + 1), 0).is_err());
        for i in 0..64 {
            cache.put("quota", &i.to_string(), "x", 0).unwrap();
        }
        assert_eq!(cache.put("quota", "65", "x", 0).unwrap_err().kind, "limit_exceeded");
        cache.delete("a", "key").unwrap();
        assert!(cache.get("a", "key").unwrap().is_none());
        #[cfg(unix)] {
            use std::os::unix::fs::symlink;
            symlink(&dir, dir.join(sha256("evil"))).unwrap();
            assert_eq!(cache.put("evil", "x", "x", 0).unwrap_err().kind, "permission_denied");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn expired_entries_free_quota_and_clear_is_namespace_local() {
        let dir = root();
        let cache = FileCache::at(dir.clone());
        cache.put("other", "keep", "saved", 0).unwrap();
        // Seed the legacy disk format directly: expiry needs no wall-clock sleeps.
        let folder = dir.join(sha256("source"));
        fs::create_dir(&folder).unwrap();
        for index in 0..MAX_ENTRIES {
            let file = folder.join(format!("{}.json", sha256(&index.to_string())));
            fs::write(file, br#"{"version":1,"value":"expired","expires":1}"#).unwrap();
        }
        assert_eq!(cache.get("source", "0").unwrap(), None);
        cache.put("source", "new", "fresh", 0).unwrap();
        assert_eq!(cache.get("source", "new").unwrap().as_deref(), Some("fresh"));
        let invalid = cache.invoke("source", "put", &json!({"key":"bad","value":"x","saveTime":0.5}));
        assert_eq!(invalid["error"]["kind"], "invalid_argument");
        cache.clear("source").unwrap();
        cache.clear("source").unwrap();
        cache.clear("missing").unwrap();
        assert_eq!(cache.get("source", "new").unwrap(), None);
        assert_eq!(cache.get("other", "keep").unwrap().as_deref(), Some("saved"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_neighbor_does_not_block_writes_but_still_counts_toward_quota() {
        let dir = root();
        let cache = FileCache::at(dir.clone());
        cache.put("source", "good", "old", 0).unwrap();
        let folder = dir.join(sha256("source"));
        let broken = folder.join(format!("{}.json", sha256("broken")));
        fs::write(&broken, "{broken").unwrap();
        assert_eq!(cache.get("source", "broken").unwrap_err().kind, "operation_failed");
        cache.put("source", "good", "updated", 0).unwrap();
        assert_eq!(cache.get("source", "good").unwrap().as_deref(), Some("updated"));
        assert_eq!(fs::read_to_string(&broken).unwrap(), "{broken");
        for index in 2..MAX_ENTRIES {
            cache.put("source", &index.to_string(), "x", 0).unwrap();
        }
        assert_eq!(cache.put("source", "overflow", "x", 0).unwrap_err().kind, "limit_exceeded");
        cache.delete("source", "broken").unwrap();
        cache.put("source", "overflow", "x", 0).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn failed_publication_removes_temporary_file() {
        let dir = root();
        let destination = dir.join(format!("{}.json", sha256("key")));
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("sentinel"), "unchanged").unwrap();
        let failure = atomic_write(&dir, &destination, b"replacement").unwrap_err();
        assert_eq!(failure.kind, "operation_failed");
        assert_eq!(fs::read_to_string(destination.join("sentinel")).unwrap(), "unchanged");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "temporary file leaked");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn entry_symlinks_are_rejected_without_touching_the_target() {
        use std::os::unix::fs::symlink;
        let dir = root();
        let cache = FileCache::at(dir.clone());
        cache.put("source", "regular", "saved", 0).unwrap();
        let target = dir.join("outside");
        fs::write(&target, "untouched").unwrap();
        let entry = dir.join(sha256("source")).join(format!("{}.json", sha256("link")));
        symlink(&target, &entry).unwrap();
        assert_eq!(cache.get("source", "link").unwrap_err().kind, "permission_denied");
        assert_eq!(cache.put("source", "link", "unsafe", 0).unwrap_err().kind, "permission_denied");
        assert_eq!(cache.delete("source", "link").unwrap_err().kind, "permission_denied");
        assert_eq!(fs::read_to_string(target).unwrap(), "untouched");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn committed_write_and_delete_do_not_repeat_after_directory_sync_failure() {
        let dir = root();
        let cache = FileCache::at(dir.clone());
        cache.put("source", "key", "old", 0).unwrap();
        SYNC_FAILURES.with(|calls| calls.set(Some(0)));
        let written = cache.put("source", "key", "published", 0);
        let write_syncs = SYNC_FAILURES.with(|calls| calls.replace(None));
        assert_eq!(written.unwrap_err().kind, "operation_failed");
        assert_eq!(write_syncs, Some(1));
        assert_eq!(cache.get("source", "key").unwrap().as_deref(), Some("published"));
        let folder = dir.join(sha256("source"));
        assert_eq!(fs::read_dir(&folder).unwrap().count(), 1, "lock or temporary file leaked");

        SYNC_FAILURES.with(|calls| calls.set(Some(0)));
        let deleted = cache.delete("source", "key");
        let delete_syncs = SYNC_FAILURES.with(|calls| calls.replace(None));
        assert_eq!(deleted.unwrap_err().kind, "operation_failed");
        assert_eq!(delete_syncs, Some(1));
        assert_eq!(cache.get("source", "key").unwrap(), None);
        cache.delete("source", "key").unwrap();
        assert_eq!(fs::read_dir(folder).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn failed_file_publication_preserves_existing_value() {
        use std::os::unix::fs::PermissionsExt;
        unsafe extern "C" { fn geteuid() -> u32; }
        if unsafe { geteuid() } == 0 {
            eprintln!("permission failure fixture requires a non-root user");
            return;
        }
        let dir = root();
        let path = dir.join("existing.json");
        fs::write(&path, "old").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let failed = atomic_write(&dir, &path, b"replacement");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(failed.unwrap_err().kind, "operation_failed");
        assert_eq!(fs::read_to_string(path).unwrap(), "old");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1, "temporary file leaked");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn lfs_writer_lock_interoperability() {
        let dir = root();
        let cache = FileCache::at(dir.clone());
        cache.put("source", "a", "old", 0).unwrap();
        let folder = dir.join(sha256("source"));
        let lock = folder.join("lockfile.lfs");
        #[cfg(unix)] std::os::unix::fs::symlink("lock", &lock).unwrap();
        #[cfg(not(unix))] File::create(&lock).unwrap();
        assert_eq!(cache.put("source", "a", "new", 0).unwrap_err().kind, "cache_busy");
        assert_eq!(cache.delete("source", "a").unwrap_err().kind, "cache_busy");
        assert_eq!(cache.clear("source").unwrap_err().kind, "cache_busy");
        assert_eq!(cache.get("source", "a").unwrap().as_deref(), Some("old"));
        fs::remove_file(lock).unwrap();
        cache.put("source", "a", "new", 0).unwrap();
        assert_eq!(cache.get("source", "a").unwrap().as_deref(), Some("new"));
        let _ = fs::remove_dir_all(dir);
    }
}

// infoMap persists snapshots through the same source-js file cache.
// Unsaved state remains strictly process-local.
const INFO_PREFIX: &str = "legado-info-map-v1:";
const INFO_SNAPSHOT: &str = "snapshot";

struct InfoStateEntry {
    state: InfoMapState,
    save_error: Option<String>,
}

thread_local! {
    static INFO_STATES: RefCell<HashMap<String, InfoStateEntry>> = RefCell::new(HashMap::new());
}

fn info_namespace(source: &str) -> Result<String> {
    if source.is_empty() || source.len() + INFO_PREFIX.len() > 8192 {
        return Err(CacheError {
            kind: "permission_denied",
            message: "invalid infoMap source identity",
        });
    }
    Ok(format!("{INFO_PREFIX}{source}"))
}

fn serialize_info_map(state: &InfoMapState) -> Result<String> {
    let snapshot = json!({
        "values": state.values,
        "needSave": false,
        "saveTime": state.save_time,
    });
    serde_json::to_string(&snapshot).map_err(|_| CacheError {
        kind: "operation_failed",
        message: "infoMap JSON encoding failed",
    })
}

fn write_info_map(cache: &FileCache, source: &str, state: &InfoMapState) -> Result<()> {
    let name = info_namespace(source)?;
    let data = serialize_info_map(state)?;
    cache.put(&name, INFO_SNAPSHOT, &data, state.save_time)
}

pub(crate) fn load_info_map(cache: &FileCache, source: &str) -> Result<InfoMapState> {
    let name = info_namespace(source)?;
    if let Some(state) = INFO_STATES.with(|entries| {
        let mut entries = entries.borrow_mut();
        let existing = entries.get_mut(source)?;
        existing.save_error = None; // New request allows an explicit retry.
        Some(existing.state.clone())
    }) {
        return Ok(state);
    }
    let loaded = match cache.get(&name, INFO_SNAPSHOT)? {
        Some(raw) => {
            let value: Value = serde_json::from_str(&raw).map_err(|_| CacheError {
                kind: "operation_failed",
                message: "invalid persisted infoMap snapshot",
            })?;
            let mut state = InfoMapState::from_value(value).map_err(|_| CacheError {
                kind: "operation_failed",
                message: "invalid persisted infoMap snapshot",
            })?;
            state.need_save = false;
            state
        }
        None => InfoMapState::default(),
    };
    INFO_STATES.with(|entries| {
        entries.borrow_mut().insert(source.to_owned(), InfoStateEntry {
            state: loaded.clone(),
            save_error: None,
        });
    });
    Ok(loaded)
}

pub(crate) fn save_info_map_now(
    cache: &FileCache,
    source: &str,
    state: &InfoMapState,
) -> Result<()> {
    let result = write_info_map(cache, source, state);
    INFO_STATES.with(|entries| {
        entries.borrow_mut().insert(source.to_owned(), InfoStateEntry {
            state: if result.is_ok() {
                let mut persisted = state.clone();
                persisted.need_save = false;
                persisted
            } else {
                state.clone()
            },
            save_error: result.as_ref().err().map(|error| error.message.to_owned()),
        });
    });
    result
}

pub(crate) struct InfoCommit {
    pub state: InfoMapState,
    pub persistence_error: Option<String>,
}

pub(crate) fn commit_info_map(
    cache: &FileCache,
    source: &str,
    mut state: InfoMapState,
    flush: bool,
) -> Result<InfoCommit> {
    info_namespace(source)?;
    let prior_error = INFO_STATES.with(|entries| {
        entries.borrow().get(source).and_then(|entry| entry.save_error.clone())
    });
    let mut persistence_error = prior_error;
    if flush && state.need_save && persistence_error.is_none() {
        if let Err(error) = write_info_map(cache, source, &state) {
            persistence_error = Some(error.message.to_owned());
        } else {
            state.need_save = false;
        }
    }
    INFO_STATES.with(|entries| {
        entries.borrow_mut().insert(source.to_owned(), InfoStateEntry {
            state: state.clone(),
            save_error: persistence_error.clone(),
        });
    });
    Ok(InfoCommit { state, persistence_error })
}

#[cfg(test)]
mod info_map_tests {
    use super::*;
    use std::fs;

    #[test]
    fn legacy_snapshot_roundtrip_without_implicit_save() {
        let root = std::env::temp_dir().join(format!("infomap-rust-{:016x}", rand::random::<u64>()));
        fs::create_dir(&root).unwrap();
        let cache = FileCache::at(root.clone());
        let source = "https://info.example/";
        let mut state = load_info_map(&cache, source).unwrap();
        assert!(state.values.is_empty());
        state.values.insert("a".into(), "unchanged".into());
        assert!(!commit_info_map(&cache, source, state.clone(), false).unwrap().state.need_save);
        let info_namespace = info_namespace(source).unwrap();
        assert_eq!(cache.get(&info_namespace, INFO_SNAPSHOT).unwrap(), None);
        let mut state = load_info_map(&cache, source).unwrap();
        state.need_save = true;
        state.save_time = 0;
        let committed = commit_info_map(&cache, source, state, true).unwrap();
        assert!(!committed.state.need_save);
        let stored = cache.get(&info_namespace, INFO_SNAPSHOT).unwrap().unwrap();
        let parsed: Value = serde_json::from_str(&stored).unwrap();
        assert_eq!(parsed, json!({"values":{"a":"unchanged"},"needSave":false,"saveTime":0}));
        let _ = fs::remove_dir_all(root);
        INFO_STATES.with(|state| state.borrow_mut().clear());
    }
}
