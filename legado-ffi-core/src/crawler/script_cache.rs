//! Optional URL-keyed JS download cache. The trusted Lua host supplies only its root.
//! Never cache generic HTTP, replay Set-Cookie, or turn a failed cache write into an HTTP error.
use crate::crawler::RawHttpResponse;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use ureq::http::HeaderMap;
use url::Url;

const VERSION: u32 = 1;
const MAX_ITEM: usize = 4 * 1024 * 1024;
const MAX_META: u64 = 4096;
const MAX_AGE: u64 = 24 * 60 * 60;

#[derive(Clone)]
pub(crate) struct ScriptCache {
    root: PathBuf,
}

#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    version: u32,
    url: String,
    final_url: String,
    status: u16,
    body_hash: String,
    size: usize,
    fetched_at: u64,
    expires_at: u64,
    last_access: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hash(data: &[u8]) -> String {
    hex::encode(digest(&SHA256, data).as_ref())
}

fn valid_directory(path: &Path, create: bool) -> bool {
    if create && !path.exists() && fs::create_dir(path).is_err() {
        return false;
    }
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_dir())
}

pub(crate) fn read_limited(path: &Path, max: u64) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > max {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() as u64 <= max).then_some(bytes)
}

fn normalized_url(raw: &str) -> Option<String> {
    let mut url = Url::parse(raw).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}

// The cache has a simple owner lock for publication/eviction. Readers only follow
// an atomically published manifest to a content-versioned body, so never need a lock.
struct WriterLock(PathBuf);
impl WriterLock {
    fn acquire(dir: &Path) -> Option<Self> {
        let path = dir.join(".write.lock");
        if fs::create_dir(&path).is_err() {
            // A crashed worker may leave a stale lock. Never touch a live writer.
            let stale = fs::symlink_metadata(&path).ok().is_some_and(|metadata| {
                metadata.file_type().is_dir()
                    && metadata.modified().ok().is_some_and(|time| {
                        SystemTime::now().duration_since(time).unwrap_or_default()
                            > Duration::from_secs(300)
                    })
            });
            if !stale || fs::remove_dir(&path).is_err() || fs::create_dir(&path).is_err() {
                return None;
            }
        }
        Some(Self(path))
    }
}
impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn temp_file(dir: &Path, stem: &str, bytes: &[u8]) -> Option<PathBuf> {
    for _ in 0..4 {
        let path = dir.join(format!("{stem}.tmp-{:016x}", rand::random::<u64>()));
        let Ok(mut file) = OpenOptions::new().write(true).create_new(true).open(&path) else {
            continue;
        };
        // Rebuildable cache entries need atomic publication, not forced durability.
        // Missing or corrupt files after a crash are treated as cache misses.
        let result = file.write_all(bytes);
        if result.is_ok() {
            return Some(path);
        }
        let _ = fs::remove_file(path);
    }
    None
}

// Share the existing short writer lock and atomic publication with the bootstrap cache.
pub(crate) fn publish_bootstrap(dir: &Path, target: &Path, bytes: &[u8]) {
    let Some(_lock) = WriterLock::acquire(dir) else {
        return;
    };
    let Some(temp) = temp_file(dir, "bootstrap-entry", bytes) else {
        return;
    };
    if fs::rename(&temp, target).is_err() {
        let _ = fs::remove_file(temp);
    }
}

fn cache_ttl(headers: &HeaderMap) -> Option<u64> {
    let current = now() as i64;
    let date = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| chrono::DateTime::parse_from_rfc2822(value).ok())
            .map(|value| value.timestamp())
    };
    let response_date = date("date");
    let max_age = headers
        .get("cache-control")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            value.split(',').find_map(|part| {
                let (name, seconds) = part.trim().split_once('=')?;
                name.trim()
                    .eq_ignore_ascii_case("max-age")
                    .then(|| seconds.trim().trim_matches('"').parse::<u64>().ok())
                    .flatten()
            })
        });
    let expires = date("expires");
    let lifetime = max_age
        .or_else(|| {
            expires.map(|expiry| {
                expiry
                    .saturating_sub(response_date.unwrap_or(current))
                    .max(0) as u64
            })
        })
        .unwrap_or(MAX_AGE);
    let age = headers
        .get("age")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    let elapsed = age.max(
        response_date
            .map(|date| current.saturating_sub(date).max(0) as u64)
            .unwrap_or(0),
    );
    // Expires without Date is already relative to the local clock; don't deduct Age twice.
    let elapsed = if max_age.is_none() && expires.is_some() && response_date.is_none() {
        0
    } else {
        elapsed
    };
    let ttl = lifetime.saturating_sub(elapsed).min(MAX_AGE);
    (ttl > 0).then_some(ttl)
}

impl ScriptCache {
    pub(crate) fn from_host() -> Option<Self> {
        let reply = crate::host_services::call("resource.cache.config", &serde_json::json!({}));
        let root = reply
            .get("ok")
            .and_then(serde_json::Value::as_bool)
            .filter(|ok| *ok)
            .and_then(|_| reply.get("data"))
            .and_then(serde_json::Value::as_str)?;
        let root = PathBuf::from(root);
        if !root.is_absolute()
            || root
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || !valid_directory(&root, false)
        {
            return None;
        }
        Some(Self { root })
    }

    pub(crate) fn directory(&self, create: bool) -> Option<PathBuf> {
        if !valid_directory(&self.root, false) {
            return None;
        }
        let parent = self.root.join("resources");
        if !valid_directory(&parent, create) {
            return None;
        }
        let dir = parent.join("js");
        valid_directory(&dir, create).then_some(dir)
    }

    fn paths(dir: &Path, url: &str, hash_body: &str) -> (PathBuf, PathBuf) {
        let key = hash(url.as_bytes());
        (
            dir.join(format!("http-{key}.json")),
            dir.join(format!("http-{key}-{hash_body}.body")),
        )
    }

    fn read_entry(path: &Path) -> Option<Entry> {
        let entry: Entry = serde_json::from_slice(&read_limited(path, MAX_META)?).ok()?;
        (entry.version == VERSION
            && entry.size <= MAX_ITEM
            && entry.status == 200
            && entry.body_hash.len() == 64
            && entry
                .body_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && entry.expires_at >= entry.fetched_at
            && entry.expires_at.saturating_sub(entry.fetched_at) <= MAX_AGE
            && normalized_url(&entry.final_url).is_some())
        .then_some(entry)
    }

    pub(crate) fn get(&self, raw_url: &str, response_limit: usize) -> Option<RawHttpResponse> {
        let url = normalized_url(raw_url)?;
        let dir = self.directory(false)?;
        let (manifest, _) = Self::paths(&dir, &url, "");
        let entry = Self::read_entry(&manifest)?;
        if entry.url != url
            || entry.expires_at <= now()
            || entry.size > response_limit
            || entry.status != 200
        {
            return None;
        }
        let (_, body_path) = Self::paths(&dir, &url, &entry.body_hash);
        let body = read_limited(&body_path, entry.size as u64)?;
        if body.len() != entry.size || hash(&body) != entry.body_hash {
            return None;
        }
        // Deliberately do not replay Set-Cookie or any other response side effects.
        // Avoid rewriting metadata on every hit; an hour-granular LRU touch is best effort.
        if now().saturating_sub(entry.last_access) >= 3600 {
            self.touch(&dir, &manifest, &entry);
        }
        Some(RawHttpResponse {
            url: entry.final_url,
            status: entry.status,
            headers: HeaderMap::new(),
            body,
        })
    }

    fn touch(&self, dir: &Path, manifest: &Path, entry: &Entry) {
        let Some(_lock) = WriterLock::acquire(dir) else {
            return;
        };
        let Some(current) = Self::read_entry(manifest) else {
            return;
        };
        if current.body_hash != entry.body_hash || current.expires_at != entry.expires_at {
            return;
        }
        let updated = Entry {
            last_access: now(),
            ..current
        };
        let Ok(bytes) = serde_json::to_vec(&updated) else {
            return;
        };
        if let Some(temp) = temp_file(dir, "http-touch", &bytes) {
            if fs::rename(&temp, manifest).is_err() {
                let _ = fs::remove_file(temp);
            }
        }
    }

    pub(crate) fn put(&self, raw_url: &str, response: &RawHttpResponse) {
        if response.status != 200 || response.body.len() > MAX_ITEM {
            return;
        }
        let Some(ttl) = cache_ttl(&response.headers) else {
            return;
        };
        let (Some(url), Some(final_url)) = (normalized_url(raw_url), normalized_url(&response.url))
        else {
            return;
        };
        let Some(dir) = self.directory(true) else {
            return;
        };
        let Some(_lock) = WriterLock::acquire(&dir) else {
            return;
        };
        let checksum = hash(&response.body);
        let (manifest, body_path) = Self::paths(&dir, &url, &checksum);
        let current = now();
        let entry = Entry {
            version: VERSION,
            url,
            final_url,
            status: 200,
            body_hash: checksum,
            size: response.body.len(),
            fetched_at: current,
            expires_at: current.saturating_add(ttl),
            last_access: current,
        };
        let Ok(meta) = serde_json::to_vec(&entry) else {
            return;
        };
        if meta.len() > MAX_META as usize {
            return;
        }
        // The Lua host owns the directory quota and eviction. No total-size
        // accounting or directory scans are performed by Rust on publication.
        let existing_body_is_valid =
            read_limited(&body_path, MAX_ITEM as u64).is_some_and(|bytes| bytes == response.body);
        if !existing_body_is_valid {
            let Some(temp) = temp_file(&dir, "http-body", &response.body) else {
                return;
            };
            if fs::rename(&temp, &body_path).is_err() {
                let _ = fs::remove_file(temp);
                return;
            }
        }
        let Some(temp) = temp_file(&dir, "http-meta", &meta) else {
            return;
        };
        if fs::rename(&temp, &manifest).is_err() {
            let _ = fs::remove_file(temp);
        }
    }
}
