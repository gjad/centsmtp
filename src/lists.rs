//! In-memory white/black lists backed by JSON files.
//!
//! * `whitelist.json`: `{ "domains": ["gmail.com", ...] }` - domains that skip the DNS check.
//!   Edited by hand; reloaded automatically when the file changes.
//! * `blacklist.json`: `{ "addresses": { "user@example.com": { "reason": "...", "added": "..." } } }`
//!   Written by the server whenever an address is added.
//!
//! Lookups only touch memory; the files are written only when the lists change.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const DEFAULT_WHITELIST: &[&str] = &[
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "icloud.com", "me.com", "qq.com", "foxmail.com", "163.com", "126.com", "sina.com", "aol.com",
    "protonmail.com", "proton.me",
];

#[derive(Serialize, Deserialize, Default)]
struct WhitelistFile {
    domains: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BlacklistEntry {
    pub reason: String,
    pub added: String,
}

#[derive(Serialize, Deserialize, Default)]
struct BlacklistFile {
    addresses: BTreeMap<String, BlacklistEntry>,
}

pub struct Lists {
    whitelist_path: PathBuf,
    blacklist_path: PathBuf,
    whitelist: RwLock<HashSet<String>>,
    whitelist_mtime: Mutex<Option<SystemTime>>,
    blacklist: RwLock<BTreeMap<String, BlacklistEntry>>,
    /// Domains from the downloaded open-source disposable-email blocklist.
    disposable: RwLock<HashSet<String>>,
}

fn norm(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// Short domains (qq.com, 163.com, ...) are too close to many legitimate ones; only longer
/// whitelisted domains are used as typo references.
const MIN_TYPO_REF_LEN: usize = 9;

/// True when `a` and `b` differ by exactly one substitution, insertion, deletion or
/// transposition of adjacent characters.
fn within_one_edit(a: &[u8], b: &[u8]) -> bool {
    if a == b || a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    if a.len() == b.len() {
        let diff: Vec<usize> = (0..a.len()).filter(|&i| a[i] != b[i]).collect();
        return match diff.as_slice() {
            [_] => true,
            [i, j] => *j == i + 1 && a[*i] == b[*j] && a[*j] == b[*i],
            _ => false,
        };
    }
    let (short, long) = if a.len() < b.len() { (a, b) } else { (b, a) };
    let i = (0..short.len()).find(|&i| short[i] != long[i]).unwrap_or(short.len());
    short[i..] == long[i + 1..]
}

fn mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).and_then(|m| m.modified()).ok()
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Lists {
    pub fn load(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        let whitelist_path = dir.join("whitelist.json");
        let blacklist_path = dir.join("blacklist.json");

        if !whitelist_path.exists() {
            let wl = WhitelistFile { domains: DEFAULT_WHITELIST.iter().map(|s| s.to_string()).collect() };
            write_json_atomic(&whitelist_path, &wl)?;
        }
        if !blacklist_path.exists() {
            write_json_atomic(&blacklist_path, &BlacklistFile::default())?;
        }

        let wl: WhitelistFile = serde_json::from_slice(&fs::read(&whitelist_path)?)
            .with_context(|| format!("invalid {}", whitelist_path.display()))?;
        let bl: BlacklistFile = serde_json::from_slice(&fs::read(&blacklist_path)?)
            .with_context(|| format!("invalid {}", blacklist_path.display()))?;
        let bl = bl.addresses.into_iter().map(|(k, v)| (norm(&k), v)).collect();

        Ok(Self {
            whitelist_mtime: Mutex::new(mtime(&whitelist_path)),
            whitelist: RwLock::new(wl.domains.iter().map(|d| norm(d)).collect()),
            blacklist: RwLock::new(bl),
            disposable: RwLock::new(HashSet::new()),
            whitelist_path,
            blacklist_path,
        })
    }

    pub fn is_whitelisted(&self, domain: &str) -> bool {
        self.whitelist.read().unwrap().contains(&norm(domain))
    }

    /// Returns the matching blocklist entry when the domain (or a parent domain) is on the
    /// downloaded disposable-email blocklist.
    pub fn disposable_match(&self, domain: &str) -> Option<String> {
        let set = self.disposable.read().unwrap();
        let d = norm(domain);
        let mut cur = d.as_str();
        loop {
            if set.contains(cur) {
                return Some(cur.to_string());
            }
            match cur.split_once('.') {
                Some((_, rest)) if rest.contains('.') => cur = rest,
                _ => return None,
            }
        }
    }

    pub fn set_disposable(&self, domains: HashSet<String>) {
        *self.disposable.write().unwrap() = domains;
    }

    /// For a non-whitelisted domain that is exactly one typo (substitution, insertion,
    /// deletion or swap of adjacent characters) away from a longer whitelisted domain,
    /// returns that whitelisted domain, e.g. `gmial.com` -> `gmail.com`.
    /// Add the domain itself to the whitelist to allow it anyway.
    pub fn typo_suggestion(&self, domain: &str) -> Option<String> {
        let d = norm(domain);
        let wl = self.whitelist.read().unwrap();
        if wl.contains(&d) {
            return None;
        }
        wl.iter()
            .filter(|w| w.len() >= MIN_TYPO_REF_LEN && within_one_edit(d.as_bytes(), w.as_bytes()))
            .min()
            .cloned()
    }

    /// Returns the reason when the address is blacklisted.
    pub fn blacklist_reason(&self, addr: &str) -> Option<String> {
        self.blacklist.read().unwrap().get(&norm(addr)).map(|e| e.reason.clone())
    }

    /// Adds an address to the blacklist and persists it. Returns `false` if it was already listed.
    pub fn blacklist_add(&self, addr: &str, reason: &str) -> Result<bool> {
        let key = norm(addr);
        let mut bl = self.blacklist.write().unwrap();
        if bl.contains_key(&key) {
            return Ok(false);
        }
        let added = OffsetDateTime::now_utc().format(&Rfc3339).unwrap_or_default();
        bl.insert(key, BlacklistEntry { reason: reason.to_string(), added });
        let file = BlacklistFile { addresses: bl.clone() };
        write_json_atomic(&self.blacklist_path, &file)?;
        Ok(true)
    }

    /// Reloads `whitelist.json` if it changed on disk. Returns `true` when reloaded.
    pub fn reload_whitelist_if_changed(&self) -> Result<bool> {
        let current = mtime(&self.whitelist_path);
        let mut last = self.whitelist_mtime.lock().unwrap();
        if current == *last {
            return Ok(false);
        }
        let wl: WhitelistFile = serde_json::from_slice(&fs::read(&self.whitelist_path)?)
            .with_context(|| format!("invalid {}", self.whitelist_path.display()))?;
        *self.whitelist.write().unwrap() = wl.domains.iter().map(|d| norm(d)).collect();
        *last = current;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::within_one_edit as e;

    #[test]
    fn one_edit() {
        assert!(e(b"gmial.com", b"gmail.com")); // swap
        assert!(e(b"gmai.com", b"gmail.com")); // deletion
        assert!(e(b"gmaill.com", b"gmail.com")); // insertion
        assert!(e(b"gmail.con", b"gmail.com")); // substitution
        assert!(e(b"hotmail.co", b"hotmail.com")); // trailing deletion
        assert!(!e(b"gmail.com", b"gmail.com"));
        assert!(!e(b"gmal.co", b"gmail.com")); // two edits
        assert!(!e(b"example.com", b"gmail.com"));
    }
}
