//! Keeps an open-source disposable-email domain blocklist up to date.
//!
//! The list (one domain per line, `#` comments) is downloaded periodically, validated,
//! cached in the data directory and swapped into memory. The cached copy is loaded on
//! startup so the list is available even when the download fails.

use crate::lists::Lists;
use anyhow::{bail, Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// A download with fewer entries than this is treated as broken and ignored.
const MIN_ENTRIES: usize = 100;
const MAX_BYTES: usize = 20 * 1024 * 1024;

pub const DEFAULT_URL: &str =
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/main/disposable_email_blocklist.conf";

fn valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn parse(text: &str) -> HashSet<String> {
    text.lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}').to_ascii_lowercase())
        .filter(|l| !l.is_empty() && !l.starts_with('#') && valid_domain(l))
        .collect()
}

pub fn load_cache(lists: &Lists, path: &Path) {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let set = parse(&text);
            info!("loaded {} disposable-email domains from {}", set.len(), path.display());
            lists.set_disposable(set);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("cannot read {}: {e}", path.display()),
    }
}

async fn update(http: &reqwest::Client, url: &str, path: &Path, lists: &Lists) -> Result<usize> {
    let resp = http.get(url).send().await?.error_for_status()?;
    if resp.content_length().is_some_and(|n| n as usize > MAX_BYTES) {
        bail!("blocklist too large");
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_BYTES {
        bail!("blocklist too large");
    }
    let text = String::from_utf8(bytes.to_vec()).context("blocklist is not UTF-8")?;
    let set = parse(&text);
    if set.len() < MIN_ENTRIES {
        bail!("blocklist has only {} valid entries, ignoring", set.len());
    }
    let tmp = path.with_extension("txt.tmp");
    tokio::fs::write(&tmp, text).await?;
    tokio::fs::rename(&tmp, path).await?;
    let n = set.len();
    lists.set_disposable(set);
    Ok(n)
}

pub async fn run(lists: Arc<Lists>, url: String, path: PathBuf, interval: Duration) {
    let http = match reqwest::Client::builder().timeout(Duration::from_secs(60)).build() {
        Ok(c) => c,
        Err(e) => {
            warn!("blocklist updater disabled: {e}");
            return;
        }
    };
    loop {
        let wait = match update(&http, &url, &path, &lists).await {
            Ok(n) => {
                info!("disposable-email blocklist updated: {n} domains");
                interval
            }
            Err(e) => {
                warn!("cannot update disposable-email blocklist: {e:#}");
                Duration::from_secs(600).min(interval)
            }
        };
        tokio::time::sleep(wait).await;
    }
}
