//! Minimal `KEY=VALUE` config file loader (lines starting with `#` are comments).
//!
//! Values are exported as environment variables before the command line is parsed,
//! so every `env = "..."` option of the binaries can be set in the file. Variables that
//! are already set in the real environment win, and empty values are ignored.

use anyhow::{Context, Result};
use std::path::Path;

pub fn load_env_file(path: &Path) -> Result<bool> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    for (n, line) in text.lines().enumerate() {
        let line = line.trim().trim_start_matches('\u{feff}');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("{}:{}: expected KEY=VALUE", path.display(), n + 1))?;
        let (k, v) = (k.trim(), v.trim().trim_matches(|c| c == '"' || c == '\''));
        if k.is_empty() || v.is_empty() || std::env::var_os(k).is_some() {
            continue;
        }
        std::env::set_var(k, v);
    }
    Ok(true)
}
