//! Module 2 - drag & drop registration.
//!
//! `hermes add ./game.origin` parses the dropped file, validates it, and
//! copies it into `~/.config/hermes/origins/<id>.toml`. From then on the CLI
//! knows to track it. There is no server to register with and nothing is
//! phoned home; the registry is a folder of TOML files the user owns.
//!
//! The registry is also where **key pinning** lives. Re-adding an origin whose
//! `public_key` differs from the stored one is treated as a trust event and
//! requires an explicit `--force`, because a swapped key means a different
//! studio can sign updates for software the user already installed.

use crate::error::SecurityError;
use crate::paths;
use crate::schema::{validate_id, OriginFile};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Per-origin state that is *not* part of the studio's document.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OriginState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installed_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_dir: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_checked: Option<i64>,
    /// `issued_at` of the newest manifest we have accepted. A manifest older
    /// than this is a replay even if its signature is perfectly valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_manifest_issued_at: Option<i64>,
    #[serde(default)]
    pub added_at: i64,
}

impl OriginState {
    pub fn installed_version(&self) -> Option<semver::Version> {
        self.installed_version
            .as_deref()
            .and_then(|v| semver::Version::parse(v).ok())
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredOrigin {
    pub origin: OriginFile,
    pub state: OriginState,
}

fn origin_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(paths::origins_dir()?.join(format!("{id}.toml")))
}

fn state_path(id: &str) -> Result<PathBuf> {
    validate_id(id)?;
    Ok(paths::state_dir()?.join(format!("{id}.json")))
}

/// Read a `.origin` from anywhere on disk (the dropped file).
pub fn read_origin_file(path: &Path) -> Result<OriginFile> {
    let meta = fs::metadata(path)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} is not a file", path.display());
    }
    // A .origin is a small TOML document; anything large is not one.
    if meta.len() > 64 * 1024 {
        bail!(
            "{} is {} bytes - a .origin file should be well under 64 KiB",
            path.display(),
            meta.len()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    OriginFile::parse(&bytes)
}

/// Register (or update) an origin. Returns `(origin, was_already_registered)`.
pub fn add_origin(origin: &OriginFile, force: bool) -> Result<bool> {
    let path = origin_path(&origin.id)?;
    let existing = load_origin(&origin.id).ok();

    if let Some(prev) = &existing {
        if prev.public_key != origin.public_key && !force {
            return Err(SecurityError::KeyPinViolation {
                id: origin.id.clone(),
            }
            .into());
        }
    }

    paths::write_atomic(&path, origin.to_toml().as_bytes())?;

    let mut state = load_state(&origin.id).unwrap_or_default();
    if state.added_at == 0 {
        state.added_at = paths::now_unix();
    }
    save_state(&origin.id, &state)?;
    Ok(existing.is_some())
}

pub fn load_origin(id: &str) -> Result<OriginFile> {
    let path = origin_path(id)?;
    let bytes = fs::read(&path)
        .with_context(|| format!("'{id}' is not registered (no {})", path.display()))?;
    OriginFile::parse(&bytes)
}

pub fn load_state(id: &str) -> Result<OriginState> {
    let path = state_path(id)?;
    match fs::read(&path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).unwrap_or_default()),
        Err(_) => Ok(OriginState::default()),
    }
}

pub fn save_state(id: &str, state: &OriginState) -> Result<()> {
    let path = state_path(id)?;
    let json = serde_json::to_string_pretty(state)?;
    paths::write_atomic(&path, json.as_bytes())
}

/// Every registered origin, sorted by id. Unreadable entries are reported
/// rather than silently skipped.
pub fn list_origins() -> Result<Vec<RegisteredOrigin>> {
    let dir = paths::origins_dir()?;
    let mut out = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Ok(out),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        match OriginFile::parse(&bytes) {
            Ok(origin) => {
                let state = load_state(&origin.id).unwrap_or_default();
                out.push(RegisteredOrigin { origin, state });
            }
            Err(e) => eprintln!("warning: ignoring {}: {e:#}", path.display()),
        }
    }
    out.sort_by(|a, b| a.origin.id.cmp(&b.origin.id));
    Ok(out)
}

pub fn remove_origin(id: &str) -> Result<()> {
    let path = origin_path(id)?;
    if !path.exists() {
        bail!("'{id}' is not registered");
    }
    fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
    let _ = fs::remove_file(state_path(id)?);
    Ok(())
}

/// Resolve a user-supplied id, accepting a unique prefix or the display name.
pub fn resolve_id(needle: &str) -> Result<OriginFile> {
    if let Ok(origin) = load_origin(needle) {
        return Ok(origin);
    }
    let all = list_origins()?;
    let needle_lc = needle.to_lowercase();
    let matches: Vec<_> = all
        .into_iter()
        .filter(|r| {
            r.origin.id.starts_with(&needle_lc) || r.origin.name.to_lowercase() == needle_lc
        })
        .collect();
    match matches.len() {
        0 => Err(anyhow!(
            "no registered origin matches '{needle}' (try `hermes list`)"
        )),
        1 => Ok(matches.into_iter().next().unwrap().origin),
        n => {
            let ids: Vec<_> = matches.iter().map(|m| m.origin.id.clone()).collect();
            Err(anyhow!(
                "'{needle}' matches {n} origins: {}",
                ids.join(", ")
            ))
        }
    }
}

/// Where an origin's files live. Studios may suggest a folder name; the user's
/// `--install-dir` always wins, and the resolved path is remembered.
pub fn install_dir_for(origin: &OriginFile, state: &OriginState) -> Result<PathBuf> {
    if let Some(dir) = &state.install_dir {
        return Ok(dir.clone());
    }
    let name = origin
        .install_dir
        .clone()
        .unwrap_or_else(|| origin.id.clone());
    let relative = crate::security::safepath::sanitize_relative(&name)
        .map_err(|e| anyhow!("install_dir is unsafe: {e}"))?;
    Ok(paths::default_install_root()?.join(relative))
}

// ---------------------------------------------------------------------------
// Drag & drop path handling
// ---------------------------------------------------------------------------

/// Make sense of a path a terminal produced by dragging a file onto it.
///
/// Terminals disagree about quoting: Windows Explorer wraps paths containing
/// spaces in `"`, GNOME/KDE emit `file://` URIs, and most Unix shells escape
/// spaces with a backslash. All three arrive here as plain argv strings.
pub fn normalize_dropped_path(raw: &str) -> PathBuf {
    let mut s = raw.trim().to_string();

    // Surrounding quotes from a drag-and-drop or a copied path.
    for quote in ['"', '\''] {
        if s.len() >= 2 && s.starts_with(quote) && s.ends_with(quote) {
            s = s[1..s.len() - 1].to_string();
        }
    }

    // GNOME Files / KDE Dolphin drop URIs.
    if let Some(rest) = s.strip_prefix("file://") {
        let rest = rest.strip_prefix("localhost").unwrap_or(rest);
        let decoded = percent_decode(rest);
        // file:///C:/x on Windows -> C:/x
        #[cfg(windows)]
        let decoded = decoded
            .strip_prefix('/')
            .filter(|r| r.chars().nth(1) == Some(':'))
            .map(str::to_string)
            .unwrap_or(decoded);
        s = decoded;
    }

    // Unix shells escape spaces and quotes with backslashes when a file is
    // dropped. Only unescape when the literal path does not exist, so genuine
    // Windows separators are left alone.
    #[cfg(not(windows))]
    if !Path::new(&s).exists() && s.contains('\\') {
        let mut unescaped = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                if let Some(next) = chars.next() {
                    unescaped.push(next);
                }
            } else {
                unescaped.push(c);
            }
        }
        s = unescaped;
    }

    // Leading ~ expansion; shells do this themselves, but pasted paths do not.
    if s == "~" || s.starts_with("~/") || s.starts_with("~\\") {
        if let Some(home) = dirs::home_dir() {
            let rest = s.trim_start_matches('~').trim_start_matches(['/', '\\']);
            return if rest.is_empty() {
                home
            } else {
                home.join(rest)
            };
        }
    }

    PathBuf::from(s)
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
            if let Ok(byte) = u8::from_str_radix(hex, 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_quotes_from_dropped_paths() {
        assert_eq!(
            normalize_dropped_path("\"D:\\Games\\My Game\\game.origin\""),
            PathBuf::from("D:\\Games\\My Game\\game.origin")
        );
        assert_eq!(
            normalize_dropped_path("'/home/u/My Game/game.origin'"),
            PathBuf::from("/home/u/My Game/game.origin")
        );
    }

    #[test]
    fn decodes_file_uris() {
        let p = normalize_dropped_path("file:///home/u/My%20Game/game.origin");
        assert!(p.to_string_lossy().contains("My Game"));
    }

    #[test]
    fn trims_surrounding_whitespace() {
        assert_eq!(
            normalize_dropped_path("  ./game.origin  "),
            PathBuf::from("./game.origin")
        );
    }
}
