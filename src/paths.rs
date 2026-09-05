//! Where HERMES keeps its state.
//!
//! Layout (`~/.config/hermes` on Unix, `%APPDATA%\Hermes` on Windows,
//! overridable with `HERMES_HOME`):
//!
//! ```text
//! hermes/
//!   origins/<id>.toml     the registered .origin files (Module 2)
//!   state/<id>.json       installed version + install dir per origin
//!   tokens/<id>.json      studio bearer tokens (Module 5), mode 0600
//!   icons/                icons extracted from the binary (Module 6)
//!   backups/<id>/<ver>/   snapshots taken by a plan's `backup` steps
//! ```
//!
//! Staging is deliberately *not* here: it lives next to the install directory
//! so the final directory swap is a same-volume `rename` (see `update.rs`).

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Directory name used for on-disk staging next to an install root.
pub const STAGING_DIR_NAME: &str = ".staging";

/// Root of all HERMES state.
pub fn hermes_home() -> Result<PathBuf> {
    if let Some(custom) = std::env::var_os("HERMES_HOME") {
        if !custom.is_empty() {
            return Ok(PathBuf::from(custom));
        }
    }
    #[cfg(unix)]
    {
        // Follow the XDG spec, which lands on ~/.config/hermes by default.
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(xdg).join("hermes"));
        }
        let home = dirs::home_dir().context("cannot determine the home directory")?;
        Ok(home.join(".config").join("hermes"))
    }
    #[cfg(not(unix))]
    {
        let base = dirs::config_dir().context("cannot determine the config directory")?;
        Ok(base.join("Hermes"))
    }
}

pub fn origins_dir() -> Result<PathBuf> {
    sub("origins")
}
pub fn state_dir() -> Result<PathBuf> {
    sub("state")
}
pub fn tokens_dir() -> Result<PathBuf> {
    sub("tokens")
}
pub fn icons_dir() -> Result<PathBuf> {
    sub("icons")
}

/// Default parent for installs when an origin does not name one.
pub fn default_install_root() -> Result<PathBuf> {
    sub("apps")
}

fn sub(name: &str) -> Result<PathBuf> {
    let p = hermes_home()?.join(name);
    ensure_private_dir(&p)?;
    Ok(p)
}

/// Create a directory (and parents) that only the current user can read.
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path)?.permissions();
        perm.set_mode(0o700);
        let _ = fs::set_permissions(path, perm);
    }
    Ok(())
}

/// Write a file that only the current user can read (tokens, private keys).
pub fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    // Write-then-rename so a crash never leaves a half-written credential.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&tmp)?.permissions();
        perm.set_mode(0o600);
        fs::set_permissions(&tmp, perm)?;
    }
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

/// Atomically replace a small file's contents (registry entries, state).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("writing {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).with_context(|| format!("installing {}", path.display()))?;
    Ok(())
}

/// Mark a directory hidden. On Unix a leading dot is enough; on Windows we set
/// the FILE_ATTRIBUTE_HIDDEN bit via `attrib` so `.staging` really is hidden.
pub fn hide_dir(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        use std::process::Command;
        let _ = Command::new("attrib")
            .arg("+h")
            .arg(path.as_os_str())
            .status();
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

/// Seconds since the Unix epoch.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
