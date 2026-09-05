//! `hermes install` - put the binary somewhere permanent and on `PATH`.
//!
//! Building with cargo leaves the binary in `target/release`, which is a
//! terrible place for it: it is not on `PATH`, and `install-system` would
//! register a file association pointing into a build directory that the next
//! `cargo clean` deletes. This module fixes both.
//!
//! Everything is per-user. Nothing here needs admin or sudo, nothing is
//! written outside the user's own profile, and `uninstall` reverses it.
//!
//! * Windows - `%LOCALAPPDATA%\Programs\Hermes`, added to the `Path` value
//!   under `HKCU\Environment` (never the machine-wide one).
//! * Linux/macOS - `~/.local/bin`, with an `export PATH=...` line appended to
//!   the shell rc files that exist, only when the directory is not already on
//!   `PATH`.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Marker written into shell rc files so we can find (and remove) our line.
/// Windows keeps PATH in the registry and never touches an rc file.
#[cfg(not(windows))]
const RC_MARKER: &str = "# added by `hermes install`";

#[derive(Debug, Default)]
pub struct Outcome {
    pub binary: PathBuf,
    /// The binary was already the installed one; nothing was copied.
    pub already_installed: bool,
    pub path_changed: bool,
    pub notes: Vec<String>,
}

/// Where the binary goes.
pub fn default_install_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let base = dirs::data_local_dir()
            .context("cannot determine %LOCALAPPDATA%")?;
        Ok(base.join("Programs").join("Hermes"))
    }
    #[cfg(not(windows))]
    {
        let home = dirs::home_dir().context("cannot determine the home directory")?;
        Ok(home.join(".local").join("bin"))
    }
}

pub const fn binary_name() -> &'static str {
    if cfg!(windows) {
        "hermes.exe"
    } else {
        "hermes"
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Copy this binary into `dir` and make sure `dir` is on `PATH`.
pub fn install(dir: Option<PathBuf>) -> Result<Outcome> {
    let dir = match dir {
        Some(dir) => dir,
        None => default_install_dir()?,
    };
    fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;

    let source = std::env::current_exe().context("cannot locate the running binary")?;
    let target = dir.join(binary_name());

    let mut outcome = Outcome {
        binary: target.clone(),
        ..Outcome::default()
    };

    if same_file(&source, &target) {
        outcome.already_installed = true;
        outcome
            .notes
            .push("already running from the install location; binary left alone".into());
    } else {
        // A previous hermes may be running from the target path, which on
        // Windows makes the file unlinkable but still renameable. Move it
        // aside, then clean up the leftover if the OS lets us.
        if target.exists() {
            let stale = dir.join(format!("{}.old", binary_name()));
            let _ = fs::remove_file(&stale);
            if fs::rename(&target, &stale).is_ok() {
                if fs::remove_file(&stale).is_err() {
                    outcome.notes.push(format!(
                        "previous binary is still running; it was moved to {} and can be \
                         deleted later",
                        stale.display()
                    ));
                }
            }
        }
        fs::copy(&source, &target).with_context(|| {
            format!("copying {} -> {}", source.display(), target.display())
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755))?;
        }
    }

    outcome.path_changed = ensure_on_path(&dir, &mut outcome.notes)?;
    Ok(outcome)
}

/// Remove the installed binary and take the directory back off `PATH`.
pub fn uninstall() -> Result<Outcome> {
    let dir = default_install_dir()?;
    let target = dir.join(binary_name());
    let mut outcome = Outcome {
        binary: target.clone(),
        ..Outcome::default()
    };

    let running = std::env::current_exe().unwrap_or_default();
    if target.exists() {
        if same_file(&running, &target) {
            // Deleting the executable that is currently running is a mess on
            // every platform. Say so plainly instead of half-doing it.
            outcome.notes.push(format!(
                "{} is the binary you are running right now - delete it manually once \
                 this process exits",
                target.display()
            ));
        } else {
            fs::remove_file(&target)
                .with_context(|| format!("removing {}", target.display()))?;
            outcome.notes.push(format!("removed {}", target.display()));
            // Only clean up the directory if we made it and it is now empty.
            if fs::read_dir(&dir).map(|mut e| e.next().is_none()).unwrap_or(false) {
                let _ = fs::remove_dir(&dir);
            }
        }
    } else {
        outcome.notes.push("no installed binary found".into());
    }

    outcome.path_changed = remove_from_path(&dir, &mut outcome.notes)?;
    Ok(outcome)
}

// ---------------------------------------------------------------------------
// PATH - Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn path_entries(value: &str) -> Vec<String> {
    value
        .split(';')
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty())
        .collect()
}

#[cfg(windows)]
fn utf16_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|unit| unit.to_le_bytes())
        .collect()
}

/// Tell running shells and Explorer that the environment changed, so a new
/// terminal picks up `PATH` without a logout.
#[cfg(windows)]
fn broadcast_environment_change() {
    const HWND_BROADCAST: isize = 0xffff;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hwnd: isize,
            msg: u32,
            wparam: usize,
            lparam: *const u16,
            flags: u32,
            timeout: u32,
            result: *mut usize,
        ) -> isize;
    }
    let param: Vec<u16> = "Environment".encode_utf16().chain(std::iter::once(0)).collect();
    let mut result: usize = 0;
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            param.as_ptr(),
            SMTO_ABORTIFHUNG,
            5000,
            &mut result,
        );
    }
}

/// Normalised comparison for a PATH entry: Windows paths are case-insensitive
/// and a trailing separator is meaningless.
#[cfg(windows)]
fn path_eq(a: &str, b: &str) -> bool {
    a.trim().trim_end_matches('\\').eq_ignore_ascii_case(b.trim().trim_end_matches('\\'))
}

/// Append `dir` unless it is already there. `None` means "no change needed",
/// which is what stops us rewriting PATH on every run.
#[cfg(windows)]
fn add_entry(mut entries: Vec<String>, dir: &str) -> Option<Vec<String>> {
    if entries.iter().any(|e| path_eq(e, dir)) {
        return None;
    }
    entries.push(dir.trim_end_matches('\\').to_string());
    Some(entries)
}

/// Drop every occurrence of `dir`, leaving everything else in order.
#[cfg(windows)]
fn remove_entry(entries: Vec<String>, dir: &str) -> Option<Vec<String>> {
    let filtered: Vec<String> = entries
        .iter()
        .filter(|e| !path_eq(e, dir))
        .cloned()
        .collect();
    if filtered.len() == entries.len() {
        None
    } else {
        Some(filtered)
    }
}

#[cfg(windows)]
fn with_user_path<F>(edit: F, notes: &mut Vec<String>) -> Result<bool>
where
    F: FnOnce(Vec<String>) -> Option<Vec<String>>,
{
    with_path_key("Environment", edit, notes)
}

/// The registry half, with the key name injected so tests can drive the exact
/// same code against a scratch key instead of the user's real PATH.
#[cfg(windows)]
fn with_path_key<F>(key_name: &str, edit: F, notes: &mut Vec<String>) -> Result<bool>
where
    F: FnOnce(Vec<String>) -> Option<Vec<String>>,
{
    use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_ALL_ACCESS};
    use winreg::{RegKey, RegValue};

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (env, _) = hkcu
        .create_subkey_with_flags(key_name, KEY_ALL_ACCESS)
        .with_context(|| format!("opening HKCU\\{key_name}"))?;

    // Preserve the value's type: user PATH is very often REG_EXPAND_SZ and
    // contains %USERPROFILE%-style references that must keep expanding.
    let (current, vtype) = match env.get_raw_value("Path") {
        Ok(raw) => {
            let text: String = env.get_value("Path").unwrap_or_default();
            (text, raw.vtype)
        }
        Err(_) => (String::new(), RegType::REG_EXPAND_SZ),
    };

    let Some(updated) = edit(path_entries(&current)) else {
        return Ok(false);
    };
    let joined = updated.join(";");
    env.set_raw_value(
        "Path",
        &RegValue {
            bytes: utf16_bytes(&joined),
            vtype,
        },
    )
    .with_context(|| format!("writing HKCU\\{key_name}\\Path"))?;
    if key_name == "Environment" {
        broadcast_environment_change();
        notes.push("updated your user PATH (open a new terminal to pick it up)".into());
    }
    Ok(true)
}

#[cfg(windows)]
fn ensure_on_path(dir: &Path, notes: &mut Vec<String>) -> Result<bool> {
    let wanted = dir.to_string_lossy().to_string();
    with_user_path(|entries| add_entry(entries, &wanted), notes)
}

#[cfg(windows)]
fn remove_from_path(dir: &Path, notes: &mut Vec<String>) -> Result<bool> {
    let wanted = dir.to_string_lossy().to_string();
    with_user_path(|entries| remove_entry(entries, &wanted), notes)
}

// ---------------------------------------------------------------------------
// PATH - Unix
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn already_on_path(dir: &Path) -> bool {
    std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).any(|entry| entry == dir))
        .unwrap_or(false)
}

#[cfg(not(windows))]
fn rc_files() -> Vec<PathBuf> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    [
        home.join(".profile"),
        home.join(".bashrc"),
        home.join(".zshrc"),
        home.join(".config/fish/config.fish"),
    ]
    .into_iter()
    .filter(|p| p.exists())
    .collect()
}

#[cfg(not(windows))]
fn ensure_on_path(dir: &Path, notes: &mut Vec<String>) -> Result<bool> {
    if already_on_path(dir) {
        notes.push(format!("{} is already on your PATH", dir.display()));
        return Ok(false);
    }

    let files = rc_files();
    if files.is_empty() {
        notes.push(format!(
            "could not find a shell rc file - add this to yours by hand:\n      \
             export PATH=\"{}:$PATH\"",
            dir.display()
        ));
        return Ok(false);
    }

    let mut changed = false;
    for file in files {
        let existing = fs::read_to_string(&file).unwrap_or_default();
        if existing.contains(RC_MARKER) {
            continue;
        }
        let is_fish = file.extension().and_then(|e| e.to_str()) == Some("fish");
        let line = if is_fish {
            format!("\n{RC_MARKER}\nfish_add_path {}\n", dir.display())
        } else {
            format!("\n{RC_MARKER}\nexport PATH=\"{}:$PATH\"\n", dir.display())
        };
        // Append only. We never rewrite what is already in a user's rc file.
        use std::io::Write;
        let mut handle = fs::OpenOptions::new().append(true).open(&file)?;
        handle.write_all(line.as_bytes())?;
        notes.push(format!("added {} to PATH in {}", dir.display(), file.display()));
        changed = true;
    }
    if changed {
        notes.push("open a new terminal (or source your rc file) to pick it up".into());
    }
    Ok(changed)
}

#[cfg(not(windows))]
fn remove_from_path(_dir: &Path, notes: &mut Vec<String>) -> Result<bool> {
    let mut changed = false;
    for file in rc_files() {
        let Ok(existing) = fs::read_to_string(&file) else {
            continue;
        };
        if !existing.contains(RC_MARKER) {
            continue;
        }
        // Drop the marker line and the one line that follows it.
        let mut out = Vec::new();
        let mut skip_next = false;
        for line in existing.lines() {
            if skip_next {
                skip_next = false;
                continue;
            }
            if line.trim() == RC_MARKER {
                skip_next = true;
                continue;
            }
            out.push(line);
        }
        fs::write(&file, format!("{}\n", out.join("\n")))?;
        notes.push(format!("removed the PATH line from {}", file.display()));
        changed = true;
    }
    Ok(changed)
}

/// Sanity check: can the shell find `hermes` by name right now?
pub fn resolvable_on_path() -> Option<PathBuf> {
    let name = binary_name();
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Refuse silly install targets before we copy anything into them.
pub fn validate_target(dir: &Path) -> Result<()> {
    if dir.as_os_str().is_empty() {
        bail!("install directory is empty");
    }
    if !dir.is_absolute() {
        bail!("install directory must be an absolute path");
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    fn entries(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn path_is_split_and_cleaned() {
        let parsed = path_entries(r"C:\a;  C:\b  ;;C:\c;");
        assert_eq!(parsed, entries(&[r"C:\a", r"C:\b", r"C:\c"]));
    }

    #[test]
    fn adding_is_idempotent_and_case_insensitive() {
        let base = entries(&[r"C:\Windows", r"C:\Users\me\Programs\Hermes"]);
        // Already present, differing only in case and a trailing separator.
        assert!(add_entry(base.clone(), r"c:\users\me\programs\hermes\").is_none());

        let added = add_entry(base.clone(), r"C:\Tools").expect("appended");
        assert_eq!(added.len(), 3);
        assert_eq!(added[2], r"C:\Tools");
        // Existing entries keep their order and their spelling.
        assert_eq!(&added[..2], &base[..]);
    }

    #[test]
    fn removing_only_drops_our_entry() {
        let base = entries(&[r"C:\Windows", r"C:\Hermes", r"C:\Windows\System32"]);
        let removed = remove_entry(base.clone(), r"c:\hermes").expect("removed");
        assert_eq!(removed, entries(&[r"C:\Windows", r"C:\Windows\System32"]));
        // Nothing to do means PATH is not rewritten at all.
        assert!(remove_entry(base, r"C:\NotThere").is_none());
    }

    /// Round-trip against a scratch key. The value type has to survive: a user
    /// PATH is usually REG_EXPAND_SZ and holds %USERPROFILE%-style references
    /// that stop expanding the moment it is rewritten as a plain REG_SZ.
    #[test]
    fn registry_round_trip_preserves_expand_sz() {
        use winreg::enums::{RegType, HKEY_CURRENT_USER, KEY_ALL_ACCESS};
        use winreg::{RegKey, RegValue};

        const SCRATCH: &str = r"Software\Hermes.SelfTest.Path";
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let _ = hkcu.delete_subkey_all(SCRATCH);
        let (key, _) = hkcu
            .create_subkey_with_flags(SCRATCH, KEY_ALL_ACCESS)
            .expect("scratch key");
        key.set_raw_value(
            "Path",
            &RegValue {
                bytes: utf16_bytes(r"%USERPROFILE%\bin;C:\Windows"),
                vtype: RegType::REG_EXPAND_SZ,
            },
        )
        .expect("seed value");

        let mut notes = Vec::new();
        assert!(with_path_key(
            SCRATCH,
            |entries| add_entry(entries, r"C:\Tools\Hermes"),
            &mut notes
        )
        .expect("append"));

        let raw = key.get_raw_value("Path").expect("read back");
        assert_eq!(raw.vtype, RegType::REG_EXPAND_SZ, "value type must survive");
        let text: String = key.get_value("Path").expect("read back as string");
        assert_eq!(text, r"%USERPROFILE%\bin;C:\Windows;C:\Tools\Hermes");

        // Removal restores exactly what was there before.
        assert!(with_path_key(
            SCRATCH,
            |entries| remove_entry(entries, r"C:\Tools\Hermes"),
            &mut notes
        )
        .expect("remove"));
        let text: String = key.get_value("Path").expect("read back");
        assert_eq!(text, r"%USERPROFILE%\bin;C:\Windows");

        hkcu.delete_subkey_all(SCRATCH).expect("clean up");
    }
}
