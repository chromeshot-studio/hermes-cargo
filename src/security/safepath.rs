//! Module 3a - path canonicalisation and Zip-Slip prevention.
//!
//! Rule of the house: **a path that came from outside this machine is a
//! string, not a path**, until it has been through [`sanitize_relative`]. The
//! archive, the manifest and the `.foiled` plan are all attacker-controlled in
//! the threat model (a compromised CDN, a hostile mirror, a studio account
//! takeover), so every one of their paths is treated as hostile input.
//!
//! Three independent layers, any of which alone would stop classic Zip-Slip:
//!
//! 1. **Lexical** ([`sanitize_relative`]) - the string may only be a sequence
//!    of ordinary components. No `..`, no absolute prefix, no drive letter, no
//!    UNC, no NTFS stream, no reserved DOS device name, no control characters.
//! 2. **Topological** ([`resolve_within`]) - the resolved path is re-checked
//!    against the canonicalised destination root, and every existing ancestor
//!    is stat-ed to make sure we are not writing *through* a symlink that was
//!    planted on disk earlier.
//! 3. **Structural** ([`extract_zip_secure`]) - symlink and special-file
//!    entries are refused outright, duplicate entries cannot overwrite each
//!    other, and the archive is bounded in entries, size and ratio.

use crate::error::{SecResult, SecurityError};
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

/// Longest single path component we will create.
const MAX_COMPONENT_LEN: usize = 255;
/// Longest relative path, in components and in bytes.
const MAX_COMPONENTS: usize = 64;
const MAX_PATH_LEN: usize = 4096;

/// DOS device names. Windows resolves `CON`, `aux.txt`, `COM1` and friends to
/// devices no matter which directory they appear in.
const RESERVED_DOS_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

fn unsafe_path(path: &str, reason: impl Into<String>) -> SecurityError {
    SecurityError::UnsafePath {
        path: path.to_string(),
        reason: reason.into(),
    }
}

/// Turn an untrusted path string into a relative [`PathBuf`] that is safe to
/// join onto a root, or fail loudly.
///
/// The returned path is rebuilt component by component from validated pieces;
/// none of the original string survives as-is.
pub fn sanitize_relative(raw: &str) -> SecResult<PathBuf> {
    if raw.is_empty() {
        return Err(unsafe_path(raw, "empty path"));
    }
    if raw.len() > MAX_PATH_LEN {
        return Err(unsafe_path(raw, format!("longer than {MAX_PATH_LEN} bytes")));
    }
    if raw.contains('\0') {
        return Err(unsafe_path(raw, "contains a NUL byte"));
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(unsafe_path(raw, "contains control characters"));
    }
    // Bidi overrides let an archive display "safe.txt" while writing
    // something else entirely.
    if raw.chars().any(|c| {
        matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')
    }) {
        return Err(unsafe_path(raw, "contains bidirectional override characters"));
    }
    // A colon is a drive separator or an NTFS alternate data stream. Neither
    // has any business in an archive entry.
    if raw.contains(':') {
        return Err(unsafe_path(
            raw,
            "contains ':' (drive letter or NTFS alternate data stream)",
        ));
    }
    // Zip entries must use '/', but archives in the wild use '\'. Treat both
    // as separators rather than letting '\' through as a literal character
    // that Windows would later interpret as one anyway.
    if raw.starts_with('/') || raw.starts_with('\\') {
        return Err(unsafe_path(raw, "absolute path"));
    }

    let mut out = PathBuf::new();
    let mut count = 0usize;
    for part in raw.split(['/', '\\']) {
        if part.is_empty() {
            // Trailing separator on a directory entry is fine; an empty
            // component in the middle is not.
            continue;
        }
        if part == "." {
            return Err(unsafe_path(raw, "contains a '.' component"));
        }
        if part == ".." {
            return Err(unsafe_path(raw, "contains a '..' traversal component"));
        }
        if part.len() > MAX_COMPONENT_LEN {
            return Err(unsafe_path(raw, "path component is too long"));
        }
        // Windows silently strips trailing dots and spaces, so "evil." and
        // "evil" would collide - and "..&nbsp;" style names can walk up.
        if part.ends_with('.') || part.ends_with(' ') || part.starts_with(' ') {
            return Err(unsafe_path(
                raw,
                "path component has leading/trailing spaces or a trailing dot",
            ));
        }
        let stem = part.split('.').next().unwrap_or(part).to_ascii_uppercase();
        if RESERVED_DOS_NAMES.contains(&stem.as_str()) {
            return Err(unsafe_path(
                raw,
                format!("'{part}' is a reserved device name on Windows"),
            ));
        }
        count += 1;
        if count > MAX_COMPONENTS {
            return Err(unsafe_path(raw, "too many path components"));
        }
        out.push(part);
    }

    if out.as_os_str().is_empty() {
        return Err(unsafe_path(raw, "resolves to an empty path"));
    }
    // Belt and braces: whatever we just built must still be purely relative.
    for comp in out.components() {
        match comp {
            Component::Normal(_) => {}
            other => {
                return Err(unsafe_path(
                    raw,
                    format!("unexpected path component {other:?}"),
                ))
            }
        }
    }
    Ok(out)
}

/// Sanitize `rel`, join it onto `root`, and prove the result is still inside
/// `root` on the real filesystem.
///
/// `root` must already exist; it is canonicalised once so that a symlinked
/// install directory is compared like for like.
pub fn resolve_within(root: &Path, rel: &str) -> SecResult<PathBuf> {
    let relative = sanitize_relative(rel)?;
    let canonical_root = fs::canonicalize(root).map_err(|e| {
        unsafe_path(
            &root.display().to_string(),
            format!("destination root cannot be resolved: {e}"),
        )
    })?;

    let mut cursor = canonical_root.clone();
    for comp in relative.components() {
        let Component::Normal(name) = comp else {
            return Err(unsafe_path(rel, "non-normal component survived sanitizing"));
        };
        cursor.push(name);
        // If this component already exists it must not be a symlink: writing
        // through a pre-existing link is how a "safe" relative path ends up
        // in /etc or C:\Windows.
        match fs::symlink_metadata(&cursor) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(SecurityError::PathTraversal {
                    entry: rel.to_string(),
                    reason: format!("'{}' is a symlink", cursor.display()),
                });
            }
            _ => {}
        }
    }

    if !cursor.starts_with(&canonical_root) {
        return Err(SecurityError::PathTraversal {
            entry: rel.to_string(),
            reason: format!(
                "'{}' is outside '{}'",
                cursor.display(),
                canonical_root.display()
            ),
        });
    }
    Ok(cursor)
}

/// Same check for a path we have already resolved (used by the scope engine).
pub fn assert_within(root: &Path, candidate: &Path) -> SecResult<()> {
    let root_c = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let cand_c = fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf());
    if cand_c.starts_with(&root_c) {
        Ok(())
    } else {
        Err(SecurityError::PathTraversal {
            entry: candidate.display().to_string(),
            reason: format!("outside '{}'", root_c.display()),
        })
    }
}

/// Strip the Windows `\\?\` verbatim prefix so paths read normally in prompts.
pub fn display_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

// ---------------------------------------------------------------------------
// Archive extraction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExtractLimits {
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    /// Uncompressed:compressed ratio ceiling, against zip bombs.
    pub max_ratio: u64,
    /// Allow an entry to replace a file that was already in the destination
    /// (true when unpacking over a cloned install tree). Duplicate entries
    /// *within the same archive* are refused either way.
    pub allow_replace_existing: bool,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_entries: 200_000,
            max_total_bytes: 64 * 1024 * 1024 * 1024, // 64 GiB
            max_file_bytes: 16 * 1024 * 1024 * 1024,  // 16 GiB
            max_ratio: 500,
            allow_replace_existing: false,
        }
    }
}

#[derive(Debug, Default)]
pub struct ExtractReport {
    pub files: usize,
    pub dirs: usize,
    pub bytes: u64,
}

/// Extract `archive` into `dest_root`, refusing anything that tries to leave.
///
/// Streams every entry through a 256 KiB buffer - an entry is never held in
/// memory, however large it is.
pub fn extract_zip_secure(
    archive: &Path,
    dest_root: &Path,
    limits: &ExtractLimits,
) -> SecResult<ExtractReport> {
    fs::create_dir_all(dest_root).map_err(|e| {
        unsafe_path(
            &dest_root.display().to_string(),
            format!("cannot create destination: {e}"),
        )
    })?;

    let file = File::open(archive).map_err(|e| {
        unsafe_path(
            &archive.display().to_string(),
            format!("cannot open archive: {e}"),
        )
    })?;
    let mut zip = zip::ZipArchive::new(BufReader::new(file))
        .map_err(|e| SecurityError::ArchiveLimit(format!("not a readable zip: {e}")))?;

    if zip.len() > limits.max_entries {
        return Err(SecurityError::ArchiveLimit(format!(
            "{} entries exceeds the cap of {}",
            zip.len(),
            limits.max_entries
        )));
    }

    let mut report = ExtractReport::default();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    let mut buf = vec![0u8; 256 * 1024];

    for i in 0..zip.len() {
        let mut entry = zip
            .by_index(i)
            .map_err(|e| SecurityError::ArchiveLimit(format!("entry {i} is unreadable: {e}")))?;
        let raw_name = entry.name().to_string();

        // Only regular files and directories. Symlinks are the sharpest tool
        // in the Zip-Slip box: extract a link, then extract "through" it.
        if let Some(mode) = entry.unix_mode() {
            let kind = mode & 0o170000;
            if kind != 0 && kind != 0o100000 && kind != 0o040000 {
                return Err(SecurityError::UnsafeEntryKind(raw_name));
            }
        }

        if entry.is_dir() {
            let rel = sanitize_relative(&raw_name)?;
            let target = resolve_within(dest_root, &rel.to_string_lossy())?;
            fs::create_dir_all(&target).map_err(|e| {
                unsafe_path(&raw_name, format!("cannot create directory: {e}"))
            })?;
            report.dirs += 1;
            continue;
        }

        let declared = entry.size();
        if declared > limits.max_file_bytes {
            return Err(SecurityError::ArchiveLimit(format!(
                "'{raw_name}' declares {declared} bytes, over the {} byte per-file cap",
                limits.max_file_bytes
            )));
        }
        let compressed = entry.compressed_size().max(1);
        if declared / compressed > limits.max_ratio {
            return Err(SecurityError::ArchiveLimit(format!(
                "'{raw_name}' has a {}:1 compression ratio, over the {}:1 cap (zip bomb?)",
                declared / compressed,
                limits.max_ratio
            )));
        }

        let rel = sanitize_relative(&raw_name)?;
        if !seen.insert(rel.clone()) {
            return Err(SecurityError::DuplicateEntry(raw_name));
        }

        // Create parents *before* resolving the target so the symlink walk in
        // resolve_within sees the real directories.
        if let Some(parent) = rel.parent().filter(|p| !p.as_os_str().is_empty()) {
            let parent_abs = resolve_within(dest_root, &parent.to_string_lossy())?;
            fs::create_dir_all(&parent_abs)
                .map_err(|e| unsafe_path(&raw_name, format!("cannot create parent: {e}")))?;
        }
        let target = resolve_within(dest_root, &rel.to_string_lossy())?;

        // Unlink first, then create exclusively: an existing file (from a
        // cloned tree, possibly a hardlink into the live install) is replaced,
        // never written through.
        match fs::symlink_metadata(&target) {
            Ok(meta) => {
                if !limits.allow_replace_existing {
                    return Err(SecurityError::DuplicateEntry(raw_name));
                }
                if meta.is_dir() {
                    return Err(unsafe_path(&raw_name, "a directory already exists here"));
                }
                fs::remove_file(&target)
                    .map_err(|e| unsafe_path(&raw_name, format!("cannot replace: {e}")))?;
            }
            Err(_) => {}
        }

        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| unsafe_path(&raw_name, format!("cannot create file: {e}")))?;

        // Bound the reader independently of the header's claim, so a lying
        // size field cannot fill the disk.
        let mut limited = (&mut entry).take(limits.max_file_bytes.saturating_add(1));
        let mut written: u64 = 0;
        loop {
            let n = limited
                .read(&mut buf)
                .map_err(|e| unsafe_path(&raw_name, format!("decompression failed: {e}")))?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > limits.max_file_bytes {
                let _ = fs::remove_file(&target);
                return Err(SecurityError::ArchiveLimit(format!(
                    "'{raw_name}' expands past the {} byte per-file cap",
                    limits.max_file_bytes
                )));
            }
            report.bytes += n as u64;
            if report.bytes > limits.max_total_bytes {
                let _ = fs::remove_file(&target);
                return Err(SecurityError::ArchiveLimit(format!(
                    "archive expands past the {} byte total cap",
                    limits.max_total_bytes
                )));
            }
            out.write_all(&buf[..n])
                .map_err(|e| unsafe_path(&raw_name, format!("write failed: {e}")))?;
        }
        out.flush()
            .map_err(|e| unsafe_path(&raw_name, format!("flush failed: {e}")))?;
        drop(out);

        apply_safe_permissions(&target, entry.unix_mode());
        report.files += 1;
    }

    Ok(report)
}

/// Honour only the executable bit. setuid, setgid and sticky bits from an
/// archive are dropped on the floor.
fn apply_safe_permissions(path: &Path, mode: Option<u32>) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let executable = mode.map(|m| m & 0o111 != 0).unwrap_or(false);
        let safe = if executable { 0o755 } else { 0o644 };
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(safe));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
}

/// Copy a stream with a fixed buffer - never buffers a whole file in RAM.
pub fn stream_copy<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> io::Result<u64> {
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(total);
        }
        writer.write_all(&buf[..n])?;
        total += n as u64;
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_relative_paths() {
        for good in [
            "file.txt",
            "a/b/c.bin",
            "Data/Content/level_01.pak",
            "deep/dir/",
            "unicode-\u{00e9}\u{00e8}/name.txt",
        ] {
            assert!(sanitize_relative(good).is_ok(), "should accept {good}");
        }
    }

    #[test]
    fn blocks_classic_zip_slip() {
        for evil in [
            "../evil",
            "../../etc/passwd",
            "a/../../b",
            "a/b/../../../c",
            "..\\..\\Windows\\System32\\evil.dll",
            "foo/..",
        ] {
            let err = sanitize_relative(evil).unwrap_err();
            assert!(
                matches!(err, SecurityError::UnsafePath { .. }),
                "should reject {evil}, got {err:?}"
            );
        }
    }

    #[test]
    fn blocks_absolute_and_device_paths() {
        for evil in [
            "/etc/passwd",
            "\\Windows\\system.ini",
            "C:/Windows/system.ini",
            "C:\\Windows\\system.ini",
            "\\\\server\\share\\payload.dll",
            "file.txt:hidden",
            "CON",
            "aux.txt",
            "COM1.dat",
            "nul",
        ] {
            assert!(
                sanitize_relative(evil).is_err(),
                "should reject {evil}"
            );
        }
    }

    #[test]
    fn blocks_trick_names() {
        for evil in [
            "evil.",
            "evil ",
            " evil",
            "a\0b",
            "a\nb",
            "safe\u{202E}txt.exe",
            ".",
            "..",
            "",
        ] {
            assert!(sanitize_relative(evil).is_err(), "should reject {evil:?}");
        }
    }

    #[test]
    fn enforces_component_limits() {
        let deep = vec!["a"; MAX_COMPONENTS + 1].join("/");
        assert!(sanitize_relative(&deep).is_err());
        let long = "x".repeat(MAX_COMPONENT_LEN + 1);
        assert!(sanitize_relative(&long).is_err());
    }

    #[test]
    fn resolve_within_keeps_paths_inside_root() {
        let tmp = std::env::temp_dir().join(format!("hermes-safepath-{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        let inside = resolve_within(&tmp, "sub/dir/file.txt").expect("inside root");
        assert!(inside.starts_with(fs::canonicalize(&tmp).unwrap()));
        assert!(resolve_within(&tmp, "../outside.txt").is_err());
        let _ = fs::remove_dir_all(&tmp);
    }
}
