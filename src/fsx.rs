//! Filesystem helpers used while building a new install tree.
//!
//! Nothing here trusts a path: callers resolve every path through
//! [`crate::security::safepath`] first. These functions only care about doing
//! the copy/move/delete correctly and about never following a symlink out of
//! the tree they were handed.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

/// Recursively duplicate `src` into `dst`.
///
/// Files are hard-linked when the filesystem allows it and copied otherwise.
/// Linking is safe here because every writer in HERMES unlinks before it
/// creates (see `extract_zip_secure` and [`copy_path`]), so a link is never
/// written *through* into the live install.
pub fn clone_tree(src: &Path, dst: &Path) -> Result<u64> {
    copy_tree_inner(src, dst, true)
}

/// Recursively copy `src` into `dst` with real copies throughout.
pub fn copy_tree(src: &Path, dst: &Path) -> Result<u64> {
    copy_tree_inner(src, dst, false)
}

fn copy_tree_inner(src: &Path, dst: &Path, try_link: bool) -> Result<u64> {
    let meta = fs::symlink_metadata(src)
        .with_context(|| format!("reading {}", src.display()))?;

    if meta.file_type().is_symlink() {
        // We never reproduce links: a link in the source tree could point
        // anywhere, and recreating it would smuggle that reach into the new
        // tree. Skipping is the conservative choice.
        eprintln!("  note: skipping symlink {}", src.display());
        return Ok(0);
    }

    if meta.is_file() {
        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }
        if dst.exists() {
            fs::remove_file(dst).ok();
        }
        if try_link && fs::hard_link(src, dst).is_ok() {
            return Ok(meta.len());
        }
        fs::copy(src, dst)
            .with_context(|| format!("copying {} -> {}", src.display(), dst.display()))?;
        return Ok(meta.len());
    }

    if !meta.is_dir() {
        bail!("{} is neither a file nor a directory", src.display());
    }

    fs::create_dir_all(dst).with_context(|| format!("creating {}", dst.display()))?;
    let mut bytes = 0;
    for entry in fs::read_dir(src).with_context(|| format!("listing {}", src.display()))? {
        let entry = entry?;
        bytes += copy_tree_inner(&entry.path(), &dst.join(entry.file_name()), try_link)?;
    }
    Ok(bytes)
}

/// Copy a single path (file or directory) into place, replacing what is there.
pub fn copy_path(src: &Path, dst: &Path) -> Result<u64> {
    if dst.exists() {
        remove_path(dst, true)?;
    }
    copy_tree(src, dst)
}

/// Move within one tree; falls back to copy+delete across filesystems.
pub fn move_path(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    if dst.exists() {
        remove_path(dst, true)?;
    }
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            copy_tree(src, dst)?;
            remove_path(src, true)
        }
    }
}

/// Delete a file or (with `recursive`) a directory tree.
pub fn remove_path(path: &Path, recursive: bool) -> Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()), // already gone
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        if !recursive {
            // Refuse to silently nuke a tree the plan only asked to unlink.
            return fs::remove_dir(path)
                .with_context(|| format!("removing directory {} (not recursive)", path.display()));
        }
        return fs::remove_dir_all(path)
            .with_context(|| format!("removing {}", path.display()));
    }
    fs::remove_file(path).with_context(|| format!("removing {}", path.display()))
}

/// Best-effort recursive delete used for staging cleanup.
pub fn cleanup(path: &Path) {
    if path.exists() {
        let _ = fs::remove_dir_all(path);
    }
}
