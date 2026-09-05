//! `hermes self-update` - HERMES updating itself from its own repository.
//!
//! This is the project eating its own cooking: the HERMES repo is just another
//! studio, GitHub Releases is just another CDN, and `hermes.origin` is a
//! perfectly ordinary origin file - the same format any studio publishes.
//!
//! # The one key that is compiled in
//!
//! `hermes.origin` is embedded in the binary ([`SELF_ORIGIN`]), so
//! `hermes self-update` works on a fresh install with nothing to add by hand.
//!
//! That is the *only* key in this binary, and it authorises exactly one thing:
//! HERMES replacing itself. It is not a default trust root for anybody else's
//! software - there is still no key list, no bundled publishers, and no way
//! for this key to sign an update for an application you added. HERMES holds
//! to the promise it makes about *other* people's software, which is the one
//! that matters: a fresh build trusts nobody until you drop in an `.origin`.
//!
//! Embedding it adds no trust that is not already there. You are running this
//! binary; it can already do anything you can. Telling it where its own updates
//! live does not widen that, and pinning the key here means an update to HERMES
//! is verified against a key that shipped *inside the thing being updated*
//! rather than one fetched at the moment of use.
//!
//! A key rotation therefore travels with the update itself: the new binary
//! carries the next `hermes.origin`.
//!
//! It cannot go through [`crate::update::apply`], though. That finishes with a
//! directory rename, and Windows will not rename a directory containing a
//! running `.exe`. So the ordinary pipeline is reused right up to the point
//! where the bytes are verified, and only the final move differs:
//!
//! ```text
//!   fetch manifest -> verify signature -> stream + hash -> compare checksum
//!   -> extract in the Zip-Slip sandbox -> ask -> rename running exe aside
//!   -> move the new one into place
//! ```
//!
//! Renaming a running executable *is* allowed on Windows, which is what makes
//! the swap possible at all. The old binary is left as `<exe>.old` and deleted
//! on the next launch, because it cannot be unlinked while it is still mapped.

use crate::net::{human_bytes, HttpClient};
use crate::registry;
use crate::schema::OriginFile;
use crate::security::consent;
use crate::security::crypto;
use crate::security::safepath::{display_path, extract_zip_secure, resolve_within, ExtractLimits};
use crate::update;
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// The origin id HERMES publishes for itself.
pub const SELF_ORIGIN_ID: &str = "chromeshot.hermes";

/// HERMES's own origin file, compiled in from the repository root.
///
/// `tools/release.py` regenerates this file *before* it builds, so the binary
/// in a release always embeds the origin that release is published under.
pub const SELF_ORIGIN: &str = include_str!("../hermes.origin");

/// Suffix for the outgoing binary. It cannot be deleted while it is running.
const RETIRED_SUFFIX: &str = ".old";

/// Delete the previous binary left behind by an earlier self-update.
///
/// Called on every start. Best effort by design: if it is still locked we
/// simply try again next time rather than bothering anybody about it.
pub fn clean_previous() {
    if let Ok(exe) = std::env::current_exe() {
        let retired = PathBuf::from(format!("{}{RETIRED_SUFFIX}", exe.display()));
        if retired.exists() {
            let _ = fs::remove_file(&retired);
        }
    }
}

/// The origin HERMES updates itself from.
///
/// Always the embedded one. A `chromeshot.hermes` entry in the registry is
/// *not* consulted: a registry file is ordinary data on disk, and letting it
/// redirect where the binary fetches its own replacement from would undo the
/// point of pinning the key inside the binary. If one is there and disagrees,
/// say so rather than silently ignoring it - the user put it there for a
/// reason, and the two keys disagreeing is worth knowing about.
fn self_origin() -> Result<OriginFile> {
    let origin = OriginFile::parse(SELF_ORIGIN.as_bytes()).map_err(|e| {
        anyhow!("the origin file compiled into this build is not usable: {e:#}")
    })?;
    if origin.id != SELF_ORIGIN_ID {
        bail!(
            "the compiled-in origin is for '{}', not '{SELF_ORIGIN_ID}'",
            origin.id
        );
    }
    if let Ok(registered) = registry::load_origin(SELF_ORIGIN_ID) {
        if registered.public_key != origin.public_key {
            eprintln!(
                "  note: a registered '{SELF_ORIGIN_ID}' origin pins a different key than\n  \
                 this build does. Self-update uses the built-in one:\n    \
                 built in  : {}\n    registered: {}",
                short_key(&origin.public_key),
                short_key(&registered.public_key)
            );
        }
    }
    Ok(origin)
}

fn short_key(key: &str) -> String {
    let clean: String = key.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() <= 16 {
        clean
    } else {
        format!("{}...{}", &clean[..8], &clean[clean.len() - 8..])
    }
}

/// Find the new binary inside the extracted payload.
fn locate_binary(payload: &Path) -> Result<PathBuf> {
    let name = if cfg!(windows) { "hermes.exe" } else { "hermes" };

    // Root of the archive first, then one directory down, which is how most
    // release tarballs are laid out.
    if let Ok(direct) = resolve_within(payload, name) {
        if direct.is_file() {
            return Ok(direct);
        }
    }
    for entry in fs::read_dir(payload).with_context(|| format!("listing {}", payload.display()))? {
        let entry = entry?;
        if entry.path().is_dir() {
            let nested = entry.path().join(name);
            if nested.is_file() {
                // Re-resolve through the sandbox rather than trusting the join.
                let relative = format!("{}/{name}", entry.file_name().to_string_lossy());
                if let Ok(safe) = resolve_within(payload, &relative) {
                    if safe.is_file() {
                        return Ok(safe);
                    }
                }
            }
        }
    }
    bail!("the release archive does not contain a '{name}'")
}

/// Swap the running executable for `replacement`.
fn swap_binary(current: &Path, replacement: &Path) -> Result<PathBuf> {
    let retired = PathBuf::from(format!("{}{RETIRED_SUFFIX}", current.display()));
    let _ = fs::remove_file(&retired);

    // Renaming a running image is permitted; deleting or overwriting one is
    // not. This is the whole trick.
    fs::rename(current, &retired).with_context(|| {
        format!(
            "cannot move {} aside - is another copy of HERMES running?",
            display_path(current)
        )
    })?;

    match fs::copy(replacement, current) {
        Ok(_) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(current, fs::Permissions::from_mode(0o755));
            }
            Ok(retired)
        }
        Err(e) => {
            // Put the old binary back; the user keeps a working HERMES.
            let restored = fs::rename(&retired, current);
            if restored.is_ok() {
                Err(anyhow!(
                    "could not install the new binary ({e}); the previous one was restored"
                ))
            } else {
                Err(anyhow!(
                    "could not install the new binary ({e}) AND could not restore the old \
                     one - it is intact at {}",
                    retired.display()
                ))
            }
        }
    }
}

/// Check for, and optionally apply, an update to HERMES itself.
pub fn run(client: &HttpClient, assume_yes: bool, check_only: bool) -> Result<()> {
    let origin = self_origin()?;
    let running = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;

    println!("\n  HERMES {running}");
    let available = update::check(client, &origin).map_err(|e| {
        // `releases/latest/download/...` 404s until the first release exists,
        // which is exactly what a maintainer sees before publishing one. Say
        // so rather than leaving them to guess at an HTTP status.
        if format!("{e:#}").contains("404") {
            e.context(
                "no release has been published at that address yet \
                 (`releases/latest/download/manifest.json` only resolves once a \
                 release with those assets exists)",
            )
        } else {
            e
        }
    })?;
    let offered = available.manifest.version()?;

    // The running binary is the truth here, not the registry: someone may have
    // replaced it by hand, and a downgrade is refused either way.
    crypto::assert_no_rollback(Some(&running), &offered)?;
    if offered == running {
        println!("  Already up to date.\n");
        return Ok(());
    }

    let artifact = available.manifest.artifact()?;
    println!("  Update available: {running} -> {offered}");
    if let Some(platform) = &artifact.platform {
        println!("  Build: {platform} ({})", human_bytes(artifact.size_bytes));
    }
    if let Some(notes) = available.manifest.display_notes() {
        println!("\n  What's new in {offered}:\n");
        for line in notes {
            println!("    {line}");
        }
    }
    if check_only {
        println!("\n  Run `hermes self-update` to install it.\n");
        return Ok(());
    }

    let exe = std::env::current_exe().context("cannot locate the running binary")?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);

    println!("\n  This will replace:\n    {}\n", display_path(&exe));
    if !consent::confirm("  Install it?", assume_yes) {
        println!("  Cancelled.\n");
        return Ok(());
    }

    // Stage beside the binary so the final move is a same-volume rename.
    let parent = exe
        .parent()
        .ok_or_else(|| anyhow!("the running binary has no parent directory"))?;
    let staging = parent.join(format!(".hermes-selfupdate-{:016x}", rand::random::<u64>()));
    fs::create_dir_all(&staging).with_context(|| format!("creating {}", staging.display()))?;
    let _guard = CleanupGuard(staging.clone());

    let archive = staging.join("download.zip");
    let digest = client.stream_download(
        &artifact.download_url,
        None,
        &archive,
        artifact.size_bytes,
        "download",
    )?;

    // Untrusted bytes until this line.
    crypto::verify_checksum(&artifact.checksum_sha256, &digest)?;
    println!("  checksum ok  sha256:{}", &digest[..16]);

    let payload = staging.join("payload");
    extract_zip_secure(&archive, &payload, &ExtractLimits::default())?;
    let replacement = locate_binary(&payload)?;

    let retired = swap_binary(&exe, &replacement)?;
    println!("  Installed HERMES {offered}.");
    println!(
        "  The previous binary is at {} and is removed on the next run.",
        display_path(&retired)
    );
    println!("\n  Restart HERMES to use the new version.\n");
    Ok(())
}

/// Wipes the staging directory however this function exits.
struct CleanupGuard(PathBuf);

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        crate::fsx::cleanup(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "hermes-selfupdate-{tag}-{:016x}",
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn finds_the_binary_at_the_archive_root() {
        let payload = temp_dir("root");
        let name = if cfg!(windows) { "hermes.exe" } else { "hermes" };
        fs::write(payload.join(name), b"new binary").unwrap();
        let found = locate_binary(&payload).expect("located");
        assert_eq!(found.file_name().unwrap(), name);
        fs::remove_dir_all(&payload).ok();
    }

    #[test]
    fn finds_the_binary_one_directory_down() {
        let payload = temp_dir("nested");
        let name = if cfg!(windows) { "hermes.exe" } else { "hermes" };
        let inner = payload.join("hermes-0.2.0-x86_64");
        fs::create_dir_all(&inner).unwrap();
        fs::write(inner.join(name), b"new binary").unwrap();
        let found = locate_binary(&payload).expect("located");
        assert_eq!(found.file_name().unwrap(), name);
        fs::remove_dir_all(&payload).ok();
    }

    #[test]
    fn reports_an_archive_with_no_binary() {
        let payload = temp_dir("empty");
        fs::write(payload.join("README.md"), b"nothing useful").unwrap();
        assert!(locate_binary(&payload).is_err());
        fs::remove_dir_all(&payload).ok();
    }

    /// The swap has to survive being interrupted: if the copy fails, the old
    /// binary must come back rather than leaving the user with nothing.
    #[test]
    fn a_failed_swap_restores_the_previous_binary() {
        let dir = temp_dir("swap");
        let current = dir.join("hermes-test.bin");
        fs::write(&current, b"old binary").unwrap();

        // A directory is not a copyable source, so fs::copy fails.
        let bogus = dir.join("not-a-file");
        fs::create_dir_all(&bogus).unwrap();

        let err = swap_binary(&current, &bogus).unwrap_err();
        assert!(err.to_string().contains("restored"), "{err}");
        assert_eq!(fs::read(&current).unwrap(), b"old binary");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_successful_swap_replaces_the_binary_and_keeps_the_old_one() {
        let dir = temp_dir("swap-ok");
        let current = dir.join("hermes-test.bin");
        fs::write(&current, b"old binary").unwrap();
        let replacement = dir.join("new.bin");
        fs::write(&replacement, b"new binary").unwrap();

        let retired = swap_binary(&current, &replacement).expect("swapped");
        assert_eq!(fs::read(&current).unwrap(), b"new binary");
        assert_eq!(fs::read(&retired).unwrap(), b"old binary");
        fs::remove_dir_all(&dir).ok();
    }

    /// The compiled-in origin is what `self-update` trusts, so a bad commit to
    /// `hermes.origin` must fail here rather than in a user's terminal.
    #[test]
    fn the_compiled_in_origin_is_usable() {
        let origin = OriginFile::parse(SELF_ORIGIN.as_bytes())
            .expect("hermes.origin at the repository root must be a valid .origin");
        assert_eq!(origin.id, SELF_ORIGIN_ID);
        assert!(
            origin.upstream_manifest_url.starts_with("https://"),
            "self-update must fetch over https: {}",
            origin.upstream_manifest_url
        );
        // Points at the release the users get, not at a local test server.
        assert!(
            origin.upstream_manifest_url.contains("github.com"),
            "expected the GitHub releases URL, got {}",
            origin.upstream_manifest_url
        );
        // Parsing already decoded the key; this asserts it is really pinned.
        assert!(!origin.public_key.is_empty());
    }

    #[test]
    fn self_origin_reads_the_compiled_in_file() {
        let origin = self_origin().expect("the built-in origin resolves");
        assert_eq!(origin.id, SELF_ORIGIN_ID);
    }
}
