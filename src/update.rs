//! Module 4b - the update pipeline and the atomic swap.
//!
//! Order matters, and it is this:
//!
//! ```text
//!  1. fetch manifest         (bytes, unparsed)
//!  2. verify signature       <- pinned key from the .origin
//!  3. refuse replays/rollbacks
//!  4. stream .zip -> .staging, hashing in flight, never in RAM
//!  5. compare digest to the signed checksum   <- nothing is unpacked before this
//!  6. extract into staging   <- Zip-Slip sandbox
//!  7. read the .foiled plan
//!  8. if the plan asks, find out where the software is installed
//!  9. enforce the plan's declared scope against that folder
//! 10. ask the user for the scope, verbatim
//! 11. build the new tree in staging
//! 12. rename the new tree into place
//! ```
//!
//! The live install directory is not touched at all until step 12, and step 12
//! is two renames. A crash, a power cut or a `Ctrl-C` anywhere before it leaves
//! the installed application exactly as it was.
//!
//! Step 8 answers "which folder?", never "may I?" - the folder comes from the
//! user, and steps 9 and 10 then run against it unchanged.

use crate::auth;
use crate::error::SecurityError;
use crate::fsx;
use crate::net::{human_bytes, HttpClient};
use crate::paths;
use crate::registry::{self, OriginState};
use crate::schema::{BaseTree, FoiledPlan, FoiledStep, Manifest, OriginFile};
use crate::security::consent::{self, ResolvedGrant};
use crate::security::crypto;
use crate::security::safepath::{
    display_path, extract_zip_secure, resolve_within, sanitize_relative, ExtractLimits,
};
use anyhow::{anyhow, bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct UpdateOptions {
    /// Skip the keystroke, not the scope enforcement (for unattended runs).
    pub assume_yes: bool,
    /// Override where the application is installed.
    pub install_dir: Option<PathBuf>,
    /// Re-apply even when the installed version already matches.
    pub force: bool,
    /// Install this version instead of the newest one on offer.
    pub version: Option<semver::Version>,
    /// Permit an explicitly chosen version that is older than the installed
    /// one. Deliberately separate from `assume_yes`: granting folder access
    /// and accepting a downgrade are two different decisions.
    pub allow_downgrade: bool,
}

pub struct Available {
    pub manifest: Manifest,
    pub installed: Option<semver::Version>,
    pub is_newer: bool,
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

/// Fetch and fully verify the studio's manifest. Nothing is downloaded here.
pub fn check(client: &HttpClient, origin: &OriginFile) -> Result<Available> {
    let token = auth::bearer_for(origin)?;
    if origin.requires_auth && token.is_none() {
        bail!(
            "'{}' requires a studio account. Run `hermes login {}` first.",
            origin.name,
            origin.id
        );
    }

    let raw = client.fetch_manifest(&origin.upstream_manifest_url, token.as_deref())?;
    let now = paths::now_unix();
    let manifest = crypto::verify_manifest(origin, &raw, now)?;

    let mut state = registry::load_state(&origin.id)?;

    // A validly signed but *older* manifest is a replay: a CDN or a mirror
    // serving yesterday's document to pin a user on a vulnerable build.
    if let Some(seen) = state.last_manifest_issued_at {
        if manifest.issued_at < seen {
            bail!(
                "the studio's CDN served a manifest dated {} but HERMES has already \
                 accepted one dated {} - refusing a replayed manifest",
                manifest.issued_at,
                seen
            );
        }
    }

    if let Some(min) = &manifest.minimum_client_version {
        let required = semver::Version::parse(min)
            .with_context(|| format!("manifest minimum_client_version '{min}' is not semver"))?;
        let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
        if current < required {
            bail!("this update needs HERMES {required} or newer (you have {current})");
        }
    }

    let installed = state.installed_version();
    let offered = manifest.version()?;
    let is_newer = installed.as_ref().map(|i| offered > *i).unwrap_or(true);

    state.last_checked = Some(now);
    state.last_manifest_issued_at = Some(manifest.issued_at.max(state.last_manifest_issued_at.unwrap_or(i64::MIN)));
    registry::save_state(&origin.id, &state)?;

    Ok(Available {
        manifest,
        installed,
        is_newer,
    })
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

/// Staging area, deliberately created next to the install directory so the
/// final swap is a same-volume rename.
struct Staging {
    root: PathBuf,
    work: PathBuf,
    archive: PathBuf,
    payload: PathBuf,
    next: PathBuf,
    backup: PathBuf,
    /// False when we had to fall back to `~/.config/hermes`, which may be on
    /// another volume - the swap then degrades from a rename to a copy.
    same_volume: bool,
}

impl Staging {
    fn create(install_dir: &Path, origin_id: &str) -> Result<Self> {
        let parent = install_dir
            .parent()
            .ok_or_else(|| anyhow!("install directory has no parent"))?;
        fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;

        let (root, same_volume) = {
            let preferred = parent.join(paths::STAGING_DIR_NAME);
            match fs::create_dir_all(&preferred) {
                Ok(()) => (preferred, true),
                Err(_) => {
                    let fallback = paths::hermes_home()?.join(paths::STAGING_DIR_NAME);
                    fs::create_dir_all(&fallback)?;
                    eprintln!(
                        "  note: {} is not writable; staging in {} instead \
                         (the final swap will be a copy, not a rename)",
                        parent.display(),
                        fallback.display()
                    );
                    (fallback, false)
                }
            }
        };
        let _ = paths::hide_dir(&root);

        let work = root.join(format!("{origin_id}-{:016x}", rand::random::<u64>()));
        let payload = work.join("payload");
        let next = work.join("next");
        let backup = work.join("backup");
        for dir in [&work, &payload, &next, &backup] {
            fs::create_dir_all(dir)
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        Ok(Self {
            archive: work.join("download.zip"),
            root,
            work,
            payload,
            next,
            backup,
            same_volume,
        })
    }

    /// Move this job next to a different install directory.
    ///
    /// A plan's `[locate]` block can only be answered *after* the archive has
    /// been unpacked, and by then staging is sitting beside the folder we
    /// guessed. Since the final swap is a rename only while staging shares a
    /// volume with the install directory, a wrong guess moves the whole job
    /// rather than letting the swap quietly degrade into a copy.
    ///
    /// Consumes the old staging area, so its `Drop` clears what is left of it.
    fn relocate(self, install_dir: &Path, origin_id: &str) -> Result<Self> {
        let fresh = Staging::create(install_dir, origin_id)?;
        fsx::move_path(&self.payload, &fresh.payload)
            .context("moving the verified payload next to the chosen folder")?;
        Ok(fresh)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        fsx::cleanup(&self.work);
        // Remove the staging root too if this was the last job in it.
        if let Ok(mut entries) = fs::read_dir(&self.root) {
            if entries.next().is_none() {
                let _ = fs::remove_dir(&self.root);
            }
        }
    }
}

/// Download, verify, plan, ask, build, swap.
pub fn apply(
    client: &HttpClient,
    origin: &OriginFile,
    available: &Available,
    opts: &UpdateOptions,
) -> Result<()> {
    let manifest = &available.manifest;

    // Which release: the newest on offer, or the one the user named.
    let target = match &opts.version {
        Some(want) => manifest.release(want)?,
        None => manifest.latest_release()?,
    };
    let offered = target.version.clone();

    if opts.version.is_some() {
        // The user picked this version themselves, so an older one is a
        // deliberate choice rather than a CDN pinning them on a stale build.
        // It still has to be said out loud - that is what the anti-rollback
        // rule is protecting, and `--yes` does not cover it.
        if let Some(installed) = &available.installed {
            if offered < *installed {
                consent::confirm_downgrade(
                    &origin.name,
                    installed,
                    &offered,
                    opts.allow_downgrade,
                )?;
            }
        }
    } else {
        crypto::assert_no_rollback(available.installed.as_ref(), &offered)?;
    }

    if available.installed.as_ref() == Some(&offered) && !opts.force {
        println!("  {} {} is already installed.", origin.name, offered);
        return Ok(());
    }

    let mut state = registry::load_state(&origin.id)?;
    let mut install_dir = match &opts.install_dir {
        Some(dir) => dir.clone(),
        None => registry::install_dir_for(origin, &state)?,
    };

    let mut staging = Staging::create(&install_dir, &origin.id)?;

    // ---- 1. stream the archive to disk, hashing on the fly ---------------
    let artifact = target.artifact()?;
    println!(
        "  downloading {} {} ({}{})",
        origin.name,
        offered,
        human_bytes(artifact.size_bytes),
        artifact
            .platform
            .as_ref()
            .map(|p| format!(", {p}"))
            .unwrap_or_default()
    );
    let token = auth::bearer_for(origin)?;
    let digest = client.stream_download(
        &artifact.download_url,
        token.as_deref(),
        &staging.archive,
        artifact.size_bytes,
        "download",
    )?;

    // ---- 2. the archive is untrusted until this line ----------------------
    crypto::verify_checksum(&artifact.checksum_sha256, &digest)?;
    println!("  checksum ok  sha256:{}", &digest[..16]);

    // ---- 3. unpack inside the Zip-Slip sandbox ---------------------------
    let report = extract_zip_secure(&staging.archive, &staging.payload, &ExtractLimits::default())?;
    println!(
        "  unpacked {} file(s), {} into staging",
        report.files,
        human_bytes(report.bytes)
    );

    // ---- 4. read the plan -------------------------------------------------
    let plan_path = resolve_within(&staging.payload, manifest.foiled_entry())?;
    let plan_bytes = fs::read(&plan_path).with_context(|| {
        format!(
            "the update archive does not contain '{}'",
            manifest.foiled_entry()
        )
    })?;
    let plan = FoiledPlan::parse(&plan_bytes)?;
    if plan.origin_id != origin.id {
        return Err(SecurityError::OriginMismatch {
            expected: origin.id.clone(),
            found: plan.origin_id,
        }
        .into());
    }
    // The plan must match the release we actually asked for, not merely the
    // newest one: otherwise a studio could serve the 1.4.0 archive from the
    // 1.2.0 catalogue entry and the mismatch would go unnoticed.
    if plan.version != offered.to_string() {
        bail!(
            "the plan inside the archive is for version {} but the signed manifest \
             offers it as {offered}",
            plan.version
        );
    }

    // ---- 5. find out where the software actually lives -------------------
    //
    // Only when the plan asks and HERMES does not already know. The answer is
    // the user's, is checked before it is used, and is remembered afterwards -
    // so this is asked once per application, not once per update. It happens
    // before the scope is resolved so that the permission prompt below shows
    // absolute paths under the folder the user actually named.
    if let Some(locate) = &plan.locate {
        if opts.install_dir.is_none() && state.install_dir.is_none() {
            let suggestion = install_dir.is_dir().then(|| install_dir.clone());
            let chosen =
                consent::locate_install_dir(&origin.name, locate, suggestion.as_deref())?;
            if chosen != install_dir {
                staging = staging.relocate(&chosen, &origin.id)?;
                install_dir = chosen;
            }
        }
    }

    // ---- 6. enforce the declared scope, then ask -------------------------
    let grants = consent::resolve_scope(&plan, &install_dir)?;
    consent::enforce_plan_scope(&plan, &grants)?;
    let notes = target.display_notes();
    consent::request_consent(
        &origin.name,
        &plan,
        &install_dir,
        &grants,
        notes.as_deref(),
        opts.assume_yes,
    )?;

    // ---- 7. build the new tree in staging --------------------------------
    if plan.base == BaseTree::Clone && install_dir.exists() {
        println!("  cloning the current install into staging...");
        fsx::clone_tree(&install_dir, &staging.next)
            .context("cloning the current install")?;
    }
    execute_plan(&plan, &staging, &install_dir, &grants)?;

    // ---- 8. swap ----------------------------------------------------------
    let retired = swap_into_place(&install_dir, &staging.next, &staging.work, staging.same_volume)?;
    println!("  installed into {}", display_path(&install_dir));

    // Keep backups outside staging: staging is wiped when this call returns.
    if has_backups(&staging.backup)? {
        let kept = paths::hermes_home()?
            .join("backups")
            .join(&origin.id)
            .join(offered.to_string());
        fsx::cleanup(&kept);
        fsx::copy_tree(&staging.backup, &kept)?;
        println!("  backups kept in {}", display_path(&kept));
    }
    if let Some(retired) = retired {
        fsx::cleanup(&retired);
    }

    // ---- 9. record ---------------------------------------------------------
    state.installed_version = Some(offered.to_string());
    state.install_dir = Some(install_dir.clone());
    registry::save_state(&origin.id, &state)?;
    Ok(())
}

fn has_backups(dir: &Path) -> Result<bool> {
    Ok(fs::read_dir(dir)
        .map(|mut e| e.next().is_some())
        .unwrap_or(false))
}

// ---------------------------------------------------------------------------
// Plan execution
// ---------------------------------------------------------------------------

/// Run the declarative steps against the staged tree.
///
/// Every path is resolved through the sandbox again here. The scope check has
/// already passed, but resolution is what stops a path from escaping the
/// staging tree on a filesystem that disagrees with the string.
fn execute_plan(
    plan: &FoiledPlan,
    staging: &Staging,
    install_dir: &Path,
    _grants: &[ResolvedGrant],
) -> Result<()> {
    println!("  applying {} step(s)...", plan.steps.len());
    for (index, step) in plan.steps.iter().enumerate() {
        let n = index + 1;
        match step {
            FoiledStep::ExtractZip { archive, dest } => {
                let src = resolve_within(&staging.payload, archive)?;
                let dst = resolve_within(&staging.next, dest)?;
                fs::create_dir_all(&dst)?;
                let limits = ExtractLimits {
                    // The tree may already hold cloned files; replacing them is
                    // the point. Duplicate entries inside one archive are still
                    // refused by extract_zip_secure.
                    allow_replace_existing: true,
                    ..ExtractLimits::default()
                };
                let report = extract_zip_secure(&src, &dst, &limits)?;
                println!("    {n}. unpacked {archive} -> {dest} ({} files)", report.files);
            }
            FoiledStep::Copy { from, to } => {
                let src = resolve_within(&staging.payload, from)?;
                let dst = resolve_within(&staging.next, to)?;
                fsx::copy_path(&src, &dst)?;
                println!("    {n}. copied {from} -> {to}");
            }
            FoiledStep::Move { from, to } => {
                let src = resolve_within(&staging.next, from)?;
                let dst = resolve_within(&staging.next, to)?;
                if !src.exists() {
                    println!("    {n}. move {from}: nothing there, skipped");
                    continue;
                }
                fsx::move_path(&src, &dst)?;
                println!("    {n}. moved {from} -> {to}");
            }
            FoiledStep::Delete { path, recursive } => {
                let target = resolve_within(&staging.next, path)?;
                if !target.exists() {
                    println!("    {n}. delete {path}: nothing there, skipped");
                    continue;
                }
                fsx::remove_path(&target, *recursive)?;
                println!("    {n}. deleted {path}");
            }
            FoiledStep::Backup { path } => {
                let relative = sanitize_relative(path)
                    .map_err(|e| anyhow!("backup path is unsafe: {e}"))?;
                let live = install_dir.join(&relative);
                if !live.exists() {
                    println!("    {n}. backup {path}: not installed yet, skipped");
                    continue;
                }
                crate::security::safepath::assert_within(install_dir, &live)?;
                let dst = staging.backup.join(&relative);
                fsx::copy_path(&live, &dst)?;
                println!("    {n}. backed up {path}");
            }
            FoiledStep::Preserve { path } => {
                let relative = sanitize_relative(path)
                    .map_err(|e| anyhow!("preserve path is unsafe: {e}"))?;
                let live = install_dir.join(&relative);
                if !live.exists() {
                    println!("    {n}. preserve {path}: nothing to keep, skipped");
                    continue;
                }
                crate::security::safepath::assert_within(install_dir, &live)?;
                let dst = resolve_within(&staging.next, path)?;
                fsx::copy_path(&live, &dst)?;
                println!("    {n}. preserved your {path}");
            }
            FoiledStep::Mkdir { path } => {
                let dst = resolve_within(&staging.next, path)?;
                fs::create_dir_all(&dst)?;
                println!("    {n}. created {path}");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic swap
// ---------------------------------------------------------------------------

/// Put `next` where `install` is, as close to atomically as the platform
/// allows, and hand back the retired tree for deletion.
///
/// Same-volume path: two renames. Between them the install directory does not
/// exist for a few milliseconds; if the second rename fails the first is undone
/// so the user is never left without their application.
fn swap_into_place(
    install: &Path,
    next: &Path,
    work: &Path,
    same_volume: bool,
) -> Result<Option<PathBuf>> {
    if let Some(parent) = install.parent() {
        fs::create_dir_all(parent)?;
    }

    if !install.exists() {
        return match fs::rename(next, install) {
            Ok(()) => Ok(None),
            Err(_) => {
                fsx::copy_tree(next, install)?;
                Ok(None)
            }
        };
    }

    if !same_volume {
        // Cross-volume: no rename is possible, so do the honest thing and say
        // so rather than pretending this is atomic.
        eprintln!("  warning: staging is on another volume; the swap is a copy and is NOT atomic");
        let retired = work.join("retired");
        fs::rename(install, &retired)
            .with_context(|| format!("moving {} aside", install.display()))?;
        match fsx::copy_tree(next, install) {
            Ok(_) => return Ok(Some(retired)),
            Err(e) => {
                let _ = fs::remove_dir_all(install);
                let _ = fs::rename(&retired, install);
                return Err(e.context("copying the new tree into place; the old one was restored"));
            }
        }
    }

    let retired = work.join(format!("retired-{:016x}", rand::random::<u64>()));
    fs::rename(install, &retired).with_context(|| {
        format!(
            "cannot move {} aside - is the application running? Close it and try again",
            install.display()
        )
    })?;

    match fs::rename(next, install) {
        Ok(()) => Ok(Some(retired)),
        Err(e) => {
            // Undo. The user keeps the version they had.
            let restored = fs::rename(&retired, install);
            if restored.is_ok() {
                Err(anyhow!(
                    "could not install the new version ({e}); the previous version was restored"
                ))
            } else {
                Err(anyhow!(
                    "could not install the new version ({e}) AND could not restore the previous \
                     one - it is intact at {}",
                    retired.display()
                ))
            }
        }
    }
}

/// Human-readable summary used by `hermes check`.
pub fn describe_available(origin: &OriginFile, available: &Available) -> String {
    let installed = available
        .installed
        .as_ref()
        .map(|v| v.to_string())
        .unwrap_or_else(|| "not installed".into());
    if available.is_newer {
        format!(
            "{} : {} -> {} available",
            origin.name, installed, available.manifest.latest_version
        )
    } else {
        format!("{} : up to date ({installed})", origin.name)
    }
}

/// Shared state helper for `hermes list`.
pub fn state_summary(state: &OriginState) -> String {
    match (&state.installed_version, &state.install_dir) {
        (Some(v), Some(dir)) => format!("v{v} in {}", display_path(dir)),
        (Some(v), None) => format!("v{v}"),
        _ => "not installed".into(),
    }
}
