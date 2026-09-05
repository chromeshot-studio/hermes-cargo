//! Module 3c - interactive isolation.
//!
//! A `.foiled` plan must declare, up front, exactly which folders it wants.
//! HERMES then does two separate things with that declaration:
//!
//! * **Enforcement** ([`enforce_plan_scope`]) - every path in every step is
//!   checked against the declaration *before* the user is asked anything. A
//!   plan that declares `patch/` but tries to write `saves/` is dead on
//!   arrival; the user is never given the chance to approve something the plan
//!   did not admit to. Sub-folders are not implied: a non-recursive grant
//!   covers its direct children only.
//! * **Consent** ([`request_consent`]) - the declaration is printed verbatim,
//!   resolved to absolute paths, and the user must press `Y`.
//!
//! Deny by default: no TTY means no consent, not silent approval.

use crate::error::{SecResult, SecurityError};
use crate::schema::{Access, FoiledPlan, LocateRequest};
use crate::security::safepath::{display_path, sanitize_relative};
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

/// A scope grant with its relative path validated and absolute path resolved.
#[derive(Debug, Clone)]
pub struct ResolvedGrant {
    pub declared: String,
    /// Relative to the install root; empty means the root itself.
    pub relative: PathBuf,
    pub absolute: PathBuf,
    pub recursive: bool,
    pub access: Access,
    pub reason: Option<String>,
}

/// `"."` (or `""`) means the install root; everything else must be a plain
/// relative path.
fn normalize_scope_path(raw: &str) -> SecResult<PathBuf> {
    let trimmed = raw.trim();
    if trimmed == "." || trimmed.is_empty() || trimmed == "./" {
        return Ok(PathBuf::new());
    }
    let trimmed = trimmed.trim_end_matches(['/', '\\']);
    sanitize_relative(trimmed)
}

/// Validate the declared scope and resolve it against the install root.
pub fn resolve_scope(plan: &FoiledPlan, install_root: &Path) -> SecResult<Vec<ResolvedGrant>> {
    let mut out = Vec::with_capacity(plan.scope.len());
    for grant in &plan.scope {
        let relative = normalize_scope_path(&grant.path).map_err(|e| match e {
            SecurityError::UnsafePath { path, reason } => SecurityError::UnsafePath {
                path,
                reason: format!("declared scope is unusable: {reason}"),
            },
            other => other,
        })?;
        let absolute = install_root.join(&relative);
        // sanitize_relative already forbids `..`, so this is a belt-and-braces
        // check against a future refactor loosening that.
        if !absolute.starts_with(install_root) {
            return Err(SecurityError::ScopeEscape { path: absolute });
        }
        out.push(ResolvedGrant {
            declared: grant.path.clone(),
            relative,
            absolute,
            recursive: grant.recursive,
            access: grant.access,
            reason: grant.reason.clone(),
        });
    }
    Ok(out)
}

/// Does this grant cover `target` (a sanitized path relative to the root)?
fn covers(grant: &ResolvedGrant, target: &Path) -> bool {
    if grant.relative.as_os_str().is_empty() {
        // Grant on the install root itself.
        return if grant.recursive {
            true
        } else {
            target.components().count() <= 1
        };
    }
    if target == grant.relative {
        return true;
    }
    match target.strip_prefix(&grant.relative) {
        Ok(rest) => {
            if grant.recursive {
                true
            } else {
                rest.components().count() == 1
            }
        }
        Err(_) => false,
    }
}

/// Read < Write < Delete. A write grant does not authorise a delete.
fn permits(granted: Access, required: Access) -> bool {
    granted >= required
}

/// Check every step against the declared scope. Runs before the prompt, so an
/// over-reaching plan is refused rather than negotiated.
pub fn enforce_plan_scope(plan: &FoiledPlan, grants: &[ResolvedGrant]) -> SecResult<()> {
    for step in &plan.steps {
        for (raw, required) in step.touched() {
            let target = sanitize_relative(raw).map_err(|e| match e {
                SecurityError::UnsafePath { path, reason } => SecurityError::UnsafePath {
                    path,
                    reason: format!("step '{}' uses an unsafe path: {reason}", step.name()),
                },
                other => other,
            })?;
            let allowed = grants
                .iter()
                .any(|g| covers(g, &target) && permits(g.access, required));
            if !allowed {
                return Err(SecurityError::UndeclaredScope {
                    step: step.name().to_string(),
                    path: raw.to_string(),
                });
            }
        }
    }
    Ok(())
}

/// Show the exact folder scope and require a `Y`.
///
/// `assume_yes` exists for unattended pipelines; it does not skip
/// [`enforce_plan_scope`], it only skips the keystroke.
pub fn request_consent(
    app_name: &str,
    plan: &FoiledPlan,
    install_root: &Path,
    grants: &[ResolvedGrant],
    release_notes: Option<&[String]>,
    assume_yes: bool,
) -> SecResult<()> {
    let bar = "-".repeat(72);
    println!("\n{bar}");
    println!("  UPDATE PERMISSION REQUEST");
    println!("{bar}");
    println!("  Application : {app_name}");
    println!("  Version     : {}", plan.version);
    println!("  Install root: {}", display_path(install_root));
    if let Some(notes) = &plan.notes {
        println!("  Notes       : {notes}");
    }

    // Studio-authored, but signed and sanitised: what changed belongs in front
    // of the user *before* they decide, not in a changelog they never open.
    if let Some(lines) = release_notes {
        println!("\n  What's new in {}:\n", plan.version);
        for line in lines {
            println!("    {line}");
        }
    }
    println!("\n  This update is asking for access to these folders ONLY:\n");
    for grant in grants {
        let label = if grant.relative.as_os_str().is_empty() {
            "<install root>".to_string()
        } else {
            grant.declared.clone()
        };
        println!(
            "    [{}{}] {}",
            grant.access,
            if grant.recursive {
                ", incl. sub-folders"
            } else {
                ", this folder only"
            },
            label
        );
        println!("        -> {}", display_path(&grant.absolute));
        if let Some(reason) = &grant.reason {
            println!("        why: {reason}");
        }
    }

    println!("\n  It will perform {} step(s):\n", plan.steps.len());
    for step in plan.steps.iter().take(20) {
        println!("    - {}", step.describe());
    }
    if plan.steps.len() > 20 {
        println!("    ... and {} more", plan.steps.len() - 20);
    }

    println!("\n  Nothing outside the folders listed above can be read, written");
    println!("  or deleted. The plan contains no executable steps.");
    println!("{bar}");

    if assume_yes {
        println!("  --yes supplied: scope granted without prompting.");
        println!("{bar}\n");
        return Ok(());
    }

    if !io::stdin().is_terminal() {
        println!("  No interactive terminal available - denying by default.");
        println!("{bar}\n");
        return Err(SecurityError::ConsentUnavailable);
    }

    print!("  Grant this access and apply the update? [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return Err(SecurityError::ConsentDenied);
    }
    let answer = answer.trim();
    if answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes") {
        println!("{bar}\n");
        Ok(())
    } else {
        println!("  Denied.\n{bar}\n");
        Err(SecurityError::ConsentDenied)
    }
}

// ---------------------------------------------------------------------------
// "Where is it installed?"
// ---------------------------------------------------------------------------

/// Ask the user to point at the folder a plan wants to patch.
///
/// Reached only from [`crate::update::apply`], and only when the plan carries
/// a `[locate]` block and HERMES does not already know where the software is.
/// The answer becomes the install root, so it is remembered afterwards and
/// this is asked exactly once per application.
///
/// The studio contributes a question and, at most, the name of a file it
/// expects to find. Everything else - the folder, and whether it is allowed
/// to be that folder - comes from the user and from
/// [`validate_install_choice`]. Consent is still requested afterwards, with
/// every granted path resolved against whatever was chosen here, so this
/// prompt grants nothing on its own.
pub fn locate_install_dir(
    app_name: &str,
    locate: &LocateRequest,
    suggestion: Option<&Path>,
) -> SecResult<PathBuf> {
    let bar = "-".repeat(72);
    println!("\n{bar}");
    println!("  WHERE IS {} INSTALLED?", app_name.to_uppercase());
    println!("{bar}");
    match locate.display_prompt() {
        Some(question) => println!("  {question}"),
        None => println!("  This update patches an existing installation of {app_name}."),
    }
    if let Some(expect) = &locate.expect {
        println!("  The folder should contain: {expect}");
    }
    println!("\n  Type or drag the folder in. Press Enter on its own to cancel.");
    if let Some(dir) = suggestion {
        println!("  Enter alone accepts: {}", display_path(dir));
    }

    if !io::stdin().is_terminal() {
        println!("  No interactive terminal available - denying by default.");
        println!("  Pass --install-dir <folder> to answer this without a prompt.");
        println!("{bar}\n");
        return Err(SecurityError::ConsentUnavailable);
    }

    // Three tries: a mistyped or half-dropped path is a slip, not an attack,
    // and making the user restart a verified download over one is unkind.
    for attempt in 0..3 {
        print!("  folder > ");
        let _ = io::stdout().flush();
        let mut answer = String::new();
        if io::stdin().read_line(&mut answer).is_err() {
            return Err(SecurityError::ConsentDenied);
        }
        let answer = answer.trim();

        if answer.is_empty() {
            match suggestion {
                Some(dir) => match validate_install_choice(dir, locate.expect.as_deref()) {
                    Ok(resolved) => {
                        println!("{bar}\n");
                        return Ok(resolved);
                    }
                    Err(why) => println!("  {why}"),
                },
                None => {
                    println!("  Cancelled.\n{bar}\n");
                    return Err(SecurityError::ConsentDenied);
                }
            }
        } else {
            let candidate = crate::registry::normalize_dropped_path(answer);
            match validate_install_choice(&candidate, locate.expect.as_deref()) {
                Ok(resolved) => {
                    println!("  using {}", display_path(&resolved));
                    println!("{bar}\n");
                    return Ok(resolved);
                }
                Err(why) => println!("  {why}"),
            }
        }
        if attempt < 2 {
            println!("  Try again, or press Enter on its own to cancel.");
        }
    }
    println!("  No usable folder given.\n{bar}\n");
    Err(SecurityError::ConsentDenied)
}

/// Is this folder something HERMES is willing to treat as an install root?
///
/// Returns the canonical directory, or a sentence to print back at the user.
/// Split out from the prompt so the rules are testable without a terminal.
///
/// The rules are deliberately blunt. An install root is a folder that already
/// exists and holds one application; it is never a whole drive, never the
/// user's home directory, and never anything containing HERMES's own state.
/// A plan whose scope says `[write] .` would otherwise reach every one of
/// those with a single mistyped answer.
pub fn validate_install_choice(candidate: &Path, expect: Option<&str>) -> Result<PathBuf, String> {
    if candidate.as_os_str().is_empty() {
        return Err("that is empty.".into());
    }
    if !candidate.is_absolute() {
        return Err(format!(
            "'{}' is a relative path - give the full path to the folder.",
            display_path(candidate)
        ));
    }
    let meta = std::fs::metadata(candidate)
        .map_err(|e| format!("cannot open {}: {e}", display_path(candidate)))?;
    if !meta.is_dir() {
        return Err(format!(
            "{} is a file - point at the folder that contains it.",
            display_path(candidate)
        ));
    }
    // Canonicalising resolves any symlink in the path *now*, so every later
    // `assert_within` check measures against the real location rather than a
    // link that could be repointed underneath us.
    let resolved = std::fs::canonicalize(candidate)
        .map_err(|e| format!("cannot resolve {}: {e}", display_path(candidate)))?;

    if resolved.parent().is_none() {
        return Err(format!(
            "{} is the root of a drive; pick the application's own folder.",
            display_path(&resolved)
        ));
    }
    // `home.starts_with(dir)` is true when dir *is* home and when dir contains
    // it, which catches both `C:\Users\me` and `C:\Users`.
    if let Some(home) = dirs::home_dir().and_then(|h| std::fs::canonicalize(h).ok()) {
        if home.starts_with(&resolved) {
            return Err(format!(
                "{} is your home folder (or contains it); pick the application's own folder.",
                display_path(&resolved)
            ));
        }
    }
    if let Some(state) = crate::paths::hermes_home()
        .ok()
        .and_then(|h| std::fs::canonicalize(h).ok())
    {
        if state.starts_with(&resolved) {
            return Err(format!(
                "{} holds HERMES's own settings; an update may not be pointed at it.",
                display_path(&resolved)
            ));
        }
    }

    if let Some(expect) = expect {
        let relative = sanitize_relative(expect)
            .map_err(|e| format!("the plan asked for an unusable file name: {e}"))?;
        if !resolved.join(&relative).exists() {
            return Err(format!(
                "{} does not contain {expect} - that is not the right folder.",
                display_path(&resolved)
            ));
        }
    }
    Ok(resolved)
}

/// Confirm going back to an older version than the one installed.
///
/// HERMES refuses downgrades outright when it is choosing the version itself
/// ([`crate::security::crypto::assert_no_rollback`]) - a CDN serving an old
/// build to pin someone on a version with a known hole is a real attack. When
/// the *user* names the version, it stops being that attack and becomes their
/// call, but it is still a decision they have to make on purpose.
///
/// So `--yes` does not answer this one. `--allow-downgrade` does, because it
/// says the one thing `--yes` cannot: that the person running this knew the
/// version was older.
pub fn confirm_downgrade(
    app_name: &str,
    installed: &semver::Version,
    target: &semver::Version,
    allow: bool,
) -> SecResult<()> {
    let bar = "-".repeat(72);
    println!("\n{bar}");
    println!("  GOING BACK TO AN OLDER VERSION");
    println!("{bar}");
    println!("  {app_name} {installed} is installed; you asked for {target}.");
    println!();
    println!("  An older release can be missing security fixes that the newer");
    println!("  one carries. It may also be unable to read data the newer");
    println!("  version has already written - save files, project files and");
    println!("  databases are rarely backwards compatible.");
    println!();
    println!("  HERMES will still verify the signature and the checksum. This");
    println!("  is about the version being old, not about it being untrusted.");
    println!("{bar}");

    if allow {
        println!("  --allow-downgrade supplied: continuing.");
        println!("{bar}\n");
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        println!("  No interactive terminal available - denying by default.");
        println!("  Pass --allow-downgrade to answer this without a prompt.");
        println!("{bar}\n");
        return Err(SecurityError::ConsentUnavailable);
    }
    if confirm(&format!("  Install {app_name} {target} anyway?"), false) {
        println!("{bar}\n");
        Ok(())
    } else {
        println!("  Cancelled.\n{bar}\n");
        Err(SecurityError::ConsentDenied)
    }
}

/// Generic yes/no prompt used elsewhere in the CLI (key changes, overwrites).
pub fn confirm(question: &str, assume_yes: bool) -> bool {
    if assume_yes {
        return true;
    }
    if !io::stdin().is_terminal() {
        return false;
    }
    print!("{question} [y/N] ");
    let _ = io::stdout().flush();
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    let answer = answer.trim();
    answer.eq_ignore_ascii_case("y") || answer.eq_ignore_ascii_case("yes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BaseTree, FoiledStep, ScopeGrant};

    fn grant(path: &str, recursive: bool, access: Access) -> ScopeGrant {
        ScopeGrant {
            path: path.into(),
            recursive,
            access,
            reason: None,
        }
    }

    fn plan(scope: Vec<ScopeGrant>, steps: Vec<FoiledStep>) -> FoiledPlan {
        FoiledPlan {
            schema: crate::schema::FOILED_SCHEMA.into(),
            origin_id: "studio.game".into(),
            version: "1.0.0".into(),
            base: BaseTree::Clone,
            scope,
            steps,
            notes: None,
            locate: None,
        }
    }

    fn resolved(scope: Vec<ScopeGrant>) -> Vec<ResolvedGrant> {
        let p = plan(scope, vec![FoiledStep::Mkdir { path: "x".into() }]);
        resolve_scope(&p, Path::new("/opt/game")).unwrap()
    }

    #[test]
    fn allows_a_step_inside_a_declared_folder() {
        let grants = resolved(vec![grant("data", true, Access::Write)]);
        let p = plan(
            vec![grant("data", true, Access::Write)],
            vec![FoiledStep::Copy {
                from: "new.pak".into(),
                to: "data/content/new.pak".into(),
            }],
        );
        assert!(enforce_plan_scope(&p, &grants).is_ok());
    }

    #[test]
    fn blocks_a_step_outside_the_declared_folder() {
        let grants = resolved(vec![grant("data", true, Access::Write)]);
        let p = plan(
            vec![grant("data", true, Access::Write)],
            vec![FoiledStep::Delete {
                path: "saves/profile.sav".into(),
                recursive: false,
            }],
        );
        let err = enforce_plan_scope(&p, &grants).unwrap_err();
        assert!(matches!(err, SecurityError::UndeclaredScope { .. }));
    }

    #[test]
    fn non_recursive_grant_does_not_cover_sub_folders() {
        let grants = resolved(vec![grant("data", false, Access::Write)]);
        let p = plan(
            vec![grant("data", false, Access::Write)],
            vec![FoiledStep::Copy {
                from: "a".into(),
                to: "data/deep/a".into(),
            }],
        );
        assert!(enforce_plan_scope(&p, &grants).is_err());

        let ok = plan(
            vec![grant("data", false, Access::Write)],
            vec![FoiledStep::Copy {
                from: "a".into(),
                to: "data/a".into(),
            }],
        );
        assert!(enforce_plan_scope(&ok, &grants).is_ok());
    }

    #[test]
    fn root_grant_without_recursion_covers_only_top_level() {
        let grants = resolved(vec![grant(".", false, Access::Write)]);
        let top = plan(
            vec![grant(".", false, Access::Write)],
            vec![FoiledStep::Mkdir {
                path: "bin".into(),
            }],
        );
        assert!(enforce_plan_scope(&top, &grants).is_ok());
        let deep = plan(
            vec![grant(".", false, Access::Write)],
            vec![FoiledStep::Mkdir {
                path: "bin/tools".into(),
            }],
        );
        assert!(enforce_plan_scope(&deep, &grants).is_err());
    }

    #[test]
    fn write_grant_does_not_authorise_delete() {
        let grants = resolved(vec![grant("data", true, Access::Write)]);
        let p = plan(
            vec![grant("data", true, Access::Write)],
            vec![FoiledStep::Delete {
                path: "data/old.pak".into(),
                recursive: false,
            }],
        );
        assert!(enforce_plan_scope(&p, &grants).is_err());
    }

    #[test]
    fn traversal_in_a_step_is_rejected_not_just_unscoped() {
        let grants = resolved(vec![grant(".", true, Access::Delete)]);
        let p = plan(
            vec![grant(".", true, Access::Delete)],
            vec![FoiledStep::Delete {
                path: "../../Windows/System32".into(),
                recursive: true,
            }],
        );
        let err = enforce_plan_scope(&p, &grants).unwrap_err();
        assert!(matches!(err, SecurityError::UnsafePath { .. }));
    }

    #[test]
    fn traversal_in_a_scope_declaration_is_rejected() {
        let p = plan(
            vec![grant("../elsewhere", true, Access::Write)],
            vec![FoiledStep::Mkdir { path: "a".into() }],
        );
        assert!(resolve_scope(&p, Path::new("/opt/game")).is_err());
    }

    // -- "where is it installed?" -------------------------------------------

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("hermes-locate-tests")
            .join(format!("{name}-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    #[test]
    fn an_existing_folder_holding_the_expected_file_is_accepted() {
        let dir = scratch("ok");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::write(dir.join("bin/game.exe"), b"x").unwrap();

        let chosen = validate_install_choice(&dir, Some("bin/game.exe")).expect("accepted");
        assert_eq!(
            std::fs::canonicalize(&dir).unwrap(),
            chosen,
            "the canonical path is what gets used"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Without this check "point at your install" quietly becomes "point at
    /// anything", and the plan's scope is then measured from the wrong root.
    #[test]
    fn a_folder_without_the_expected_file_is_refused() {
        let dir = scratch("wrong");
        let why = validate_install_choice(&dir, Some("bin/game.exe")).expect_err("refused");
        assert!(why.contains("does not contain bin/game.exe"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_is_not_an_install_folder() {
        let dir = scratch("file");
        let file = dir.join("game.exe");
        std::fs::write(&file, b"x").unwrap();
        let why = validate_install_choice(&file, None).expect_err("refused");
        assert!(why.contains("is a file"), "{why}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_relative_answer_is_refused() {
        let why = validate_install_choice(Path::new("games/starfall"), None).expect_err("refused");
        assert!(why.contains("relative path"), "{why}");
    }

    #[test]
    fn a_missing_folder_is_refused() {
        let dir = scratch("gone");
        let missing = dir.join("not-here");
        assert!(validate_install_choice(&missing, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The home directory, a drive root, and anything containing HERMES's own
    /// state are refused outright: a plan declaring `[write] .` would reach
    /// every file under them from one mistyped answer.
    #[test]
    fn a_root_or_the_home_directory_is_refused() {
        let home = dirs::home_dir().expect("a home directory");
        let why = validate_install_choice(&home, None).expect_err("home is refused");
        assert!(why.contains("home folder"), "{why}");

        // The ancestor case: whatever contains the home directory.
        if let Some(above) = home.parent() {
            assert!(validate_install_choice(above, None).is_err());
        }

        let mut root = home.clone();
        while let Some(parent) = root.parent() {
            root = parent.to_path_buf();
        }
        assert!(validate_install_choice(&root, None).is_err());
    }
}
