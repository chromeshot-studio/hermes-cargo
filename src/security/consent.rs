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
use crate::schema::{Access, FoiledPlan};
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
}
