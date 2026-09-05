//! HERMES - a decentralized CLI updater.
//!
//! The author of this binary hosts nothing. There is no HERMES server, no
//! account, no package index and no default key. A studio publishes a signed
//! `manifest.json` and an archive on its own CDN; a user drops a `.origin`
//! file into the terminal and that file - on their disk, under their control -
//! becomes the trust root for everything that follows.
//!
//! ```text
//!   hermes add ./starfall.origin     register a studio's software
//!   hermes login starfall            sign in on the studio's own website
//!   hermes check                     verify manifests, report versions
//!   hermes update starfall           download, verify, ask, swap
//!   hermes install-system            file icons + double-click support
//! ```

mod auth;
mod error;
mod fsx;
mod install;
mod net;
mod paths;
mod registry;
mod schema;
mod security;
mod selfupdate;
mod system_icons;
mod tui;
mod update;

use anyhow::{bail, Context, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use error::SecurityError;
use security::safepath::display_path;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(
    name = "hermes",
    version,
    about = "A decentralized, zero-infrastructure updater",
    long_about = "HERMES updates software from studios that host their own files.\n\
                  Trust comes from the .origin file you added, not from a server."
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Register a .origin file (drag and drop it onto the terminal)
    Add(AddArgs),
    /// List everything HERMES is tracking
    List,
    /// Stop tracking an application
    Remove {
        /// Origin id, a unique prefix of one, or its display name
        id: String,
    },
    /// Show what a .origin or .foiled file contains, without acting on it
    Inspect {
        path: String,
        #[command(flatten)]
        shell: ShellArgs,
    },
    /// Open a HERMES file - what a double-click in the file manager runs
    Open {
        path: String,
        #[command(flatten)]
        shell: ShellArgs,
    },
    /// Fetch and verify manifests; report available updates
    Check {
        /// Limit to one application (default: all of them)
        id: Option<String>,
    },
    /// Show every version a studio offers, with its release notes
    #[command(alias = "releases")]
    Versions {
        /// Application to look at
        id: String,
        /// Print the full release notes for each version
        #[arg(long)]
        notes: bool,
    },
    /// Download, verify and apply an update
    Update(UpdateArgs),
    /// Sign in on the studio's own website via a localhost callback
    Login {
        id: String,
        /// Do not ask before replacing a session that is still valid
        #[arg(long)]
        yes: bool,
    },
    /// Forget a studio session token
    Logout { id: String },
    /// Open the interactive list (the same as running `hermes` with no arguments)
    #[command(alias = "tui")]
    Ui,
    /// Copy this binary somewhere permanent, add it to PATH, register file types
    Install {
        /// Install directory (default: a per-user programs directory)
        #[arg(long)]
        dir: Option<PathBuf>,
        /// Do not register icons and double-click handling
        #[arg(long)]
        no_associations: bool,
    },
    /// Remove the installed binary, its PATH entry and its file associations
    Uninstall,
    /// Update HERMES itself from the origin it publishes for itself
    SelfUpdate {
        /// Report what is available without installing it
        #[arg(long)]
        check: bool,
        /// Do not ask before replacing the binary
        #[arg(long, short = 'y')]
        yes: bool,
    },
    /// Register .origin/.foiled icons and double-click handling with the OS
    InstallSystem,
    /// Undo `install-system`
    UninstallSystem,
    /// Studio-side tooling: keys, signed manifests, .origin files
    #[command(subcommand)]
    Studio(StudioCommand),
}

#[derive(Args)]
struct AddArgs {
    /// One or more .origin files. Omit to be prompted to drop one.
    paths: Vec<String>,
    /// Accept a changed studio public key for an origin already registered
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    shell: ShellArgs,
}

#[derive(Args)]
struct UpdateArgs {
    /// Application to update (default: every one with an update available)
    id: Option<String>,
    /// Grant the plan's declared scope without the interactive prompt
    #[arg(long, short = 'y')]
    yes: bool,
    /// Install to a specific directory instead of the tracked one
    #[arg(long)]
    install_dir: Option<PathBuf>,
    /// Re-apply even if the installed version already matches
    #[arg(long)]
    force: bool,
    /// Install this exact version instead of the newest (see `hermes versions`)
    #[arg(long, value_name = "VERSION")]
    version: Option<String>,
    /// Accept a chosen version older than the installed one
    #[arg(long)]
    allow_downgrade: bool,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum TemplateKind {
    /// The trust root a user adds: identity, and the address updates come from
    Origin,
    /// The plan that ships inside a release archive: what to install, and how
    Foiled,
    /// The manifest body you fill in and hand to `studio sign`
    Manifest,
}

#[derive(Args, Clone, Copy)]
struct ShellArgs {
    /// Launched from a file association: keep the window open at the end
    #[arg(long, hide = true)]
    from_shell: bool,
}

#[derive(Subcommand)]
enum StudioCommand {
    /// Generate an Ed25519 signing key pair
    Keygen {
        /// Where to write <id>.key (keep this file offline)
        #[arg(long, default_value = ".")]
        out: PathBuf,
        /// Origin id this key will sign for
        #[arg(long)]
        id: String,
    },
    /// Sign a manifest payload, producing a publishable manifest.json
    Sign {
        /// The .key file from `studio keygen`
        #[arg(long)]
        key: PathBuf,
        /// JSON file holding the manifest payload (the inner object)
        #[arg(long, value_name = "PAYLOAD")]
        payload: PathBuf,
        /// Where to write the signed manifest
        #[arg(long, default_value = "manifest.json")]
        out: PathBuf,
    },
    /// Emit a .origin file for users to drag into their terminal
    NewOrigin {
        #[arg(long)]
        key: PathBuf,
        /// Display name of the application
        #[arg(long)]
        name: String,
        /// Who made it - shown wherever the application is listed
        #[arg(long)]
        publisher: Option<String>,
        /// The application's home page
        #[arg(long)]
        homepage: Option<String>,
        #[arg(long)]
        manifest_url: String,
        #[arg(long)]
        auth_url: Option<String>,
        #[arg(long)]
        requires_auth: bool,
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Write a starter .origin, .foiled or manifest body to copy and edit
    Template {
        /// Which document to write
        #[arg(value_enum)]
        kind: TemplateKind,
        /// Where to write it ("-" for stdout)
        #[arg(long, default_value = "-")]
        out: PathBuf,
    },
    /// Print the sha256 and byte size of a release archive, for the payload
    Checksum { path: PathBuf },
    /// Check a manifest against a .origin exactly as a user's CLI would
    Verify {
        #[arg(long)]
        origin: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
}

fn main() {
    // A previous `self-update` leaves the outgoing binary behind, because a
    // running image cannot be unlinked. Clear it on the next start.
    selfupdate::clean_previous();

    let cli = Cli::parse();
    let keep_open = matches!(
        &cli.command,
        Some(Command::Add(AddArgs {
            shell: ShellArgs { from_shell: true },
            ..
        })) | Some(Command::Open {
            shell: ShellArgs { from_shell: true },
            ..
        }) | Some(Command::Inspect {
            shell: ShellArgs { from_shell: true },
            ..
        })
    );

    let code = match run(cli) {
        Ok(()) => 0,
        Err(e) => {
            // Security failures are called out loudly and get their own exit
            // code so scripts can tell "no update" from "something is wrong".
            if let Some(sec) = e.downcast_ref::<SecurityError>() {
                eprintln!("\n  ############ SECURITY CHECK FAILED ############");
                eprintln!("  {sec}");
                eprintln!("  Nothing was installed.");
                eprintln!("  ##############################################\n");
                2
            } else {
                eprintln!("error: {e:#}");
                1
            }
        }
    };

    if keep_open {
        wait_for_enter();
    }
    std::process::exit(code);
}

fn wait_for_enter() {
    if std::io::stdin().is_terminal() {
        print!("\nPress Enter to close...");
        let _ = std::io::stdout().flush();
        let mut discard = String::new();
        let _ = std::io::stdin().read_line(&mut discard);
    }
}

fn run(cli: Cli) -> Result<()> {
    // No subcommand: open the interactive list. Printing clap's help and
    // exiting non-zero here meant a double-clicked binary flashed a console
    // window and vanished, which every user reasonably reads as a crash.
    let Some(command) = cli.command else {
        return run_default();
    };
    match command {
        Command::Add(args) => cmd_add(args),
        Command::List => cmd_list(),
        Command::Remove { id } => cmd_remove(&id),
        Command::Inspect { path, .. } => cmd_inspect(&path),
        Command::Open { path, .. } => cmd_open(&path),
        Command::Check { id } => cmd_check(id.as_deref()),
        Command::Versions { id, notes } => cmd_versions(&id, notes),
        Command::Update(args) => cmd_update(args),
        Command::Login { id, yes } => cmd_login(&id, yes),
        Command::Logout { id } => cmd_logout(&id),
        Command::Ui => cmd_ui(),
        Command::Install {
            dir,
            no_associations,
        } => cmd_install(dir, no_associations),
        Command::Uninstall => cmd_uninstall(),
        Command::SelfUpdate { check, yes } => {
            selfupdate::run(&net::HttpClient::new()?, yes, check)
        }
        Command::InstallSystem => cmd_install_system(),
        Command::UninstallSystem => cmd_uninstall_system(),
        Command::Studio(cmd) => studio::run(cmd),
    }
}

fn run_default() -> Result<()> {
    if tui::is_available() {
        return cmd_ui();
    }
    // Redirected or piped: the caller wants help text, not an alternate
    // screen full of escape codes. This is not a usage error, so exit 0.
    Cli::command().print_help()?;
    println!();
    Ok(())
}

fn cmd_ui() -> Result<()> {
    if !tui::is_available() {
        bail!("the interactive list needs a terminal on both stdin and stdout");
    }
    tui::run()?;
    if let Some(hint) = tui::install_hint() {
        println!("
  {hint}
");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Module 2 - registration
// ---------------------------------------------------------------------------

fn cmd_add(args: AddArgs) -> Result<()> {
    let mut inputs = args.paths;
    if inputs.is_empty() {
        inputs.push(prompt_for_drop()?);
    }

    for raw in rejoin_split_path(inputs) {
        let path = registry::normalize_dropped_path(&raw);
        add_one(&path, args.force)?;
    }
    Ok(())
}

/// Put back together a path the shell tore apart.
///
/// Dragging a file onto a terminal pastes its path unquoted in a good number
/// of them. `C:\Program Files\Starfall\game.origin` then reaches us as three
/// arguments, none of which is a file, and the user is told that
/// `C:\Program` does not exist - which is true, and useless.
///
/// So: if the arguments joined back together with spaces name a file that
/// exists, that is what was dragged in. Checking existence first is what keeps
/// `hermes add a.origin b.origin` working - two real files are never rejoined.
fn rejoin_split_path(inputs: Vec<String>) -> Vec<String> {
    if inputs.len() < 2 {
        return inputs;
    }
    let joined = inputs.join(" ");
    if registry::normalize_dropped_path(&joined).is_file() {
        return vec![joined];
    }
    // Not a file either way - but if none of the pieces is one on its own,
    // this was almost certainly one split path rather than several files, and
    // saying so beats reporting that `C:\Program` does not exist.
    if !inputs
        .iter()
        .any(|raw| registry::normalize_dropped_path(raw).exists())
    {
        eprintln!(
            "  note: this looks like one path that the shell split on its spaces:\n    \
             {joined}\n  \
             If you dragged it in, put quotes around it: hermes add \"{joined}\"\n"
        );
    }
    inputs
}

/// The literal drag-and-drop gesture: the user drops the file onto a waiting
/// prompt and the terminal pastes its path.
fn prompt_for_drop() -> Result<String> {
    if !std::io::stdin().is_terminal() {
        bail!("usage: hermes add <file.origin>");
    }
    println!("\n  Drag a .origin file into this window and press Enter.");
    print!("  > ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the dropped path")?;
    let line = line.trim().to_string();
    if line.is_empty() {
        bail!("nothing was dropped");
    }
    Ok(line)
}

fn add_one(path: &Path, force: bool) -> Result<()> {
    let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if !extension.eq_ignore_ascii_case("origin") {
        eprintln!(
            "  note: {} does not end in .origin - parsing it anyway",
            display_path(path)
        );
    }

    let origin = registry::read_origin_file(path)
        .with_context(|| format!("reading {}", display_path(path)))?;

    // Key pinning is a trust decision, so it is the user's to make.
    if let Ok(existing) = registry::load_origin(&origin.id) {
        if existing.public_key != origin.public_key && !force {
            println!("\n  ###############################################");
            println!("  '{}' is already registered with a DIFFERENT", origin.id);
            println!("  studio signing key.");
            println!();
            println!("    trusted now : {}", short_key(&existing.public_key));
            println!("    this file   : {}", short_key(&origin.public_key));
            println!();
            println!("  This is normal after a studio rotates its key, and is");
            println!("  exactly what a supply-chain attack also looks like.");
            println!("  Only accept it if the studio published the new key.");
            println!("  ###############################################\n");
            if !security::consent::confirm("  Replace the trusted key?", false) {
                return Err(SecurityError::KeyPinViolation { id: origin.id }.into());
            }
            registry::add_origin(&origin, true)?;
            println!("  Key replaced for {}.", origin.name);
            return Ok(());
        }
    }

    let existed = registry::add_origin(&origin, force)?;
    println!(
        "\n  {} {} ({})",
        if existed { "Updated" } else { "Added" },
        origin.name,
        origin.id
    );
    println!("    creator   : {}", origin.publisher.as_deref().unwrap_or("(not stated)"));
    if let Some(homepage) = &origin.homepage {
        println!("    home      : {homepage}");
    }
    println!("    manifest  : {}", origin.upstream_manifest_url);
    println!("    signing key: {}", short_key(&origin.public_key));
    if origin.requires_auth {
        println!("\n  This studio requires an account: run `hermes login {}`.", origin.id);
    } else {
        println!("\n  Run `hermes check {}` to look for updates.", origin.id);
    }
    Ok(())
}

fn short_key(key: &str) -> String {
    let clean: String = key.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() <= 16 {
        clean
    } else {
        format!("{}...{}", &clean[..8], &clean[clean.len() - 8..])
    }
}

fn cmd_list() -> Result<()> {
    let all = registry::list_origins()?;
    if all.is_empty() {
        println!("\n  Nothing registered yet.");
        println!("  Drop a .origin file in with:  hermes add <file.origin>\n");
        return Ok(());
    }
    println!("\n  {} registered application(s):\n", all.len());
    for entry in &all {
        println!("  {}", entry.origin.name);
        println!("    id      : {}", entry.origin.id);
        println!("    status  : {}", update::state_summary(&entry.state));
        println!("    manifest: {}", entry.origin.upstream_manifest_url);
        if entry.origin.requires_auth {
            let signed_in = auth::load_token(&entry.origin.id)
                .ok()
                .flatten()
                .map(|t| !t.is_expired(paths::now_unix()))
                .unwrap_or(false);
            println!(
                "    account : {}",
                if signed_in { "signed in" } else { "not signed in" }
            );
        }
        println!();
    }
    Ok(())
}

fn cmd_remove(id: &str) -> Result<()> {
    let origin = registry::resolve_id(id)?;
    registry::remove_origin(&origin.id)?;
    let _ = auth::logout(&origin.id);
    println!("  Removed {} ({}).", origin.name, origin.id);
    println!("  Files already installed were left alone.");
    Ok(())
}

fn cmd_inspect(raw: &str) -> Result<()> {
    let path = registry::normalize_dropped_path(raw);
    let bytes = std::fs::read(&path)
        .with_context(|| format!("reading {}", display_path(&path)))?;
    let extension = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    match extension.as_str() {
        "foiled" => {
            let plan = schema::FoiledPlan::parse(&bytes)?;
            println!("\n  .foiled update plan");
            println!("    for      : {} v{}", plan.origin_id, plan.version);
            println!("    base tree: {:?}", plan.base);
            if let Some(notes) = &plan.notes {
                println!("    notes    : {notes}");
            }
            if let Some(locate) = &plan.locate {
                println!("\n    this plan will ask where the software is installed:");
                if let Some(question) = locate.display_prompt() {
                    println!("      \"{question}\"");
                }
                if let Some(expect) = &locate.expect {
                    println!("      the folder you pick must contain: {expect}");
                }
                println!("      the scope below is measured from the folder you name.");
            }
            println!("\n    requested folder scope:");
            for grant in &plan.scope {
                println!(
                    "      [{}{}] {}{}",
                    grant.access,
                    if grant.recursive { ", recursive" } else { "" },
                    grant.path,
                    grant
                        .reason
                        .as_ref()
                        .map(|r| format!("  ({r})"))
                        .unwrap_or_default()
                );
            }
            println!("\n    steps:");
            for (i, step) in plan.steps.iter().enumerate() {
                println!("      {}. {}", i + 1, step.describe());
            }
            println!("\n  Nothing was applied. This is a read-only view.\n");
        }
        _ => {
            let origin = schema::OriginFile::parse(&bytes)?;
            println!("\n  .origin file");
            println!("    name      : {}", origin.name);
            println!("    id        : {}", origin.id);
            println!("    creator   : {}", origin.publisher.as_deref().unwrap_or("(not stated)"));
            println!("    home      : {}", origin.homepage.as_deref().unwrap_or("(not stated)"));
            println!("    manifest  : {}", origin.upstream_manifest_url);
            println!("    auth      : {}", origin.studio_auth_url.as_deref().unwrap_or("(none)"));
            println!("    key       : {}", short_key(&origin.public_key));
            let known = registry::load_origin(&origin.id).is_ok();
            println!(
                "\n  {}\n",
                if known {
                    "Already registered."
                } else {
                    "Not registered yet - run `hermes add` on this file to track it."
                }
            );
        }
    }
    Ok(())
}

/// What a double-click runs. Routing by extension keeps a `.foiled` plan from
/// being mistaken for a source to register.
fn cmd_open(raw: &str) -> Result<()> {
    let path = registry::normalize_dropped_path(raw);
    match path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "origin" => add_one(&path, false),
        "foiled" => cmd_inspect(raw),
        other => bail!("'{other}' is not a HERMES file type (.origin or .foiled)"),
    }
}

// ---------------------------------------------------------------------------
// Modules 3 + 4 - check and update
// ---------------------------------------------------------------------------

fn cmd_check(id: Option<&str>) -> Result<()> {
    let client = net::HttpClient::new()?;
    let targets = targets_for(id)?;
    println!();
    for origin in targets {
        match update::check(&client, &origin) {
            Ok(available) => println!("  {}", update::describe_available(&origin, &available)),
            Err(e) => println!("  {} : {e:#}", origin.name),
        }
    }
    println!();
    Ok(())
}

fn cmd_versions(id: &str, full_notes: bool) -> Result<()> {
    let origin = registry::resolve_id(id)?;
    let client = net::HttpClient::new()?;
    let available = update::check(&client, &origin)?;
    let releases = available.manifest.releases()?;
    let installed = available.installed.clone();

    println!("\n  {} - {} version(s) offered\n", origin.name, releases.len());
    for release in &releases {
        let mut tags = Vec::new();
        if release.is_latest {
            tags.push("latest".to_string());
        }
        if installed.as_ref() == Some(&release.version) {
            tags.push("installed".to_string());
        }
        let size = match release.artifact() {
            Ok(artifact) => net::human_bytes(artifact.size_bytes),
            // A release with no build for this platform is worth showing -
            // silently hiding it looks like the studio never published it.
            Err(_) => "no build for this platform".into(),
        };
        println!(
            "  {:<14} {:<28}{}",
            release.version.to_string(),
            size,
            if tags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", tags.join(", "))
            }
        );
        if let Some(notes) = release.display_notes() {
            for line in notes.iter().take(if full_notes { usize::MAX } else { 2 }) {
                println!("      {line}");
            }
        }
    }
    println!("\n  Install one with:  hermes update {} --version <version>\n", origin.id);
    Ok(())
}

fn cmd_update(args: UpdateArgs) -> Result<()> {
    let client = net::HttpClient::new()?;
    let targets = targets_for(args.id.as_deref())?;
    let wanted = args
        .version
        .as_deref()
        .map(|raw| {
            semver::Version::parse(raw)
                .with_context(|| format!("--version '{raw}' is not a semantic version"))
        })
        .transpose()?;
    if wanted.is_some() && targets.len() > 1 {
        bail!("--version needs one application: try `hermes update <id> --version ...`");
    }
    let options = update::UpdateOptions {
        assume_yes: args.yes,
        install_dir: args.install_dir.clone(),
        force: args.force,
        version: wanted.clone(),
        allow_downgrade: args.allow_downgrade,
    };

    let mut failures = 0;
    for origin in targets {
        println!("\n  {}", origin.name);
        let available = match update::check(&client, &origin) {
            Ok(a) => a,
            Err(e) => {
                println!("  cannot check: {e:#}");
                failures += 1;
                continue;
            }
        };
        // "Nothing newer" is not a reason to skip a version the user named.
        if wanted.is_none() && !available.is_newer && !options.force {
            println!(
                "  already on {}",
                available
                    .installed
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| available.manifest.latest_version.clone())
            );
            continue;
        }
        if let Err(e) = update::apply(&client, &origin, &available, &options) {
            if e.downcast_ref::<SecurityError>().is_some() {
                return Err(e);
            }
            println!("  update failed: {e:#}");
            failures += 1;
        }
    }
    println!();
    if failures > 0 {
        bail!("{failures} application(s) could not be updated");
    }
    Ok(())
}

fn targets_for(id: Option<&str>) -> Result<Vec<schema::OriginFile>> {
    match id {
        Some(id) => Ok(vec![registry::resolve_id(id)?]),
        None => {
            let all: Vec<_> = registry::list_origins()?
                .into_iter()
                .map(|r| r.origin)
                .collect();
            if all.is_empty() {
                bail!("nothing is registered yet - run `hermes add <file.origin>`");
            }
            Ok(all)
        }
    }
}

// ---------------------------------------------------------------------------
// Module 5 - auth
// ---------------------------------------------------------------------------

fn cmd_login(id: &str, yes: bool) -> Result<()> {
    let origin = registry::resolve_id(id)?;
    if !auth::confirm_relogin(&origin, yes)? {
        println!("  Keeping your existing session.");
        return Ok(());
    }
    auth::login(&origin)?;
    Ok(())
}

fn cmd_logout(id: &str) -> Result<()> {
    let origin = registry::resolve_id(id)?;
    if auth::logout(&origin.id)? {
        println!("  Signed out of {}.", origin.name);
    } else {
        println!("  You were not signed in to {}.", origin.name);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Module 6 - system integration
// ---------------------------------------------------------------------------

fn cmd_install(dir: Option<PathBuf>, no_associations: bool) -> Result<()> {
    if let Some(dir) = &dir {
        install::validate_target(dir)?;
    }
    println!("\n  Installing HERMES...\n");

    let outcome = install::install(dir)?;
    if outcome.already_installed {
        println!("  = already installed at {}", display_path(&outcome.binary));
    } else {
        println!("  + installed {}", display_path(&outcome.binary));
    }
    for note in &outcome.notes {
        println!("  . {note}");
    }

    if !no_associations {
        println!();
        // Register against the *installed* path, not the binary we are running
        // from, so the association survives a `cargo clean`.
        let report = system_icons::install(Some(outcome.binary.clone()))?;
        report.print();
    }

    println!("\n  Done. Open a new terminal and run `hermes`.\n");
    Ok(())
}

fn cmd_uninstall() -> Result<()> {
    println!("\n  Removing HERMES...\n");
    let associations = system_icons::uninstall()?;
    associations.print();
    let outcome = install::uninstall()?;
    for note in &outcome.notes {
        println!("  . {note}");
    }
    println!("\n  Registered applications and installed files were left alone.");
    println!(
        "  Delete {} to remove those too.\n",
        display_path(&paths::hermes_home()?)
    );
    Ok(())
}

fn cmd_install_system() -> Result<()> {
    println!("\n  Registering HERMES file types for {}...\n", std::env::consts::OS);
    let report = system_icons::install(None)?;
    report.print();
    println!("\n  .origin and .foiled files now use the HERMES icons.");
    println!("  Double-clicking one opens this CLI.\n");
    Ok(())
}

fn cmd_uninstall_system() -> Result<()> {
    println!("\n  Removing HERMES file associations...\n");
    let report = system_icons::uninstall()?;
    report.print();
    println!("\n  Done. Registered applications were left untouched.\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Studio-side tooling
// ---------------------------------------------------------------------------

mod studio {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ed25519_dalek::SigningKey;
    use rand::RngCore;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize)]
    struct KeyFile {
        id: String,
        /// base64 Ed25519 seed. Whoever holds this can sign updates.
        private_key: String,
        public_key: String,
    }

    fn load_key(path: &Path) -> Result<(SigningKey, KeyFile)> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let file: KeyFile = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} is not a HERMES key file", path.display()))?;
        let seed = STANDARD
            .decode(&file.private_key)
            .context("private_key is not base64")?;
        let seed: [u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("private_key must be 32 bytes"))?;
        Ok((SigningKey::from_bytes(&seed), file))
    }

    pub fn run(command: StudioCommand) -> Result<()> {
        match command {
            StudioCommand::Keygen { out, id } => {
                schema::validate_id(&id)?;
                let mut seed = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut seed);
                let signing = SigningKey::from_bytes(&seed);
                let file = KeyFile {
                    id: id.clone(),
                    private_key: STANDARD.encode(seed),
                    public_key: security::crypto::encode_public(&signing.verifying_key()),
                };
                std::fs::create_dir_all(&out)?;
                let path = out.join(format!("{id}.key"));
                paths::write_private_file(&path, serde_json::to_string_pretty(&file)?.as_bytes())?;
                println!("\n  Key pair written to {}", path.display());
                println!("  public_key: {}", file.public_key);
                println!("\n  Keep the .key file offline. Anyone holding it can sign");
                println!("  updates that every user of this .origin will install.\n");
                Ok(())
            }

            StudioCommand::Sign { key, payload, out } => {
                let (signing, key_file) = load_key(&key)?;
                let raw = std::fs::read(&payload)
                    .with_context(|| format!("reading {}", payload.display()))?;
                let text = std::str::from_utf8(&raw).context("payload must be UTF-8 JSON")?;

                // Validate before signing - a studio should not be able to
                // publish a manifest its users' clients would reject.
                let manifest: schema::Manifest =
                    serde_json::from_str(text).context("payload is not a manifest")?;
                manifest.validate_shape()?;
                if manifest.origin_id != key_file.id {
                    bail!(
                        "this key signs for '{}' but the payload is for '{}'",
                        key_file.id,
                        manifest.origin_id
                    );
                }

                // Embed the payload bytes verbatim: the signature covers
                // exactly what a client will verify.
                let trimmed = text.trim();
                let signature = security::crypto::sign_payload(&signing, trimmed.as_bytes());
                let document = format!(
                    "{{\n  \"payload\": {trimmed},\n  \"signature\": {{\n    \"algorithm\": \"ed25519\",\n    \"value\": \"{signature}\",\n    \"key_id\": \"{}\"\n  }}\n}}\n",
                    key_file.id
                );
                std::fs::write(&out, &document)
                    .with_context(|| format!("writing {}", out.display()))?;
                println!("  Signed manifest written to {}", out.display());
                Ok(())
            }

            StudioCommand::NewOrigin {
                key,
                name,
                publisher,
                homepage,
                manifest_url,
                auth_url,
                requires_auth,
                out,
            } => {
                let (_, key_file) = load_key(&key)?;
                let origin = schema::OriginFile {
                    schema: schema::ORIGIN_SCHEMA.into(),
                    id: key_file.id.clone(),
                    name,
                    upstream_manifest_url: manifest_url,
                    studio_auth_url: auth_url,
                    public_key: key_file.public_key,
                    publisher,
                    homepage,
                    requires_auth,
                };
                origin.validate()?;
                let document = origin.to_toml();
                if out == Path::new("-") {
                    println!("{document}");
                } else {
                    std::fs::write(&out, &document)
                        .with_context(|| format!("writing {}", out.display()))?;
                    println!("  .origin written to {}", out.display());
                }
                Ok(())
            }

            StudioCommand::Template { kind, out } => {
                let (document, suggested) = match kind {
                    TemplateKind::Origin => (schema::ORIGIN_TEMPLATE, "starfall.origin"),
                    TemplateKind::Foiled => (schema::FOILED_TEMPLATE, "update.foiled"),
                    TemplateKind::Manifest => (schema::PAYLOAD_TEMPLATE, "payload.json"),
                };
                if out == Path::new("-") {
                    print!("{document}");
                    return Ok(());
                }
                // A template is a starting point, so refuse to be the reason
                // someone loses the edited version of one.
                if out.exists() {
                    bail!("{} already exists", display_path(&out));
                }
                std::fs::write(&out, document)
                    .with_context(|| format!("writing {}", out.display()))?;
                println!("\n  Wrote {}", display_path(&out));
                match kind {
                    TemplateKind::Origin => {
                        println!("  Read the comments in it, then edit it.");
                        println!(
                            "  Replace the placeholder key: hermes studio keygen --id <your.id>\n"
                        );
                    }
                    TemplateKind::Foiled => {
                        println!("  Read the comments in it, then edit it.");
                        println!(
                            "  It belongs at the root of your release archive as {suggested}.\n"
                        );
                    }
                    TemplateKind::Manifest => {
                        // JSON carries no comments, so everything a copied
                        // payload will be wrong about has to be said here.
                        println!("  This is the manifest *body*. Every checksum, size and URL in");
                        println!("  it is a placeholder, and issued_at must be the moment you");
                        println!("  publish. Get the real numbers with:");
                        println!("      hermes studio checksum <your-release.zip>");
                        println!("  Delete `platforms` unless you ship a different build per");
                        println!("  platform, and `versions` unless you offer older releases.");
                        println!("  Then sign it into the document you upload:");
                        println!("      hermes studio sign --key <your.key> \\");
                        println!("          --payload {suggested} --out manifest.json\n");
                    }
                }
                Ok(())
            }

            StudioCommand::Checksum { path } => {
                let digest = security::crypto::sha256_file(&path)?;
                let size = std::fs::metadata(&path)?.len();
                println!("
  {}", path.display());
                println!("    \"checksum_sha256\": \"{digest}\",");
                println!("    \"size_bytes\": {size}
");
                Ok(())
            }

            StudioCommand::Verify { origin, manifest } => {
                let origin_file = registry::read_origin_file(&origin)?;
                let raw = std::fs::read(&manifest)
                    .with_context(|| format!("reading {}", manifest.display()))?;
                let verified =
                    match security::crypto::verify_manifest(&origin_file, &raw, paths::now_unix()) {
                        Ok(verified) => verified,
                        Err(e) => {
                            // Studio-side self-check on your own artifact, so a
                            // diagnosis is safe here in a way it would not be on
                            // the user-facing path: the refusal still stands, and
                            // the commonest cause by far is an editor or git
                            // rewriting line endings after signing.
                            if raw.contains(&b'\r') {
                                eprintln!(
                                    "\n  note: this file has CRLF line endings. The signature \
                                     covers the payload's\n  raw bytes, so anything that \
                                     rewrites them - an editor, or git's end-of-line\n  \
                                     conversion - invalidates it. Re-run `hermes studio sign` \
                                     rather than\n  editing manifest.json, and mark it `-text` \
                                     in .gitattributes."
                                );
                            }
                            return Err(e);
                        }
                    };
                println!("\n  Signature OK.");
                println!("    origin  : {}", verified.origin_id);
                println!("    version : {}", verified.latest_version);
                println!("    download: {}", verified.download_url);
                println!("    sha256  : {}\n", verified.checksum_sha256);
                Ok(())
            }
        }
    }
}
