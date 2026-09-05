//! Module 1 - Decentralized data schemas.
//!
//! Three documents, no central authority anywhere in the chain of trust:
//!
//! * `.origin`   - TOML, dropped in by the user. It *is* the trust root: it
//!                 pins the studio's Ed25519 public key. HERMES ships with no
//!                 keys and no server list.
//! * `manifest.json` - JSON, fetched from the studio's own CDN. Signed by the
//!                 key in the `.origin`, so the CDN is untrusted transport only.
//! * `.foiled`   - TOML, the execution plan shipped *inside* the update
//!                 archive. It declares the folder scope it wants before it may
//!                 touch a single file.
//!
//! Every document is self-describing (`schema` field) and parsed offline.
//!
//! # Why TOML for two of them and JSON for the third
//!
//! `.origin` and `.foiled` are written and read by people - a studio hands out
//! an `.origin`, and a user who is about to grant folder access should be able
//! to open the `.foiled` and understand it. TOML is unambiguous where that
//! matters: no implicit type coercion turning a version into a float, no
//! anchors or aliases to expand, one obvious parser. For a file carrying a
//! public key and a list of folder permissions, boring parsing is a security
//! property.
//!
//! `manifest.json` stays JSON because it is machine-generated, machine-verified
//! wire format whose signature covers the *raw bytes* of its payload (see
//! [`SignedManifest`]). JSON has a `RawValue` that hands back those bytes
//! untouched; keeping it removes any re-serialisation step from the trust path.

use crate::error::SecurityError;
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

pub const ORIGIN_SCHEMA: &str = "hermes.origin/v1";
pub const MANIFEST_SCHEMA: &str = "hermes.manifest/v1";
pub const FOILED_SCHEMA: &str = "hermes.foiled/v1";

/// Conventional name of the plan inside an update archive.
pub const FOILED_ENTRY_NAME: &str = "update.foiled";

// ---------------------------------------------------------------------------
// .origin
// ---------------------------------------------------------------------------

/// The file a user drags into the terminal: `hermes add ./game.origin`.
///
/// ```toml
/// schema = "hermes.origin/v1"
/// id     = "moonforge.starfall"
/// name   = "Starfall"
/// publisher = "Moonforge Games"
///
/// upstream_manifest_url = "https://cdn.moonforge.dev/starfall/manifest.json"
/// studio_auth_url       = "https://moonforge.dev/hermes/login"
///
/// # Ed25519, base64 or hex. Everything this CLI will ever install for
/// # Starfall has to be signed by this key.
/// public_key = "0FMFR1Kx8Tn0aQb0lJ0KpXQMPzGSTQFyO7oxVw2vGxk="
///
/// requires_auth = true
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginFile {
    pub schema: String,
    /// Stable identity, also the registry filename - strictly validated.
    pub id: String,
    pub name: String,
    pub upstream_manifest_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub studio_auth_url: Option<String>,
    /// Ed25519 public key, base64 or hex, 32 bytes. The whole trust anchor.
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    /// Suggested install directory name (relative; never absolute).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_dir: Option<String>,
    /// Manifest requests must carry a studio bearer token (Module 5).
    #[serde(default)]
    pub requires_auth: bool,
}

impl OriginFile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("a .origin file must be UTF-8 TOML")?;
        let origin: OriginFile =
            toml::from_str(text).context("this does not look like a HERMES .origin file")?;
        origin.validate()?;
        Ok(origin)
    }

    /// Reject anything we would not want to act on later. Cheap now, load
    /// bearing later: `id` becomes a filename and `install_dir` a directory.
    pub fn validate(&self) -> Result<()> {
        if self.schema != ORIGIN_SCHEMA {
            bail!(
                "unsupported .origin schema '{}' (this build understands {})",
                self.schema,
                ORIGIN_SCHEMA
            );
        }
        validate_id(&self.id)?;
        if self.name.trim().is_empty() || self.name.chars().count() > 128 {
            bail!("origin 'name' must be 1-128 characters");
        }
        if self.name.chars().any(|c| c.is_control()) {
            bail!("origin 'name' contains control characters");
        }
        require_secure_url(&self.upstream_manifest_url, "upstream_manifest_url")?;
        if let Some(auth) = &self.studio_auth_url {
            require_secure_url(auth, "studio_auth_url")?;
        }
        // Decoding here means a malformed key is rejected at `hermes add`
        // time rather than at update time.
        crate::security::crypto::parse_public_key(&self.public_key)?;
        if let Some(dir) = &self.install_dir {
            crate::security::safepath::sanitize_relative(dir)
                .map_err(|e| anyhow!("invalid install_dir: {e}"))?;
        }
        Ok(())
    }

    /// Render a commented `.origin` document.
    ///
    /// This is the file a studio publishes and a user opens before trusting
    /// it, so it is written to be read: the key gets a comment explaining what
    /// it authorises. Values go through `toml::Value` so quoting and escaping
    /// are the TOML crate's problem, not ours.
    pub fn to_toml(&self) -> String {
        fn kv(key: &str, value: &str) -> String {
            format!("{key} = {}\n", toml::Value::String(value.to_string()))
        }

        let mut out = String::new();
        out.push_str(
            "# HERMES origin file\n\
             #\n\
             # Add it with:  hermes add <this file>   (or drag it into a terminal)\n\
             #\n\
             # Every update HERMES installs for this application must be signed by\n\
             # the public key below. Nothing else in this file is trusted: if the\n\
             # URLs start serving something the key did not sign, the update stops.\n\n",
        );
        out.push_str(&kv("schema", &self.schema));
        out.push_str(&kv("id", &self.id));
        out.push_str(&kv("name", &self.name));
        if let Some(publisher) = &self.publisher {
            out.push_str(&kv("publisher", publisher));
        }
        if let Some(homepage) = &self.homepage {
            out.push_str(&kv("homepage", homepage));
        }

        out.push_str("\n# Where the signed manifest lives - the studio's own CDN.\n");
        out.push_str(&kv("upstream_manifest_url", &self.upstream_manifest_url));

        if let Some(auth) = &self.studio_auth_url {
            out.push_str("\n# The studio's own login page, opened by `hermes login`.\n");
            out.push_str(&kv("studio_auth_url", auth));
        }

        out.push_str("\n# Ed25519 public key (base64). The trust anchor for this application.\n");
        out.push_str(&kv("public_key", &self.public_key));

        if let Some(dir) = &self.install_dir {
            out.push_str("\n# Suggested folder name; the user's --install-dir always wins.\n");
            out.push_str(&kv("install_dir", dir));
        }
        if self.requires_auth {
            out.push_str("\n# Manifest requests must carry a studio token: `hermes login` first.\n");
            out.push_str("requires_auth = true\n");
        }
        out
    }
}

/// Identifiers become filenames and registry keys: lowercase, dotted, no
/// separators, no traversal, no surprises.
pub fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 96 {
        bail!("id must be 1-96 characters");
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-' | '_'))
    {
        bail!("id '{id}' may only contain a-z, 0-9, '.', '-' and '_'");
    }
    if id.starts_with(['.', '-']) || id.ends_with('.') || id.contains("..") {
        bail!("id '{id}' has a leading/trailing separator or a '..' sequence");
    }
    Ok(())
}

/// https everywhere. `HERMES_ALLOW_INSECURE_HTTP=1` unlocks plain http against
/// loopback only, so a studio can test its own stack locally.
pub fn require_secure_url(raw: &str, field: &str) -> Result<url::Url> {
    let parsed = url::Url::parse(raw).with_context(|| format!("{field} is not a valid URL"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if insecure_http_allowed() && is_loopback_host(&parsed) => {}
        _ => return Err(SecurityError::InsecureUrl(raw.to_string()).into()),
    }
    if parsed.host().is_none() {
        bail!("{field} has no host");
    }
    Ok(parsed)
}

pub fn insecure_http_allowed() -> bool {
    matches!(
        std::env::var("HERMES_ALLOW_INSECURE_HTTP").as_deref(),
        Ok("1") | Ok("true")
    )
}

pub fn is_loopback_host(u: &url::Url) -> bool {
    matches!(
        u.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

// ---------------------------------------------------------------------------
// manifest.json
// ---------------------------------------------------------------------------

/// The wire format the studio publishes.
///
/// The signature covers the **raw bytes of `payload` exactly as they appear in
/// the file**. Keeping the payload as a [`RawValue`] sidesteps JSON
/// canonicalisation entirely - there is no re-serialisation step in which a
/// verifier and a signer could disagree, which is where most "signed JSON"
/// schemes get broken.
#[derive(Debug, Deserialize)]
pub struct SignedManifest<'a> {
    #[serde(borrow)]
    pub payload: &'a RawValue,
    pub signature: SignatureBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    pub algorithm: String,
    /// base64 (standard alphabet) or hex encoded 64-byte Ed25519 signature.
    pub value: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema: String,
    /// Must equal the `.origin` id: stops a valid manifest signed by a studio
    /// for one product from being replayed as the update for another.
    pub origin_id: String,
    pub latest_version: String,
    pub download_url: String,
    /// Lowercase hex, 64 chars.
    pub checksum_sha256: String,
    /// Exact expected size. Bounds the download and catches truncation early.
    pub size_bytes: u64,
    /// Unix seconds. Freshness, not decoration - see `verify_manifest`.
    pub issued_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// What changed, in plain text. Carried *inside* the signed payload so the
    /// notes a user reads before pressing Y are the notes the studio signed -
    /// unlike `release_notes_url`, which is unauthenticated content fetched
    /// from wherever it points.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_client_version: Option<String>,
    /// Path of the plan inside the archive; defaults to `update.foiled`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foiled_path: Option<String>,
    /// Per-platform artifacts, keyed by [`platform_key`] (`windows-x86_64`,
    /// `linux-x86_64`, `macos-aarch64`, ...).
    ///
    /// Software that ships a different binary per platform - a CLI updating
    /// itself, for one - cannot describe itself with a single `download_url`.
    /// When this map is present and contains the running platform, its entry
    /// wins; the top-level fields stay as the fallback for anything portable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platforms: Option<std::collections::BTreeMap<String, PlatformArtifact>>,
    #[serde(default)]
    pub requires_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformArtifact {
    pub download_url: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
}

/// How the running platform names itself in a manifest's `platforms` map.
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The download a client should actually fetch.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub download_url: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    /// `None` when the top-level fallback was used.
    pub platform: Option<String>,
}

impl Manifest {
    pub fn version(&self) -> Result<semver::Version> {
        semver::Version::parse(&self.latest_version)
            .with_context(|| format!("latest_version '{}' is not semver", self.latest_version))
    }

    pub fn foiled_entry(&self) -> &str {
        self.foiled_path.as_deref().unwrap_or(FOILED_ENTRY_NAME)
    }

    /// Pick the artifact for the platform we are running on.
    ///
    /// A manifest that lists platforms but not *this* one is a hard error
    /// rather than a silent fallback: quietly installing another platform's
    /// binary is worse than saying there is no build.
    pub fn artifact(&self) -> Result<Artifact> {
        let Some(platforms) = &self.platforms else {
            return Ok(Artifact {
                download_url: self.download_url.clone(),
                checksum_sha256: self.checksum_sha256.clone(),
                size_bytes: self.size_bytes,
                platform: None,
            });
        };
        let key = platform_key();
        let entry = platforms.get(&key).ok_or_else(|| {
            anyhow!(
                "this release has no build for {key} (it offers: {})",
                platforms.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;
        Ok(Artifact {
            download_url: entry.download_url.clone(),
            checksum_sha256: entry.checksum_sha256.clone(),
            size_bytes: entry.size_bytes,
            platform: Some(key),
        })
    }

    /// Structural checks. Signature and freshness live in `security::crypto`.
    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != MANIFEST_SCHEMA {
            bail!(
                "unsupported manifest schema '{}' (expected {})",
                self.schema,
                MANIFEST_SCHEMA
            );
        }
        validate_id(&self.origin_id)?;
        self.version()?;
        require_secure_url(&self.download_url, "download_url")?;
        if self.checksum_sha256.len() != 64
            || !self.checksum_sha256.chars().all(|c| c.is_ascii_hexdigit())
        {
            bail!("checksum_sha256 must be 64 hex characters");
        }
        // Non-zero, and inside anything a real release could be: the field
        // bounds the download, so a nonsense value would loosen that bound.
        const MAX_RELEASE_BYTES: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB
        if self.size_bytes == 0 || self.size_bytes > MAX_RELEASE_BYTES {
            bail!(
                "size_bytes must be between 1 and {MAX_RELEASE_BYTES} (got {})",
                self.size_bytes
            );
        }
        crate::security::safepath::sanitize_relative(self.foiled_entry())
            .map_err(|e| anyhow!("foiled_path is unsafe: {e}"))?;
        if let Some(notes) = &self.release_notes {
            if notes.len() > MAX_RELEASE_NOTES_BYTES {
                bail!(
                    "release_notes is {} bytes; the cap is {MAX_RELEASE_NOTES_BYTES}",
                    notes.len()
                );
            }
        }
        if let Some(platforms) = &self.platforms {
            if platforms.is_empty() {
                bail!("platforms is present but empty");
            }
            if platforms.len() > 32 {
                bail!("platforms lists {} entries; the cap is 32", platforms.len());
            }
            for (key, artifact) in platforms {
                if key.is_empty() || key.len() > 64 {
                    bail!("platform key '{key}' must be 1-64 characters");
                }
                require_secure_url(&artifact.download_url, "platform download_url")?;
                if artifact.checksum_sha256.len() != 64
                    || !artifact.checksum_sha256.chars().all(|c| c.is_ascii_hexdigit())
                {
                    bail!("platform '{key}' checksum_sha256 must be 64 hex characters");
                }
                if artifact.size_bytes == 0 || artifact.size_bytes > MAX_RELEASE_BYTES {
                    bail!("platform '{key}' size_bytes is out of range");
                }
            }
        }
        Ok(())
    }

    /// Release notes, made safe to print: control characters (other than
    /// newlines) stripped, lines trimmed, length bounded. Notes are studio
    /// text rendered into the user's terminal right before a trust decision,
    /// so they do not get to move the cursor or repaint the screen.
    pub fn display_notes(&self) -> Option<Vec<String>> {
        let notes = self.release_notes.as_deref()?;
        let lines: Vec<String> = notes
            .lines()
            .take(MAX_RELEASE_NOTES_LINES)
            .map(|line| {
                line.chars()
                    .filter(|c| !c.is_control())
                    .take(160)
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect();
        if lines.iter().all(|l| l.trim().is_empty()) {
            return None;
        }
        Some(lines)
    }
}

/// Notes are shown before a trust decision, so they are bounded like anything
/// else that crosses the wire.
pub const MAX_RELEASE_NOTES_BYTES: usize = 8 * 1024;
pub const MAX_RELEASE_NOTES_LINES: usize = 40;

// ---------------------------------------------------------------------------
// .foiled
// ---------------------------------------------------------------------------

/// The update execution plan, shipped inside the signed archive.
///
/// A plan is *declarative on purpose*: there is no `run`, `exec` or `script`
/// step and there never will be. Everything a studio can ask for is a file
/// operation inside a scope the user approved, so an update can never
/// escalate into arbitrary code execution during `hermes update`.
///
/// ```toml
/// schema    = "hermes.foiled/v1"
/// origin_id = "moonforge.starfall"
/// version   = "1.4.0"
/// base      = "clone"          # or "empty" for a full replacement package
/// notes     = "Adds the Deep Field expansion."
///
/// # Folders this plan may touch. The user sees this list verbatim and has to
/// # approve it; anything a step touches outside it aborts the update.
/// [[scope]]
/// path      = "bin"
/// recursive = true
/// access    = "write"
/// reason    = "replace the game executable"
///
/// [[scope]]
/// path      = "saves"
/// recursive = true
/// access    = "read"
/// reason    = "keep your save files"
///
/// [[steps]]
/// action = "preserve"
/// path   = "saves"
///
/// [[steps]]
/// action = "copy"
/// from   = "bin/game.bin"      # read from the update payload
/// to     = "bin/game.bin"      # written into the new install tree
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoiledPlan {
    pub schema: String,
    pub origin_id: String,
    pub version: String,
    /// How the new tree starts out before steps run.
    #[serde(default)]
    pub base: BaseTree,
    /// Folders this plan is allowed to touch, shown verbatim in the consent
    /// prompt. Anything outside these grants aborts the update before a single
    /// byte is written.
    pub scope: Vec<ScopeGrant>,
    pub steps: Vec<FoiledStep>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BaseTree {
    /// Start from a clone of the current install (patch-style update).
    #[default]
    Clone,
    /// Start from nothing (full replacement package).
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
    Delete,
}

impl std::fmt::Display for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Access::Read => "read",
            Access::Write => "write",
            Access::Delete => "delete",
        })
    }
}

/// One folder the plan asks for, relative to the install root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeGrant {
    /// Relative path; `"."` means the install root itself.
    pub path: String,
    /// Whether sub-folders are included. `false` means direct children only -
    /// a plan that wants `saves/` must say so even if it already holds `.`.
    #[serde(default)]
    pub recursive: bool,
    #[serde(default = "default_access")]
    pub access: Access,
    /// Shown to the user in the prompt. Studios should fill this in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn default_access() -> Access {
    Access::Write
}

/// The step vocabulary. Paths in `archive`/`from` for `extract_zip` and `copy`
/// are read out of the extracted payload; every other path is relative to the
/// install tree being built.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum FoiledStep {
    /// Unpack a zip that shipped inside the update archive.
    ExtractZip {
        /// Archive path inside the payload.
        archive: String,
        /// Destination inside the install tree.
        dest: String,
    },
    /// Copy a file or directory from the payload into the install tree.
    Copy { from: String, to: String },
    /// Move a path within the install tree.
    Move { from: String, to: String },
    /// Remove a path from the new tree.
    Delete {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    /// Snapshot a path from the *current* install into the backup folder
    /// before it is replaced.
    Backup { path: String },
    /// Carry a path from the current install into the new tree untouched
    /// (save games, configs, mods).
    Preserve { path: String },
    /// Create a directory in the install tree.
    Mkdir { path: String },
}

impl FoiledStep {
    pub fn name(&self) -> &'static str {
        match self {
            FoiledStep::ExtractZip { .. } => "extract_zip",
            FoiledStep::Copy { .. } => "copy",
            FoiledStep::Move { .. } => "move",
            FoiledStep::Delete { .. } => "delete",
            FoiledStep::Backup { .. } => "backup",
            FoiledStep::Preserve { .. } => "preserve",
            FoiledStep::Mkdir { .. } => "mkdir",
        }
    }

    /// Every install-tree path this step touches, with the access it needs.
    /// Payload-side paths are excluded: the payload is a sandbox we own.
    pub fn touched(&self) -> Vec<(&str, Access)> {
        match self {
            FoiledStep::ExtractZip { dest, .. } => vec![(dest.as_str(), Access::Write)],
            FoiledStep::Copy { to, .. } => vec![(to.as_str(), Access::Write)],
            FoiledStep::Move { from, to } => {
                vec![(from.as_str(), Access::Delete), (to.as_str(), Access::Write)]
            }
            FoiledStep::Delete { path, .. } => vec![(path.as_str(), Access::Delete)],
            FoiledStep::Backup { path } => vec![(path.as_str(), Access::Read)],
            FoiledStep::Preserve { path } => vec![(path.as_str(), Access::Read)],
            FoiledStep::Mkdir { path } => vec![(path.as_str(), Access::Write)],
        }
    }

    /// One line for the consent prompt.
    pub fn describe(&self) -> String {
        match self {
            FoiledStep::ExtractZip { archive, dest } => format!("unpack {archive} -> {dest}"),
            FoiledStep::Copy { from, to } => format!("copy {from} -> {to}"),
            FoiledStep::Move { from, to } => format!("move {from} -> {to}"),
            FoiledStep::Delete { path, recursive } => format!(
                "delete {path}{}",
                if *recursive { " (recursive)" } else { "" }
            ),
            FoiledStep::Backup { path } => format!("back up {path}"),
            FoiledStep::Preserve { path } => format!("keep your existing {path}"),
            FoiledStep::Mkdir { path } => format!("create folder {path}"),
        }
    }
}

impl FoiledPlan {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("a .foiled plan must be UTF-8 TOML")?;
        let plan: FoiledPlan =
            toml::from_str(text).context("this does not look like a .foiled plan")?;
        plan.validate_shape()?;
        Ok(plan)
    }

    pub fn validate_shape(&self) -> Result<()> {
        if self.schema != FOILED_SCHEMA {
            bail!(
                "unsupported .foiled schema '{}' (expected {})",
                self.schema,
                FOILED_SCHEMA
            );
        }
        validate_id(&self.origin_id)?;
        semver::Version::parse(&self.version)
            .with_context(|| format!("plan version '{}' is not semver", self.version))?;
        if self.steps.is_empty() {
            bail!("plan has no steps");
        }
        if self.steps.len() > 512 {
            bail!("plan has {} steps; the cap is 512", self.steps.len());
        }
        if self.scope.is_empty() {
            bail!("plan declares no scope; HERMES will not run an unscoped plan");
        }
        if self.scope.len() > 64 {
            bail!("plan declares {} scopes; the cap is 64", self.scope.len());
        }
        Ok(())
    }
}
