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

/// Commented starter documents, emitted by `hermes studio template`.
///
/// Embedded rather than described in prose so there is one copy of each: the
/// file in `templates/` is the file a studio receives, and the tests at the
/// bottom of this module parse both. A template that does not parse is worse
/// than no template at all.
pub const ORIGIN_TEMPLATE: &str = include_str!("../templates/starfall.origin");
pub const FOILED_TEMPLATE: &str = include_str!("../templates/update.foiled");

// ---------------------------------------------------------------------------
// .origin
// ---------------------------------------------------------------------------

/// The file a user drags into the terminal: `hermes add ./game.origin`.
///
/// It says who made the software, what it is called, and **the address updates
/// come from** - a studio's CDN, a GitHub Releases page, anywhere that serves
/// bytes. It says nothing about the user's disk: no install path, no folder
/// name, nothing local at all. Where files land is a question for the update
/// itself (`.foiled`, and `[locate]` when only the user knows the answer).
///
/// ```toml
/// schema = "hermes.origin/v1"
/// id     = "moonforge.starfall"
/// name   = "Starfall"
/// publisher = "Moonforge Games"
/// homepage  = "https://moonforge.dev"
///
/// upstream_manifest_url = "https://github.com/moonforge/starfall/releases/latest/download/manifest.json"
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
    /// Manifest requests must carry a studio bearer token (Module 5).
    #[serde(default)]
    pub requires_auth: bool,
}

/// Turn raw file bytes into TOML text, or say precisely what is wrong.
///
/// The awkward one is the **byte-order mark**. A `.origin` saved by Notepad,
/// exported by a CMS, or served by a webserver that helpfully re-encodes it
/// starts with `EF BB BF`. That is valid UTF-8 - `from_utf8` is perfectly
/// happy - but TOML sees `\u{FEFF}schema` as a key name and fails at line 1,
/// column 1, on a line that looks perfectly correct to the person reading it. Strip it
/// rather than making them guess.
fn decode_document(bytes: &[u8], kind: &str) -> Result<String> {
    // UTF-16, which is what "Save as Unicode" means on Windows.
    if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
        bail!(
            "this {kind} file is UTF-16 encoded. Re-save it as UTF-8 \
             (in Notepad: Save As, then set Encoding to UTF-8)."
        );
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    let text = std::str::from_utf8(bytes)
        .map_err(|e| anyhow!("a {kind} file must be UTF-8 text (invalid byte at offset {})", e.valid_up_to()))?;
    Ok(text.trim_start_matches('\u{FEFF}').to_string())
}

/// Say what is actually wrong with a document, in the words of someone who has
/// the file open in front of them.
fn explain_toml_error(error: toml::de::Error, text: &str, kind: &str) -> anyhow::Error {
    let head = text.trim_start();
    if head.starts_with('{') {
        return anyhow!(
            "this {kind} file is JSON. HERMES {kind} files are TOML - \
             `hermes studio template {}` writes a correct one to start from.",
            kind.trim_start_matches('.')
        );
    }
    if head.is_empty() {
        return anyhow!("this {kind} file is empty");
    }
    // Quote the offending line in full: the whole point is that the person
    // reading this can look at their file and see it.
    let detail = match error.span() {
        Some(span) => {
            let line_number = text[..span.start.min(text.len())].lines().count().max(1);
            let line = text.lines().nth(line_number - 1).unwrap_or("").trim_end();
            format!("\n         line {line_number}: {line}")
        }
        None => String::new(),
    };
    anyhow!(
        "this does not look like a HERMES {kind} file: {}{detail}",
        error.message()
    )
}

impl OriginFile {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = decode_document(bytes, ".origin")?;
        let origin: OriginFile =
            toml::from_str(&text).map_err(|e| explain_toml_error(e, &text, ".origin"))?;
        origin.validate()?;
        Ok(origin)
    }

    /// Reject anything we would not want to act on later. Cheap now, load
    /// bearing later: `id` becomes a filename, and the URLs are fetched.
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
             # This file points HERMES at the address updates come from. It says\n\
             # nothing about your disk - no install path, no folder name.\n\
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
    /// Other releases the studio still offers, so a user can look at what is
    /// available and pick one instead of always taking the newest.
    ///
    /// The latest release is described by the fields above and must **not**
    /// appear here - one release, one description, no field meaning two
    /// things. Everything in this list is covered by the same signature as the
    /// rest of the payload, so an older version is offered on the studio's
    /// authority, not the CDN's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<ReleaseEntry>>,
    #[serde(default)]
    pub requires_auth: bool,
}

/// One older release in a manifest's [`Manifest::versions`] catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseEntry {
    pub version: String,
    pub download_url: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_notes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platforms: Option<std::collections::BTreeMap<String, PlatformArtifact>>,
}

/// A release a user can actually choose, latest or otherwise.
///
/// Flattens the two shapes a release arrives in - the manifest's top-level
/// fields, or an entry in `versions` - so nothing downstream has to care which
/// one it came from.
#[derive(Debug, Clone)]
pub struct Release {
    pub version: semver::Version,
    pub is_latest: bool,
    pub download_url: String,
    pub checksum_sha256: String,
    pub size_bytes: u64,
    pub release_notes: Option<String>,
    pub platforms: Option<std::collections::BTreeMap<String, PlatformArtifact>>,
}

impl Release {
    /// The download for the platform we are running on.
    pub fn artifact(&self) -> Result<Artifact> {
        pick_artifact(
            &self.download_url,
            &self.checksum_sha256,
            self.size_bytes,
            self.platforms.as_ref(),
        )
    }

    pub fn display_notes(&self) -> Option<Vec<String>> {
        sanitize_notes(self.release_notes.as_deref())
    }
}

/// Pick the artifact for the running platform, or say there is no build.
///
/// A manifest that lists platforms but not *this* one is a hard error rather
/// than a silent fallback: quietly installing another platform's binary is
/// worse than saying there is no build.
fn pick_artifact(
    download_url: &str,
    checksum_sha256: &str,
    size_bytes: u64,
    platforms: Option<&std::collections::BTreeMap<String, PlatformArtifact>>,
) -> Result<Artifact> {
    let Some(platforms) = platforms else {
        return Ok(Artifact {
            download_url: download_url.to_string(),
            checksum_sha256: checksum_sha256.to_string(),
            size_bytes,
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

    /// Pick the artifact for the platform we are running on, for the latest
    /// release. Use [`Release::artifact`] when a specific version was chosen.
    pub fn artifact(&self) -> Result<Artifact> {
        pick_artifact(
            &self.download_url,
            &self.checksum_sha256,
            self.size_bytes,
            self.platforms.as_ref(),
        )
    }

    /// The newest release, described by the manifest's top-level fields.
    pub fn latest_release(&self) -> Result<Release> {
        Ok(Release {
            version: self.version()?,
            is_latest: true,
            download_url: self.download_url.clone(),
            checksum_sha256: self.checksum_sha256.clone(),
            size_bytes: self.size_bytes,
            release_notes: self.release_notes.clone(),
            platforms: self.platforms.clone(),
        })
    }

    /// Everything on offer, newest first - what `hermes versions` prints and
    /// what the interactive picker lists.
    pub fn releases(&self) -> Result<Vec<Release>> {
        let mut out = vec![self.latest_release()?];
        for entry in self.versions.iter().flatten() {
            out.push(Release {
                version: semver::Version::parse(&entry.version).with_context(|| {
                    format!("version '{}' in the catalogue is not semver", entry.version)
                })?,
                is_latest: false,
                download_url: entry.download_url.clone(),
                checksum_sha256: entry.checksum_sha256.clone(),
                size_bytes: entry.size_bytes,
                release_notes: entry.release_notes.clone(),
                platforms: entry.platforms.clone(),
            });
        }
        out.sort_by(|a, b| b.version.cmp(&a.version));
        Ok(out)
    }

    /// The release the user asked for by name.
    pub fn release(&self, want: &semver::Version) -> Result<Release> {
        let all = self.releases()?;
        all.iter()
            .find(|r| &r.version == want)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "this studio does not offer {want} (available: {})",
                    all.iter()
                        .map(|r| r.version.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
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
        validate_platforms(self.platforms.as_ref(), &self.latest_version)?;

        // The catalogue is chosen from, so every entry in it gets exactly the
        // scrutiny the latest release gets. An older release is still a
        // download this client will verify and install.
        if let Some(versions) = &self.versions {
            if versions.len() > MAX_CATALOGUE_ENTRIES {
                bail!(
                    "versions lists {} releases; the cap is {MAX_CATALOGUE_ENTRIES}",
                    versions.len()
                );
            }
            let mut seen = std::collections::BTreeSet::new();
            for entry in versions {
                let version = semver::Version::parse(&entry.version).with_context(|| {
                    format!("version '{}' in the catalogue is not semver", entry.version)
                })?;
                // One release, one description: the latest is the top-level
                // fields, and a duplicate here would make "which bytes?"
                // ambiguous for the version a user is most likely to pick.
                if entry.version == self.latest_version {
                    bail!(
                        "{} is both latest_version and a versions entry; list it once",
                        entry.version
                    );
                }
                if !seen.insert(version.clone()) {
                    bail!("versions lists {version} more than once");
                }
                require_secure_url(&entry.download_url, "versions download_url")?;
                if entry.checksum_sha256.len() != 64
                    || !entry.checksum_sha256.chars().all(|c| c.is_ascii_hexdigit())
                {
                    bail!("version {version} checksum_sha256 must be 64 hex characters");
                }
                if entry.size_bytes == 0 || entry.size_bytes > MAX_RELEASE_BYTES {
                    bail!("version {version} size_bytes is out of range");
                }
                if let Some(notes) = &entry.release_notes {
                    if notes.len() > MAX_RELEASE_NOTES_BYTES {
                        bail!(
                            "version {version} release_notes is {} bytes; the cap is \
                             {MAX_RELEASE_NOTES_BYTES}",
                            notes.len()
                        );
                    }
                }
                validate_platforms(entry.platforms.as_ref(), &entry.version)?;
            }
        }
        Ok(())
    }

    /// Release notes for the latest release, made safe to print.
    pub fn display_notes(&self) -> Option<Vec<String>> {
        sanitize_notes(self.release_notes.as_deref())
    }
}

/// Control characters (other than newlines) stripped, lines trimmed, length
/// bounded. Notes are studio text rendered into the user's terminal right
/// before a trust decision, so they do not get to move the cursor or repaint
/// the screen.
fn sanitize_notes(notes: Option<&str>) -> Option<Vec<String>> {
    let lines: Vec<String> = notes?
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

/// Notes are shown before a trust decision, so they are bounded like anything
/// else that crosses the wire.
pub const MAX_RELEASE_NOTES_BYTES: usize = 8 * 1024;
pub const MAX_RELEASE_NOTES_LINES: usize = 40;
/// How many older releases one manifest may offer. Generous for a real
/// project's history, small enough that the whole catalogue prints.
pub const MAX_CATALOGUE_ENTRIES: usize = 256;
/// Non-zero, and inside anything a real release could be: `size_bytes` bounds
/// the download, so a nonsense value would loosen that bound.
pub const MAX_RELEASE_BYTES: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB

/// Shared by the latest release and by every catalogue entry - the same map,
/// the same rules, checked in one place.
fn validate_platforms(
    platforms: Option<&std::collections::BTreeMap<String, PlatformArtifact>>,
    version: &str,
) -> Result<()> {
    let Some(platforms) = platforms else {
        return Ok(());
    };
    if platforms.is_empty() {
        bail!("platforms is present but empty (version {version})");
    }
    if platforms.len() > 32 {
        bail!(
            "version {version} lists {} platforms; the cap is 32",
            platforms.len()
        );
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
    Ok(())
}

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
    /// Ask the user where the software already lives instead of guessing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locate: Option<LocateRequest>,
}

/// A plan's request to be *told* where the software it patches is installed.
///
/// HERMES did not necessarily put it there. A game bought elsewhere, an editor
/// unzipped by hand years ago - the folder is something only the user knows,
/// and a plan that has to replace a file inside it has to ask.
///
/// This is the whole of what a plan may say: one line of prompt text and the
/// name of a file it expects to find in the folder. **The studio never names
/// the folder** - the user types it, HERMES checks it
/// (`consent::validate_install_choice`), and the ordinary permission prompt
/// then prints every granted path resolved against it. So a `locate` block
/// widens nothing. It moves the root the declared scope is measured from, and
/// the user sees the resulting absolute paths before approving them.
///
/// ```toml
/// [locate]
/// prompt = "Where is Starfall installed?"
/// expect = "bin/starfall.exe"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocateRequest {
    /// Shown above the prompt, sanitised like release notes are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// A relative path that must exist inside the folder the user picks.
    ///
    /// This is what turns "some folder" into "the right folder": a mistyped
    /// path, or a home directory picked in a hurry, is refused rather than
    /// patched. Studios should always set it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
}

/// The prompt is studio-authored text printed immediately before a trust
/// decision, so it is bounded like everything else that crosses the wire.
pub const MAX_LOCATE_PROMPT_BYTES: usize = 400;

impl LocateRequest {
    pub fn validate(&self) -> Result<()> {
        if let Some(expect) = &self.expect {
            crate::security::safepath::sanitize_relative(expect)
                .map_err(|e| anyhow!("locate.expect is unsafe: {e}"))?;
        }
        if let Some(prompt) = &self.prompt {
            if prompt.len() > MAX_LOCATE_PROMPT_BYTES {
                bail!(
                    "locate.prompt is {} bytes; the cap is {MAX_LOCATE_PROMPT_BYTES}",
                    prompt.len()
                );
            }
        }
        Ok(())
    }

    /// The studio's question, made safe to print: no control characters, so it
    /// cannot move the cursor or repaint the screen around the answer.
    pub fn display_prompt(&self) -> Option<String> {
        let clean: String = self
            .prompt
            .as_deref()?
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect();
        let clean = clean.trim().to_string();
        (!clean.is_empty()).then_some(clean)
    }
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
        let text = decode_document(bytes, ".foiled")?;
        let plan: FoiledPlan =
            toml::from_str(&text).map_err(|e| explain_toml_error(e, &text, ".foiled"))?;
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
        if let Some(locate) = &self.locate {
            locate.validate()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_toml(extra: &str) -> String {
        format!(
            "schema = \"{FOILED_SCHEMA}\"\n\
             origin_id = \"studio.game\"\n\
             version = \"1.0.0\"\n\
             [[scope]]\n\
             path = \"bin\"\n\
             [[steps]]\n\
             action = \"mkdir\"\n\
             path = \"bin\"\n\
             {extra}"
        )
    }

    #[test]
    fn a_plan_without_a_locate_block_still_parses() {
        let plan = FoiledPlan::parse(plan_toml("").as_bytes()).expect("parses");
        assert!(plan.locate.is_none());
    }

    #[test]
    fn locate_carries_a_prompt_and_an_expected_file() {
        let plan = FoiledPlan::parse(
            plan_toml("[locate]\nprompt = \"Where is Starfall installed?\"\nexpect = \"bin/starfall.exe\"\n")
                .as_bytes(),
        )
        .expect("parses");
        let locate = plan.locate.expect("locate block");
        assert_eq!(
            locate.display_prompt().as_deref(),
            Some("Where is Starfall installed?")
        );
        assert_eq!(locate.expect.as_deref(), Some("bin/starfall.exe"));
    }

    /// `expect` is joined onto a directory the user named, so it goes through
    /// the same sanitiser as everything else that comes off the wire.
    #[test]
    fn locate_refuses_a_traversing_expect() {
        let err = FoiledPlan::parse(
            plan_toml("[locate]\nexpect = \"../../etc/passwd\"\n").as_bytes(),
        )
        .expect_err("must be refused");
        assert!(format!("{err:#}").contains("locate.expect"), "{err:#}");
    }

    // -- reading a file someone actually has on disk -------------------------

    /// The one that bit a real user: a `.origin` saved or served with a UTF-8
    /// byte-order mark parsed as a TOML key called `\u{FEFF}schema` and failed
    /// at line 1, column 1, on a line that reads perfectly.
    #[test]
    fn a_byte_order_mark_does_not_break_a_valid_file() {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(ORIGIN_TEMPLATE.as_bytes());
        let origin = OriginFile::parse(&bytes).expect("a BOM must not matter");
        assert_eq!(origin.id, "moonforge.starfall");

        let mut plan_bytes = vec![0xEF, 0xBB, 0xBF];
        plan_bytes.extend_from_slice(FOILED_TEMPLATE.as_bytes());
        assert!(FoiledPlan::parse(&plan_bytes).is_ok());
    }

    #[test]
    fn a_utf16_file_says_so_instead_of_failing_at_column_one() {
        let bytes = [0xFF, 0xFE, b's', 0, b'c', 0];
        let err = OriginFile::parse(&bytes).expect_err("refused");
        let text = format!("{err:#}");
        assert!(text.contains("UTF-16"), "{text}");
        assert!(text.contains("UTF-8"), "{text}");
    }

    #[test]
    fn a_json_file_is_named_as_json() {
        let err = OriginFile::parse(br#"{"schema": "hermes.origin/v1"}"#).expect_err("refused");
        let text = format!("{err:#}");
        assert!(text.contains("is JSON"), "{text}");
        assert!(text.contains("studio template"), "{text}");
    }

    /// An error about a broken line should quote that line, so the person
    /// reading it can look at their file and see the problem.
    #[test]
    fn a_syntax_error_quotes_the_offending_line() {
        let broken = "schema = \"hermes.origin/v1\"\nid = moonforge.starfall\n";
        let err = OriginFile::parse(broken.as_bytes()).expect_err("refused");
        let text = format!("{err:#}");
        assert!(text.contains("line 2"), "{text}");
        assert!(text.contains("id = moonforge.starfall"), "{text}");
    }

    #[test]
    fn an_empty_file_says_it_is_empty() {
        let err = OriginFile::parse(b"   \n\n").expect_err("refused");
        assert!(format!("{err:#}").contains("empty"), "{err:#}");
    }

    // -- the version catalogue ----------------------------------------------

    fn manifest_json(versions: &str) -> String {
        format!(
            r#"{{
              "schema": "{MANIFEST_SCHEMA}",
              "origin_id": "studio.game",
              "latest_version": "2.0.0",
              "download_url": "https://cdn.example.com/2.0.0.zip",
              "checksum_sha256": "{}",
              "size_bytes": 2048,
              "issued_at": 1000,
              "release_notes": "- the new one"
              {versions}
            }}"#,
            "aa".repeat(32)
        )
    }

    fn catalogue() -> String {
        format!(
            r#", "versions": [
                 {{"version": "1.0.0",
                   "download_url": "https://cdn.example.com/1.0.0.zip",
                   "checksum_sha256": "{}", "size_bytes": 1024,
                   "release_notes": "- the old one"}},
                 {{"version": "1.5.0",
                   "download_url": "https://cdn.example.com/1.5.0.zip",
                   "checksum_sha256": "{}", "size_bytes": 1536}}
               ]"#,
            "bb".repeat(32),
            "cc".repeat(32)
        )
    }

    fn parse_manifest(json: &str) -> Manifest {
        let manifest: Manifest = serde_json::from_str(json).expect("deserialises");
        manifest.validate_shape().expect("valid");
        manifest
    }

    #[test]
    fn a_manifest_without_a_catalogue_offers_one_release() {
        let manifest = parse_manifest(&manifest_json(""));
        let releases = manifest.releases().unwrap();
        assert_eq!(releases.len(), 1);
        assert!(releases[0].is_latest);
        assert_eq!(releases[0].version.to_string(), "2.0.0");
    }

    #[test]
    fn the_catalogue_lists_every_release_newest_first() {
        let manifest = parse_manifest(&manifest_json(&catalogue()));
        let versions: Vec<_> = manifest
            .releases()
            .unwrap()
            .iter()
            .map(|r| r.version.to_string())
            .collect();
        assert_eq!(versions, ["2.0.0", "1.5.0", "1.0.0"]);
    }

    /// Each entry carries its own bytes, so choosing 1.0.0 must not download
    /// the 2.0.0 archive or check it against 2.0.0's digest.
    #[test]
    fn choosing_a_version_selects_that_versions_artifact() {
        let manifest = parse_manifest(&manifest_json(&catalogue()));
        let old = manifest
            .release(&semver::Version::parse("1.0.0").unwrap())
            .unwrap();
        assert!(!old.is_latest);
        let artifact = old.artifact().unwrap();
        assert_eq!(artifact.download_url, "https://cdn.example.com/1.0.0.zip");
        assert_eq!(artifact.checksum_sha256, "bb".repeat(32));
        assert_eq!(artifact.size_bytes, 1024);
        assert_eq!(
            old.display_notes().unwrap(),
            vec!["- the old one".to_string()]
        );
    }

    #[test]
    fn asking_for_a_version_that_is_not_offered_says_what_is() {
        let manifest = parse_manifest(&manifest_json(&catalogue()));
        let err = manifest
            .release(&semver::Version::parse("9.9.9").unwrap())
            .expect_err("not offered");
        let text = format!("{err:#}");
        assert!(text.contains("does not offer 9.9.9"), "{text}");
        assert!(text.contains("2.0.0, 1.5.0, 1.0.0"), "{text}");
    }

    /// One release, one description. A duplicate would make "which bytes?"
    /// ambiguous for exactly the version a user is most likely to pick.
    #[test]
    fn a_catalogue_may_not_repeat_the_latest_version() {
        let json = manifest_json(&format!(
            r#", "versions": [{{"version": "2.0.0",
                 "download_url": "https://cdn.example.com/other.zip",
                 "checksum_sha256": "{}", "size_bytes": 99}}]"#,
            "dd".repeat(32)
        ));
        let manifest: Manifest = serde_json::from_str(&json).unwrap();
        let err = manifest.validate_shape().expect_err("refused");
        assert!(format!("{err:#}").contains("list it once"), "{err:#}");
    }

    #[test]
    fn a_catalogue_may_not_repeat_itself() {
        let json = manifest_json(&format!(
            r#", "versions": [
                 {{"version": "1.0.0", "download_url": "https://cdn.example.com/a.zip",
                   "checksum_sha256": "{}", "size_bytes": 10}},
                 {{"version": "1.0.0", "download_url": "https://cdn.example.com/b.zip",
                   "checksum_sha256": "{}", "size_bytes": 10}}]"#,
            "dd".repeat(32),
            "ee".repeat(32)
        ));
        let manifest: Manifest = serde_json::from_str(&json).unwrap();
        assert!(manifest.validate_shape().is_err());
    }

    /// An older release is still something this client downloads and installs,
    /// so it gets the same scrutiny as the newest one.
    #[test]
    fn catalogue_entries_are_checked_like_the_latest_release() {
        for bad in [
            r#"{"version": "1.0.0", "download_url": "http://cdn.example.com/a.zip",
                "checksum_sha256": "AACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACC",
                "size_bytes": 10}"#,
            r#"{"version": "1.0.0", "download_url": "https://cdn.example.com/a.zip",
                "checksum_sha256": "short", "size_bytes": 10}"#,
            r#"{"version": "1.0.0", "download_url": "https://cdn.example.com/a.zip",
                "checksum_sha256": "AACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACC",
                "size_bytes": 0}"#,
            r#"{"version": "not-semver", "download_url": "https://cdn.example.com/a.zip",
                "checksum_sha256": "AACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACCAACC",
                "size_bytes": 10}"#,
        ] {
            let json = manifest_json(&format!(", \"versions\": [{bad}]"));
            let manifest: Manifest = serde_json::from_str(&json).expect("deserialises");
            assert!(
                manifest.validate_shape().is_err(),
                "should have been refused: {bad}"
            );
        }
    }

    /// A template a studio copies has to be a working document, not prose
    /// that looks like one.
    #[test]
    fn the_shipped_templates_parse() {
        let origin = OriginFile::parse(ORIGIN_TEMPLATE.as_bytes()).expect("origin template parses");
        assert_eq!(origin.id, "moonforge.starfall");
        assert_eq!(origin.publisher.as_deref(), Some("Moonforge Games"));

        let plan = FoiledPlan::parse(FOILED_TEMPLATE.as_bytes()).expect("foiled template parses");
        assert_eq!(plan.origin_id, origin.id);
        assert!(plan.steps.len() >= 3);
        // The [locate] block is commented out: most plans do not need it, and
        // one left on by accident would ask every user an odd question.
        assert!(plan.locate.is_none());
    }

    /// The whole point of the .origin format is that it is an address, not a
    /// location. Nothing in it may name a folder on the user's disk.
    #[test]
    fn the_origin_template_names_no_local_path() {
        for line in ORIGIN_TEMPLATE.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            assert!(
                !line.starts_with("install_dir"),
                "a .origin must not carry an install path: {line}"
            );
        }
    }

    /// The prompt is printed straight into the terminal right before a trust
    /// decision; it does not get to draw anything of its own.
    #[test]
    fn locate_prompt_cannot_paint_the_screen() {
        let locate = LocateRequest {
            prompt: Some("Where is it?\u{1b}[2J\u{1b}[HGranted!".into()),
            expect: None,
        };
        assert_eq!(
            locate.display_prompt().as_deref(),
            Some("Where is it?[2J[HGranted!")
        );
    }
}
