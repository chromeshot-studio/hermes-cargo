//! Module 4a - HTTP fetching that never buffers a payload in RAM.
//!
//! Two clients with deliberately different postures:
//!
//! * the **manifest** client is short-timeout and hard-capped at 1 MiB - a
//!   manifest is a small JSON document and anything else is an attack or a
//!   misconfiguration;
//! * the **download** client is given hours rather than seconds (a 40 GiB game
//!   is a legitimate download) with TCP keepalives to notice a dead peer, and
//!   a hard byte cap so a server cannot stream more than it promised.
//!
//! Both refuse to be redirected off https, and both cap what they will write.

use crate::error::SecurityError;
use crate::schema::{insecure_http_allowed, is_loopback_host};
use crate::security::crypto::HashingWriter;
use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// A manifest larger than this is not a manifest.
pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
/// Refuse a download that overruns its declared size by more than this.
const SIZE_SLACK_BYTES: u64 = 4096;

const USER_AGENT: &str = concat!("hermes/", env!("CARGO_PKG_VERSION"));

pub struct HttpClient {
    manifest: reqwest::blocking::Client,
    download: reqwest::blocking::Client,
}

fn redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= 5 {
            return attempt.error("too many redirects");
        }
        let url = attempt.url();
        let ok = url.scheme() == "https"
            || (insecure_http_allowed() && url.scheme() == "http" && is_loopback_host(url));
        if ok {
            attempt.follow()
        } else {
            // A downgrade to http would leak the bearer token and hand the
            // response to anyone on the path.
            attempt.error("refusing to follow a redirect off https")
        }
    })
}

impl HttpClient {
    pub fn new() -> Result<Self> {
        let manifest = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30))
            .redirect(redirect_policy())
            .https_only(!insecure_http_allowed())
            .build()
            .context("building the manifest HTTP client")?;

        let download = reqwest::blocking::Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(15))
            // Keepalives spot a dead peer; the blocking client has no
            // read-timeout knob, so the long total cap is the backstop for a
            // server that accepts the connection and then goes quiet.
            .tcp_keepalive(Duration::from_secs(30))
            .timeout(Duration::from_secs(12 * 60 * 60))
            .redirect(redirect_policy())
            .https_only(!insecure_http_allowed())
            .build()
            .context("building the download HTTP client")?;

        Ok(Self { manifest, download })
    }

    /// Fetch `manifest.json`, capped. The bytes are returned unparsed so the
    /// signature can be checked over exactly what came off the wire.
    pub fn fetch_manifest(&self, url: &str, token: Option<&str>) -> Result<Vec<u8>> {
        let mut req = self.manifest.get(url);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let response = req
            .send()
            .with_context(|| format!("fetching {url}"))?;

        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            bail!(
                "the studio rejected this request ({status}). Run `hermes login <id>` \
                 if this app requires an account."
            );
        }
        if !status.is_success() {
            bail!("{url} returned {status}");
        }
        if let Some(len) = response.content_length() {
            if len > MAX_MANIFEST_BYTES {
                return Err(SecurityError::ResponseTooLarge {
                    what: "manifest.json",
                    limit: MAX_MANIFEST_BYTES,
                }
                .into());
            }
        }

        let mut buf = Vec::new();
        let read = response
            .take(MAX_MANIFEST_BYTES + 1)
            .read_to_end(&mut buf)
            .context("reading the manifest body")?;
        if read as u64 > MAX_MANIFEST_BYTES {
            return Err(SecurityError::ResponseTooLarge {
                what: "manifest.json",
                limit: MAX_MANIFEST_BYTES,
            }
            .into());
        }
        Ok(buf)
    }

    /// Stream a download straight to `dest`, hashing as the bytes go past.
    ///
    /// Nothing larger than the 256 KiB copy buffer is ever resident: the
    /// response reader feeds a [`HashingWriter`] wrapping a `BufWriter<File>`,
    /// so network -> SHA-256 -> disk happens in a single pass. Returns the
    /// lowercase hex digest.
    pub fn stream_download(
        &self,
        url: &str,
        token: Option<&str>,
        dest: &Path,
        expected_size: u64,
        label: &str,
    ) -> Result<String> {
        let mut req = self.download.get(url);
        if let Some(token) = token {
            req = req.bearer_auth(token);
        }
        let mut response = req.send().with_context(|| format!("fetching {url}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!("{url} returned {status}");
        }

        if let Some(len) = response.content_length() {
            if len > expected_size.saturating_add(SIZE_SLACK_BYTES) {
                return Err(SecurityError::ResponseTooLarge {
                    what: "update archive",
                    limit: expected_size,
                }
                .into());
            }
        }

        let file = File::create(dest)
            .with_context(|| format!("creating {}", dest.display()))?;
        let mut writer = HashingWriter::new(BufWriter::with_capacity(1024 * 1024, file));

        let hard_cap = expected_size.saturating_add(SIZE_SLACK_BYTES);
        let mut buf = vec![0u8; 256 * 1024];
        let mut progress = Progress::new(label, expected_size);
        loop {
            let n = response.read(&mut buf).context("reading the download")?;
            if n == 0 {
                break;
            }
            if writer.bytes_written().saturating_add(n as u64) > hard_cap {
                progress.finish_line();
                return Err(SecurityError::ResponseTooLarge {
                    what: "update archive",
                    limit: expected_size,
                }
                .into());
            }
            writer.write_all(&buf[..n]).context("writing to staging")?;
            progress.update(writer.bytes_written());
        }
        writer.flush().context("flushing staged download")?;
        progress.finish_line();

        let (digest, written) = writer.finish();
        if written != expected_size {
            bail!(
                "download is {written} bytes but the signed manifest promised {expected_size}"
            );
        }
        Ok(digest)
    }
}

/// Throttled single-line progress. Silent when stdout is not a terminal so
/// logs stay clean.
struct Progress {
    label: String,
    total: u64,
    last: Instant,
    enabled: bool,
    printed: bool,
}

impl Progress {
    fn new(label: &str, total: u64) -> Self {
        use std::io::IsTerminal;
        Self {
            label: label.to_string(),
            total,
            last: Instant::now() - Duration::from_secs(1),
            enabled: std::io::stdout().is_terminal(),
            printed: false,
        }
    }

    fn update(&mut self, done: u64) {
        if !self.enabled || self.last.elapsed() < Duration::from_millis(200) {
            return;
        }
        self.last = Instant::now();
        self.printed = true;
        let pct = if self.total > 0 {
            (done as f64 / self.total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        print!(
            "\r  {} {:>5.1}%  {} / {}   ",
            self.label,
            pct,
            human_bytes(done),
            human_bytes(self.total)
        );
        let _ = std::io::stdout().flush();
    }

    fn finish_line(&mut self) {
        if self.enabled && self.printed {
            println!();
        }
    }
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
