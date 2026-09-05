//! Module 5 - studio-hosted web auth over a localhost callback.
//!
//! HERMES hosts no identity service and holds no client secret. The studio's
//! own website does the login (Patreon, Steam, itch.io, a password form - it
//! never matters here), mints a JWT, and hands it back through the loopback
//! interface:
//!
//! ```text
//!   hermes login starfall
//!        |
//!        |-- bind 127.0.0.1:8080, mint a random `state`
//!        |-- open  https://studio.example/hermes/login?port=8080&state=...
//!        |                                                   |
//!        |                          (the studio authenticates the user)
//!        |                                                   |
//!        '-- GET http://127.0.0.1:8080/callback?token=<JWT>&state=...
//!             verify state -> store token 0600 -> shut the server down
//! ```
//!
//! The token is opaque to HERMES: it is the studio's credential for the
//! studio's own CDN, and HERMES only ever replays it as a `Bearer` header to
//! the manifest host named in the `.origin` file. The `state` parameter is what
//! stops any other page on the machine from POSTing a token of its choosing
//! into the CLI.

use crate::paths;
use crate::schema::OriginFile;
use crate::security::consent;
use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{Duration, Instant};

/// The port the spec asks for; we fall back if it is taken.
const PREFERRED_PORT: u16 = 8080;
const PORT_FALLBACKS: &[u16] = &[8080, 8081, 8082, 8090, 9080];
/// How long the user gets to finish logging in.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(180);
const MAX_TOKEN_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub origin_id: String,
    pub token: String,
    pub obtained_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

impl StoredToken {
    pub fn is_expired(&self, now: i64) -> bool {
        self.expires_at.map(|e| now >= e).unwrap_or(false)
    }
}

fn token_path(origin_id: &str) -> Result<std::path::PathBuf> {
    crate::schema::validate_id(origin_id)?;
    Ok(paths::tokens_dir()?.join(format!("{origin_id}.json")))
}

pub fn load_token(origin_id: &str) -> Result<Option<StoredToken>> {
    let path = token_path(origin_id)?;
    let Ok(bytes) = fs::read(&path) else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

/// The `Bearer` value to attach to this origin's requests, if any is valid.
pub fn bearer_for(origin: &OriginFile) -> Result<Option<String>> {
    let Some(stored) = load_token(&origin.id)? else {
        return Ok(None);
    };
    if stored.is_expired(paths::now_unix()) {
        eprintln!(
            "  note: your session for '{}' has expired - run `hermes login {}`",
            origin.name, origin.id
        );
        return Ok(None);
    }
    Ok(Some(stored.token))
}

pub fn logout(origin_id: &str) -> Result<bool> {
    let path = token_path(origin_id)?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        return Ok(true);
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// The login flow
// ---------------------------------------------------------------------------

pub fn login(origin: &OriginFile) -> Result<StoredToken> {
    let auth_url = origin
        .studio_auth_url
        .as_deref()
        .ok_or_else(|| anyhow!("'{}' does not publish a studio_auth_url", origin.name))?;
    // Re-validate: the .origin may have been edited on disk since it was added.
    let base = crate::schema::require_secure_url(auth_url, "studio_auth_url")?;

    let (server, port) = bind_callback_server()?;
    let state = random_state();

    let mut url = base.clone();
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("port", &port.to_string());
        query.append_pair("state", &state);
        query.append_pair("client", "hermes");
        query.append_pair("redirect_uri", &format!("http://127.0.0.1:{port}/callback"));
    }

    println!("\n  Signing in to {}", origin.name);
    println!("  Opening your browser at:\n    {url}");
    println!("  Waiting for the studio to send the token back to 127.0.0.1:{port} ...");
    println!("  (press Ctrl-C to cancel)\n");

    // Headless boxes, SSH sessions and test harnesses have no browser to open;
    // the flow is identical, the user (or the harness) just follows the URL.
    let suppress_browser = matches!(
        std::env::var("HERMES_NO_BROWSER").as_deref(),
        Ok("1") | Ok("true")
    );
    if suppress_browser {
        println!("  HERMES_NO_BROWSER is set - open the URL above yourself.");
    } else if webbrowser::open(url.as_str()).is_err() {
        println!("  Could not open a browser automatically - paste the URL above into one.");
    }

    let deadline = Instant::now() + LOGIN_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            bail!("timed out after {} seconds waiting for the studio callback", LOGIN_TIMEOUT.as_secs());
        }
        let request = match server.recv_timeout(Duration::from_millis(500)) {
            Ok(Some(req)) => req,
            Ok(None) => continue,
            Err(e) => bail!("the local callback server failed: {e}"),
        };

        // Everything we serve is on loopback and is thrown away immediately
        // afterwards; the server exists for exactly one request.
        let raw_url = request.url().to_string();
        let parsed = url::Url::parse(&format!("http://127.0.0.1:{port}{raw_url}"))
            .unwrap_or_else(|_| url::Url::parse("http://127.0.0.1/").unwrap());

        if parsed.path() != "/callback" {
            let _ = request.respond(html_response(404, PAGE_NOT_FOUND));
            continue;
        }

        let mut token = None;
        let mut got_state = None;
        let mut studio_error = None;
        for (key, value) in parsed.query_pairs() {
            match key.as_ref() {
                "token" | "access_token" => token = Some(value.into_owned()),
                "state" => got_state = Some(value.into_owned()),
                "error" | "error_description" => studio_error = Some(value.into_owned()),
                _ => {}
            }
        }

        if let Some(message) = studio_error {
            let safe = sanitize_for_display(&message);
            let _ = request.respond(html_response(400, &page_failed(&safe)));
            bail!("the studio reported a login failure: {safe}");
        }

        // CSRF: only the browser tab we opened knows this value.
        if got_state.as_deref().map(|s| constant_time_eq(s, &state)) != Some(true) {
            let _ = request.respond(html_response(400, &page_failed("state mismatch")));
            return Err(crate::error::SecurityError::StateMismatch.into());
        }

        let Some(token) = token else {
            let _ = request.respond(html_response(400, &page_failed("no token in the callback")));
            bail!("the studio's callback carried no token");
        };

        let stored = match validate_and_store(origin, &token) {
            Ok(stored) => stored,
            Err(e) => {
                let _ = request.respond(html_response(400, &page_failed("malformed token")));
                return Err(e);
            }
        };

        let _ = request.respond(html_response(200, &page_ok(&origin.name)));
        // `server` drops here: the listener closes as soon as we return.
        println!("  Signed in to {}.", origin.name);
        if let Some(exp) = stored.expires_at {
            println!("  Session valid for {} more minutes.", (exp - paths::now_unix()).max(0) / 60);
        }
        return Ok(stored);
    }
}

/// Bind the callback listener, preferring :8080 as the spec describes.
fn bind_callback_server() -> Result<(tiny_http::Server, u16)> {
    for port in PORT_FALLBACKS {
        if let Ok(server) = tiny_http::Server::http(("127.0.0.1", *port)) {
            return Ok((server, *port));
        }
        if *port == PREFERRED_PORT {
            eprintln!("  note: 127.0.0.1:{PREFERRED_PORT} is busy, trying another port");
        }
    }
    // Last resort: let the OS pick. The studio is told the port anyway.
    let server = tiny_http::Server::http(("127.0.0.1", 0u16))
        .map_err(|e| anyhow!("cannot bind a localhost callback server: {e}"))?;
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .ok_or_else(|| anyhow!("callback server bound to a non-IP address"))?;
    Ok((server, port))
}

fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------
// Token handling
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JwtClaims {
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

/// Structural checks only.
///
/// HERMES cannot verify the JWT's signature and must not pretend to: the key
/// belongs to the studio, and the studio is the party that will verify it. What
/// we do check is that the thing is a sane bearer credential, that it is not
/// already expired, and that it is safe to put in a header.
fn validate_and_store(origin: &OriginFile, token: &str) -> Result<StoredToken> {
    let token = token.trim();
    if token.is_empty() || token.len() > MAX_TOKEN_BYTES {
        return Err(crate::error::SecurityError::MalformedToken(format!(
            "token must be 1-{MAX_TOKEN_BYTES} bytes"
        ))
        .into());
    }
    // A header value cannot contain control characters or non-ASCII.
    if !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(crate::error::SecurityError::MalformedToken(
            "token contains characters that are not valid in an HTTP header".into(),
        )
        .into());
    }

    let now = paths::now_unix();
    let mut stored = StoredToken {
        origin_id: origin.id.clone(),
        token: token.to_string(),
        obtained_at: now,
        expires_at: None,
        issuer: None,
        subject: None,
    };

    // Opaque tokens are allowed; JWTs give us an expiry to respect.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3 {
        if let Ok(payload) = URL_SAFE_NO_PAD.decode(parts[1]) {
            if let Ok(claims) = serde_json::from_slice::<JwtClaims>(&payload) {
                if let Some(exp) = claims.exp {
                    if exp <= now {
                        return Err(crate::error::SecurityError::MalformedToken(
                            "the studio issued an already-expired token".into(),
                        )
                        .into());
                    }
                    stored.expires_at = Some(exp);
                }
                stored.issuer = claims.iss;
                stored.subject = claims.sub;
            }
        }
    }

    let path = token_path(&origin.id)?;
    let json = serde_json::to_vec_pretty(&stored)?;
    paths::write_private_file(&path, &json)?;
    Ok(stored)
}

/// Strip anything that could scramble a terminal or an HTML page.
fn sanitize_for_display(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '<' | '>' | '&' | '"' | '\'' => ' ',
            other => other,
        })
        .take(200)
        .collect()
}

/// Ask before replacing a session that is still valid.
pub fn confirm_relogin(origin: &OriginFile, assume_yes: bool) -> Result<bool> {
    if let Some(existing) = load_token(&origin.id)? {
        if !existing.is_expired(paths::now_unix()) {
            let question = format!(
                "  You already have a valid session for '{}'. Sign in again?",
                origin.name
            );
            return Ok(consent::confirm(&question, assume_yes));
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// The pages the browser lands on
// ---------------------------------------------------------------------------

fn html_response(status: u16, body: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let mut response = tiny_http::Response::from_string(body).with_status_code(status);
    if let Ok(header) = tiny_http::Header::from_bytes(
        &b"Content-Type"[..],
        &b"text/html; charset=utf-8"[..],
    ) {
        response.add_header(header);
    }
    // Nothing here should ever be cached or framed.
    for (name, value) in [
        (&b"Cache-Control"[..], &b"no-store"[..]),
        (&b"X-Frame-Options"[..], &b"DENY"[..]),
        (&b"Referrer-Policy"[..], &b"no-referrer"[..]),
    ] {
        if let Ok(header) = tiny_http::Header::from_bytes(name, value) {
            response.add_header(header);
        }
    }
    response
}

const PAGE_NOT_FOUND: &str = "<!doctype html><title>HERMES</title><p>Not found.";

fn page_shell(title: &str, heading: &str, message: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title>\
<style>body{{background:#171717;color:#d6d6d6;font:16px/1.6 system-ui,sans-serif;\
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}\
main{{max-width:26rem;text-align:center}}h1{{font-size:1.3rem;letter-spacing:.02em;margin:0 0 .5rem}}\
p{{color:#999;margin:0}}</style></head><body><main><h1>{heading}</h1><p>{message}</p></main></body></html>"
    )
}

fn page_ok(app: &str) -> String {
    page_shell(
        "Signed in - HERMES",
        &format!("Signed in to {}", sanitize_for_display(app)),
        "You can close this tab and return to your terminal.",
    )
}

fn page_failed(reason: &str) -> String {
    page_shell(
        "Sign-in failed - HERMES",
        "Sign-in failed",
        &format!("{reason}. Nothing was saved; return to your terminal and try again."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_comparison_is_length_safe() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
    }

    #[test]
    fn display_sanitizer_strips_markup_and_controls() {
        let out = sanitize_for_display("<script>alert(1)</script>\n\u{7}bad");
        assert!(!out.contains('<'));
        assert!(!out.contains('\n'));
    }

    #[test]
    fn random_state_is_unique_and_long() {
        let a = random_state();
        let b = random_state();
        assert_ne!(a, b);
        assert!(a.len() >= 40);
    }
}
