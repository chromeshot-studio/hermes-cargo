#!/usr/bin/env python3
"""End-to-end round trip for HERMES against a throwaway local "studio".

Plays every part: generates a studio key, builds a release archive with a
.foiled plan, signs a manifest, serves both over loopback HTTP, then drives the
real CLI through add -> login -> check -> update and asserts what landed on
disk.

Also runs the negative cases that matter: a tampered manifest, a Zip-Slip
archive, a plan that reaches outside its declared scope, a CSRF'd auth
callback, and an expired token.

    cargo build && python tools/e2e_test.py
"""
import base64
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import tomllib
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
EXE = ROOT / "target" / "debug" / ("hermes.exe" if os.name == "nt" else "hermes")
WORK = ROOT / "target" / "e2e"
PORT = 8099

PASS, FAIL = [], []
REQUESTS = []            # (path, Authorization header) seen by the studio
LOGIN_TOKEN = [""]       # what the studio's login page hands back
STATE_OVERRIDE = [None]  # set to forge the CSRF state parameter


def check(name, condition, detail=""):
    (PASS if condition else FAIL).append(name)
    suffix = ("  -> " + str(detail).strip()) if detail and not condition else ""
    print(f"  {'PASS' if condition else 'FAIL'}  {name}{suffix}")


def hermes(*args, expect=0, stdin=""):
    proc = subprocess.run(
        [str(EXE), *map(str, args)],
        capture_output=True, text=True, env=cli_env(), input=stdin, cwd=WORK,
    )
    if expect is not None and proc.returncode != expect:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(
            f"`hermes {' '.join(map(str, args))}` exited {proc.returncode}, expected {expect}"
        )
    return proc


def cli_env():
    env = dict(os.environ)
    env["HERMES_HOME"] = str(WORK / "home")
    env["HERMES_ALLOW_INSECURE_HTTP"] = "1"
    env["HERMES_NO_BROWSER"] = "1"
    return env


# ---------------------------------------------------------------------------
# The studio: a CDN and a login page, on one loopback port
# ---------------------------------------------------------------------------

class StudioHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the manifest/archives, and plays the studio's own login page."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WORK / "serve"), **kwargs)

    def do_GET(self):
        REQUESTS.append((self.path, self.headers.get("Authorization")))
        if self.path.startswith("/login"):
            query = parse_qs(urlparse(self.path).query)
            port = query.get("port", [""])[0]
            state = STATE_OVERRIDE[0] or query.get("state", [""])[0]
            # This is exactly what a studio's backend does after it has
            # authenticated the user itself: bounce back to the CLI.
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{port}/callback?token={LOGIN_TOKEN[0]}&state={state}",
            )
            self.end_headers()
            return
        super().do_GET()

    def log_message(self, *args):
        pass


def serve():
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), StudioHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def make_jwt(expires_in=3600, subject="patron-42"):
    """A structurally real JWT. The signature is opaque to HERMES by design:
    the studio is the party that verifies it."""
    def segment(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")
    header = segment({"alg": "HS256", "typ": "JWT"})
    payload = segment({
        "sub": subject,
        "iss": "https://studio.example",
        "tier": "supporter",
        "exp": int(time.time()) + expires_in,
    })
    return f"{header}.{payload}.c3R1ZGlvLXNpZ25hdHVyZQ"


def browser_visit(url):
    """Stand in for the user's browser: follow the studio's redirect into the
    CLI's localhost callback."""
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            return response.status, response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # the CLI may have closed the listener already
        return 0, str(e)


def run_login(token, state_override=None, timeout=30):
    """Drive `hermes login` with the harness acting as the browser."""
    LOGIN_TOKEN[0] = token
    STATE_OVERRIDE[0] = state_override
    proc = subprocess.Popen(
        [str(EXE), "login", "demo.game", "--yes"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env=cli_env(), cwd=WORK,
    )
    url, output = None, []
    deadline = time.time() + timeout
    while time.time() < deadline:
        line = proc.stdout.readline()
        if not line:
            break
        output.append(line)
        if "http://127.0.0.1" in line and "/login" in line:
            url = line.strip()
            break
    status, page = (0, "") if url is None else browser_visit(url)
    try:
        rest_out, rest_err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        rest_out, rest_err = proc.communicate()
    return proc.returncode, "".join(output) + rest_out + rest_err, url, status, page


# ---------------------------------------------------------------------------

def foiled_toml(version="1.1.0", extra_steps=""):
    """The .foiled plan, written the way a studio would hand-write it."""
    return f'''schema    = "hermes.foiled/v1"
origin_id = "demo.game"
version   = "{version}"
base      = "clone"
notes     = "Adds the Starfall expansion."

# Folders this plan may touch. The user is shown this list and has to approve
# it; a step touching anything outside it aborts the update.
[[scope]]
path      = "bin"
recursive = true
access    = "write"
reason    = "replace the game executable"

[[scope]]
path      = "saves"
recursive = true
access    = "read"
reason    = "keep your save files"

[[scope]]
path      = "data"
recursive = true
access    = "delete"
reason    = "install new content, remove retired content"

[[steps]]
action = "backup"
path   = "saves"

[[steps]]
action = "preserve"
path   = "saves"

[[steps]]
action = "copy"
from   = "bin/game.bin"
to     = "bin/game.bin"

[[steps]]
action  = "extract_zip"
archive = "content.zip"
dest    = "data"

[[steps]]
action    = "delete"
path      = "data/old.pak"
recursive = false
{extra_steps}'''


def zip_dir(src, dest, extra_entries=()):
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(src).as_posix())
        for name, content in extra_entries:
            z.writestr(name, content)


def sign(payload: dict, key: Path, out: Path):
    payload_file = WORK / "payload.json"
    payload_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    hermes("studio", "sign", "--key", key, "--payload", payload_file, "--out", out)


def sha_and_size(path):
    proc = hermes("studio", "checksum", path)
    digest = proc.stdout.split('"checksum_sha256": "')[1].split('"')[0]
    size = int(proc.stdout.split('"size_bytes": ')[1].split("\n")[0].strip())
    return digest, size


def main():
    if not EXE.exists():
        raise SystemExit(f"{EXE} not found - run `cargo build` first")
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "serve").mkdir(parents=True)
    (WORK / "keys").mkdir()
    serve_dir = WORK / "serve"

    print("\n== studio side ==")
    hermes("studio", "keygen", "--id", "demo.game", "--out", WORK / "keys")
    key = WORK / "keys" / "demo.game.key"
    check("keygen wrote a key file", key.exists())

    pkg = WORK / "pkg"
    (pkg / "bin").mkdir(parents=True)
    (pkg / "bin" / "game.bin").write_text("VERSION 1.1.0", encoding="utf-8")
    content = WORK / "content"
    content.mkdir()
    (content / "new.pak").write_text("new content", encoding="utf-8")
    zip_dir(content, pkg / "content.zip")

    (pkg / "update.foiled").write_text(foiled_toml(), encoding="utf-8")
    release = serve_dir / "release.zip"
    zip_dir(pkg, release)

    digest, size = sha_and_size(release)
    payload = {
        "schema": "hermes.manifest/v1",
        "origin_id": "demo.game",
        "latest_version": "1.1.0",
        "download_url": f"http://127.0.0.1:{PORT}/release.zip",
        "checksum_sha256": digest,
        "size_bytes": size,
        "issued_at": int(time.time()),
        # Studio-authored text that gets printed into the user's terminal right
        # before a trust decision - including, here, an ANSI escape that must
        # not survive to the screen.
        "release_notes": (
            "- Adds the Deep Field expansion\n"
            "- Fixes save corruption on exit\n"
            "\x1b[2J- Rebalances the endgame"
        ),
    }
    sign(payload, key, serve_dir / "manifest.json")
    check("signed manifest published", (serve_dir / "manifest.json").exists())

    hermes("studio", "new-origin", "--key", key, "--name", "Demo Game",
           "--manifest-url", f"http://127.0.0.1:{PORT}/manifest.json",
           "--auth-url", f"http://127.0.0.1:{PORT}/login",
           "--out", WORK / "demo.origin")
    origin_text = (WORK / "demo.origin").read_text(encoding="utf-8")
    origin_doc = tomllib.loads(origin_text)
    check("origin is TOML, not JSON",
          not origin_text.lstrip().startswith("{") and "public_key" in origin_text)
    check("origin pins the studio public key",
          origin_doc["public_key"] == json.loads(key.read_text(encoding="utf-8"))["public_key"])
    # A leftover JSON .origin from the old format must not silently parse.
    (WORK / "legacy.origin").write_text(json.dumps(origin_doc), encoding="utf-8")
    legacy = hermes("add", WORK / "legacy.origin", expect=None)
    check("a JSON .origin is rejected", legacy.returncode != 0,
          legacy.stdout + legacy.stderr)

    verify = hermes("studio", "verify", "--origin", WORK / "demo.origin",
                    "--manifest", serve_dir / "manifest.json")
    check("studio verify accepts its own manifest", "Signature OK" in verify.stdout)

    # ---- pre-existing v1.0.0 install ----------------------------------
    install = WORK / "home" / "apps" / "demo.game"
    (install / "bin").mkdir(parents=True)
    (install / "saves").mkdir()
    (install / "data").mkdir()
    (install / "bin" / "game.bin").write_text("VERSION 1.0.0", encoding="utf-8")
    (install / "saves" / "profile.sav").write_text("hard-won progress", encoding="utf-8")
    (install / "data" / "old.pak").write_text("retired content", encoding="utf-8")

    httpd = serve()
    try:
        print("\n== user side ==")
        added = hermes("add", WORK / "demo.origin")
        check("hermes add registers the origin", "Added Demo Game" in added.stdout)
        check("registry file written",
              (WORK / "home" / "origins" / "demo.game.toml").exists())

        hermes("add", f'"{WORK / "demo.origin"}"')
        check("quoted drag-and-drop path accepted", True)

        listed = hermes("list")
        check("hermes list shows the app", "demo.game" in listed.stdout)

        checked = hermes("check", "demo.game")
        check("check reports the available update",
              "1.1.0 available" in checked.stdout, checked.stdout)

        denied = hermes("update", "demo.game", expect=None)
        check("update without consent is refused",
              denied.returncode != 0 and "denying by default" in denied.stdout,
              f"rc={denied.returncode}")
        check("refusal left the old version in place",
              (install / "bin" / "game.bin").read_text(encoding="utf-8") == "VERSION 1.0.0")

        applied = hermes("update", "demo.game", "--yes")
        check("update applied", "installed into" in applied.stdout, applied.stdout)
        check("release notes shown with the permission request",
              "What's new in 1.1.0" in applied.stdout
              and "Deep Field expansion" in applied.stdout, applied.stdout)
        check("ansi escapes in release notes are stripped",
              "\x1b" not in applied.stdout and "Rebalances the endgame" in applied.stdout,
              repr(applied.stdout[-400:]))
        check("new executable installed",
              (install / "bin" / "game.bin").read_text(encoding="utf-8") == "VERSION 1.1.0")
        check("save file preserved",
              (install / "saves" / "profile.sav").read_text(encoding="utf-8") == "hard-won progress")
        check("new content extracted", (install / "data" / "new.pak").exists())
        check("retired content deleted", not (install / "data" / "old.pak").exists())
        check("backup kept outside staging",
              (WORK / "home" / "backups" / "demo.game" / "1.1.0" / "saves" / "profile.sav").exists())
        check("staging cleaned up",
              not any((WORK / "home" / "apps").glob(".staging/*")))
        state = json.loads((WORK / "home" / "state" / "demo.game.json").read_text(encoding="utf-8"))
        check("installed version recorded", state.get("installed_version") == "1.1.0")

        rerun = hermes("update", "demo.game", "--yes")
        check("re-running is a no-op", "already on 1.1.0" in rerun.stdout, rerun.stdout)

        # ---- Module 5: web-to-CLI login -------------------------------
        print("\n== studio login (localhost callback) ==")
        token_file = WORK / "home" / "tokens" / "demo.game.json"

        code, out, url, _, _ = run_login(make_jwt(), state_override="forged-state")
        check("login URL carries port and state",
              url is not None and "port=" in url and "state=" in url, url)
        check("forged state is rejected as CSRF",
              code == 2 and "state parameter" in out, f"rc={code} {out}")
        check("no token saved after a CSRF attempt", not token_file.exists())

        code, out, _, _, _ = run_login(make_jwt(expires_in=-60))
        check("expired token is refused", code != 0 and "expired" in out, f"rc={code} {out}")
        check("no token saved after an expired token", not token_file.exists())

        good_token = make_jwt()
        code, out, url, status, page = run_login(good_token)
        check("login completes", code == 0 and "Signed in to Demo Game" in out,
              f"rc={code} {out}")
        check("browser lands on the success page",
              status == 200 and "Signed in" in page, f"{status} {page[:120]}")
        check("token stored", token_file.exists())
        if token_file.exists():
            stored = json.loads(token_file.read_text(encoding="utf-8"))
            check("stored token matches what the studio issued",
                  stored["token"] == good_token)
            check("JWT expiry and subject parsed",
                  stored.get("expires_at", 0) > time.time() and stored.get("subject") == "patron-42",
                  stored)

        REQUESTS.clear()
        hermes("check", "demo.game")
        manifest_auth = [auth for path, auth in REQUESTS if path.endswith("manifest.json")]
        check("token is attached as a Bearer header on manifest requests",
              manifest_auth and manifest_auth[0] == f"Bearer {good_token}", manifest_auth)

        hermes("logout", "demo.game")
        check("logout removes the token", not token_file.exists())

        print("\n== attacks ==")
        # 1. Tampered manifest: flip the version, keep the signature.
        good = json.loads((serve_dir / "manifest.json").read_text(encoding="utf-8"))
        tampered = json.loads(json.dumps(good))
        tampered["payload"]["latest_version"] = "9.9.9"
        (serve_dir / "manifest.json").write_text(json.dumps(tampered), encoding="utf-8")
        out = hermes("check", "demo.game", expect=None)
        check("tampered manifest rejected",
              "SIGNATURE VERIFICATION FAILED" in out.stdout, out.stdout)

        # 2. Valid signature from the wrong key.
        hermes("studio", "keygen", "--id", "demo.game", "--out", WORK / "keys2")
        sign(payload | {"latest_version": "9.9.9"}, WORK / "keys2" / "demo.game.key",
             serve_dir / "manifest.json")
        out = hermes("check", "demo.game", expect=None)
        check("manifest signed by another key rejected",
              "SIGNATURE VERIFICATION FAILED" in out.stdout, out.stdout)

        # 3. Zip-Slip: a correctly signed archive containing ../escaped.txt
        evil = serve_dir / "evil.zip"
        zip_dir(pkg, evil, extra_entries=[("../escaped.txt", "pwned")])
        digest, size = sha_and_size(evil)
        sign(payload | {"latest_version": "1.2.0", "checksum_sha256": digest,
                        "size_bytes": size,
                        "download_url": f"http://127.0.0.1:{PORT}/evil.zip"},
             key, serve_dir / "manifest.json")
        out = hermes("update", "demo.game", "--yes", expect=None)
        check("zip-slip archive aborts the update",
              out.returncode == 2 and "traversal" in (out.stdout + out.stderr).lower(),
              (out.stdout + out.stderr))
        check("nothing escaped the install root",
              not (WORK / "home" / "apps" / "escaped.txt").exists()
              and not (install.parent / "escaped.txt").exists())
        check("install untouched after the abort",
              (install / "bin" / "game.bin").read_text(encoding="utf-8") == "VERSION 1.1.0")

        # 4. Corrupted download: signature fine, bytes do not match the checksum.
        sign(payload | {"latest_version": "1.3.0",
                        "checksum_sha256": "00" * 32,
                        "download_url": f"http://127.0.0.1:{PORT}/release.zip"},
             key, serve_dir / "manifest.json")
        out = hermes("update", "demo.game", "--yes", expect=None)
        check("checksum mismatch aborts before unpacking",
              out.returncode == 2 and "checksum mismatch" in (out.stdout + out.stderr),
              (out.stdout + out.stderr))

        # 5. A plan that reaches outside the folders it declared.
        overreaching_step = '''
[[steps]]
action    = "delete"
path      = "config/secrets.json"
recursive = false
'''
        (pkg / "update.foiled").write_text(
            foiled_toml(version="1.4.0", extra_steps=overreaching_step), encoding="utf-8")
        overreach = serve_dir / "overreach.zip"
        zip_dir(pkg, overreach)
        digest, size = sha_and_size(overreach)
        sign(payload | {"latest_version": "1.4.0", "checksum_sha256": digest,
                        "size_bytes": size,
                        "download_url": f"http://127.0.0.1:{PORT}/overreach.zip"},
             key, serve_dir / "manifest.json")
        out = hermes("update", "demo.game", "--yes", expect=None)
        check("undeclared folder access is refused",
              out.returncode == 2 and "outside the folder scope" in (out.stdout + out.stderr),
              (out.stdout + out.stderr))

        # 6. Rollback: an older version, correctly signed.
        sign(payload | {"latest_version": "0.9.0"}, key, serve_dir / "manifest.json")
        out = hermes("update", "demo.game", "--yes", "--force", expect=None)
        check("downgrade refused", "rollback refused" in (out.stdout + out.stderr).lower(),
              (out.stdout + out.stderr))
    finally:
        httpd.shutdown()

    print(f"\n  {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("  failed: " + ", ".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
