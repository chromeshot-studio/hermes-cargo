#!/usr/bin/env python3
"""Run a throwaway studio on loopback so you can drive HERMES by hand.

    python tools/demo_studio.py            start the studio and register the app
    python tools/demo_studio.py --clean    unregister it and delete the files

It generates a signing key, packages a fake "Nebula Drift 1.1.0" release with a
.foiled plan and signed release notes, serves it over 127.0.0.1, and registers
the .origin in your real HERMES config so the app shows up when you run
`hermes`. A pretend 1.0.0 install is seeded first - with a save file to
preserve and retired content to delete - so an update visibly does something.

Nothing outside `target/demo` and one registry entry is touched, and --clean
removes both.
"""
import argparse
import http.server
import json
import os
import shutil
import socketserver
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "target" / "demo"
SERVE = DEMO / "serve"
INSTALL = DEMO / "NebulaDrift"
ORIGIN_ID = "hermes.demo"
APP_NAME = "Nebula Drift"


def find_hermes():
    """Prefer the installed binary, fall back to a build in this tree."""
    exe = "hermes.exe" if os.name == "nt" else "hermes"
    found = shutil.which("hermes")
    if found:
        return Path(found)
    for build in ("release", "debug"):
        candidate = ROOT / "target" / build / exe
        if candidate.exists():
            return candidate
    raise SystemExit("no hermes binary found - run `cargo build --release` first")


HERMES = find_hermes()


def run(*args, check=True):
    env = dict(os.environ)
    env["HERMES_ALLOW_INSECURE_HTTP"] = "1"   # loopback http, demo only
    proc = subprocess.run(
        [str(HERMES), *map(str, args)],
        capture_output=True, text=True, env=env, cwd=DEMO,
    )
    if check and proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"`hermes {args[0]}` failed with {proc.returncode}")
    return proc


def hermes_home():
    override = os.environ.get("HERMES_HOME")
    if override:
        return Path(override)
    if os.name == "nt":
        return Path(os.environ["APPDATA"]) / "Hermes"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return Path(xdg) / "hermes" if xdg else Path.home() / ".config" / "hermes"


FOILED = """schema    = "hermes.foiled/v1"
origin_id = "{origin_id}"
version   = "1.1.0"
base      = "clone"
notes     = "Nebula Drift 1.1.0 - the Deep Field update."

# The folders this update is allowed to touch. HERMES shows you this list and
# refuses any step that strays outside it.
[[scope]]
path      = "bin"
recursive = true
access    = "write"
reason    = "replace the game executable"

[[scope]]
path      = "saves"
recursive = true
access    = "read"
reason    = "carry your save files across"

[[scope]]
path      = "data"
recursive = true
access    = "delete"
reason    = "add new content and remove the retired starfield"

[[steps]]
action = "backup"
path   = "saves"

[[steps]]
action = "preserve"
path   = "saves"

[[steps]]
action = "copy"
from   = "bin/nebula.bin"
to     = "bin/nebula.bin"

[[steps]]
action  = "extract_zip"
archive = "content.zip"
dest    = "data"

[[steps]]
action    = "delete"
path      = "data/starfield_old.pak"
recursive = false
"""

RELEASE_NOTES = (
    "Deep Field update\n"
    "\n"
    "  - New sector: the Deep Field, with 12 hand-built stations\n"
    "  - Fixes the save corruption when quitting during a warp\n"
    "  - Rebalances late-game fuel costs\n"
    "  - Retires the old starfield renderer"
)


def build():
    shutil.rmtree(DEMO, ignore_errors=True)
    SERVE.mkdir(parents=True)
    keys = DEMO / "keys"
    keys.mkdir()

    print(f"  using {HERMES}")
    run("studio", "keygen", "--id", ORIGIN_ID, "--out", keys)
    key = keys / f"{ORIGIN_ID}.key"

    # ---- the pretend 1.0.0 that is already installed -------------------
    (INSTALL / "bin").mkdir(parents=True)
    (INSTALL / "saves").mkdir()
    (INSTALL / "data").mkdir()
    (INSTALL / "bin" / "nebula.bin").write_text("NEBULA DRIFT 1.0.0", encoding="utf-8")
    (INSTALL / "saves" / "commander.sav").write_text(
        "40 hours of hard-won progress", encoding="utf-8")
    (INSTALL / "data" / "starfield_old.pak").write_text(
        "the retired starfield renderer", encoding="utf-8")

    # ---- the 1.1.0 release archive -------------------------------------
    pkg = DEMO / "pkg"
    (pkg / "bin").mkdir(parents=True)
    (pkg / "bin" / "nebula.bin").write_text("NEBULA DRIFT 1.1.0", encoding="utf-8")
    (pkg / "update.foiled").write_text(FOILED.format(origin_id=ORIGIN_ID), encoding="utf-8")

    content = DEMO / "content"
    content.mkdir()
    (content / "deep_field.pak").write_text("12 hand-built stations", encoding="utf-8")
    with zipfile.ZipFile(pkg / "content.zip", "w", zipfile.ZIP_DEFLATED) as z:
        z.write(content / "deep_field.pak", "deep_field.pak")

    release = SERVE / "nebula-1.1.0.zip"
    with zipfile.ZipFile(release, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(pkg.rglob("*")):
            if path.is_file():
                z.write(path, path.relative_to(pkg).as_posix())

    checksum = run("studio", "checksum", release)
    digest = checksum.stdout.split('"checksum_sha256": "')[1].split('"')[0]
    size = int(checksum.stdout.split('"size_bytes": ')[1].split("\n")[0].strip())

    payload = {
        "schema": "hermes.manifest/v1",
        "origin_id": ORIGIN_ID,
        "latest_version": "1.1.0",
        "download_url": f"http://127.0.0.1:{PORT}/nebula-1.1.0.zip",
        "checksum_sha256": digest,
        "size_bytes": size,
        "issued_at": int(time.time()),
        "release_notes": RELEASE_NOTES,
    }
    payload_file = DEMO / "payload.json"
    payload_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    run("studio", "sign", "--key", key, "--payload", payload_file,
        "--out", SERVE / "manifest.json")

    # ---- the .origin the user would be given ---------------------------
    origin_file = DEMO / "nebula-drift.origin"
    run("studio", "new-origin", "--key", key, "--name", APP_NAME,
        "--manifest-url", f"http://127.0.0.1:{PORT}/manifest.json",
        "--out", origin_file)
    run("add", origin_file)

    # Tell HERMES the pretend 1.0.0 is already installed, so the update has
    # something real to preserve and delete. This is the ordinary state file.
    state_dir = hermes_home() / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / f"{ORIGIN_ID}.json").write_text(json.dumps({
        "installed_version": "1.0.0",
        "install_dir": str(INSTALL),
        "added_at": int(time.time()),
    }, indent=2), encoding="utf-8")

    return origin_file


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SERVE), **kwargs)

    def log_message(self, fmt, *args):
        print(f"  studio  {fmt % args}")


def clean():
    proc = run("remove", ORIGIN_ID, check=False)
    print("  " + (proc.stdout.strip() or proc.stderr.strip() or "not registered"))
    state = hermes_home() / "state" / f"{ORIGIN_ID}.json"
    if state.exists():
        state.unlink()
    shutil.rmtree(DEMO, ignore_errors=True)
    print(f"  removed {DEMO}")
    print("\n  Demo cleaned up.\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()

    global PORT
    PORT = args.port

    if args.clean:
        DEMO.mkdir(parents=True, exist_ok=True)
        clean()
        return 0

    print("\n  Building the demo studio...\n")
    origin_file = build()

    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", PORT), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    exports = (
        '$env:HERMES_ALLOW_INSECURE_HTTP = "1"'
        if os.name == "nt"
        else "export HERMES_ALLOW_INSECURE_HTTP=1"
    )
    print(f"""
  Studio running at http://127.0.0.1:{PORT}
  Registered "{APP_NAME}" ({ORIGIN_ID}) - pretending 1.0.0 is installed at
    {INSTALL}

  In ANOTHER terminal:

    {exports}
    hermes

  The demo serves plain http on loopback, which HERMES only allows with that
  variable set - that is the point of it.

  In the list:
    * arrow keys to select "{APP_NAME}"
    * c   check          -> "update -> 1.1.0"
    * enter              -> details and the signed release notes
    * u   update         -> the permission prompt; press y

  Afterwards, look at {INSTALL}:
    bin/nebula.bin        now says 1.1.0
    saves/commander.sav   untouched  (the plan declared read-only access)
    data/deep_field.pak   new
    data/starfield_old.pak deleted

  The .origin file, if you want to try a drag-and-drop into the terminal:
    {origin_file}

  Ctrl-C here to stop the studio, then:
    python tools/demo_studio.py --clean
""")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Studio stopped. Run with --clean to unregister the demo.\n")
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
