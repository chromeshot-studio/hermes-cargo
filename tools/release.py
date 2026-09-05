#!/usr/bin/env python3
"""Cut a HERMES release that HERMES itself can install.

    python tools/release.py --version 0.2.0

Builds the release binary for *this* platform, packages it, signs a manifest,
and writes everything to `dist/`. Run it once per platform you ship - the
`platforms` map in the payload accumulates, so building on Windows and then on
Linux produces one manifest covering both.

    dist/
      hermes-0.2.0-windows-x86_64.zip
      payload.json      the manifest body, re-signed on every run
      manifest.json     <- upload this
      hermes.origin     <- commit this; users add it by hand

Then:

    gh release create v0.2.0 dist/manifest.json dist/hermes-0.2.0-*.zip \\
        --title "HERMES 0.2.0" --notes-file dist/NOTES.md

GitHub's `releases/latest/download/manifest.json` always resolves to the newest
release, which is what the .origin points at.

THE SIGNING KEY NEVER LIVES IN THIS REPOSITORY. It defaults to a path in your
home directory and `.gitignore` refuses `*.key` as a second line of defence.
Anyone holding it can sign an update that every HERMES user installs.
"""
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
DEFAULT_KEY = Path.home() / ".hermes-keys" / "chromeshot.hermes.key"
ORIGIN_ID = "chromeshot.hermes"
APP_NAME = "HERMES"


def platform_key():
    """Must match `schema::platform_key()` in the Rust side."""
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(
        platform.system(), platform.system().lower())
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64",
            "aarch64": "aarch64"}.get(platform.machine(), platform.machine().lower())
    return f"{os_name}-{arch}"


def binary_name():
    return "hermes.exe" if os.name == "nt" else "hermes"


def hermes(*args, check=True):
    """Run the freshly built binary for its studio tooling."""
    exe = ROOT / "target" / "release" / binary_name()
    proc = subprocess.run([str(exe), *map(str, args)],
                          capture_output=True, text=True, cwd=ROOT)
    if check and proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"`hermes {args[0]}` failed")
    return proc


def ensure_key(key_path: Path):
    if key_path.exists():
        return
    print(f"\n  No signing key at {key_path}")
    print("  Generating one now. This key IS the trust root for every HERMES user.\n")
    key_path.parent.mkdir(parents=True, exist_ok=True)
    hermes("studio", "keygen", "--id", ORIGIN_ID, "--out", key_path.parent)
    generated = key_path.parent / f"{ORIGIN_ID}.key"
    if generated != key_path:
        generated.rename(key_path)
    print(f"  Wrote {key_path}")
    print("  Back it up somewhere offline. Losing it means you can never ship")
    print("  another update to anyone who already added your .origin.\n")


def cargo_version():
    for line in (ROOT / "Cargo.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version ="):
            return line.split('"')[1]
    raise SystemExit("could not read version from Cargo.toml")


def set_cargo_version(version):
    path = ROOT / "Cargo.toml"
    lines = path.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.startswith("version ="):
            lines[i] = f'version = "{version}"'
            break
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", help="release version (default: Cargo.toml)")
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY)
    parser.add_argument("--repo", default="chromeshot-studio/hermes")
    parser.add_argument("--notes", type=Path, help="file with the release notes")
    parser.add_argument("--base-url", help="override the download base (for testing)")
    args = parser.parse_args()

    version = args.version or cargo_version()
    if args.version and args.version != cargo_version():
        set_cargo_version(args.version)
        print(f"  Cargo.toml version -> {version}")

    DIST.mkdir(exist_ok=True)
    print(f"\n  Building HERMES {version} for {platform_key()}...\n")
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True)

    ensure_key(args.key)

    # ---- package ------------------------------------------------------
    asset = f"hermes-{version}-{platform_key()}.zip"
    archive = DIST / asset
    binary = ROOT / "target" / "release" / binary_name()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(binary, binary_name())
        z.write(ROOT / "README.md", "README.md")
        z.write(ROOT / "LICENSE", "LICENSE")
    print(f"  packaged {archive.name}")

    checksum = hermes("studio", "checksum", archive)
    digest = checksum.stdout.split('"checksum_sha256": "')[1].split('"')[0]
    size = int(checksum.stdout.split('"size_bytes": ')[1].split("\n")[0].strip())

    base = args.base_url or f"https://github.com/{args.repo}/releases/download/v{version}"

    # ---- payload, merging any platform built earlier -------------------
    payload_path = DIST / "payload.json"
    previous = {}
    if payload_path.exists():
        try:
            old = json.loads(payload_path.read_text(encoding="utf-8"))
            if old.get("latest_version") == version:
                previous = old.get("platforms", {})
        except json.JSONDecodeError:
            pass

    platforms = dict(previous)
    platforms[platform_key()] = {
        "download_url": f"{base}/{asset}",
        "checksum_sha256": digest,
        "size_bytes": size,
    }

    notes = None
    if args.notes and args.notes.exists():
        notes = args.notes.read_text(encoding="utf-8").strip()

    payload = {
        "schema": "hermes.manifest/v1",
        "origin_id": ORIGIN_ID,
        "latest_version": version,
        # The top-level fields are the fallback for clients with no entry in
        # the platforms map; point them at this build so they are never bogus.
        "download_url": f"{base}/{asset}",
        "checksum_sha256": digest,
        "size_bytes": size,
        "issued_at": int(time.time()),
        "platforms": platforms,
    }
    if notes:
        payload["release_notes"] = notes
    payload_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    hermes("studio", "sign", "--key", args.key,
           "--payload", payload_path, "--out", DIST / "manifest.json")
    print(f"  signed manifest.json  ({len(platforms)} platform(s): "
          f"{', '.join(sorted(platforms))})")

    # ---- the .origin users add ----------------------------------------
    origin_path = DIST / "hermes.origin"
    manifest_url = (f"{args.base_url}/manifest.json" if args.base_url
                    else f"https://github.com/{args.repo}/releases/latest/download/manifest.json")
    hermes("studio", "new-origin", "--key", args.key, "--name", APP_NAME,
           "--manifest-url", manifest_url, "--out", origin_path)
    shutil.copy(origin_path, ROOT / "hermes.origin")
    print(f"  wrote {origin_path.name} (also copied to the repository root)")

    verify = hermes("studio", "verify", "--origin", origin_path,
                    "--manifest", DIST / "manifest.json")
    print("  " + verify.stdout.strip().splitlines()[0])

    print(f"""
  Ready. To publish:

    git add hermes.origin Cargo.toml Cargo.lock
    git commit -m "Release {version}"
    git tag v{version} && git push --tags && git push

    gh release create v{version} \\
        dist/manifest.json {archive.relative_to(ROOT).as_posix()} \\
        --title "HERMES {version}"

  Users then run, once:

    hermes add hermes.origin
    hermes self-update
""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
