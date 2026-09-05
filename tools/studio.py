#!/usr/bin/env python3
"""Set up and ship a HERMES project without writing any of it by hand.

Two commands:

    python studio.py init         answer a few questions once
    python studio.py release      package, sign and print the publish commands

`init` makes your signing key, your `.origin` and a starter `update.foiled`,
and remembers the answers in `hermes-studio.json` so `release` needs no flags
afterwards.

`release` packages a folder, checksums it, writes the manifest payload, signs
it, verifies the result the way a user's CLI will, and tells you what to
upload. It also **carries the previous release forward into the `versions`
catalogue**, which is the part nobody wants to maintain by hand: ship three
times and your users can pick any of the three.

Nothing here reimplements any of the security-critical work. Every key, every
signature and every checksum comes from `hermes studio ...` itself, so this
script cannot disagree with the CLI that verifies its output.

    python studio.py init --id moonforge.starfall --name Starfall \\
        --repo moonforge/starfall

    python studio.py release --version 1.4.0 --from ./build --notes NOTES.md

THE SIGNING KEY NEVER LIVES IN YOUR PROJECT. It defaults to `~/.hermes-keys/`.
Anyone holding it can sign an update that every one of your users installs.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

CONFIG_NAME = "hermes-studio.json"
KEY_HOME = Path.home() / ".hermes-keys"
# Enough history to be useful, small enough that the whole list still prints.
DEFAULT_CATALOGUE_DEPTH = 10


# ---------------------------------------------------------------------------
# Finding the CLI
# ---------------------------------------------------------------------------

def find_hermes() -> str:
    """The `hermes` binary: on PATH, or built in this repository."""
    found = shutil.which("hermes")
    if found:
        return found
    local = Path(__file__).resolve().parent.parent / "target" / "release" / (
        "hermes.exe" if os.name == "nt" else "hermes")
    if local.exists():
        return str(local)
    raise SystemExit(
        "cannot find `hermes` on PATH.\n"
        "  Install it with `hermes install`, or build it with `cargo build --release`."
    )


HERMES = None  # resolved in main()


def hermes(*args, check=True):
    proc = subprocess.run([HERMES, *map(str, args)], capture_output=True, text=True)
    if check and proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(f"`hermes {args[0]} {args[1] if len(args) > 1 else ''}` failed")
    return proc


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def load_config(project: Path) -> dict:
    path = project / CONFIG_NAME
    if not path.exists():
        raise SystemExit(
            f"no {CONFIG_NAME} in {project}\n"
            f"  Run `python studio.py init` there first."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def save_config(project: Path, config: dict):
    (project / CONFIG_NAME).write_text(
        json.dumps(config, indent=2) + "\n", encoding="utf-8")


# Everything that must never reach a repository, and everything this script
# regenerates anyway. Kept in one place so `init` and the docs cannot drift.
IGNORE_RULES = [
    ("*.key", "signing keys - one of these lets anyone ship to all your users"),
    ("*.pem", None),
    ("keys/", None),
    (".hermes-keys/", None),
    ("dist/", "build output; `studio.py release` recreates it"),
]


def guard_gitignore(project: Path) -> None:
    """Make sure this project ignores signing keys before one can exist.

    Printed advice is not a safeguard - it scrolls past. A generated project
    gets a real `.gitignore` entry, and an existing one is appended to rather
    than replaced, so nobody's rules are lost.
    """
    path = project / ".gitignore"
    existing = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    present = {line.strip() for line in existing}
    missing = [(rule, why) for rule, why in IGNORE_RULES if rule not in present]
    if not missing:
        return

    block = []
    if existing and existing[-1].strip():
        block.append("")
    block.append("# HERMES - never commit a signing key.")
    for rule, why in missing:
        # Comments go on their own line. git only treats `#` as a comment at
        # the START of a line, so `*.key  # why` is a pattern containing
        # spaces and a hash - it matches nothing, and the .gitignore looks
        # protective while protecting nothing.
        if why:
            block.append(f"# {why}")
        block.append(rule)

    with path.open("a", encoding="utf-8") as f:
        if existing and not path.read_text(encoding="utf-8").endswith("\n"):
            f.write("\n")
        f.write("\n".join(block) + "\n")
    print(f"  {'Updated' if existing else 'Wrote'} .gitignore "
          f"({', '.join(rule for rule, _ in missing)})")


def warn_if_key_is_inside(project: Path, key_path: Path) -> None:
    """A key inside the project is one `git add -f` from being published."""
    try:
        inside = key_path.resolve().is_relative_to(project.resolve())
    except (AttributeError, ValueError, OSError):  # Python < 3.9 / odd paths
        inside = str(key_path.resolve()).startswith(str(project.resolve()))
    if not inside:
        return
    print()
    print("  " + "!" * 68)
    print("  Your signing key is INSIDE the project directory:")
    print(f"    {key_path}")
    print()
    print("  .gitignore covers it, but that is one `git add -f` or one archive")
    print(f"  away from being published. {KEY_HOME} is safer - nothing there")
    print("  can be committed by accident because it is not in a repository.")
    print("  " + "!" * 68)


def ask(question: str, default: str = "", required: bool = True) -> str:
    """Prompt with a default, falling back to it when there is nobody to ask.

    `isatty` is not enough on its own: a console can look interactive and still
    hand back EOF immediately, which is how this runs under CI and under the
    test harness. Catching that keeps the script scriptable - every prompt has
    a matching flag, so a non-interactive run is fully driven by arguments.
    """
    suffix = f" [{default}]" if default else ""
    while True:
        if not sys.stdin.isatty():
            return default
        try:
            answer = input(f"  {question}{suffix}: ").strip() or default
        except EOFError:
            print()
            return default
        if answer or not required:
            return answer
        print("    (required)")


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

def cmd_init(args):
    project = args.project.resolve()
    project.mkdir(parents=True, exist_ok=True)
    existing = project / CONFIG_NAME
    if existing.exists() and not args.force:
        raise SystemExit(f"{existing} already exists (use --force to redo it)")

    print(f"\n  Setting up a HERMES project in {project}\n")

    name = args.name or ask("Application name", project.name)
    default_id = re.sub(r"[^a-z0-9]+", "", name.lower()) or "app"
    origin_id = args.id or ask(
        "Origin id (permanent, lowercase, e.g. moonforge.starfall)",
        f"studio.{default_id}")
    publisher = args.publisher or ask("Publisher / studio name", "", required=False)
    repo = args.repo or ask(
        "GitHub repo for releases (owner/name), or blank for a custom URL",
        "", required=False)

    if repo:
        manifest_url = f"https://github.com/{repo}/releases/latest/download/manifest.json"
        homepage = args.homepage or f"https://github.com/{repo}"
    else:
        manifest_url = args.manifest_url or ask(
            "URL your signed manifest.json will live at")
        homepage = args.homepage or ask("Home page", "", required=False)

    requires_auth = args.requires_auth
    auth_url = args.auth_url or ""

    # ---- refuse to leave the project committable before the key exists -
    #
    # Written *first*, so there is no window in which a key exists in a
    # repository that does not yet ignore it.
    guard_gitignore(project)

    # ---- the key ------------------------------------------------------
    key_path = Path(args.key).expanduser() if args.key else KEY_HOME / f"{origin_id}.key"
    if key_path.exists():
        print(f"\n  Using the existing key at {key_path}")
    else:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        hermes("studio", "keygen", "--id", origin_id, "--out", key_path.parent)
        generated = key_path.parent / f"{origin_id}.key"
        if generated != key_path:
            generated.rename(key_path)
        print(f"\n  Signing key written to {key_path}")
        print("  BACK IT UP OFFLINE. Anyone holding it can sign an update that")
        print("  every one of your users installs, and losing it means you can")
        print("  never ship to them again.\n")
    warn_if_key_is_inside(project, key_path)

    # ---- the .origin --------------------------------------------------
    origin_path = project / f"{origin_id}.origin"
    new_origin = ["studio", "new-origin", "--key", key_path, "--name", name,
                  "--manifest-url", manifest_url, "--out", origin_path]
    if publisher:
        new_origin += ["--publisher", publisher]
    if homepage:
        new_origin += ["--homepage", homepage]
    if auth_url:
        new_origin += ["--auth-url", auth_url]
    if requires_auth:
        new_origin += ["--requires-auth"]
    if origin_path.exists():
        origin_path.unlink()
    hermes(*new_origin)
    print(f"  Wrote {origin_path.name} - this is what your users add.")

    # ---- a starter plan -----------------------------------------------
    plan_path = project / "update.foiled"
    if not plan_path.exists():
        hermes("studio", "template", "foiled", "--out", plan_path)
        text = plan_path.read_text(encoding="utf-8")
        text = text.replace('origin_id = "moonforge.starfall"',
                            f'origin_id = "{origin_id}"')
        plan_path.write_text(text, encoding="utf-8")
        print(f"  Wrote {plan_path.name} - edit it to say what your update installs.")
    else:
        print(f"  Kept the existing {plan_path.name}.")

    # ---- the folder that gets packaged --------------------------------
    #
    # `release` packages this, and refusing to run because it does not exist
    # is a terrible first experience. Make it, and say what belongs in it.
    build = project / "build"
    build.mkdir(exist_ok=True)
    readme = build / "README.txt"
    if not readme.exists() and not any(build.iterdir()):
        readme.write_text(
            "Everything in this folder is packaged into your release archive,\n"
            "keeping the layout you put it in.\n"
            "\n"
            "Your update.foiled reads files out of here by the paths its `copy`\n"
            "and `extract_zip` steps name. So if a step says\n"
            "\n"
            "    from = \"bin/app.exe\"\n"
            "\n"
            "then this folder needs bin/app.exe.\n"
            "\n"
            "Delete this file once you put something real here - it would\n"
            "otherwise be shipped to your users along with everything else.\n",
            encoding="utf-8")
        print(f"  Created {build.name}/ - put the files your update installs in it.")

    config = {
        "id": origin_id,
        "name": name,
        "publisher": publisher,
        "homepage": homepage,
        "repo": repo,
        "manifest_url": manifest_url,
        "key": str(key_path),
        "requires_auth": bool(requires_auth),
        "catalogue_depth": DEFAULT_CATALOGUE_DEPTH,
    }
    save_config(project, config)

    print(f"""
  Done. {CONFIG_NAME} remembers all of that.

  Next:
    1. Put the files your update installs into build/, in the layout they
       should have once installed.
    2. Edit {plan_path.name} so its steps name those files, and so the scope
       it asks for is what you want your users to approve.
    3. python studio.py release --version 1.0.0

  Step 2 is the one that matters: the starter plan still refers to the
  example's files, and `release` will tell you exactly which ones are
  missing rather than shipping a broken update.

  Your .gitignore already refuses *.key and dist/, so a signing key cannot
  be committed from here by accident. Keep it that way.
""")
    return 0


# ---------------------------------------------------------------------------
# release
# ---------------------------------------------------------------------------

def platform_key() -> str:
    """Must match `schema::platform_key()` on the Rust side."""
    import platform
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(
        platform.system(), platform.system().lower())
    arch = {"AMD64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64",
            "aarch64": "aarch64"}.get(platform.machine(), platform.machine().lower())
    return f"{os_name}-{arch}"


def set_plan_version(plan: Path, version: str):
    """Make the plan's version match the release.

    HERMES refuses an update whose plan disagrees with its signed manifest, so
    a forgotten bump here is a broken release. Only the first top-level
    `version =` is touched - anything after the first `[section]` belongs to
    something else.
    """
    lines = plan.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines):
        if line.lstrip().startswith("["):
            break
        if re.match(r'\s*version\s*=', line):
            current = line.split('"')[1] if '"' in line else ""
            if current != version:
                lines[i] = f'version   = "{version}"'
                plan.write_text("\n".join(lines) + "\n", encoding="utf-8")
                print(f"  {plan.name}: version {current or '(unset)'} -> {version}")
            return
    raise SystemExit(f"{plan} has no top-level `version =` line")


def missing_payload_paths(plan: Path, source: Path) -> list:
    """Files the plan reads out of the archive that the folder does not have.

    Only `copy.from` and `extract_zip.archive` are payload-side; every other
    path in a plan refers to the install tree on the user's machine, which
    obviously is not here. Catching this at release time matters because the
    alternative is finding out from a user whose update failed halfway.
    """
    import tomllib
    data = tomllib.loads(plan.read_text(encoding="utf-8"))
    wanted = []
    for step in data.get("steps", []):
        action = step.get("action")
        if action == "copy" and step.get("from"):
            wanted.append(step["from"])
        elif action == "extract_zip" and step.get("archive"):
            wanted.append(step["archive"])
    return [w for w in wanted if not (source / w).exists()]


def package(source: Path, plan: Path, archive: Path) -> None:
    """Zip the release: everything in `source`, plus the plan at the root."""
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(source.rglob("*")):
            if path.is_file():
                relative = path.relative_to(source).as_posix()
                if relative == "update.foiled":
                    continue  # added from `plan` below, so there is one copy
                z.write(path, relative)
        z.write(plan, "update.foiled")


def checksum(archive: Path):
    out = hermes("studio", "checksum", archive).stdout
    digest = out.split('"checksum_sha256": "')[1].split('"')[0]
    size = int(out.split('"size_bytes": ')[1].split("\n")[0].strip())
    return digest, size


def carry_forward(previous: dict, version: str, depth: int) -> list:
    """Turn the last release into the first entry of the version catalogue.

    This is the whole reason `versions` is maintainable. Each release pushes
    the one before it into the list, so a user can always go back to something
    that was actually published, and the studio never edits the list by hand.
    """
    if not previous or previous.get("latest_version") in (None, version):
        # Nothing to carry, or this is a re-run of the same version.
        return [v for v in previous.get("versions", []) if v.get("version") != version]

    entry = {
        "version": previous["latest_version"],
        "download_url": previous["download_url"],
        "checksum_sha256": previous["checksum_sha256"],
        "size_bytes": previous["size_bytes"],
    }
    if previous.get("release_notes"):
        entry["release_notes"] = previous["release_notes"]
    if previous.get("platforms"):
        entry["platforms"] = previous["platforms"]

    catalogue = [entry] + [
        v for v in previous.get("versions", [])
        if v.get("version") not in (version, entry["version"])
    ]
    return catalogue[:depth]


def cmd_release(args):
    project = args.project.resolve()
    config = load_config(project)
    dist = project / "dist"
    dist.mkdir(exist_ok=True)

    version = args.version or ask("Version to release", "")
    if not version:
        raise SystemExit("a version is required (--version 1.4.0)")

    source = (args.source or project / "build").resolve()
    if not source.is_dir():
        raise SystemExit(
            f"nothing to package: {source} does not exist.\n"
            f"  That folder is what gets zipped into your release. Create it and\n"
            f"  put the files your update installs in it, or point somewhere else\n"
            f"  with --from <folder>.")

    plan = args.plan or project / "update.foiled"
    if not plan.exists():
        raise SystemExit(f"no plan at {plan} - `studio.py init` writes a starter one")
    set_plan_version(plan, version)

    # The plan names files it expects to find in the archive. If they are not
    # in the folder being packaged, the update fails on every user's machine
    # rather than here - so it has to fail here.
    missing = missing_payload_paths(plan, source)
    if missing:
        listed = "\n".join(f"      {m}" for m in missing)
        raise SystemExit(
            f"{plan.name} installs files that {source} does not contain:\n{listed}\n\n"
            f"  Either put them there, or edit the steps in {plan.name} to match what\n"
            f"  you are actually shipping. A release missing them would fail partway\n"
            f"  through, on your users' machines.")

    # Read it back through the CLI, so an unshippable plan fails here rather
    # than in a user's terminal.
    inspected = hermes("inspect", plan, check=False)
    if inspected.returncode != 0:
        sys.stdout.write(inspected.stdout)
        sys.stderr.write(inspected.stderr)
        raise SystemExit("the plan is not valid - fix it before releasing")

    asset = f"{config['id']}-{version}-{platform_key()}.zip" if args.per_platform \
        else f"{config['id']}-{version}.zip"
    archive = dist / asset
    package(source, plan, archive)
    digest, size = checksum(archive)
    print(f"\n  packaged {archive.name}  ({size:,} bytes)")

    if config.get("repo"):
        base = args.base_url or \
            f"https://github.com/{config['repo']}/releases/download/v{version}"
    else:
        base = args.base_url or ask("Base URL the archive will be served from", "")
    if not base:
        raise SystemExit("a download base URL is required (--base-url)")
    base = base.rstrip("/")

    # ---- payload -------------------------------------------------------
    payload_path = dist / "payload.json"
    previous = {}
    if payload_path.exists():
        try:
            previous = json.loads(payload_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    payload = {
        "schema": "hermes.manifest/v1",
        "origin_id": config["id"],
        "latest_version": version,
        "download_url": f"{base}/{asset}",
        "checksum_sha256": digest,
        "size_bytes": size,
        "issued_at": int(time.time()),
    }

    notes = None
    if args.notes and Path(args.notes).exists():
        notes = Path(args.notes).read_text(encoding="utf-8").strip()
    elif previous.get("latest_version") == version:
        notes = previous.get("release_notes")
    if notes:
        payload["release_notes"] = notes

    if args.per_platform:
        # Re-running on another machine adds that platform to the same release.
        platforms = dict(previous.get("platforms", {})) \
            if previous.get("latest_version") == version else {}
        platforms[platform_key()] = {
            "download_url": f"{base}/{asset}",
            "checksum_sha256": digest,
            "size_bytes": size,
        }
        payload["platforms"] = platforms

    if not args.no_catalogue:
        catalogue = carry_forward(previous, version, config.get(
            "catalogue_depth", DEFAULT_CATALOGUE_DEPTH))
        if catalogue:
            payload["versions"] = catalogue

    if config.get("requires_auth"):
        payload["requires_auth"] = True

    payload_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # ---- sign and verify ----------------------------------------------
    manifest_path = dist / "manifest.json"
    hermes("studio", "sign", "--key", config["key"],
           "--payload", payload_path, "--out", manifest_path)

    origin_path = project / f"{config['id']}.origin"
    if origin_path.exists():
        verify = hermes("studio", "verify", "--origin", origin_path,
                        "--manifest", manifest_path, check=False)
        if verify.returncode != 0:
            sys.stdout.write(verify.stdout)
            sys.stderr.write(verify.stderr)
            raise SystemExit("the signed manifest does not verify against your .origin")
        print("  signature verified against " + origin_path.name)
        shutil.copy(origin_path, dist / origin_path.name)

    offered = [version] + [v["version"] for v in payload.get("versions", [])]
    print(f"  manifest offers: {', '.join(offered)}")

    if args.per_platform:
        print(f"  platforms: {', '.join(sorted(payload['platforms']))}")

    upload = f"dist/manifest.json dist/{origin_path.name} dist/{asset}" \
        if origin_path.exists() else f"dist/manifest.json dist/{asset}"
    if config.get("repo"):
        publish = (f"gh release create v{version} {upload} \\\n"
                   f"        --repo {config['repo']} --title \"{config['name']} {version}\"")
    else:
        publish = f"Upload {upload} to {base}/ and your manifest URL."

    print(f"""
  Ready in {dist}

    {publish}

  Upload the archive before anything points at it - a manifest naming a file
  that is not there yet is a broken update for anyone checking in between.
  `gh release create` uploads them together, so that is handled.

  Users who already added your .origin get it with:  hermes check
""")
    return 0


# ---------------------------------------------------------------------------

def main():
    global HERMES
    parser = argparse.ArgumentParser(
        description="Create and ship a HERMES project.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--project", type=Path, default=Path("."),
                        help="project directory (default: here)")
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="create the key, .origin and starter plan")
    init.add_argument("--id", help="origin id, e.g. moonforge.starfall")
    init.add_argument("--name", help="application name")
    init.add_argument("--publisher")
    init.add_argument("--homepage")
    init.add_argument("--repo", help="GitHub owner/name for releases")
    init.add_argument("--manifest-url", help="if you are not using GitHub")
    init.add_argument("--auth-url", help="your login page, if updates need an account")
    init.add_argument("--requires-auth", action="store_true")
    init.add_argument("--key", help=f"key file (default: {KEY_HOME}/<id>.key)")
    init.add_argument("--force", action="store_true", help="redo an existing project")
    init.set_defaults(func=cmd_init)

    rel = sub.add_parser("release", help="package, sign and print publish commands")
    rel.add_argument("--version", help="version to release, e.g. 1.4.0")
    rel.add_argument("--from", dest="source", type=Path,
                     help="folder holding the files to install (default: ./build)")
    rel.add_argument("--plan", type=Path, help="the .foiled (default: ./update.foiled)")
    rel.add_argument("--notes", help="file with this release's notes")
    rel.add_argument("--base-url", help="override where the archive is served from")
    rel.add_argument("--per-platform", action="store_true",
                     help="this build is platform-specific; add it to the platforms map")
    rel.add_argument("--no-catalogue", action="store_true",
                     help="do not carry older releases forward into `versions`")
    rel.set_defaults(func=cmd_release)

    args = parser.parse_args()
    HERMES = find_hermes()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
