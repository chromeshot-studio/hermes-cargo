# HERMES

A decentralized CLI updater. **The author of this tool hosts nothing.**

There is no HERMES server, no account system, no package index, and no default
signing key compiled into the binary. Studios host their own files, their own
manifests and their own login pages. A user drags a `.origin` file into their
terminal, and *that file* — sitting on their disk, under their control — becomes
the trust root for everything that follows.

```
  hermes add ./starfall.origin     register a studio's software
  hermes login starfall            sign in on the studio's own website
  hermes check                     verify manifests, report versions
  hermes update starfall           download, verify, ask, swap
```

## How the trust works

```
  .origin  (on your disk, pinned by you)
     │  pins an Ed25519 public key
     ▼
  manifest.json  (the studio's CDN — untrusted transport)
     │  signature must verify against that key
     │  carries a SHA-256 of the release
     ▼
  update.zip  (the studio's CDN — untrusted transport)
     │  hashed while streaming to disk; unpacked only if it matches
     ▼
  update.foiled  (inside the archive)
     │  declares the exact folders it wants
     │  you press Y, or nothing happens
     ▼
  atomic swap into place
```

TLS is transport hygiene, not trust. A hostile CDN, a hostile mirror, or
anybody who can mint a certificate still cannot produce a manifest that
verifies against the key in your `.origin`, and cannot alter a byte of the
archive without breaking the checksum.

## Building

You need a Rust toolchain (**1.74+**; developed and verified on 1.97.1). Get one
from <https://rustup.rs>.

```sh
git clone <your-repo-url> hermes
cd hermes
cargo build --release
```

The binary lands at `target/release/hermes` (`hermes.exe` on Windows). To make
it available from any terminal:

```sh
./target/release/hermes install
```

That copies the binary to a permanent per-user location, adds it to your
`PATH`, and registers the file icons and double-click handling — all without
admin or sudo, and all reversible with `hermes uninstall`.

| | Binary goes to | `PATH` updated via |
| --- | --- | --- |
| Windows | `%LOCALAPPDATA%\Programs\Hermes` | `HKCU\Environment` (never the machine-wide `PATH`) |
| Linux / macOS | `~/.local/bin` | an `export` line appended to your shell rc files, only if that directory is not already on `PATH` |

Open a new terminal afterwards and `hermes` will just work. Installing this way
also means the file associations point at a stable path rather than into
`target/`, where the next `cargo clean` would delete them out from under you.

You need a working C compiler, because TLS goes through rustls's `ring`
backend, which builds C and assembly. In practice this is already satisfied:

* **Windows** — the Visual Studio Build Tools that the default MSVC toolchain
  needs for linking anyway (the "Desktop development with C++" workload).
* **Linux** — `build-essential` / `gcc`, or clang.
* **macOS** — the Xcode command line tools (`xcode-select --install`).

Nothing else is required. The signing crypto (`ed25519-dalek`, `sha2`),
compression (`miniz_oxide`) and everything above them are pure Rust, so there
are no system libraries to install and no OpenSSL to find.

If you only want the desktop integration (custom icons, double-click support)
without moving the binary:

```sh
hermes install-system      # per-user only; never needs admin/sudo
hermes uninstall-system    # reverses all of it
```

Cross-compiling is ordinary `cargo`: `rustup target add <triple>` then
`cargo build --release --target <triple>`. Note that `install-system` compiles
the icon set for the *target* OS only (`.ico` on Windows, `.icns` on macOS,
PNGs on Linux), so each platform's binary carries only what it needs.

### Regenerating the icons

Icons are embedded in the binary with `include_bytes!`, and derived from the
source artwork in `assets/` - edit those three PNGs, then:

```sh
python tools/gen_icons.py     # needs Pillow
cargo build --release         # re-embeds them
```

## Quick start — users

Run `hermes` with no arguments and you get an interactive list:

```
  HERMES  0.1.0  -  decentralized updater
  ------------------------------------------------------------------
  > Starfall                     update -> 1.4.0            account
    Tidepool Editor              up to date (2.1.0)
    Nightjar                     not installed
  ------------------------------------------------------------------
  up/down move   enter details   c check   u update   a add   ? help   q quit
```

| Key | Does |
| --- | --- |
| `↑` `↓` or `k` `j` | move between applications |
| `Enter` | details and release notes |
| `c` / `C` | check the selected one / check everything |
| `u` | update the selected application |
| `a` | add a `.origin` (drag and drop it onto the window) |
| `l` / `L` | sign in to / out of a studio |
| `r` | stop tracking an application |
| `?` | key help |
| `q`, `Esc`, `Ctrl-C` | quit |

The interactive list never approves an update on your behalf. Pressing `u`
drops back to the normal terminal and runs the same permission prompt you would
get from the command line.

Every action is also a plain subcommand, which is what you want in scripts:

```sh
hermes add ./starfall.origin   # or just `hermes add` and drop the file in
hermes list
hermes login starfall          # only if the studio requires an account
hermes check
hermes update starfall
```

`hermes add` with no arguments waits for you to drag a file onto the terminal
window. Quoted paths, `file://` URIs and backslash-escaped spaces all work.

Before anything is written, you get the permission prompt:

```
------------------------------------------------------------------------
  UPDATE PERMISSION REQUEST
------------------------------------------------------------------------
  Application : Starfall
  Version     : 1.4.0
  Install root: C:\Games\Starfall

  This update is asking for access to these folders ONLY:

    [write, incl. sub-folders] bin
        -> C:\Games\Starfall\bin
        why: replace the game executable
    [read, incl. sub-folders] saves
        -> C:\Games\Starfall\saves
        why: keep your save files

  It will perform 5 step(s):

    - back up saves
    - keep your existing saves
    - copy bin/game.bin -> bin/game.bin
    ...

  Nothing outside the folders listed above can be read, written
  or deleted. The plan contains no executable steps.
------------------------------------------------------------------------
  Grant this access and apply the update? [y/N]
```

Answer anything but `y` and nothing happens. On a non-interactive terminal the
answer is always no.

## Updating HERMES itself

HERMES ships as a studio of its own. This repository is the studio, GitHub
Releases is the CDN, and `hermes.origin` is an ordinary origin file — the same
format any other publisher would hand you.

```sh
hermes add hermes.origin     # once; it comes with every release
hermes self-update --check   # what is available, and why
hermes self-update           # verify, ask, replace the binary
```

**Nothing is compiled in.** There is still no key baked into the binary: a
fresh build trusts nobody until you add an `.origin` by hand, HERMES's own
included. `self-update` refuses to run until you have. The tool holds itself to
the promise it makes about everyone else.

It cannot use the ordinary update pipeline, though, and the reason is worth
knowing. A normal update finishes by renaming a directory into place, and
Windows will not rename a directory that contains a running `.exe`. So
`self-update` reuses the pipeline exactly as far as the bytes are verified —
manifest signature, streamed SHA-256, checksum, Zip-Slip-sandboxed extraction —
and then differs only in the final move: it renames the *running binary* aside
(which is permitted) and puts the new one in its place. The old binary stays as
`hermes.exe.old` until the next launch, because a running image cannot be
unlinked.

If the copy fails, the old binary is renamed back. You are never left without a
working HERMES.

### Cutting a release (maintainers)

```sh
python tools/release.py --version 0.2.0 --notes dist/NOTES.md
```

That builds, packages, checksums, signs, and writes `dist/manifest.json` plus
the `hermes.origin` users add. Run it once per platform you ship — the
`platforms` map accumulates, so building on Windows and then on Linux yields a
single manifest covering both. It prints the `gh release create` line to
finish with.

The signing key lives in `~/.hermes-keys/`, never in the repository, and
`.gitignore` refuses `*.key` as a second line of defence. Anyone holding it can
sign an update that every HERMES user installs.

## Quick start — studios

You host two files on any static host (S3, R2, a VPS, GitHub Releases) and hand
out one small file. That is the entire integration.

```sh
# 1. One-time: generate your signing key. Keep the .key file OFFLINE.
hermes studio keygen --id moonforge.starfall --out ./keys

# 2. Build a release archive containing your files plus an update.foiled plan.
#    (see "File formats" below)

# 3. Get the numbers for the manifest.
hermes studio checksum ./starfall-1.4.0.zip
#     "checksum_sha256": "9f86d081884c7d65...",
#     "size_bytes": 734003200

# 4. Write payload.json, then sign it into a publishable manifest.
hermes studio sign --key ./keys/moonforge.starfall.key \
                   --payload ./payload.json --out ./manifest.json

# 5. Upload manifest.json and the .zip to your CDN.

# 6. Generate the .origin file your users will drag in, and publish it.
hermes studio new-origin --key ./keys/moonforge.starfall.key \
    --name "Starfall" \
    --manifest-url https://cdn.moonforge.dev/starfall/manifest.json \
    --auth-url https://moonforge.dev/hermes/login \
    --out starfall.origin

# 7. Sanity-check it exactly as a user's CLI would.
hermes studio verify --origin ./starfall.origin --manifest ./manifest.json
```

### If your software needs an account

HERMES never sees your users' credentials and holds no client secret. Your
website does the login; HERMES only catches the result on loopback.

1. `hermes login <id>` binds `127.0.0.1:8080` and opens
   `<studio_auth_url>?port=8080&state=<random>&client=hermes&redirect_uri=http://127.0.0.1:8080/callback`
2. Your backend authenticates the user however you like — Patreon, Steam,
   itch.io, your own password form. None of that involves HERMES.
3. You redirect the browser to
   `http://127.0.0.1:<port>/callback?token=<JWT>&state=<the same state, echoed back verbatim>`
4. HERMES verifies the `state`, stores the token (mode 0600), and shuts the
   server down.
5. Every later manifest and download request carries
   `Authorization: Bearer <token>`. Your CDN or edge worker checks it.

The token is opaque to HERMES. It checks structure and expiry (`exp`) and
nothing else — the signature is yours to verify, because the key is yours. If
`:8080` is busy HERMES falls back to another port and tells you which in the
`port` parameter, so always read the port from the query string.

## File formats

`.origin` and `.foiled` are **TOML**, because people read and write them.
`manifest.json` is **JSON**, because it is machine-generated wire format whose
signature covers the raw bytes of its payload.

### `starfall.origin` — the trust root

```toml
schema = "hermes.origin/v1"
id     = "moonforge.starfall"
name   = "Starfall"
publisher = "Moonforge Games"

upstream_manifest_url = "https://cdn.moonforge.dev/starfall/manifest.json"
studio_auth_url       = "https://moonforge.dev/hermes/login"

# Ed25519, base64 or hex. The trust anchor for this application.
public_key = "UepisXeS+U1Eehy5elRw+1d9QM00EGqg1XKp6kueHF8="

requires_auth = true
```

### `manifest.json` — signed, on your CDN

`hermes studio sign` wraps your payload and embeds it byte-for-byte:

```json
{
  "payload": {
    "schema": "hermes.manifest/v1",
    "origin_id": "moonforge.starfall",
    "latest_version": "1.4.0",
    "download_url": "https://cdn.moonforge.dev/starfall/1.4.0.zip",
    "checksum_sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "size_bytes": 734003200,
    "issued_at": 1767225600,
    "release_notes": "- Adds the Deep Field expansion
- Fixes save corruption on exit",
    "requires_auth": true
  },
  "signature": { "algorithm": "ed25519", "value": "base64...", "key_id": "moonforge.starfall" }
}
```

Optional payload fields: `expires_at`, `release_notes`, `release_notes_url`,
`minimum_client_version`, `foiled_path`, `platforms`.

`platforms` maps `os-arch` keys (`windows-x86_64`, `linux-x86_64`,
`macos-aarch64`) to a `download_url` / `checksum_sha256` / `size_bytes` of their
own, for software that ships a different binary per platform. When it is
present, the entry for the running platform wins and the top-level fields are
the fallback. A manifest that lists platforms but not yours is an error rather
than a silent fallback - quietly installing another platform's binary is worse
than saying there is no build.

`release_notes` is plain text carried **inside the signed payload**, so what a
user reads before granting folder access is exactly what you signed. It is
shown in the permission prompt and in the interactive detail view, capped at
8 KiB and 40 lines, and stripped of control characters — studio text is
rendered into a terminal at the moment of a trust decision, so it does not get
to move the cursor or repaint the screen. `release_notes_url` still exists for
a full changelog, but nothing fetches it automatically: a URL's contents are
not covered by your signature.

### `update.foiled` — the plan, inside the archive

```toml
schema    = "hermes.foiled/v1"
origin_id = "moonforge.starfall"
version   = "1.4.0"
base      = "clone"          # or "empty" for a full replacement package
notes     = "Adds the Deep Field expansion."

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

[[steps]]
action = "preserve"
path   = "saves"

[[steps]]
action = "copy"
from   = "bin/game.bin"      # read from the update payload
to     = "bin/game.bin"      # written into the new install tree
```

Steps: `extract_zip`, `copy`, `move`, `delete`, `backup`, `preserve`, `mkdir`.
Access levels are ordered `read` < `write` < `delete`, and a `write` grant does
**not** authorise a delete.

**There is no `run`, `exec` or `script` step, and there never will be.** Every
operation a studio can request is a file operation inside a scope the user
approved, so an update cannot escalate into arbitrary code execution.

## Commands

| Command | What it does |
| --- | --- |
| *(no arguments)* | Open the interactive list |
| `ui` | The same, explicitly |
| `install` | Copy the binary somewhere permanent, add it to `PATH`, register file types |
| `self-update [--check]` | Update HERMES itself from the origin it publishes |
| `uninstall` | Reverse all of that |
| `add [paths...]` | Register `.origin` files; prompts for a drop if given none |
| `list` | Everything HERMES tracks, with installed versions |
| `remove <id>` | Stop tracking (leaves installed files alone) |
| `inspect <path>` | Read-only dump of a `.origin` or `.foiled` |
| `open <path>` | Extension dispatcher — what a double-click runs |
| `check [id]` | Fetch and verify manifests; report versions |
| `update [id]` | Download, verify, ask, swap. `--yes`, `--install-dir`, `--force` |
| `login <id>` / `logout <id>` | Studio session via localhost callback |
| `install-system` / `uninstall-system` | Desktop icons and file associations |
| `studio keygen \| sign \| new-origin \| checksum \| verify` | Publisher-side tooling |

Exit codes: `0` success, `1` ordinary failure, `2` **security check failed**.
Scripts should treat `2` as "stop and investigate", never as "retry".

Environment: `HERMES_HOME` (state directory), `HERMES_NO_BROWSER=1` (headless
login), `HERMES_ALLOW_INSECURE_HTTP=1` (permits plain http to loopback hosts
only, for local studio testing).

## What HERMES refuses to do

Each of these is covered by a test in `tools/e2e_test.py`:

| Attack | Result |
| --- | --- |
| Manifest edited in transit | Signature fails; abort |
| Manifest signed by a different key | Signature fails; abort |
| Manifest replayed for another product | `origin_id` mismatch; abort |
| Stale manifest replayed to pin an old build | Refused via `issued_at` floor |
| Signed downgrade to a vulnerable version | Rollback refused |
| Archive contains `../escaped.txt` | Path traversal blocked; abort |
| Archive contains a symlink | Entry kind refused |
| Zip bomb / oversized archive | Entry, size and ratio caps |
| Corrupted or substituted download | Checksum mismatch before anything is unpacked |
| Plan touches a folder it did not declare | Refused *before* the user is prompted |
| Forged `state` on the auth callback | Token discarded as CSRF |
| Studio issues an already-expired token | Refused |
| No interactive terminal | Consent denied by default |

The live install directory is not touched until the final swap, which is two
renames. A crash, a power cut or a `Ctrl-C` at any earlier point leaves the
installed application exactly as it was.

## Testing

```sh
cargo test                    # 43 unit tests, no network
cargo build && python tools/e2e_test.py    # 44 checks against a local studio
```

The end-to-end suite is a real round trip, not mocks: real Ed25519 signing, a
real HTTP studio on `127.0.0.1:8099`, real zip extraction, a real atomic swap,
and the full attack battery above. It runs entirely under `target/e2e` with
`HERMES_HOME` redirected, so your own configuration is never touched.

## Status

Pre-1.0. The formats are versioned (`hermes.origin/v1` and friends) but not yet
frozen.

Verified on Windows 11. The Linux and macOS branches of `install-system`
compile under `cfg` but have not been executed on those platforms; everything
else is platform-independent and covered by the suites above.

## License

Code is MIT OR Apache-2.0. Icons are CC BY 4.0. The **name and mark are
reserved** — fork freely, but ship your fork under your own name. See
[LICENSE](LICENSE) for the reasoning, which is a security argument rather than
a branding one.
