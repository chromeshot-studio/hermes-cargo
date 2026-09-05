# HERMES internals

Notes for people changing HERMES itself.

**Publishing software with HERMES?** You want [DEVELOPERS.md](DEVELOPERS.md) —
keys, `.origin` files, `.foiled` plans, signing and releasing. Nothing on this
page is needed to ship an update.

Read the [invariants](#invariants) before touching anything under
`src/security/` or `src/update.rs`. Most of them are one line of code away from
being silently broken, and none of them fail loudly on their own.

## Layout

| Path | Role |
| --- | --- |
| `src/main.rs` | CLI surface (clap), command handlers, `studio` subcommands |
| `src/tui.rs` | The interactive list shown when `hermes` is run with no arguments |
| `src/install.rs` | `hermes install` - permanent location and `PATH` management |
| `src/selfupdate.rs` | `hermes self-update` - replacing the running binary |
| `src/schema.rs` | The three document formats and their validation |
| `src/registry.rs` | The `.origin` registry, key pinning, drag-and-drop path parsing |
| `src/security/crypto.rs` | Ed25519 verification, streaming SHA-256, rollback refusal |
| `src/security/safepath.rs` | Path sanitising, Zip-Slip prevention, archive limits |
| `src/security/consent.rs` | Scope resolution, scope enforcement, the `Y` prompt |
| `src/net.rs` | The two HTTP clients; streaming download that hashes in flight |
| `src/update.rs` | The pipeline and the atomic swap |
| `src/fsx.rs` | Tree copy/clone/move/delete helpers |
| `src/auth.rs` | Localhost callback login, token storage |
| `src/system_icons.rs` | Per-OS file associations, embedded icons |
| `src/paths.rs` | Where state lives; private-file helpers |
| `src/error.rs` | `SecurityError` — the type that means "stop" |
| `templates/` | The commented starter `.origin` and `.foiled`, embedded in the binary |
| `DEVELOPERS.md` | The publishing guide - studio-facing, not about this code |
| `tools/gen_icons.py` | Generates `assets/icons/` from primitives |
| `tools/e2e_test.py` | Full round trip against a local studio, plus attacks |
| `tools/studio.py` | The guided path for *any* studio: `init` and `release` |
| `tools/release.py` | Build, package, sign and lay out a release in `dist/` |
| `tools/demo_studio.py` | A local studio to drive the CLI against by hand |

## The pipeline

`update::apply` runs in this order, and **the order is the design**:

```
 1. fetch manifest                      net::HttpClient::fetch_manifest
 2. verify signature                    crypto::verify_manifest
 3. pick the release, refuse rollbacks  Manifest::release, assert_no_rollback
 4. stream .zip -> staging, hashing     net::stream_download
 5. compare digest to signed checksum   crypto::verify_checksum
 6. extract into staging                safepath::extract_zip_secure
 7. read the plan                       schema::FoiledPlan::parse
 8. ask where it is installed, if asked consent::locate_install_dir
 9. enforce the declared scope          consent::enforce_plan_scope
10. ask the user                        consent::request_consent
11. build the new tree in staging       update::execute_plan
12. rename into place                   update::swap_into_place
```

Nothing is unpacked before step 5. The live install directory is not touched
before step 12. Both facts are load-bearing — if you find yourself moving work
earlier for performance, you are removing a security property.

Step 8 runs only when the plan carries a `[locate]` block and HERMES does not
already know where the software lives. It answers "which folder?", never
"may I?" — steps 9 and 10 then run against the user's answer unchanged. Because
staging was created next to the folder we *guessed*, a different answer moves
the whole job (`Staging::relocate`) rather than letting step 12 quietly degrade
from a rename into a copy.

Staging lives in `<install-parent>/.staging/<id>-<nonce>/`, deliberately *not*
in `~/.config/hermes`, so that step 12 is a same-volume `rename`. `Staging`
implements `Drop`, so an early return at any point cleans up after itself.

## Invariants

**1. An untrusted path is a string, not a path.**
Anything from an archive, a manifest or a `.foiled` plan goes through
`safepath::sanitize_relative` or `safepath::resolve_within` before it is joined
onto anything. Never `root.join(untrusted)`. `resolve_within` also walks every
existing ancestor and refuses symlinks, which is what stops a write from
travelling through a link planted earlier in the same archive.

**2. Nothing is unpacked before the checksum matches.**
`verify_checksum` runs on the digest computed *during* the download. Do not add
a "peek inside the archive first" step.

**3. The manifest signature covers raw bytes.**
`SignedManifest.payload` is a `serde_json::value::RawValue`. Verification runs
over `payload.get().as_bytes()` — the exact bytes on the wire. Never
re-serialize a parsed struct and verify against that; the moment a verifier and
a signer can disagree about formatting, the scheme is broken. This is also why
`manifest.json` stays JSON while the other two formats are TOML.

**4. Scope is enforced before consent, not after.**
`enforce_plan_scope` runs first and aborts on any undeclared path. The user is
never offered the chance to approve something the plan did not declare. Keep
these two steps in that order and keep them separate.

**5. Every path a step touches must appear in `FoiledStep::touched()`.**
This is the easiest way to introduce a hole. `touched()` is the *only* thing
the scope engine consults. A path your step writes but does not report is a
path nobody checked.

**6. There is no code execution step.**
No `run`, no `exec`, no `script`, no post-install hook, no shelling out to an
installer. If a feature seems to need one, it does not belong in `.foiled`.

**7. Deny by default.**
No TTY means no consent (`SecurityError::ConsentUnavailable`). `--yes` skips
the keystroke, never the enforcement.

**8. Security failures surface as `SecurityError`.**
They exit with code `2` and a loud banner. Never map one into a generic
`anyhow!` string, never `unwrap_or_default()` one away, and never retry after
one. `cmd_update` deliberately propagates a `SecurityError` immediately instead
of continuing to the next application.

**9. Unlink before create.**
`clone_tree` hard-links files into the staging tree for speed, so writing into
a cloned file in place would corrupt the *live* install. Every writer removes
the target first and then creates exclusively (`create_new(true)`).

**10. Archive entries are regular files and directories only.**
Symlinks, devices, FIFOs and duplicate entries are refused outright, and
setuid/setgid/sticky bits from archive metadata are dropped on the floor.

**11. `self-update` may skip the directory swap, never the verification.**
`src/selfupdate.rs` exists only because Windows will not rename a directory
containing a running `.exe`. It reuses `update::check`, `stream_download`,
`verify_checksum` and `extract_zip_secure` unchanged, and differs *only* in the
final move. If you touch it, the rule is that every byte is still verified
before anything is written, and the old binary is restored if the swap fails.

Its origin is compiled in (`SELF_ORIGIN`, `include_str!("../hermes.origin")`),
and that is the one key in the binary. It authorises HERMES replacing itself
and nothing else — it is never consulted for a registered application, and a
registry entry for `chromeshot.hermes` never overrides it, because a file on
disk must not be able to redirect where the binary fetches its own replacement
from. `tools/release.py` writes `hermes.origin` **before** the build that
ships; reversing that order publishes a binary pinned to the previous key.

**12. The interactive mode never approves anything.**
`src/tui.rs` has no consent logic of its own. Every action that needs a
decision calls `Screen::suspend`, drops back to the ordinary terminal, and runs
the same command-line code path with the same prompt. If you ever find yourself
adding a "confirm" to the TUI, you are building a second security boundary that
will drift out of step with the real one.

**14. A `.origin` names an address, never a location.**
It carries identity, the URLs updates come from, and the pinned key. It does
not carry an install path, a folder name, or anything else about the user's
disk — a publisher does not get to decide where files land on a machine they
have never seen. Where an update goes is decided by the user's `--install-dir`,
by what was used last time, or by the plan asking (`[locate]`), in that order.
Adding a local path back to `OriginFile` would quietly hand that decision to
whoever wrote the file.

**15. A downgrade the user chose is not the downgrade we defend against.**
`assert_no_rollback` refuses an older version whenever HERMES is picking the
version itself - a CDN serving a stale build to pin someone on a version with a
known hole is a real attack, and that path must stay closed. `--version` is the
other case: the user named it. That is `consent::confirm_downgrade`, and it is
deliberately **not** covered by `--yes`, because granting folder access and
accepting an older build are two different decisions. Do not collapse them, and
do not route the automatic path through the confirmation.

**13. A plan chooses the folder's contents, never the folder.**
`[locate]` lets a plan ask *where* its software is installed. It supplies a
question and the name of a file it expects to find; the path comes from the
user and goes through `consent::validate_install_choice`, which insists on an
existing directory that is not a drive root, not the home directory, not an
ancestor of it, and not anything containing HERMES's own state. Widening that
list is not a convenience change: a plan declaring `[write] .` reaches every
file under whatever root it is handed, so the checks are what keep the scope
declaration meaningful. Consent still runs afterwards, against the chosen root.

## Adding a `.foiled` step

1. Add the variant to `FoiledStep` in `src/schema.rs`. The enum is internally
   tagged (`#[serde(tag = "action", rename_all = "snake_case")]`), so
   `[[steps]] action = "your_step"` maps to it automatically.
2. Implement its arms in `name()`, `describe()` and — carefully — `touched()`.
   Return **every** install-tree path with the weakest access that actually
   suffices: `Access::Read` for something you only read, `Delete` for anything
   that removes. Paths inside the extracted payload are excluded, because the
   payload is a sandbox we own.
3. Handle it in `update::execute_plan`, resolving each path through
   `resolve_within` against the correct root: `staging.payload` for payload
   reads, `staging.next` for the tree being built, `install_dir` for reads of
   the live install (`backup`, `preserve` — and those also call
   `assert_within`).
4. Add a test in `src/security/consent.rs` proving the step is refused when its
   path falls outside the declared scope.
5. Add a case to `tools/e2e_test.py`.

Step 4 is not optional. Every existing step has one.

## Adding an OS to `install-system`

`src/system_icons.rs` dispatches to a `platform` module selected by
`#[cfg(target_os = ...)]`, with a fallback module that warns and does nothing.
Implement `install(exe, icons, report)` and `uninstall(report)`. Rules:

* **Per-user only.** No admin, no sudo, nothing outside the user's profile.
* **Reversible.** `uninstall` must undo everything, and must not stomp an
  association that some other application has since claimed.
* **Absolute, non-verbatim exe path.** Use `current_exe()`, which strips the
  `\\?\` prefix `canonicalize` adds on Windows — a verbatim path in
  `shell\open\command` produces an association that silently does nothing.
* Embed new icon assets behind `#[cfg]` in the `embedded` module so each
  platform's binary carries only its own formats.

## Testing

```sh
cargo test                                  # 80 unit tests, no network
cargo build && python tools/e2e_test.py     # 78 checks, ~15s
```

Unit tests cover the pure logic: path sanitising (the Zip-Slip corpus),
signature verification, scope matching, install-folder validation,
drag-and-drop parsing, and — on Windows — the registry writes, which run
against a scratch key (`HKCU\Software\Hermes.SelfTest`) and never touch real
associations.

`tui::Reader` is the one input path with no test above it: a burst of
keystrokes cannot be delivered without a real terminal. Its *decision* is
`tui::dropped_path`, which is pure and tested; keep any new logic on that side
of the line.

`tools/e2e_test.py` drives the real binary against a real HTTP studio on
`127.0.0.1:8099`. It plays every role: generates a key, packages a release,
signs a manifest, serves it, acts as the browser during login, then asserts
what landed on disk. It runs under `target/e2e` with `HERMES_HOME` redirected.

Three environment variables exist for testing and nothing else:
`HERMES_HOME`, `HERMES_NO_BROWSER=1`, and `HERMES_ALLOW_INSECURE_HTTP=1` (which
relaxes the https requirement for **loopback hosts only** — check
`schema::require_secure_url` before assuming it does more).

**Any change to `src/security/` needs a test that fails without it.** A change
that tightens a check should come with the input that used to get through.

## Threat model

Defended against:

* A hostile or compromised CDN, mirror, or network path. It serves bytes; the
  pinned key decides whether they mean anything.
* Malicious archive contents — traversal, symlinks, duplicate entries, zip
  bombs, setuid bits.
* An over-reaching `.foiled` plan from an otherwise-legitimate studio.
* Replay of an old signed manifest, and signed downgrades.
* A local web page trying to POST a token into the login callback (the `state`
  parameter).
* Token leakage through a redirect off https.

**Not** defended against, by design:

* A compromised studio signing key. Pinning means the key *is* the authority.
  The mitigation is social: `hermes add` refuses a changed key for an already
  registered origin and makes the user confirm it explicitly.
* A compromised local account. HERMES's state is ordinary files owned by the
  user; anything running as that user can edit them.
* The behaviour of the software being installed. HERMES puts files on disk
  safely; it does not sandbox what you then run.
* HERMES's own dependency supply chain. `Cargo.lock` is committed so builds are
  reproducible and the tree is auditable — keep it that way, and keep the
  dependency list short.

## Conventions

* Rust 1.74+ declared (`rust-version`), developed on 1.97.1. The MSRV is
  enforced by cargo's resolver, not by CI.
* `cargo fmt` defaults; no `clippy` config, but the build is warning-clean —
  keep it that way rather than adding `#[allow]`s, except where a `cfg`-gated
  item is genuinely unused on other platforms.
* Keep the dependency tree small and boring. The one C dependency is `ring`,
  pulled in by rustls for TLS; everything else, including all of the signing
  crypto and compression, is pure Rust. Adding another C dependency (or
  anything needing cmake) needs a discussion first — it is a build-friction
  and supply-chain cost, not just a technical one.
* Errors: `anyhow` with `.context()` for ordinary failures, `SecurityError` for
  anything a user's safety depends on.
* The release profile sets `panic = "abort"`, so `Drop` does **not** run on a
  panic. Anything that puts the terminal or the filesystem into a state that
  needs restoring must also install a panic hook - see `tui::Screen::enter`.
* Comments explain *why*, especially where the code looks over-cautious. Most
  of the odd-looking checks in `safepath.rs` exist because of a specific known
  attack; say which one.

## Release checklist

1. `cargo test` and `python tools/e2e_test.py` both clean.
2. `cargo build --release` — confirm the binary runs and `--version` is right.
3. If icons changed: `python tools/gen_icons.py`, eyeball
   `assets/icons/contact-sheet.png` at real sizes, then rebuild to re-embed.
4. Bump `version` in `Cargo.toml`; commit `Cargo.lock`.
5. If a document format changed incompatibly, bump its `schema` string
   (`hermes.origin/v1` → `/v2`) and reject the old one explicitly rather than
   parsing it loosely.
