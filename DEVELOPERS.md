# Publishing with HERMES

A guide for studios and developers shipping software through HERMES. It walks
the whole path: making a signing key, writing the two files your users and your
updates need, signing a manifest, and putting a release somewhere people can
get it.

**Changing HERMES itself?** That is [INTERNALS.md](INTERNALS.md).

You host everything. There is no HERMES server, no account with anyone, no
registry to submit to and no review to pass. If you can put two files on a URL,
you can ship updates.

## The short version

[`tools/studio.py`](tools/studio.py) does all of it. Copy it into your project:

```sh
python studio.py init                        # asks a few questions, once
# put the files your update installs into build/, and edit update.foiled
python studio.py release --version 1.0.0
```

`init` makes your signing key, your `.origin`, a starter `update.foiled` and a
`build/` folder, and remembers the answers.

`release` packages, checksums, signs, verifies the result the way a user's CLI
will, and prints the commands to publish it — and it carries each release
forward into the version catalogue, so after three releases your users can pick
any of the three without you maintaining a list.

**Editing the plan is the step people skip.** It ships with the example's
filenames, so `release` refuses to package a plan naming files your `build/`
does not have, and tells you which ones. That failure would otherwise land on
your users, halfway through an update, instead of on you.

It calls `hermes studio ...` for every key, signature and checksum, so it
cannot disagree with the CLI that verifies its output.

The rest of this guide is what that script is doing, in case you want to do it
yourself, script it differently, or debug it.

## Contents

1. [The short version](#the-short-version)
2. [The three files](#the-three-files)
3. [Step 1 — make a signing key](#step-1--make-a-signing-key)
4. [Step 2 — write the `.origin`](#step-2--write-the-origin)
5. [Step 3 — write the `.foiled` plan](#step-3--write-the-foiled-plan)
6. [Step 4 — package the release](#step-4--package-the-release)
7. [Step 5 — sign the manifest](#step-5--sign-the-manifest)
8. [Step 6 — publish](#step-6--publish)
9. [Offering more than one version](#offering-more-than-one-version)
10. [Shipping for several platforms](#shipping-for-several-platforms)
11. [Patching software HERMES did not install](#patching-software-hermes-did-not-install)
12. [If your software needs an account](#if-your-software-needs-an-account)
13. [Rotating a key](#rotating-a-key)
14. [Release checklist](#release-checklist)

## The three files

| File | Who has it | What it is |
| --- | --- | --- |
| `.origin` | your users, added once | **An address.** Your identity and the URL updates come from, plus the public key that signs them. Nothing about their disk. |
| `manifest.json` | your CDN, replaced each release | **A signed statement.** Which version is current, where the archive is, and its SHA-256. |
| `.foiled` | inside each archive | **Instructions.** What to install, where it goes, what to keep. |

The `.origin` is the only thing a user has to trust, and they get it from you
once. Everything after that is verified against the key inside it, so your CDN,
your mirrors and the network in between are all untrusted transport.

Start from a template rather than a blank file:

```sh
hermes studio template origin   --out starfall.origin
hermes studio template foiled   --out update.foiled
hermes studio template manifest --out payload.json
```

The third is the manifest *body* — the part you write. `hermes studio sign`
turns it into the `manifest.json` you upload. `templates/manifest.json` in this
repository is a complete signed example to read: it is really signed by the key
in `templates/starfall.origin`, so `hermes studio verify --origin
templates/starfall.origin --manifest templates/manifest.json` passes.

## Step 1 — make a signing key

```sh
hermes studio keygen --id moonforge.starfall --out ~/.hermes-keys
```

That writes `~/.hermes-keys/moonforge.starfall.key` and prints the public half:

```
  public_key: 0FMFR1Kx8Tn0aQb0lJ0KpXQMPzGSTQFyO7oxVw2vGxk=
```

The `--id` is your permanent identifier. Lowercase letters, digits, `.`, `-`
and `_`. It becomes the filename in every user's registry, so choose it once:
changing it later makes every existing user look like a brand new one.
Reverse-domain style (`moonforge.starfall`) keeps it unique without anyone
having to hand out names.

**The `.key` file is the whole of your security.** Anyone who has it can sign
an update that every one of your users installs, without touching your servers.

* Keep it off the machine that builds releases if you can, and out of CI.
* Never commit it. HERMES's own `.gitignore` refuses `*.key` as a second line
  of defence; add the same rule to yours.
* Back it up somewhere offline. Losing it means every user has to add a new
  `.origin` by hand — see [rotating a key](#rotating-a-key).

## Step 2 — write the `.origin`

This is the file you put on your website for people to download. `hermes studio
new-origin` fills it in from your key:

```sh
hermes studio new-origin \
    --key ~/.hermes-keys/moonforge.starfall.key \
    --name "Starfall" \
    --publisher "Moonforge Games" \
    --homepage https://moonforge.dev \
    --manifest-url https://github.com/moonforge/starfall/releases/latest/download/manifest.json \
    --out starfall.origin
```

Which produces:

```toml
schema = "hermes.origin/v1"
id     = "moonforge.starfall"
name   = "Starfall"
publisher = "Moonforge Games"
homepage  = "https://moonforge.dev"

upstream_manifest_url = "https://github.com/moonforge/starfall/releases/latest/download/manifest.json"

public_key = "0FMFR1Kx8Tn0aQb0lJ0KpXQMPzGSTQFyO7oxVw2vGxk="
```

| Field | Meaning |
| --- | --- |
| `id` | Permanent identifier, same as the key's |
| `name` | What users see in listings and in the permission prompt |
| `publisher` | Who made it. A claim, not a credential |
| `homepage` | Where to read about it |
| `upstream_manifest_url` | **Where updates live.** https, any host |
| `public_key` | The trust anchor. Everything must be signed by its private half |
| `studio_auth_url`, `requires_auth` | Only if updates are behind a login |

There is **no install path in this file, and there cannot be**. A `.origin`
says where updates come from, not where they go on a machine you have never
seen. Where files land is decided by the user, or asked for by the plan.

Hand this file out however you like — a download button, an email, inside your
installer. Users run `hermes add starfall.origin` or drag it onto the HERMES
window. Serve it as `text/plain` or `application/octet-stream`; if your CMS
re-encodes it, make sure what comes out is still UTF-8.

## Step 3 — write the `.foiled` plan

This ships **inside** your release archive, named `update.foiled` at its root.
It says what to do with the files, and it is the thing your users approve.

```toml
schema    = "hermes.foiled/v1"
origin_id = "moonforge.starfall"
version   = "1.4.0"
base      = "clone"
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
from   = "bin/starfall.exe"    # from your archive
to     = "bin/starfall.exe"    # into the new install tree
```

`origin_id` and `version` must match your `.origin` and the version in the
signed manifest. HERMES refuses the update if either disagrees.

**`base`** decides what the new install starts as. `"clone"` is a copy of
what is installed now, which your steps then patch — use it for anything that
must keep user data. `"empty"` starts from nothing, for a full replacement.

### Scope

`[[scope]]` is the list of folders your plan may touch, and your users see it
verbatim before they approve anything. A step touching anything outside it
aborts the update before a single byte is written.

* `access` is `read`, `write` or `delete`, in that order of strength. A `write`
  grant does **not** authorise a delete. Ask for the weakest that works.
* `recursive = false` means direct children only. A plan holding `"."` still
  has to declare `"saves"` separately to reach inside it.
* `reason` is shown to the user. Write it for them.

Ask for less and more people say yes. A plan wanting `[delete, recursive] .`
is asking to be allowed to erase the install folder, and it reads that way.

### Steps

| Action | Does |
| --- | --- |
| `copy` | `from` your archive, `to` the install tree |
| `extract_zip` | Unpack an `archive` that shipped inside your archive, into `dest` |
| `move` | Move something within the install tree |
| `delete` | Remove a `path` (`recursive = true` for a folder) |
| `mkdir` | Create a folder |
| `preserve` | Carry something from the current install into the new one — saves, configs, mods |
| `backup` | Snapshot something before it is replaced; kept outside the install folder |

**There is no `run`, `exec` or `script` step, and there never will be.** Every
operation is a file operation inside a scope the user approved, so an update
cannot become arbitrary code execution. If your update needs to run something,
it needs to happen when your application next starts, not during the update.

Check your plan before shipping it — this is exactly what a user sees:

```sh
hermes inspect update.foiled
```

## Step 4 — package the release

Put your files and `update.foiled` in a `.zip`:

```
starfall-1.4.0.zip
├── update.foiled
├── bin/
│   └── starfall.exe
└── content.zip
```

Then get the numbers the manifest needs:

```sh
hermes studio checksum ./starfall-1.4.0.zip
#     "checksum_sha256": "9f86d081884c7d65...",
#     "size_bytes": 734003200
```

Archives are unpacked into a sandbox, so a few things are refused outright:
symlinks, duplicate entries, absolute or `..` paths, and setuid bits. An
ordinary zip of ordinary files is fine.

## Step 5 — sign the manifest

Write the payload — the inner object, not the whole document. Start from
`hermes studio template manifest`, which gives you this with a `platforms` map
and a version catalogue already filled in as examples:

```json
{
  "schema": "hermes.manifest/v1",
  "origin_id": "moonforge.starfall",
  "latest_version": "1.4.0",
  "download_url": "https://github.com/moonforge/starfall/releases/download/v1.4.0/starfall-1.4.0.zip",
  "checksum_sha256": "9f86d081884c7d65...",
  "size_bytes": 734003200,
  "issued_at": 1767225600,
  "release_notes": "- Adds the Deep Field expansion\n- Fixes save corruption on exit"
}
```

`issued_at` is Unix seconds and is not decoration: HERMES remembers the newest
it has accepted and refuses anything older, so a mirror cannot replay an old
manifest to pin someone on a stale build. Always set it to now.

`release_notes` is plain text carried **inside the signed payload**, so what a
user reads before granting folder access is exactly what you signed. It is
shown in the permission prompt and the version list, capped at 8 KiB and 40
lines, with control characters stripped.

Optional: `expires_at`, `release_notes_url`, `minimum_client_version`,
`foiled_path` (if your plan is not at `update.foiled`), `platforms`, `versions`,
`requires_auth`.

Then sign it:

```sh
hermes studio sign --key ~/.hermes-keys/moonforge.starfall.key \
                   --payload ./payload.json --out ./manifest.json
```

The signature covers the payload's **raw bytes**, embedded verbatim in the
output, which is why the document looks a little oddly indented:

```json
{
  "payload": {
  "schema": "hermes.manifest/v1",
  ...
},
  "signature": {
    "algorithm": "ed25519",
    "value": "5CNeaXKd2d7Ijaee...",
    "key_id": "moonforge.starfall"
  }
}
```

Your payload went in exactly as you wrote it. **Do not reformat
`manifest.json` afterwards** — reindenting it, or piping it through a JSON
prettifier, changes those bytes and breaks the signature. If you need to change
something, edit the payload and sign again.

Before publishing, check it the way a user's CLI will:

```sh
hermes studio verify --origin ./starfall.origin --manifest ./manifest.json
```

## Step 6 — publish

Upload `manifest.json` and the `.zip`. Anywhere that serves bytes over https
works: S3, R2, a VPS, GitHub Releases, your own web host.

**GitHub Releases** is a good default because `latest` is a stable URL:

```
https://github.com/moonforge/starfall/releases/latest/download/manifest.json
```

Attach `manifest.json` and `starfall-1.4.0.zip` to each release, point
`upstream_manifest_url` at that `latest` URL once, and you never edit the
`.origin` again. Use the versioned URL
(`.../releases/download/v1.4.0/starfall-1.4.0.zip`) for `download_url`, so an
archive URL always means one exact build.

Your CDN is untrusted by design. It cannot alter the archive without breaking
the checksum, or the manifest without breaking the signature.

## Offering more than one version

By default users get `latest_version`. To let them look through what you offer
and pick — `hermes versions <id>`, or `v` in the interactive list — add a
`versions` array to the payload:

```json
"versions": [
  {
    "version": "1.3.2",
    "download_url": "https://github.com/moonforge/starfall/releases/download/v1.3.2/starfall-1.3.2.zip",
    "checksum_sha256": "3b8c...",
    "size_bytes": 701000000,
    "release_notes": "- The release before the expansion"
  }
]
```

Each entry carries its own URL, checksum, size and notes, and the whole list is
covered by the same signature — so an older release is offered on **your**
authority, not your CDN's. The latest release is described by the top-level
fields and must not be repeated in the list.

Users install one with:

```sh
hermes versions starfall                  # look at what is on offer
hermes update starfall --version 1.3.2    # install that one
```

Going *backwards* is a separate decision from granting folder access, so
`--yes` does not cover it — HERMES warns and asks, and `--allow-downgrade`
answers it in a script. Keep old entries listed only while the archives are
still up; an entry pointing at a deleted file is a broken option in a menu.

## Shipping for several platforms

When each platform needs a different binary, use `platforms` instead of one
`download_url`:

```json
"platforms": {
  "windows-x86_64": { "download_url": "...-windows.zip", "checksum_sha256": "...", "size_bytes": 1234 },
  "linux-x86_64":   { "download_url": "...-linux.zip",   "checksum_sha256": "...", "size_bytes": 1234 },
  "macos-aarch64":  { "download_url": "...-macos.zip",   "checksum_sha256": "...", "size_bytes": 1234 }
}
```

Keys are `<os>-<arch>` using Rust's names (`windows`, `linux`, `macos`;
`x86_64`, `aarch64`). The entry for the running platform wins; the top-level
fields stay as the fallback for anything portable. A manifest that lists
platforms but not the user's is an error rather than a silent fallback —
quietly installing another platform's binary is worse than saying there is no
build. Catalogue entries under `versions` take their own `platforms` map too.

`tools/studio.py release --per-platform` builds this map for you: run it on
each machine with the same `--version`, and each run adds its own entry to the
same release rather than replacing it.

(`tools/release.py` does the same job specifically for HERMES's own releases,
and is worth reading if you want a shorter example to adapt.)

## Patching software HERMES did not install

If your users already have your software — bought elsewhere, unzipped by hand,
installed years before you adopted HERMES — HERMES does not know where it is.
Your plan can ask:

```toml
[locate]
prompt = "Where is Starfall installed?"
expect = "bin/starfall.exe"
```

That is the whole of what you may say. **You do not name the folder.** The user
types or drags it in, and HERMES refuses anything that is not an existing
folder containing `expect` — and refuses drive roots, their home directory and
its parents outright. Your declared scope is then resolved against whatever
they chose and shown to them before they approve it.

Always set `expect`: it is what turns "some folder" into "the right folder",
and without it a mistyped path gets patched instead of refused. The answer is
remembered, so this is asked once per user rather than once per update.

## If your software needs an account

HERMES never sees your users' credentials and holds no client secret. Your
website does the login; HERMES catches the result on loopback.

Set both fields in your `.origin`:

```toml
studio_auth_url = "https://moonforge.dev/hermes/login"
requires_auth   = true
```

Then:

1. `hermes login starfall` binds `127.0.0.1:8080` and opens
   `<studio_auth_url>?port=8080&state=<random>&client=hermes&redirect_uri=http://127.0.0.1:8080/callback`
2. Your backend authenticates however you like — Patreon, Steam, itch.io, your
   own password form. None of it involves HERMES.
3. You redirect the browser to
   `http://127.0.0.1:<port>/callback?token=<JWT>&state=<the same state, echoed back verbatim>`
4. HERMES checks the `state`, stores the token with owner-only permissions, and
   shuts the server down.
5. Every later manifest and archive request carries
   `Authorization: Bearer <token>`. Your CDN or edge worker checks it.

Read the port from the query string rather than assuming 8080 — if it is taken,
HERMES binds another and tells you which. Echo `state` back exactly; a mismatch
is treated as CSRF and the token is discarded.

The token is opaque to HERMES. It checks structure and expiry (`exp`) and
nothing else — the signature is yours to verify, because the key is yours.

## Rotating a key

Users pin your key on first add. If you publish a `.origin` with a different
one, HERMES stops and makes them confirm the change explicitly, showing both
keys. That is deliberate: a swapped key is what a supply-chain compromise looks
like, and it should never be silent.

So rotate rarely, and when you do:

1. Announce it somewhere users can check independently — your site, your
   release notes, wherever they already trust you.
2. Publish the new `.origin`.
3. Expect them to be asked. Tell them what the new key's first characters are
   so they can compare.

There is no revocation, because there is nobody to revoke through. The pin is
the authority, which is the point of the design and also its sharpest edge.

## Release checklist

`tools/studio.py release` does 1 to 6 of this for you. It is written out
because knowing what a release *is* makes the failures legible.

1. Bump `version` in your `.foiled`; it must match `latest_version`.
2. `hermes inspect update.foiled` — read the scope as a user would.
3. Build the archive; `hermes studio checksum` it.
4. Write the payload with a fresh `issued_at` and real `release_notes`.
5. `hermes studio sign`.
6. `hermes studio verify --origin ... --manifest ...`.
7. Upload the archive **first**, then the manifest. A manifest pointing at a
   file that is not there yet is a broken update for anyone checking in
   between.
8. Test it end to end from a machine that has never seen the release: `hermes
   add` your published `.origin`, then `hermes update`.

Step 8 is the one worth not skipping. It is the only check that covers your
actual URLs, your actual archive and your actual signature together.
