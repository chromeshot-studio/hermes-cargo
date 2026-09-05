I need you to act as an expert systems engineer in Rust to build HERMES, a highly secure, completely decentralized CLI updater. I, the creator of the CLI, will host zero infrastructure. The CLI is essentially an empty, secure shell. Studios host their own files, manifests, and authentication servers. Users add software to the CLI by dragging and dropping a .origin file into their terminal (e.g., hermes add ./game.origin).

Please write the core implementation focusing on these five specific modules.

Module 1: Decentralized Data Schemas
Define the core structs for the three main files. The CLI must parse these without connecting to any centralized database.

.origin: The local file the user drags into the CLI. It contains name, upstream_manifest_url, studio_auth_url, and the studio's public_key (Ed25519).

manifest.json: Hosted on the studio's own CDN (S3/R2). Contains latest_version, download_url, checksum_sha256, and an Ed25519 signature.

.foiled: The update execution plan included inside the downloaded update. Contains declarative steps (e.g., extract_zip, backup, delete).

Module 2: Drag & Drop Registration
Implement the CLI entry point (hermes add <file_path>). It must accept a file path (supporting terminal drag-and-drop), parse the .origin file, and save it to a local registry in ~/.config/hermes/origins/ so the CLI knows to track it for future updates.

Module 3: The Security & Sandboxing Engine (Critical)
The CLI must never blindly trust the downloaded files. Implement a strict security layer:

Cryptography: Verify the signature in the remote manifest.json against the public_key in the local .origin file.

Zip-Slip Prevention: Write a strict path canonicalization function for extraction. Any archive attempting to write outside the target directory (e.g., using ../) must instantly abort.

Interactive Isolation: When applying a .foiled update, trigger a terminal prompt showing the exact folder scope requested, forcing the user to press 'Y' to allow access (strictly blocking parent/subfolder traversal if not declared).

Module 4: Zero-Memory Streaming & Atomic Swaps
Implement the HTTP fetching logic. The CLI must stream .zip downloads directly to a hidden .staging folder on the disk while calculating the SHA-256 hash on the fly. It must never load large files into RAM. If the hash matches the manifest, execute the .foiled steps, and perform an atomic directory swap.

Module 5: Studio-Hosted Web Auth (Localhost Callback)
Implement a seamless "Web-to-CLI" login flow so users can authenticate with the studio's website (e.g., to verify Patreon access) without me hosting an auth server.

When a user runs hermes login <studio_name>, the CLI spins up a temporary HTTP server on localhost:8080.

It automatically opens the user's browser to the studio_auth_url defined in the .origin file, appending ?port=8080.

The studio's own web backend handles the login, generates a JWT, and redirects to http://localhost:8080/callback?token=<JWT>.

The CLI intercepts this token, saves it locally, shuts down the server, and attaches it as a Bearer token for future manifest requests.

Module 6: Cross-Platform File Association & Custom Icons
Extend the Hermes Rust project to handle global OS-level file associations so .origin and .foiled files display custom icons and automatically open with the Hermes CLI when double-clicked.

Implement a hermes install-system command that detects the host OS and applies the following configurations safely:

Windows: Use the winreg crate to write to HKEY_CURRENT_USER\Software\Classes (avoiding admin rights if possible). Create a ProgID for Hermes, map the .origin and .foiled extensions to it, set the DefaultIcon key to point to extracted .ico files, and set shell\open\command to execute hermes add "%1".

Linux: Generate a FreeDesktop standard XML MIME type file in ~/.local/share/mime/packages/. Extract .png or .svg icons into ~/.local/share/icons/hicolor/, create a .desktop file for Hermes, and execute update-desktop-database and update-mime-database.

macOS: Write a function to generate a minimal Hermes.app wrapper in ~/Applications/ with an Info.plist. The plist must register CFBundleDocumentTypes for the custom extensions, link them to extracted .icns files, and pass the file paths to the underlying Rust binary.

Please write the Rust module (e.g., src/system_icons.rs) with conditional compilation (#[cfg(target_os = "...")]) to handle these OS-specific registry and configuration modifications. Include logic to embed the default icons directly into the Rust binary using include_bytes! so no external installer is required.