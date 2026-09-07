# Ghost Chat Cleaner

[English](README.md) | [한국어](README.ko.md)

Ghost Chat Cleaner is a desktop utility for reviewing stale ChatGPT entries in a local `codex-dev.db` catalog and removing selected entries after safety checks. It compares the local catalog with your authenticated ChatGPT web account, shows what needs review, and creates a verified backup before cleanup.

Cleanup removes entries only from this device's `local_thread_catalog` table. It does not delete conversations from ChatGPT's servers. A web `404` means unavailable in the checked account and context; it does not prove that a conversation was deleted.

Choose `한국어` or `English` at the top right to change the interface immediately. Live mode remembers the choice for the next launch; demo mode keeps it only for that session. Switching languages preserves the current list, selection, and login state. Conversation titles, file paths, and technical diagnostics remain unchanged. This is an independent project, not an official OpenAI utility.

## Start from source

You need Git, a Rust toolchain with Cargo, and the native C/C++ build tools for your OS. Use the Xcode command-line tools on macOS or the MSVC toolchain and Visual Studio C++ build tools on Windows. The [build workflow](.github/workflows/release-build.yml) lists the Linux development libraries.

```sh
git clone https://github.com/AidALL/Ghost-Chat-Cleaner.git
cd Ghost-Chat-Cleaner
cargo run --locked --release -- --demo
```

The demo opens the GUI with fixed synthetic conversations and simulated results. It does not open a browser, read real catalog databases or evidence logs, inspect the real process list, or perform real cleanup. The header shows `Demo data`.

To inspect your real catalog, close the demo and launch without `--demo`:

```sh
cargo run --locked --release
```

Live mode uses real local catalog data and your authenticated browser session. Loading a catalog is read-only; cleanup requires a separate selection and confirmation in a dialog. There is no headless scan or cleanup CLI.

These instructions do not require a published binary. To build your own portable app, see [Build and package](#build-and-package). The repository workflow produces CI artifacts; it does not create GitHub Releases.

## Platform and account scope

| Platform | Implemented behavior | Local runtime verification |
| --- | --- | --- |
| macOS Apple silicon | Scan and guarded catalog cleanup | Saved Edge login, real read-only comparison, quit and restart exercised |
| macOS Intel | Scan and guarded catalog cleanup | Not locally exercised |
| Windows | Scan and guarded catalog cleanup | Not locally exercised |
| Linux | Scan only; cleanup disabled by policy | Not locally exercised |

The macOS Apple-silicon check was performed on 2026-09-07. It restored saved authentication without credential entry and protected web-present rows from selection. No real cleanup was performed; repair protections are tested with synthetic fixtures. This is evidence for the tested build and account, not a guarantee for every OS or future ChatGPT version. Further context is in the [browser verification notes](docs/browser-contract.md#verification-limit).

Web comparison requires a personal ChatGPT account and a supported native Chrome, Edge, or Chromium installation registered as the system default HTTPS browser. An unsupported default is refused; the app does not silently choose another browser. Workspace accounts and ambiguous account identity are blocked. The collector uses undocumented ChatGPT web endpoints, so website changes can require a collector update.

## Inspect your catalog

1. In `Conversation list file`, enter the path to `codex-dev.db` or press `Find file`. If several candidates appear, select the intended file. Press `Load` to inspect it read-only.
2. Optionally expand `Settings` and enter deletion-record files or directories, one path per line. Only those explicitly supplied roots are searched. Leave the field empty if you do not have local deletion records.
3. The app attempts to restore a saved login on startup. If it is not connected, press `Log in`, then sign in to the same personal ChatGPT account as the catalog. Enter passwords and verification codes only on the browser's official sign-in page.
4. Press `Check list`. On macOS, this action requests normal closure of the dedicated login browser and waits up to 30 seconds for successful exit before continuing. On Windows and Linux, close that dedicated browser yourself before continuing. Authentication and comparison reuse the same saved profile.
5. Review the local titles and results. If no catalog is loaded, `Check list` can load the entered path or a sole discovered candidate; multiple candidates require a choice. Successful authentication also compares an existing scan automatically.

Automatic discovery checks the entered path, `$CODEX_HOME/sqlite/codex-dev.db`, and `$HOME/.codex/sqlite/codex-dev.db`. An unset variable contributes no candidate. You can always enter a path explicitly; discovery itself does not scan database contents.

### Understand the results

The local classification and web result answer different questions:

| UI label | Meaning |
| --- | --- |
| `Delete log` | A matching local deletion marker was found. Web presence still protects the row. |
| `Review` | Manual review is required. Tick the row's `Done` acknowledgement before selecting it. |
| `Keep` | The current checks preserve this row; it is not eligible for selection. |
| `On web` | The authenticated web check found the conversation. Cleanup is blocked for this row. |
| `Unavailable` | A guarded direct check found it unavailable in the verified account/context. This is not proof of deletion. |
| `Not checked` | The app has no acceptable web evidence. Cleanup is blocked for this row. |

The collector first looks for requested IDs in active, starred, and archived metadata. List presence protects a row; list absence proves nothing. Only IDs still unknown receive direct checks. A JSON `404` is accepted as unavailable only for a row bound to the verified personal user, without project or working-directory context, and with a separately confirmed direct JSON `200` control under the same local host. A host without that positive control cannot authorize negative evidence.

A plain local row without deletion evidence that passes those unavailable checks becomes `Review` even if its local missing flag is false. A missing flag alone never proves deletion. Web-present rows, project-context rows, foreign-account rows, and unverifiable rows cannot pass the cleanup gate. Account mismatches, incomplete responses, rate limits, and inconsistent results block cleanup.

Comparison proof expires after five minutes and is invalidated by rescanning or source changes. A connected login alone does not authorize cleanup. See the [observed browser contract](docs/browser-contract.md) for the versioned evidence format and validation details.

## Clean selected local entries

Cleanup is available on Windows and macOS only, after the catalog and web checks pass.

1. Review each eligible entry, acknowledge any `Review` rows, and select the entries to remove.
2. Click `Backup folder` to inspect or edit the folder path in the popup, following the rules below.
3. Quit the ChatGPT desktop app and its native helpers yourself; keep the connected browser open. The Chrome extension and Codex CUA runtimes can remain running. While entries are selected, the cleaner quietly checks desktop-app status automatically. A running or unknown status blocks cleanup; use `Retry` if the status is unknown, or `Check list` if the web comparison needs refreshing.
4. Press the large `Clean up N` button pinned at the bottom of the window to open the confirmation dialog. It explains the local catalog change and backup. Choose `Cancel` to keep the selection without cleaning, or `Clean up N` to proceed. Changes to the selection, review, source, backup folder, or web comparison invalidate an open dialog; the app rechecks prerequisites before accepting confirmation.
5. Keep the app open until the operation ends. Retain the backup path and the displayed receipt details, including the SHA-256 hash and before/after row counts. There is no receipt export or automatic restore command.

| Platform | Backup folder requirement |
| --- | --- |
| Windows | An existing writable directory that resolves to the canonical parent of the scanned database. Other folders are refused. |
| macOS | An existing writable directory with no group or other permissions, or a new directory directly under an existing writable parent. The app creates the new directory with private permissions. |

Symlinks and non-directory paths are refused. The app does not create missing intermediate parents.

Before changing data, the worker repeats web comparison. The repair engine rechecks the source and process state, creates and verifies a full SQLite backup, and removes only selected `(host_id, thread_id)` identities in a guarded transaction. It checks row counts, integrity, foreign keys, and process state before commit, then verifies the committed state. An uncertain commit or verification result requires inspection using the preserved backup; do not assume nothing changed or immediately retry. The implementation is in [src/repair.rs](src/repair.rs).

### Recover from a backup

A backup is a snapshot of the entire database, including tables beyond the catalog. Restoring it can discard unrelated changes made afterward. There is no restore button.

Close ChatGPT, this utility, and every other database user before recovery. Preserve the current state with a SQLite-aware backup, retain the original verified backup, and check its integrity and receipt hash. Have a knowledgeable operator restore through SQLite's backup/restore facilities and verify integrity before reopening the app. Do not overwrite only the `.db` file while ignoring `-wal` or `-shm` sidecars, or delete sidecars as a shortcut. SQLite's [Online Backup API](https://sqlite.org/backup.html) and [WAL lifecycle](https://sqlite.org/wal.html#the_wal_file) describe the underlying recovery considerations.

## Saved login and privacy

The app creates a dedicated, persistent profile for the current default browser product. It does not attach to your ordinary profile or copy its cookies. Interactive login starts without debugging or automation flags. Comparison reopens the dedicated profile with a random loopback-only debugging port after the login browser exits successfully.

Browser-managed cookies and session state stay in that profile. Authentication-only checks return an authenticated boolean. Comparison returns sanitized account identity, requested conversation IDs, per-ID evidence, and positive-control IDs. Browser-executed code processes authentication and metadata; the native Rust app does not read cookie stores or receive tokens, passwords, authorization headers, or conversation bodies. Displayed titles come from the local catalog. Direct conversation checks cancel response bodies without parsing them, but some bytes may already have arrived in the browser. Loopback debugging remains privileged local access; it does not protect against malware running as the same OS user.

Saved profiles are stored separately from the executable, under `browser-profiles/<product>`, where `<product>` is `edge`, `chrome`, or `chromium`:

| Platform | Application data root |
| --- | --- |
| macOS | `$HOME/Library/Application Support/Ghost Chat Cleaner` |
| Windows | `%LOCALAPPDATA%\Ghost Chat Cleaner` |
| Linux | Absolute `$XDG_DATA_HOME/ghost-chat-cleaner`, otherwise `$HOME/.local/share/ghost-chat-cleaner` |

Normal app quit closes its owned browser and preserves login. On restart, an existing profile is reauthenticated; a readiness marker is not current authentication proof. Press `Disconnect` to invalidate comparison proof and delete the active app-owned profile after its browser exit is confirmed. Without an active session, disconnect targets the current default product's saved profile. Other products' profiles, ordinary browser profiles, and catalog data remain untouched.

Closing the dedicated login browser leaves the app waiting for an explicit `Check list`. Confirmed exit of the comparison browser clears connection and comparison proof without reopening it automatically. If a browser tab or target is lost, an explicit check enables reconnection through `Log in`. An ordinary comparison failure retains the connection for manual retry; expired authentication requires login again.

Profile conflicts and unsafe storage block reuse. Do not manually remove `.ghost-chat-cleaner-browser-active` or the sibling `browser-locks/<product>.lock` to bypass an error. The [browser lifecycle and profile contract](docs/browser-contract.md#browser-login-lifecycle) documents recovery rules and the exact ownership boundaries.

## Catalog compatibility and local evidence

Read support requires a `local_thread_catalog` table with text-affinity `host_id`, `thread_id`, `display_title`, and `source_kind` columns. Only `source_kind = 'chatgpt'` rows are displayed.

Cleanup additionally requires compatible `project_id`, `cwd`, `missing_candidate`, and `source_recency_at` columns, the exact primary key order `(host_id, thread_id)`, and no triggers on the target table or foreign keys into or out of it. Unknown or incompatible schemas stay read-only or produce an unsupported-schema result. Project and working-directory context, invalid identifiers, and untrusted classification fields are preserved. Schema support is based on inspected structure, not a promised ChatGPT or Codex version. See [src/catalog.rs](src/catalog.rs).

Local evidence must contain the exact bounded thread identifier and a bounded, case-sensitive `conversation_deleted` or `conversation deleted` marker on the same line. Supported text extensions are `.log`, `.txt`, `.json`, `.jsonl`, and `.ndjson`. Recency, byte, traversal, and path checks limit discovery; symlinks and unsafe path changes are refused. Shared thread IDs cannot be automatically confirmed from host-ambiguous evidence. These markers are local heuristics that require review. See [src/evidence.rs](src/evidence.rs).

## Build and package

From the checkout, use Rust with rustfmt and Clippy, plus Node.js for the collector fixture tests:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
node --test tests/web_collector.test.cjs
cargo build --locked --release
```

Tests use synthetic fixtures and fake process probes. A release build produces `target/release/ghost-chat-cleaner` on macOS/Linux or `target/release/ghost-chat-cleaner.exe` on Windows. SQLite is bundled through the [Cargo dependency configuration](Cargo.toml).

After building on the target OS, run its packaging script. Python 3 and cached Cargo dependencies are required to assemble dependency notices.

```sh
# macOS: creates a .app.zip archive
bash scripts/package-macos.sh

# Linux: creates a .tar.gz archive
bash scripts/package-linux.sh
```

```powershell
# Windows: creates a .zip archive
./scripts/package-windows.ps1
```

The scripts package an existing release executable; they do not build or launch it. Archives go to `dist/`, with version, OS, and architecture in the filename. An existing archive is not overwritten. macOS uses `ditto`, Linux uses `tar`, and Windows uses PowerShell `Compress-Archive`.

For a custom target directory or binary, supply paths and the matching architecture:

```sh
bash scripts/package-macos.sh path/to/ghost-chat-cleaner path/to/output aarch64
bash scripts/package-linux.sh path/to/ghost-chat-cleaner path/to/output x86_64
```

```powershell
./scripts/package-windows.ps1 -BinaryPath path/to/ghost-chat-cleaner.exe -OutputDirectory path/to/output -Architecture x86_64
```

The architecture argument labels the supplied binary; it does not cross-compile. Shell scripts accept `x86_64`, `aarch64`, or `arm64` (normalized to `aarch64`); PowerShell accepts `x86_64` or `aarch64`. The default is the packaging host's architecture.

Extract the archive and launch its executable or macOS app bundle. To use demo mode from an extracted package:

```sh
# macOS
"./Ghost Chat Cleaner.app/Contents/MacOS/ghost-chat-cleaner" --demo
# Linux
./ghost-chat-cleaner --demo
```

```powershell
# Windows
.\ghost-chat-cleaner.exe --demo
```

Portable means extraction and launch without an installer or background service. Packages remain architecture-specific and rely on OS graphics/runtime libraries; they are not universal binaries.

### CI and unsigned distribution

The [portable build workflow](.github/workflows/release-build.yml) is configured for Windows x86_64, Linux x86_64, macOS Apple silicon, and macOS Intel. It runs formatting, Clippy, synthetic tests, release builds, and packaging on pull requests, `main` pushes, `v*` tags, and manual dispatch, then uploads workflow artifacts. Configured jobs are not evidence that every platform has passed a live runtime check.

The packaging scripts and workflow provide no publisher signing or notarization. Archives are unsigned distribution artifacts; follow your organization's software policy and verify their origin before running them. There is no installer, background service, or automatic release publication in this workflow.

## Maintenance and feedback

Report reproducible problems or propose improvements through [GitHub Issues](https://github.com/AidALL/Ghost-Chat-Cleaner/issues). Include the OS, architecture, build or commit, exact error label, and steps to reproduce. Use synthetic examples and redact account identifiers; do not attach catalog databases, conversation titles, saved browser profiles, credentials, or raw private logs. The project author is garlicvread. For private contact, email [ceo@aidall.tech](mailto:ceo@aidall.tech).

Browser compatibility changes should update the [observed contract](docs/browser-contract.md) and collector fixtures together. A successful build or fixture test alone does not establish authenticated runtime compatibility.

## License and notices

Project source is distributed under the [MIT License](LICENSE). The embedded, unmodified Nanum Gothic font is distributed under the [SIL Open Font License](assets/fonts/nanumgothic/OFL.txt); [font provenance](assets/fonts/nanumgothic/PROVENANCE.md) records its source and revision. Dependencies and fonts retain their own licenses.

Portable archives include the English and Korean READMEs, project license, font license and provenance, and `THIRD_PARTY_NOTICES.txt` for the target's dependencies and default fonts. These documents live in `Contents/Resources` on macOS, or beside the executable on Windows/Linux, with Nanum Gothic notices under `licenses/nanumgothic`. Packaging generates dependency notices offline from the locked Cargo graph and [upstream references](licenses/upstream); missing notices or changed reference hashes stop packaging.
