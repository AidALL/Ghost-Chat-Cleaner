# Observed browser metadata contract

The collector in `assets/web/collect.js` uses ChatGPT's own web routes. The
observations below were made on 2026-09-06 by reading public JavaScript assets
whose URLs were obtained from the current browser DOM. No authenticated API
response, token, or conversation body was retained for this research.

These observations describe a particular client build. They are not a guarantee
that the routes or identity fields will remain compatible.
An unexpected response must block cleanup rather than become absence evidence.

## Primary sources and locations

Offsets refer to zero-based character positions in the minified source, not
lines or byte positions. The hashes identify the retrieved UTF-8 asset bytes.

| Source | SHA-256 |
| --- | --- |
| [Main client asset](https://chatgpt.com/cdn/assets/4813494d-hrplraurzfyvxb10.js) | `89c95d937bac1191e91d5ceb4872eb0c328d39a98ce05399093a663f18921aa0` |
| [Conversation asset](https://chatgpt.com/cdn/assets/conversation-small-hiw4wce20lu6te81.js) | `296ec15ad991764de750c55f3c85b1643c8f385236b9402168fa4348696e37d1` |

| Observation | Locator |
| --- | --- |
| Session fetch uses `/api/auth/session` and consumes a string `accessToken`. | Main asset, `nse`, offset 203371. |
| Account bootstrap uses `/backend-api/accounts/check/v4-2023-04-27`; ordering keys select entries with nested `account.account_id`, `account.account_user_id`, and `account.structure`. | Main asset, `kx`, offset 567330; `jje`, offset 568826; account-mapping assignment `cMe=On(...)`; version at 55803. |
| Structure values are `personal` and `workspace`. Personal account-user identity normalizes to the bare user ID. | Main asset, enum at 27772; getters at 577716 and 585081. |
| Current account selection checks token claim `https://api.openai.com/auth.chatgpt_account_id`; the lightweight account identity reads session `user.id`. | Main asset, functions `Es` and `Wje`; assignment `Jx=Sn(...)`. |
| Conversation metadata uses offset pagination, archive/star filters and updated ordering. The next page compares offset plus limit with the current page's total. | Main asset, `Bdt`, offset 1342281; next-page calculation at 1343039. |
| Direct conversation reading uses GET `/backend-api/conversation/{conversation_id}`. The client calls 404 `not_found`, not deleted. Shared-project reads may add project and owner headers. | Conversation asset, `qy`, offset 414692; direct GET at 416007. |

The official Codex source also distinguishes ChatGPT user and workspace account
identifiers. Its [token parser](https://github.com/openai/codex/blob/main/codex-rs/login/src/token_data.rs),
`AuthClaims` and `parse_chatgpt_jwt_claims`, reads `chatgpt_user_id` with `user_id`
as a fallback. This is source evidence for that fallback, not evidence that every
web token contains both fields.

## Collector choices

The native app requests validated conversation UUIDs. Inside the browser, the
collector validates the session user, token user claim, token account ID, and
one canonical matching account among accessible entries selected by the server's
validated `account_ordering`. Repeated representations of the same account ID
are accepted only when every matching entry satisfies the same strict user
binding and personal-account checks. Conflicting aliases remain blocked. It
rejects conflicting identity claims and does not switch workspaces.
Personal account-user IDs must equal either the bare user ID or that user ID
qualified with the exact account ID. The session identity is checked again at
the end.

The collector first searches paginated active, starred and archived metadata for requested IDs. A listed ID is positive evidence that protects the corresponding local row. Changing totals, overlap between pages and a bounded page budget cannot create absence evidence. Enumeration stops when every requested ID is found or its budget is exhausted. IDs still unknown receive direct GETs. Only JSON-typed 200 or 404 direct responses become evidence. The collector cancels each direct response body without parsing it. No HEAD or metadata-only direct-conversation option was established; body cancellation does not promise that the server transmitted no body bytes. This process does not establish a complete account-history snapshot.

After checking all requested IDs, the collector selects a positive ID for each local-host group containing a negative result, when such a positive exists. Reused controls are deduplicated. Every selected control must return direct JSON 200 after all initial statuses are known: listed controls combine metadata presence with the direct endpoint; directly checked controls require a second successful GET. Host identifiers remain in Rust; only groups of requested IDs enter the collector. A JSON 404 becomes `Unavailable` only when its row matches the verified personal user, carries neither project nor working-directory context, and has a confirmed positive control under that same exact local host. A host without such a control cannot authorize negative evidence. All-positive results need no controls. Blanket negative results without any positive control are rejected. Either list presence or direct JSON 200 preserves the corresponding local row even when its local host is not bound to the authenticated user.

The result has `schema_version: 3` and `kind: "requested_metadata_checks"`. Its `complete` field means that every requested ID received evidence; it does not mean that account history was fully enumerated. The payload contains sanitized identity fields, `checks` with each requested ID and `authenticated_list_item`, `authenticated_json_get_200` or `authenticated_json_get_404`, and `controls` containing the independently confirmed positive IDs. Native validation rejects missing, duplicate or unrequested checks, invalid controls, unsupported versions, and unknown payload fields.

Only those sanitized identity fields, per-ID evidence and control IDs leave browser execution. Conversation titles are read from the local catalog and are not exported by the collector. Session JSON, tokens, authorization headers, error response bodies, and conversation bodies are not returned to the native app. Implementation locations are `assets/web/collect.js` (`collectChatMetadata`) and `src/web.rs` (`WebComparison::from_value`).

The collector reads at most 100 metadata pages and limits each direct-check phase to four concurrent requests. The
initial status checks finish before selected controls start; final session validation
runs after every control settles. The first failure stops scheduling, aborts
remaining requests, and awaits their cancellation. Only its own deadline is
reported as a collection timeout. No partial proof is returned.

## Meaning of unavailable

HTTP 404 is evidence that a conversation is unavailable in the checked account
and request context. It does not establish server deletion. Missing project
context or changed access can also affect lookup. Web evidence therefore does
not replace local classification, manual-review requirements, backup creation,
or the exact-row transaction guards.

No inspected primary source defines the UUID component of
`chatgpt:<uuid>:<user-id>`. The native proof treats it as opaque, requires the
validated personal user suffix, and requires a separately confirmed direct JSON 200 control under the same local host before accepting that host's direct JSON 404 results. List absence never substitutes for that direct negative check or its control. The native proof must not reinterpret the opaque UUID as a verified workspace ID.

The synthetic regression suite is `tests/web_collector.test.cjs`. Native browser
transport, proof validation, and transaction checks are separate layers; a
passing collector test does not establish a successful authenticated live run.

## Browser login lifecycle

The system default HTTPS handler is resolved through native OS association APIs (bounded `xdg-settings` on Linux). Unsupported defaults and launcher wrappers fail explicitly. The app uses separate persistent profiles for `edge`, `chrome`, and `chromium`; it neither attaches to nor copies the user's ordinary browser profile.

Interactive login starts in the app-owned profile without debugging or automation flags. While the UI is idle and the login window is pending, it periodically checks only the owned process's exit status without interrupting it or refreshing the website. Successful normal exit moves the UI to Awaiting verification and stops login polling; it does not start authentication or reopen the browser. The explicit list-check action starts authentication and reopens the same profile in the normal browser with loopback CDP when needed. A failed or unconfirmed login-process exit does not trigger comparison. On macOS, an explicit list-check action may request normal termination of the still-owned login PID and wait for its successful exit; it does not force-kill the login browser to perform this handoff.

`BrowserSession::authenticate` runs `collectChatMetadata([], true)` on the selected `https://chatgpt.com` page. The shared collector validates the session, token/user/account binding, server acceptance of the authenticated account request, canonical account aliases, personal-account context, and final session consistency inside the browser. It does not independently check a token expiry claim. Rust accepts only the exact successful authentication result `{ "authenticated": true }`; credentials and identity details are not returned by this authentication-only call. Success records the profile as eligible for later restoration. This record is not current login proof or conversation-comparison evidence.

Before running the collector, the transport waits within the startup deadline for a committed, top-level ChatGPT document in an interactive or complete state. An initial empty target list, a sole blank page, or a loading ChatGPT document can be transient; a foreign origin, subframe, ambiguous target or changed pinned target is rejected. The collector is not retried after navigation. Exception diagnostics use fixed classifications and never include the browser's exception descriptions.

Live startup requests restoration once. `BrowserSession::restore` resolves the current supported default browser, opens its existing profile without creating missing storage, and attempts server authentication even when no readiness marker was recorded before shutdown. An existing malformed readiness marker remains an error. Missing storage returns no session; browser-resolution errors, unsafe storage, and profile conflicts are explicit failures. The worker authenticates a restored session again. A valid saved login therefore needs neither a new login window nor another user-requested browser quit.

The UI distinguishes Disconnected, Login in progress, Connecting, Awaiting verification, Connected, and Login required. Opening a login window does not establish authentication. The list-check action is available during idle login, while connected, or when an installed session awaits explicit verification, even without a loaded report. Known readiness, server-denial, rate-limit, and network failures can retain only that unverified session for an explicit retry; they retain no comparison proof and trigger no automatic authentication retry or browser reopening. Account and schema mismatches remain blocked. The explicit action completes authentication, then loads an explicit source or discovers and loads a sole candidate, and compares once. Errors, ambiguous discovery, source changes and disconnect cancel that pending action. Quiet process probes cannot suppress the explicit action or overwrite it with stale results. Once authentication succeeds without a pending list action, an available scan starts one comparison automatically; otherwise the next successful scan does so. A transient comparison failure clears comparison proof but retains the connection; an authentication-expiry error revokes the connection's authenticated state and proof. Disconnect invalidates proof immediately, and stale job completions cannot restore it. Cleanup still requires the separate requested-ID comparison and all existing local guards.

After the comparison browser has started, idle lifecycle checks inspect only that owned child's exit status. Its exit moves the UI to Disconnected, clears comparison proof and any pending list-check action, and stops further monitoring. It does not reopen a browser or delete saved profile data. An explicit Login action starts a new dedicated login browser using the saved profile. A failed operation that observes the comparison child has already exited also drops the connection instead of presenting an authentication retry for a dead process. Lifecycle implementation is in `src/browser_transport.rs` (`login_window_closed`, `comparison_browser_closed`), `src/worker.rs` (`map_browser_failure`) and `src/app_state.rs`/`src/app.rs` (browser events and pending-action handling).

If an explicit request discovers a missing, changed, or ambiguous ChatGPT target,
the UI clears comparison proof and enables Login for explicit reconnection. This
does not claim that the browser process exited or that stored login expired.
A failed CDP socket can be reconnected on the next explicit request only to the
same still-owned browser endpoint; the original target ID remains pinned and
receives a new attachment session. This path never spawns a replacement browser.

## Saved profile ownership and recovery

Profiles live under `browser-profiles/<product>` in the per-user application root:

| Platform | Application root |
| --- | --- |
| macOS | `$HOME/Library/Application Support/Ghost Chat Cleaner` |
| Windows | `%LOCALAPPDATA%\Ghost Chat Cleaner` |
| Linux | Absolute `$XDG_DATA_HOME/ghost-chat-cleaner`, otherwise `$HOME/.local/share/ghost-chat-cleaner` |

The browser can persist its cookies and session state there. Native code handles paths, locks and format-only control markers; it does not read or export browser cookie stores or tokens. An exclusive sibling `browser-locks/<product>.lock` serializes cleaner access. Ownership markers, path identity checks, symlink/reparse-point rejection, and Unix private-permission checks guard reuse and deletion. Changing browser products does not migrate the saved session.

Normal cleaner shutdown closes only its owned browser and retains the profile. Explicit Disconnect closes that owned browser, confirms termination, and deletes only its owned profile. With no live session, it attempts to clear the current default product's saved profile under the same ownership, lock and idle checks. Other products' profiles, ordinary browser profiles, catalog data, and sibling lock files are retained.

Before each browser spawn, `.ghost-chat-cleaner-browser-active` records pending use durably. Successful spawning atomically replaces it with a bounded v2 record containing the owned PID. Normal cleanup requires confirmed owned-child exit or failed spawn. Unix reopening under the exclusive profile lock may recover a v2 record only when `kill(pid, 0)` reports `ESRCH`, followed by revalidation of the locked path and marker inode. Live or reused PIDs, permission failures, uncertain outcomes, malformed records, pending/legacy records, and Windows recovery remain blocked. This recovery never terminates or attaches to an existing process and preserves browser-managed login data.

Implementation locations: `src/browser_profile.rs` (`open_at`, `begin_browser_use`, `end_browser_use`, `clear`), `src/browser_transport.rs` (`restore`, `authenticate`, `disconnect`, `OwnedBrowser::drop`), and `src/app.rs`/`src/worker.rs` (startup restore, polling and event handling).

## Verification limit

Local Computer Use verification exercised the macOS Apple-silicon app with a real browser login and a catalog opened read-only. Saved authentication restored without credential entry and the requested comparison completed, showing web-present rows protected from selection. Normal app quit was observed with the cleaner stopped and its owned browser absent. Relaunching the unchanged executable restored login and completed comparison again. This is evidence for the tested account and application build, not a guarantee of continued endpoint compatibility. No real cleanup was performed; repair protections remain fixture-tested. Other platform runtimes were not exercised locally.

Google documents that automated browsers may be denied sign-in: https://support.google.com/accounts/answer/7675428?hl=en (sign-in restrictions). Chromium documents that closing windows does not necessarily end the browser process: https://chromium.googlesource.com/chromium/src/+/main/docs/shutdown.md (Step 0/1). No default profile is copied and no login detector is spoofed.
