# DecentAuth project notes

## Purpose

This file is the project's durable, high-level memory. It records the most
important completed work, current status, decisions and trade-offs, and future
direction so that contributors do not have to reconstruct that context from the
commit history.

Keep it concise and focused on information that will remain useful. Detailed
unresolved security findings and exploit information are intentionally kept in
a private, free-floating security review rather than this repository. After an
issue is mitigated, the resulting behavior and lasting design decisions can be
summarized here.

## Current status

DecentAuth is a Rust authentication library with native and WASM/Extism build
targets. It currently includes OIDC, AT Protocol, Fediverse, email, admin-code,
QR, bearer-token, and session functionality. FedCM remains in the source tree
for future development but is disabled at both server dispatch and UI rendering.

The current security-remediation baseline includes:

- OIDC login accepts only an exact provider URI configured in
  `Config.login_methods`; request-supplied providers cannot initiate discovery.
- OAuth authorization-server endpoints enforce GET for metadata/authorization
  and POST for approval/token exchange.
- QR endpoints enforce GET for display and POST for approval/finalization.
- Successful QR finalization removes its pending state, preventing sequential
  reuse.
- Focused regression tests cover these boundaries in both direct handler and
  server-level paths.

At this baseline, `cargo test --all --all-targets --locked` passes 18 tests and
the `wasm32-wasip1` release build succeeds. Known pre-existing compiler warnings
remain outside this focused remediation work.

## Recent work

- Replaced project-specific dependency forks with upstream releases.
- Preserved AT Protocol OAuth state across request boundaries using the KV
  backend and delete it after callback use.
- Added custom session data and bearer-token session lookup.
- Disabled unfinished FedCM authentication without deleting its implementation,
  allowing it to be completed deliberately later.
- Added exact OIDC provider allowlisting while preserving the existing
  configuration and template interface.
- Added method enforcement and regression coverage for browser-facing OAuth and
  QR state transitions.

## Decisions and trade-offs

- **Configured OIDC providers are matched as exact strings.** This is simple,
  fail-closed, and preserves the current UI. URL normalization and dynamic
  provider discovery are intentionally deferred.
- **FedCM stays compiled but disabled.** Keeping the implementation makes later
  development easier, while re-enablement requires a deliberate code change and
  renewed security review.
- **Browser state changes rely on correct HTTP methods plus the explicit
  `SameSite=Lax` session cookie for the current baseline.** Stronger defense in
  depth remains desirable, but was deferred to keep the immediate changes small
  and compatible.
- **Security fixes are kept narrow.** Larger protocol redesigns and general
  cleanup should be separate changes with their own tests and migration review.
- **Sensitive unresolved findings stay outside the repository.** This document
  records mitigated outcomes and architectural direction, not an exploit
  backlog.

## Future direction

- Introduce reusable lifecycle support for transient authentication state,
  including expiration and atomic state transitions.
- Add defense in depth for browser approval and consent flows, such as
  server-held request state and explicit same-origin/CSRF validation.
- Complete session expiration and revocation semantics, including meaningful
  server-side logout.
- Continue clarifying provider-qualified identity and account-linking semantics
  before expanding multi-provider behavior.
- Finish FedCM only after its provider trust, response validation, and state
  model have been fully specified and tested.
- Upgrade older dependency stacks, keep advisories reviewed, and add automated
  dependency auditing to CI.
- Expand malformed-input, replay, concurrency, and protocol regression tests as
  shared storage primitives improve.

## Verification baseline

The main validation commands are:

```sh
cargo test --all --all-targets --locked
cargo build --target wasm32-wasip1 --release --locked
```

Security-sensitive changes should add focused regression tests in addition to
passing this baseline.
