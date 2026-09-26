# Dependency refresh (2026-09)

The project no longer needs sibling `../atrium` and `../ramhorns` checkouts. Build
from this repository alone with `cargo build --all-targets --locked`,
`cargo test --all-targets --locked`, and
`cargo build --target wasm32-wasip1 --release --locked` (install the WASI target
with `rustup target add wasm32-wasip1`). Native builds need OpenSSL headers,
`pkg-config`, and SQLite headers for the example.

## Forks and upstream

- **atrium**: the `anderspitman/atrium` `custom-oauth-state` commit `4a30115`
  modified `authorize` to use an application-supplied OAuth nonce. The
  published `atrium-oauth` 0.1.7 has a different solution: it generates its
  own nonce and persists `AuthorizeOptions.state` as `app_state` in its state
  store. `callback` returns the app state along with the OAuth session. We
  now pass the DecentAuth return target as app state and retrieve it only
  after successful callback. ATProto crates are from crates.io (`atrium-api`
  0.25.8, `atrium-xrpc` 0.12.4, `atrium-common` 0.1.4,
  `atrium-identity` 0.1.9, `atrium-oauth` 0.1.7). The OAuth state store uses the
  existing KV backend and now deletes state on callback (previously a no-op).
  The upstream OAuth session's tokens are held only in a temporary in-memory
  session store: DecentAuth uses the DID for login, not those access tokens.
- **ramhorns**: the upstream 1.0.1 crate does not have the local fork's
  `Ramhorns::new()` method. The templates use only embedded `header.html` and
  `footer.html` partials, so `Templater` expands these before parsing with
  the upstream `Template::new()`. No filesystem access is required at runtime
  (including WASM). If adding partials, update the embedded-template logic.

`Cargo.lock` was also refreshed with `cargo update` to the latest compatible
versions. This does **not** include incompatible major-version migrations
(such as `openidconnect` 4, `oauth2` 5, `axum` 0.8, `reqwest` 0.13,
`rusqlite` 0.40, or `rand` 0.10). `kv::Store` now requires `Send + Sync +
'static` so ATProto OAuth can own a shared KV backend across requests.

## Remaining verification / review

Automated tests cover the embedded templates and KV-backed OAuth-state
round-trip/deletion. Native/example and WASM builds pass. Live ATProto OAuth,
Extism host behavior, and cross-version in-flight login migration have **not**
been tested: logins started with the old fork's state format will need to be
restarted after deployment. A broader dependency major-version migration and
the full security/code review remain separate follow-up work.
