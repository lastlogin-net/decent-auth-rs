# OAuth hardening: planned work

The built-in OAuth authorization-server endpoints currently enforce HTTP
methods (`GET` for discovery and authorize, `POST` for approve and token).
The only cross-site protection on the approval flow today is the session
cookie's `SameSite=Lax` attribute. The items below are planned future work;
none of them are implemented yet.

## Pending approvals

- Stop trusting the browser-supplied hidden `auth_url` field. When the
  authorization endpoint renders the approval page, persist a short-lived
  server-side pending-approval record and put only an unpredictable one-time
  ID in the form.
- Bind that record to the authenticated identity/session and to the validated
  client ID and redirect URI. Consume it atomically (get-and-delete) at
  approval time and expire it with a short TTL, so a forged or replayed
  approval has no server-side state to act on.

## CSRF defense in depth

- Add an explicit per-session CSRF token to the approval form and validate it
  on `POST /oauth/approve`.
- Add same-origin `Origin`/`Sec-Fetch-Site` (Fetch Metadata) validation as a
  second layer instead of relying solely on `SameSite=Lax`.
- Residual risks to keep in mind: `SameSite=Lax` still sends cookies on
  top-level cross-site GET navigations, and sibling subdomains are treated as
  same-site. A page on an attacker-controlled sibling can therefore submit
  requests to the auth host that carry the auth host's Lax cookies. Also, when
  `id_header_name` is configured, the authenticated identity comes from an
  upstream request header, so the deployment's reverse proxy must strip and
  overwrite that header on all external requests.

## Authorization code binding

- Bind each authorization code to the client ID, the exact redirect URI, and
  the S256 PKCE challenge (when supplied).
- At token exchange, require the matching client and redirect URI and verify
  the PKCE code verifier against the stored challenge before issuing a
  session. Keep codes single-use and short-lived.

# QR login hardening: planned work

The QR endpoints now enforce HTTP methods (`GET` for `<path_prefix>/qr`,
`POST` for approval and finalization) and successful finalization deletes the
pending QR state, so a key cannot be finalized sequentially a second time.
The only cross-site protection on approval today is still the session cookie's
`SameSite=Lax` attribute. The items below are planned future work; none of
them are implemented yet.

## Separate approval and finalization secrets

- The QR key is currently reused for both approval and finalization, so any
  device that can read the QR code (for example a screen-sharing or video
  capture) can also finalize it. Put only a separate approval secret in the
  QR code, and keep a distinct finalization secret on the initiating device
  that is never displayed or transmitted to the approving device.
- Consider showing requesting-device context (user agent, IP/network region,
  or a short code) on the approval page so the approving user can confirm the
  request is theirs.

## State lifetime

- Give pending and approved QR state a short TTL and sweep expired entries,
  so abandoned or leaked keys stop working quickly even if never consumed.

## Atomic consumption

- The `Store` trait has no atomic take/get-and-delete. Finalization therefore
  only prevents sequential replay; two concurrent finalizations of the same
  key can both read the approved state before either deletes it. Add an atomic
  take/get-and-delete operation to the trait and consume the pending state
  with it before issuing a session, so exactly one finalization can win.
