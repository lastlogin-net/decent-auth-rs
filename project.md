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
