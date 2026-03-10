# Changelog

All notable changes to Aurora Scheduler are documented here.

---

## [Unreleased]

### Added

#### OAuth2 / OIDC Authentication for Web UI (`feature/support-oauth2`)

Aurora's Web UI can now be protected with OAuth2 Authorization Code Flow using any OIDC-compatible
identity provider (Keycloak, Okta, Auth0, etc.).  Activate it by setting
`-http_authentication_mechanism=OAUTH2`.

**New CLI flags** (all in `HttpSecurityModule.Options`):

| Flag | Default | Description |
|------|---------|-------------|
| `-oauth2_issuer_url` | _(required)_ | OIDC issuer base URL |
| `-oauth2_client_id` | _(required)_ | Client ID at the identity provider |
| `-oauth2_client_secret` | _(required)_ | Client secret |
| `-oauth2_redirect_uri` | _(required)_ | Callback URL registered in the provider |
| `-oauth2_jwt_secret` | _(required)_ | HMAC-SHA256 signing secret for session cookies (≥ 32 chars) |
| `-oauth2_exclude_paths` | `/api,/vars,/health,/apiclient` | Path prefixes that bypass OAuth2 |
| `-oauth2_cookie_name` | `aurora_token` | Name of the issued session cookie |
| `-oauth2_session_timeout_secs` | `28800` (8 h) | Session cookie validity in seconds |

**New files:**

- `src/main/java/org/apache/aurora/scheduler/http/api/security/OAuth2Filter.java`
  Servlet filter implementing the full Authorization Code Flow:
  excluded-path passthrough → callback handling (CSRF state cookie, code exchange, userinfo fetch,
  session-cookie issuance) → session validation → provider redirect.

- `src/main/java/org/apache/aurora/scheduler/http/api/security/OAuth2SessionManager.java`
  Compact JWT session manager using HMAC-SHA256 (`javax.crypto.Mac`).
  Issues and validates `base64url(header).base64url(payload).base64url(signature)` tokens
  with `sub`, `email`, `iat`, and `exp` claims.

**Modified files:**

- `src/main/java/org/apache/aurora/scheduler/http/api/security/HttpSecurityModule.java`
  - Added `OAUTH2` value to `HttpAuthenticationMechanism` enum.
  - Added eight OAuth2 `@Parameter` fields to the inner `Options` class.
  - Stored the `Options` reference in the module for use at binding time.
  - Added an OAUTH2 branch in `configureServlets()` that binds `OAuth2SessionManager` and
    `OAuth2Filter` as singletons and registers `filter("/*").through(OAuth2Filter.class)`.
    Shiro modules and Thrift AOP interceptors are intentionally not installed in this mode.

- `src/test/java/org/apache/aurora/scheduler/config/CommandLineTest.java`
  - Extended `testParseAllOptions` with non-default values and CLI strings for all eight new flags.
  - Extended `testEmptyListOptions` with an empty `oauth2ExcludePaths` case.

**Design decisions:**

- No new runtime dependencies: HTTP calls use Java 11's built-in `java.net.http.HttpClient`;
  JSON parsing reuses the existing `jackson-databind` dependency.
- CSRF is prevented via a per-login state cookie (HttpOnly, 5-minute TTL) that encodes the
  original URL and a random nonce in base64url.
- Excluded paths (`/api`, `/vars`, `/health`, `/apiclient` by default) pass through the filter
  unchanged, preserving compatibility with Thrift API clients and monitoring probes.

---
