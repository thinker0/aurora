# Changelog

All notable changes to Aurora Scheduler are documented here.

---

## [Unreleased]

### Changed

#### JDK 21 & Gradle 8.9 Support

All 1,344 tests now pass under JDK 21 (`BUILD SUCCESSFUL`).

**Build toolchain**

- Upgraded Gradle wrapper `7.6.4 → 8.9` to support JDK 21 compilation and testing.
- Upgraded `com.github.hierynomus.license` plugin `0.15.0 → 0.16.1` to fix Gradle 8.8+
  strict task-property-annotation validation that caused `licenseJmh` to fail the build.
- Fixed UI `lint` task: replaced the overly-broad `outputs.files(fileTree('.'))` with
  `outputs.upToDateWhen { true }` and added `lint.mustRunAfter('webpack')` to satisfy
  Gradle 8.x implicit-dependency validation between `lint`, `webpack`, `jar`, and
  `processResources`.

**Test dependencies**

- Upgraded EasyMock `4.3 → 5.2.0`. EasyMock 4.3's bundled cglib/ASM cannot read
  JDK 21 class files (major version 65); EasyMock 5.x replaces cglib with ByteBuddy.
- Removed unused PowerMock `2.0.9` dependency (`powermock-module-junit4`,
  `powermock-api-easymock`) — no test actually used it.
- Forced `net.bytebuddy:byte-buddy` and `byte-buddy-agent` to `1.14.18` to resolve the
  version conflict between EasyMock 5.x (`1.14.9`) and Guice 5.1.0 (`1.12.10`) under
  Gradle's `failOnVersionConflict()`.

**Test fixes**

- `Kerberos5ShiroRealmModuleTest`: replaced `createMock(GSSManager.class)` with a
  concrete anonymous subclass. EasyMock 5.x + ByteBuddy cannot proxy JDK classes in
  restricted modules (`java.security.jgss`) via `VarHandle` — even with `--add-opens`.
- `CuratorSingletonServiceTest.testDefeatTransition`: used a dedicated
  `startNewClient()` for host1's leader session instead of the shared `getClient()`.
  JDK 21's faster NIO closes the TCP connection before `NODE_DELETED` watcher events
  are delivered, causing the `CuratorCache` to miss events when the shared client is
  expired.

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

### Fixed

#### Thermos Proxy

- **503 on storage not ready** — `ThermosProxyServlet` now returns `503 Service Unavailable`
  instead of `404 Not Found` when the scheduler storage is still in `PREPARED` state (snapshot /
  log replay in progress during startup or leader re-election).
  `TransientStorageException` is unwrapped from Guava's `UncheckedExecutionException` and
  re-thrown so that `service()` can respond with the correct status code.

- **Duplicate `Date` header** — `filterServerResponseHeader` now drops the upstream Thermos
  `Date` header so Jetty manages a single authoritative `Date` on the response, preventing
  two `Date` headers from reaching the client.

- **Sensitive upstream headers leaked** — Added filtering of `Server`, `Set-Cookie`,
  `Set-Cookie2`, and `X-Powered-By` from upstream Thermos responses to prevent leaking
  internal server information. Also added RFC 7230 §5.7.1 compliant `Via` header appended
  in `onServerResponseHeaders`.

#### Local / Dev Environment

- **`FakeMaster` offer cycle** — `declineOffer` now returns `Status.DRIVER_RUNNING` instead
  of throwing `UnsupportedOperationException`, allowing the simulated offer cycle to complete
  without crashing the local scheduler.

- **`LocalSchedulerMain` startup** — Default scheduler flags are added conditionally to
  prevent duplicate option errors when arguments are already provided on the command line.

- **`FakeMaster` MasterInfo fields** — `MasterInfo.getDefaultInstance()` produced an empty
  protobuf missing required fields (`id`, `ip`, `port`), causing
  `UninitializedMessageException` in `ProtosConversion.convert()` and cascading failures on
  the first resource offer. Required fields are now populated correctly.

#### Python / Thrift Codegen

- **Python 3 iterator exhaustion in thrift codegen** — `thrift_wrapper_codegen.py` wrapped
  `map()` calls with `list()` so `struct.fields` can be iterated multiple times. Without this
  fix, the exhausted iterator produced empty `field_names`, generating `return ;` in the
  `equals()` / `hashCode()` methods of generated Java classes.

#### UI

- **Webpack 4 peer dependency conflict** — `css-loader` downgraded from `^7.1.4` to `^4.3.0`
  and `style-loader` from `^4.0.0` to `^2.0.0` to restore compatibility with the existing
  webpack `^4.44.0` build; v7/v4 of those loaders require webpack 5.

- **Babel 6 / Jest 21 compatibility** — Jest pinned back to `^21.2.1` and `babel-core` pinned
  to `^6.26.3` to prevent version conflicts; all 144 UI unit tests pass.

- **minimatch branch collision** — Resolved `minimatch` version collision and restored correct
  loader versions (`npm overrides` patching `minimatch`, `node-notifier`, `postcss`, `qs`,
  `semver`, `tough-cookie`, `get-intrinsic`, `cheerio`).

### Changed

#### Python 3 Migration

- Pants configuration updated to require CPython ≥ 3.6; Docker images in documentation,
  examples, and end-to-end tests updated to Python 3.8.
- Thrift entities codegen (`checkPython` task, `thrift_wrapper_codegen.py` shebang) now
  enforces Python 3 throughout the build.
- Script shebangs and documentation updated to reflect the Python 3 requirement.

### Security

#### Java Dependencies

- **Netty** updated to `4.1.108.Final` — addresses multiple CVEs in prior versions.
- **Apache ZooKeeper** updated to `3.9.2` — security and stability improvements.
- **Guava** updated to `31.1-jre` — resolves variant selection issues in Gradle 6.9 while
  maintaining security patches.
- **RestEasy** `3.15.6.Final`, **Jackson** `2.15.2`, **Apache HttpClient** `4.5.14` —
  security patch updates; JAX-RS bumped to `2.1.1` for compatibility.

#### Python Dependencies

- **Bottle** updated to `0.12.25`, **Requests** updated to `2.31.0`.

#### npm / UI Dependencies

- **minimatch** `3.1.2 → 3.1.5` (CVE fix).
- **moment** `^2.30.1`, **bootstrap** `^3.4.1` updated via `npm audit fix`.
- **postcss** `7.0.39 → 8.5.6`, **sassjs-loader** `1.0.0 → 2.0.0`, **ajv** `6.12.6 → 6.14.0`,
  **url-loader** `0.6.2 → 4.1.1`; `qs` and `tough-cookie` removed (no longer required after
  ancestor dependency updates).
- Node.js build image updated to `20.18.1` for compatibility with updated library versions.

---
