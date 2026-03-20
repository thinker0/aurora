/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.aurora.scheduler.http.api.security;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

import org.apache.aurora.scheduler.http.AbstractFilter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

/**
 * Servlet filter implementing OAuth2 Authorization Code Flow for Web UI protection.
 *
 * <p>Paths listed in {@code -oauth2_exclude_paths} (default: /vars, /health, /leaderhealth,
 * /apiclient) bypass the browser-redirect flow but still have Bearer token and session cookie
 * validated when present. The {@code /api} Thrift endpoint is intentionally NOT excluded so
 * that write operations are authorised via Shiro. The callback path {@code /oauth2/callback}
 * is handled internally. All other paths require a valid session cookie; absent or expired
 * cookies trigger a redirect to the configured OIDC provider.
 */
public class OAuth2Filter extends AbstractFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2Filter.class);
  private static final String CALLBACK_PATH = "/oauth2/callback";
  private static final String CLI_AUTHORIZE_PATH = "/oauth2/cli-authorize";
  private static final String DEVICE_AUTHORIZE_PATH = "/oauth2/device-authorize";
  private static final String DEVICE_TOKEN_PATH = "/oauth2/device-token";
  private static final String STATE_COOKIE = "oauth2_state";
  private static final String ORIGINAL_PATH_ATTRIBUTE = "originalPath";
  private static final String OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";
  private static final String CLI_STATE_PREFIX = "cli:";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  // Cache for validated Bearer tokens: maps token → authenticated username (email or sub).
  // Guava evicts entries after 5 minutes and caps at 10 000 to prevent OOM.
  private final Cache<String, String> bearerTokenCache = CacheBuilder.newBuilder()
      .expireAfterWrite(5, TimeUnit.MINUTES)
      .maximumSize(10_000)
      .build();

  // Single-use tracking for issued proxy_device_codes. Entries expire after 10 minutes (matching
  // the maximum device flow expiry). Each code is removed on first use to prevent replay attacks.
  private final Cache<String, Boolean> issuedProxyCodes = CacheBuilder.newBuilder()
      .expireAfterWrite(10, TimeUnit.MINUTES)
      .maximumSize(10_000)
      .build();

  private final String issuerUrl;
  private final String clientId;
  private final String clientSecret;
  private final String redirectUri;
  private final List<String> excludePaths;
  private final String cookieName;
  private final OAuth2SessionManager sessionManager;
  private final HttpClient httpClient;
  private volatile boolean discoveryComplete = false;
  private volatile String authorizationEndpoint;
  private volatile String tokenEndpoint;
  private volatile String userinfoEndpoint;
  // nullable — provider may not support Device Authorization Flow
  private volatile String deviceAuthorizationEndpoint;

  @Inject
  OAuth2Filter(HttpSecurityModule.Options options, OAuth2SessionManager sessionManager) {
    this(options, sessionManager, HttpClient.newHttpClient());
  }

  // Visible for testing
  OAuth2Filter(
      HttpSecurityModule.Options options,
      OAuth2SessionManager sessionManager,
      HttpClient httpClient) {
    requireNonNull(options);
    this.issuerUrl = requireNonNull(options.oauth2IssuerUrl, "oauth2_issuer_url is required");
    this.clientId = requireNonNull(options.oauth2ClientId, "oauth2_client_id is required");
    this.clientSecret =
        requireNonNull(options.oauth2ClientSecret, "oauth2_client_secret is required");
    this.redirectUri =
        requireNonNull(options.oauth2RedirectUri, "oauth2_redirect_uri is required");
    validateHttpsOrLocalhostHttp(this.issuerUrl, "oauth2_issuer_url");
    validateHttpsOrLocalhostHttp(this.redirectUri, "oauth2_redirect_uri");
    this.excludePaths = requireNonNull(options.oauth2ExcludePaths);
    this.cookieName = requireNonNull(options.oauth2CookieName);
    this.sessionManager = requireNonNull(sessionManager);
    this.httpClient = requireNonNull(httpClient);
  }

  private static void validateHttpsOrLocalhostHttp(String url, String optionName) {
    URI parsed = URI.create(url);
    String scheme = parsed.getScheme();
    if ("https".equalsIgnoreCase(scheme)) {
      return;
    }
    if ("http".equalsIgnoreCase(scheme) && isLoopbackHost(parsed.getHost())) {
      return;
    }
    throw new IllegalArgumentException(optionName + " must use https (localhost may use http): " + url);
  }

  private static boolean isLoopbackHost(String host) {
    if (host == null) {
      return false;
    }
    return "localhost".equalsIgnoreCase(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host);
  }

  private boolean shouldUseSecureCookies(HttpServletRequest request) {
    if (request.isSecure()) {
      return true;
    }
    String forwardedProto = request.getHeader("X-Forwarded-Proto");
    return forwardedProto != null && "https".equalsIgnoreCase(forwardedProto);
  }

  private synchronized boolean ensureEndpoints() {
    if (discoveryComplete) {
      return authorizationEndpoint != null && tokenEndpoint != null && userinfoEndpoint != null;
    }
    try {
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(issuerUrl + OPENID_CONFIGURATION_PATH))
          .GET()
          .build();
      HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() != 200) {
        LOG.warn("OIDC discovery returned HTTP {}", resp.statusCode());
        return false;
      }
      Map<String, Object> discovery = MAPPER.readValue(
          resp.body(), new TypeReference<Map<String, Object>>() { });
      authorizationEndpoint = asEndpoint(discovery, "authorization_endpoint");
      tokenEndpoint = asEndpoint(discovery, "token_endpoint");
      userinfoEndpoint = asEndpoint(discovery, "userinfo_endpoint");
      // Optional — not all providers support Device Authorization Flow.
      deviceAuthorizationEndpoint = asEndpoint(discovery, "device_authorization_endpoint");
      if (authorizationEndpoint == null || tokenEndpoint == null || userinfoEndpoint == null) {
        LOG.warn("OIDC discovery missing required endpoints");
        return false;
      }
      // Only mark discovery complete once all required endpoints are confirmed valid.
      // Leaving discoveryComplete=false on partial failure allows retry on next request.
      discoveryComplete = true;
      return true;
    } catch (Exception e) {
      LOG.error("OIDC discovery failed", e);
      return false;
    }
  }

  private static String asEndpoint(Map<String, Object> discovery, String key) {
    Object value = discovery.get(key);
    if (!(value instanceof String)) {
      return null;
    }
    String endpoint = (String) value;
    // Validate that discovered endpoints use HTTPS (or loopback HTTP for dev).
    // This prevents SSRF if the OIDC provider returns a malicious endpoint URL.
    try {
      validateHttpsOrLocalhostHttp(endpoint, key);
    } catch (IllegalArgumentException e) {
      LOG.warn("OIDC discovery returned insecure endpoint for {}: {}", key, endpoint);
      return null;
    }
    return endpoint;
  }

  @Override
  protected void doFilter(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    // If an upstream filter (e.g. TrustedHeaderAuthFilter in OAUTH2_PROXY mode) already
    // authenticated the Shiro subject, skip the OAuth2 cookie/redirect flow entirely.
    try {
      Subject subject = SecurityUtils.getSubject();
      if (subject != null && subject.isAuthenticated()) {
        chain.doFilter(request, response);
        return;
      }
    } catch (org.apache.shiro.UnavailableSecurityManagerException ignored) {
      // No Shiro SecurityManager bound (e.g. unit tests); proceed with normal OAuth2 flow.
    }

    String path = request.getRequestURI();

    // OAuth2 protocol paths are handled directly — no auth token required.
    if (path.equals(CALLBACK_PATH)) {
      handleCallback(request, response);
      return;
    }

    if (path.startsWith(CLI_AUTHORIZE_PATH)) {
      handleCliAuthorize(request, response);
      return;
    }

    if (path.equals(DEVICE_AUTHORIZE_PATH)) {
      handleDeviceAuthorize(request, response);
      return;
    }

    if (path.equals(DEVICE_TOKEN_PATH)) {
      handleDeviceToken(request, response);
      return;
    }

    // Validate credentials for ALL paths — including those in oauth2ExcludePaths such as /api.
    // Excluded paths bypass the browser-redirect flow but must still authenticate programmatic
    // clients (CLI Thrift calls via SESSION_TOKEN or Bearer token).

    // Accept Authorization: Bearer <oidc-access-token> for programmatic clients (CLI, API).
    String authHeader = request.getHeader("Authorization");
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      String bearerToken = authHeader.substring(7).trim();
      Optional<String> bearerUser = validateBearerToken(bearerToken);
      if (bearerUser.isPresent() && loginShiroSubject(bearerUser.get())) {
        chain.doFilter(request, response);
        return;
      }
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Bearer token");
      return;
    }

    Optional<String> sessionToken = getSessionCookie(request);
    if (sessionToken.isPresent()) {
      Optional<Map<String, Object>> sessionData = sessionManager.validate(sessionToken.get());
      if (sessionData.isPresent()) {
        String username = extractUsername(sessionData.get());
        if (username != null && loginShiroSubject(username)) {
          chain.doFilter(request, response);
          return;
        }
        // Invalid session claims or Shiro login failed — fall through.
      }
    }

    // Excluded paths (/api, /vars, /health, …) pass through without auth — no OIDC redirect.
    // Per-method enforcement for /api is handled by ShiroAuthenticatingThriftInterceptor.
    if (isExcludedPath(path)) {
      chain.doFilter(request, response);
      return;
    }

    initiateLogin(request, response);
  }

  private boolean isExcludedPath(String path) {
    for (String prefix : excludePaths) {
      if (path.equals(prefix) || path.startsWith(prefix + "/")) {
        return true;
      }
    }
    return false;
  }

  /**
   * Extracts the username (email preferred, sub as fallback) from OIDC claims.
   * Returns {@code null} if neither field is present or both are empty strings.
   */
  private static String extractUsername(Map<String, Object> claims) {
    Object email = claims.get("email");
    if (email instanceof String && !((String) email).isEmpty()) {
      return (String) email;
    }
    Object sub = claims.get("sub");
    if (sub instanceof String && !((String) sub).isEmpty()) {
      return (String) sub;
    }
    return null;
  }

  /**
   * Validates an OIDC Bearer token via the userinfo endpoint and returns the username.
   * Results are cached (Guava, 5-minute TTL, max 10 000 entries) to reduce OIDC provider load.
   *
   * @return the authenticated username (email, or sub if email absent), or empty if invalid.
   */
  private Optional<String> validateBearerToken(String token) {
    String cached = bearerTokenCache.getIfPresent(token);
    if (cached != null) {
      return Optional.of(cached);
    }
    if (!ensureEndpoints()) {
      return Optional.empty();
    }
    Map<String, Object> userInfo = getUserInfo(token);
    if (userInfo != null) {
      String username = extractUsername(userInfo);
      if (username == null) {
        return Optional.empty();
      }
      bearerTokenCache.put(token, username);
      return Optional.of(username);
    }
    return Optional.empty();
  }

  /**
   * Logs the given username into the Shiro Subject so that write-protected Thrift methods
   * (guarded by {@link ShiroAuthenticatingThriftInterceptor}) can authorize the request.
   * Uses the same pattern as {@link TrustedHeaderAuthFilter}.
   *
   * @return {@code true} if login succeeded (or no SecurityManager in test env),
   *         {@code false} if {@link org.apache.shiro.authc.AuthenticationException} was thrown.
   */
  private boolean loginShiroSubject(String username) {
    try {
      Subject shiroSubject = SecurityUtils.getSubject();
      if (!shiroSubject.isAuthenticated()) {
        shiroSubject.login(new UsernamePasswordToken(username, ""));
        LOG.debug("Shiro login for user: {}", username);
      }
      return true;
    } catch (org.apache.shiro.UnavailableSecurityManagerException ignored) {
      // No Shiro SecurityManager bound (e.g. unit tests); allow through.
      return true;
    } catch (Exception e) {
      LOG.warn("Shiro login failed for user {}: {}", username, e.getMessage());
      return false;
    }
  }

  /**
   * Handles {@code GET /oauth2/cli-authorize?local_port=PORT}.
   * Starts the Authorization Code flow using the scheduler's registered redirect_uri,
   * encoding the CLI local port into the OAuth2 state so the callback can redirect the
   * {@code aurora_token} back to the CLI's local HTTP server.
   */
  private void handleCliAuthorize(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    String localPortStr = request.getParameter("local_port");
    if (localPortStr == null) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "local_port parameter required");
      return;
    }
    int localPort;
    try {
      localPort = Integer.parseInt(localPortStr);
    } catch (NumberFormatException e) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid local_port");
      return;
    }
    if (localPort < 1 || localPort > 65535) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "local_port out of range");
      return;
    }
    if (!ensureEndpoints()) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");
      return;
    }

    // Encode "cli:<port>" as the originalUrl so handleCallback() can detect the CLI flow.
    String stateData = CLI_STATE_PREFIX + localPort + "|" + UUID.randomUUID();
    String stateValue = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(stateData.getBytes(StandardCharsets.UTF_8));

    Cookie stateCookie = new Cookie(STATE_COOKIE, stateValue);
    stateCookie.setHttpOnly(true);
    stateCookie.setMaxAge(300);
    stateCookie.setPath("/");
    stateCookie.setSecure(shouldUseSecureCookies(request));
    response.addCookie(stateCookie);

    String authUrl = authorizationEndpoint
        + "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
        + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
        + "&response_type=code"
        + "&scope=openid+email+profile"
        + "&state=" + stateValue;

    response.sendRedirect(authUrl);
  }

  /**
   * Handles {@code POST /oauth2/device-authorize}.
   * Proxies the Device Authorization request to the OIDC provider, replacing the real
   * {@code device_code} with an HMAC-signed {@code proxy_device_code} so the CLI client
   * never sees the real code or the {@code client_secret}.
   */
  private void handleDeviceAuthorize(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      sendJsonError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST required");
      return;
    }
    if (!ensureEndpoints()) {
      sendJsonError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");
      return;
    }
    if (deviceAuthorizationEndpoint == null) {
      sendJsonError(response, HttpServletResponse.SC_NOT_IMPLEMENTED,
          "OIDC provider does not support Device Authorization Flow");
      return;
    }

    String scope = request.getParameter("scope");
    if (scope == null || scope.isEmpty()) {
      scope = "openid email profile";
    }

    String body = "client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
        + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
        + "&scope=" + URLEncoder.encode(scope, StandardCharsets.UTF_8);

    HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create(deviceAuthorizationEndpoint))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();

    HttpResponse<String> resp;
    try {
      resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
    } catch (Exception e) {
      LOG.error("Device authorization request failed", e);
      sendJsonError(response, HttpServletResponse.SC_BAD_GATEWAY,
          "Device authorization request failed");
      return;
    }

    if (resp.statusCode() != 200) {
      LOG.warn("Device authorization returned HTTP {}", resp.statusCode());
      forwardOidcError(response, resp.statusCode(), resp.body());
      return;
    }

    Map<String, Object> dr;
    try {
      dr = MAPPER.readValue(resp.body(), new TypeReference<Map<String, Object>>() { });
    } catch (Exception e) {
      LOG.error("Failed to parse device authorization response", e);
      sendJsonError(response, HttpServletResponse.SC_BAD_GATEWAY,
          "Invalid device authorization response");
      return;
    }

    String deviceCode = (String) dr.get("device_code");
    if (deviceCode == null) {
      sendJsonError(response, HttpServletResponse.SC_BAD_GATEWAY, "No device_code in response");
      return;
    }

    // Replace real device_code with proxy_device_code (HMAC-signed opaque token).
    // Register in the single-use cache to prevent replay attacks.
    String proxyDeviceCode = sessionManager.createProxyDeviceToken(deviceCode);
    issuedProxyCodes.put(proxyDeviceCode, Boolean.TRUE);
    dr.remove("device_code");
    dr.put("proxy_device_code", proxyDeviceCode);

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().write(MAPPER.writeValueAsString(dr));
  }

  /**
   * Handles {@code POST /oauth2/device-token}.
   * Accepts a {@code proxy_device_code}, verifies its HMAC, polls the OIDC token endpoint
   * with the real credentials, and — on success — returns an {@code aurora_token} (scheduler
   * session cookie value) instead of raw OIDC tokens.
   */
  private void handleDeviceToken(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (!"POST".equalsIgnoreCase(request.getMethod())) {
      sendJsonError(response, HttpServletResponse.SC_METHOD_NOT_ALLOWED, "POST required");
      return;
    }
    if (!ensureEndpoints()) {
      sendJsonError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");
      return;
    }

    String proxyDeviceCode = request.getParameter("proxy_device_code");
    if (proxyDeviceCode == null || proxyDeviceCode.isEmpty()) {
      sendJsonError(response, HttpServletResponse.SC_BAD_REQUEST, "proxy_device_code required");
      return;
    }

    // Verify HMAC signature and check single-use cache to prevent replay attacks.
    Optional<String> deviceCodeOpt = sessionManager.extractVerifiedDeviceCode(proxyDeviceCode);
    if (!deviceCodeOpt.isPresent() || issuedProxyCodes.getIfPresent(proxyDeviceCode) == null) {
      sendJsonError(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid proxy_device_code");
      return;
    }
    // Invalidate immediately — each proxy_device_code is single-use.
    issuedProxyCodes.invalidate(proxyDeviceCode);
    String deviceCode = deviceCodeOpt.get();

    String body = "grant_type="
        + URLEncoder.encode(
            "urn:ietf:params:oauth:grant-type:device_code", StandardCharsets.UTF_8)
        + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
        + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
        + "&device_code=" + URLEncoder.encode(deviceCode, StandardCharsets.UTF_8);

    HttpRequest req = HttpRequest.newBuilder()
        .uri(URI.create(tokenEndpoint))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();

    HttpResponse<String> resp;
    try {
      resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
    } catch (Exception e) {
      LOG.error("Device token poll failed", e);
      sendJsonError(response, HttpServletResponse.SC_BAD_GATEWAY, "Device token poll failed");
      return;
    }

    // Pass-through pending/slow_down/expired errors — sanitized to only OIDC error fields.
    if (resp.statusCode() != 200) {
      forwardOidcError(response, resp.statusCode(), resp.body());
      return;
    }

    Map<String, Object> tokenData;
    try {
      tokenData = MAPPER.readValue(resp.body(), new TypeReference<Map<String, Object>>() { });
    } catch (Exception e) {
      LOG.error("Failed to parse token response", e);
      sendJsonError(response, HttpServletResponse.SC_BAD_GATEWAY, "Invalid token response");
      return;
    }

    String accessToken = (String) tokenData.get("access_token");
    if (accessToken == null) {
      sendJsonError(response, HttpServletResponse.SC_BAD_GATEWAY, "No access_token in response");
      return;
    }

    Map<String, Object> userInfo = getUserInfo(accessToken);
    if (userInfo == null) {
      sendJsonError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "UserInfo fetch failed");
      return;
    }

    String sub   = userInfo.get("sub")   instanceof String ? (String) userInfo.get("sub")   : "";
    String email = userInfo.get("email") instanceof String ? (String) userInfo.get("email") : "";
    if (sub.isEmpty() && email.isEmpty()) {
      sendJsonError(response, HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "UserInfo missing required claims");
      return;
    }
    long nowSecs = System.currentTimeMillis() / 1000L;
    String auroraToken = sessionManager.create(sub, email, nowSecs);

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("aurora_token", auroraToken);
    result.put("expires_in", sessionManager.getSessionTimeoutSecs());

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_OK);
    response.getWriter().write(MAPPER.writeValueAsString(result));
  }

  private void sendJsonError(HttpServletResponse response, int status, String message)
      throws IOException {
    response.setContentType("application/json");
    response.setStatus(status);
    response.getWriter().write(MAPPER.writeValueAsString(Map.of("error", message)));
  }

  /**
   * Forwards a non-200 OIDC upstream response to the client, extracting only the
   * {@code error} and {@code error_description} fields to avoid leaking internal server details.
   * If the upstream body is not valid JSON, a generic {@code upstream_error} is returned.
   */
  private void forwardOidcError(HttpServletResponse response, int status, String upstreamBody)
      throws IOException {
    Map<String, Object> safe = new LinkedHashMap<>();
    try {
      Map<String, Object> upstream = MAPPER.readValue(
          upstreamBody, new TypeReference<Map<String, Object>>() { });
      if (upstream.containsKey("error")) {
        safe.put("error", upstream.get("error"));
      }
      if (upstream.containsKey("error_description")) {
        safe.put("error_description", upstream.get("error_description"));
      }
    } catch (Exception ignored) {
      // Non-JSON upstream response — return a generic error.
    }
    if (safe.isEmpty()) {
      safe.put("error", "upstream_error");
    }
    response.setContentType("application/json");
    response.setStatus(status);
    response.getWriter().write(MAPPER.writeValueAsString(safe));
  }

  private Optional<String> getSessionCookie(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    for (Cookie cookie : cookies) {
      if (cookieName.equals(cookie.getName())) {
        return Optional.of(cookie.getValue());
      }
    }
    return Optional.empty();
  }

  private String getStateCookieValue(HttpServletRequest request) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return null;
    }
    for (Cookie cookie : cookies) {
      if (STATE_COOKIE.equals(cookie.getName())) {
        return cookie.getValue();
      }
    }
    return null;
  }

  private void handleCallback(HttpServletRequest request, HttpServletResponse response)
      throws IOException {

    String code = request.getParameter("code");
    String state = request.getParameter("state");
    if (!ensureEndpoints()) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");
      return;
    }

    if (code == null || state == null) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing code or state");
      return;
    }

    String stateCookieValue = getStateCookieValue(request);
    if (!state.equals(stateCookieValue)) {
      response.sendError(HttpServletResponse.SC_BAD_REQUEST, "State mismatch (CSRF check failed)");
      return;
    }

    String tokenJson = exchangeCodeForToken(code);
    if (tokenJson == null) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Token exchange failed");
      return;
    }

    Map<String, Object> tokenData;
    try {
      tokenData = MAPPER.readValue(tokenJson, new TypeReference<Map<String, Object>>() { });
    } catch (Exception e) {
      LOG.error("Failed to parse token response", e);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Invalid token response");
      return;
    }

    String accessToken = (String) tokenData.get("access_token");
    if (accessToken == null) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "No access_token received");
      return;
    }

    Map<String, Object> userInfo = getUserInfo(accessToken);
    if (userInfo == null) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "UserInfo fetch failed");
      return;
    }

    String sub   = userInfo.get("sub")   instanceof String ? (String) userInfo.get("sub")   : "";
    String email = userInfo.get("email") instanceof String ? (String) userInfo.get("email") : "";
    if (sub.isEmpty() && email.isEmpty()) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
          "UserInfo missing required claims");
      return;
    }
    long nowSecs = System.currentTimeMillis() / 1000L;
    String sessionToken = sessionManager.create(sub, email, nowSecs);
    boolean secureCookies = shouldUseSecureCookies(request);

    Cookie sessionCookie = new Cookie(cookieName, sessionToken);
    sessionCookie.setHttpOnly(true);
    sessionCookie.setPath("/");
    sessionCookie.setSecure(secureCookies);
    response.addCookie(sessionCookie);

    Cookie clearState = new Cookie(STATE_COOKIE, "");
    clearState.setMaxAge(0);
    clearState.setPath("/");
    clearState.setHttpOnly(true);
    clearState.setSecure(secureCookies);
    response.addCookie(clearState);

    String originalUrl = decodeOriginalUrl(state);
    if (originalUrl != null && originalUrl.startsWith(CLI_STATE_PREFIX)) {
      // CLI browser flow: redirect aurora_token back to the local callback server.
      try {
        int localPort = Integer.parseInt(originalUrl.substring(CLI_STATE_PREFIX.length()));
        String cliRedirect = "http://localhost:" + localPort
            + "/callback?aurora_token="
            + URLEncoder.encode(sessionToken, StandardCharsets.UTF_8);
        response.sendRedirect(cliRedirect);
      } catch (NumberFormatException e) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid CLI port in state");
      }
      return;
    }
    response.sendRedirect(originalUrl != null ? originalUrl : "/");
  }

  private String decodeOriginalUrl(String state) {
    try {
      String decoded = new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8);
      // CLI flow: "cli:<port>|<nonce>" — return "cli:<port>" as the originalUrl marker.
      if (decoded.startsWith(CLI_STATE_PREFIX)) {
        int sep = decoded.indexOf('|');
        return sep > 0 ? decoded.substring(0, sep) : decoded;
      }
      int sep = decoded.lastIndexOf('|');
      String original = sep > 0 ? decoded.substring(0, sep) : decoded;
      // Scheduler UI is served from /scheduler/, but unauthenticated requests can resolve to the
      // static asset entrypoint. Redirecting back to the asset path after login can render a blank
      // page, so normalize those cases to the UI root.
      if ("/assets/scheduler/index.html".equals(original)
          || "/assets/scheduler/".equals(original)
          || "/assets/index.html".equals(original)
          || original.startsWith("/assets/scheduler/index.html?")) {
        return "/scheduler/";
      }
      return original;
    } catch (Exception e) {
      return null;
    }
  }

  private String exchangeCodeForToken(String code) {
    try {
      String body = "grant_type=authorization_code"
          + "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8)
          + "&client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
          + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8)
          + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);

      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(tokenEndpoint))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .build();

      HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() == 200) {
        return resp.body();
      }
      LOG.warn("Token exchange returned HTTP {}", resp.statusCode());
      return null;
    } catch (Exception e) {
      LOG.error("Token exchange error", e);
      return null;
    }
  }

  private Map<String, Object> getUserInfo(String accessToken) {
    try {
      HttpRequest req = HttpRequest.newBuilder()
          .uri(URI.create(userinfoEndpoint))
          .header("Authorization", "Bearer " + accessToken)
          .GET()
          .build();

      HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
      if (resp.statusCode() == 200) {
        return MAPPER.readValue(resp.body(), new TypeReference<Map<String, Object>>() { });
      }
      LOG.warn("UserInfo returned HTTP {}", resp.statusCode());
      return null;
    } catch (Exception e) {
      LOG.error("UserInfo fetch error", e);
      return null;
    }
  }

  private void initiateLogin(HttpServletRequest request, HttpServletResponse response)
      throws IOException {
    if (!ensureEndpoints()) {
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");
      return;
    }

    String originalUrl = getOriginalRequestPath(request);
    String queryString = request.getQueryString();
    if (queryString != null) {
      originalUrl = originalUrl + "?" + queryString;
    }

    String nonce = UUID.randomUUID().toString();
    String stateValue = Base64.getUrlEncoder().withoutPadding()
        .encodeToString((originalUrl + "|" + nonce).getBytes(StandardCharsets.UTF_8));

    Cookie stateCookie = new Cookie(STATE_COOKIE, stateValue);
    stateCookie.setHttpOnly(true);
    stateCookie.setMaxAge(300);
    stateCookie.setPath("/");
    stateCookie.setSecure(shouldUseSecureCookies(request));
    response.addCookie(stateCookie);

    String authUrl = authorizationEndpoint
        + "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
        + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
        + "&response_type=code"
        + "&scope=openid+email+profile"
        + "&state=" + stateValue;

    response.sendRedirect(authUrl);
  }

  private String getOriginalRequestPath(HttpServletRequest request) {
    Object originalPath = request.getAttribute(ORIGINAL_PATH_ATTRIBUTE);
    if (originalPath instanceof String && !((String) originalPath).isEmpty()) {
      return (String) originalPath;
    }
    return request.getRequestURI();
  }
}
