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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.aurora.scheduler.http.AbstractFilter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

/**
 * Servlet filter implementing OAuth2 Authorization Code Flow for Web UI protection.
 *
 * <p>Paths listed in {@code -oauth2_exclude_paths} (default: /api, /vars, /health, /apiclient)
 * bypass authentication. The callback path {@code /oauth2/callback} is handled internally.
 * All other paths require a valid session cookie; absent or expired cookies trigger a redirect
 * to the configured OIDC provider.
 */
public class OAuth2Filter extends AbstractFilter {

  private static final Logger LOG = LoggerFactory.getLogger(OAuth2Filter.class);
  private static final String CALLBACK_PATH = "/oauth2/callback";
  private static final String CLI_AUTHORIZE_PATH = "/oauth2/cli-authorize";
  private static final String STATE_COOKIE = "oauth2_state";
  private static final String ORIGINAL_PATH_ATTRIBUTE = "originalPath";
  private static final String OPENID_CONFIGURATION_PATH = "/.well-known/openid-configuration";
  private static final String CLI_STATE_PREFIX = "cli:";
  private static final long BEARER_CACHE_TTL_MS = 5 * 60 * 1000L;
  private static final ObjectMapper MAPPER = new ObjectMapper();

  // Cache for validated Bearer tokens: token → expiry timestamp (ms)
  private final ConcurrentHashMap<String, Long> bearerTokenCache = new ConcurrentHashMap<>();

  private final String issuerUrl;
  private final String clientId;
  private final String clientSecret;
  private final String redirectUri;
  private final List<String> excludePaths;
  private final String cookieName;
  private final OAuth2SessionManager sessionManager;
  private final HttpClient httpClient;
  private volatile String authorizationEndpoint;
  private volatile String tokenEndpoint;
  private volatile String userinfoEndpoint;

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
    if (authorizationEndpoint != null && tokenEndpoint != null && userinfoEndpoint != null) {
      return true;
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
      if (authorizationEndpoint == null || tokenEndpoint == null || userinfoEndpoint == null) {
        LOG.warn("OIDC discovery missing required endpoints");
        return false;
      }
      return true;
    } catch (Exception e) {
      LOG.error("OIDC discovery failed", e);
      return false;
    }
  }

  private static String asEndpoint(Map<String, Object> discovery, String key) {
    Object value = discovery.get(key);
    return value instanceof String ? (String) value : null;
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

    if (isExcludedPath(path)) {
      chain.doFilter(request, response);
      return;
    }

    if (path.equals(CALLBACK_PATH)) {
      handleCallback(request, response);
      return;
    }

    if (path.startsWith(CLI_AUTHORIZE_PATH)) {
      handleCliAuthorize(request, response);
      return;
    }

    // Accept Authorization: Bearer <oidc-access-token> for programmatic clients (CLI, API).
    String authHeader = request.getHeader("Authorization");
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      String bearerToken = authHeader.substring(7).trim();
      if (isValidBearerToken(bearerToken)) {
        chain.doFilter(request, response);
        return;
      }
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Bearer token");
      return;
    }

    Optional<String> sessionToken = getSessionCookie(request);
    if (sessionToken.isPresent() && sessionManager.validate(sessionToken.get()).isPresent()) {
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
   * Validates an OIDC Bearer token via the userinfo endpoint.
   * Results are cached for {@link #BEARER_CACHE_TTL_MS} to reduce OIDC provider load.
   */
  private boolean isValidBearerToken(String token) {
    Long expiry = bearerTokenCache.get(token);
    if (expiry != null && System.currentTimeMillis() < expiry) {
      return true;
    }
    // Evict expired entries lazily to prevent unbounded growth.
    bearerTokenCache.entrySet().removeIf(e -> System.currentTimeMillis() >= e.getValue());

    if (!ensureEndpoints()) {
      return false;
    }
    Map<String, Object> userInfo = getUserInfo(token);
    if (userInfo != null) {
      bearerTokenCache.put(token, System.currentTimeMillis() + BEARER_CACHE_TTL_MS);
      return true;
    }
    return false;
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

    String sub = (String) userInfo.getOrDefault("sub", "");
    String email = (String) userInfo.getOrDefault("email", "");
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
            + "/cli-callback?aurora_token="
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
