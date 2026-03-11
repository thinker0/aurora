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

import javax.inject.Inject;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.aurora.scheduler.http.AbstractFilter;
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
  private static final String STATE_COOKIE = "oauth2_state";
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final String issuerUrl;
  private final String clientId;
  private final String clientSecret;
  private final String redirectUri;
  private final List<String> excludePaths;
  private final String cookieName;
  private final OAuth2SessionManager sessionManager;
  private final HttpClient httpClient;

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
    this.excludePaths = requireNonNull(options.oauth2ExcludePaths);
    this.cookieName = requireNonNull(options.oauth2CookieName);
    this.sessionManager = requireNonNull(sessionManager);
    this.httpClient = requireNonNull(httpClient);
  }

  @Override
  protected void doFilter(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    String path = request.getRequestURI();

    if (isExcludedPath(path)) {
      chain.doFilter(request, response);
      return;
    }

    if (path.equals(CALLBACK_PATH)) {
      handleCallback(request, response);
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

    Cookie sessionCookie = new Cookie(cookieName, sessionToken);
    sessionCookie.setHttpOnly(true);
    sessionCookie.setPath("/");
    response.addCookie(sessionCookie);

    Cookie clearState = new Cookie(STATE_COOKIE, "");
    clearState.setMaxAge(0);
    clearState.setPath("/");
    response.addCookie(clearState);

    String originalUrl = decodeOriginalUrl(state);
    response.sendRedirect(originalUrl != null ? originalUrl : "/");
  }

  private String decodeOriginalUrl(String state) {
    try {
      String decoded = new String(Base64.getUrlDecoder().decode(state), StandardCharsets.UTF_8);
      int sep = decoded.lastIndexOf('|');
      return sep > 0 ? decoded.substring(0, sep) : decoded;
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
          .uri(URI.create(issuerUrl + "/protocol/openid-connect/token"))
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
          .uri(URI.create(issuerUrl + "/protocol/openid-connect/userinfo"))
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

    String originalUrl = request.getRequestURI();
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
    response.addCookie(stateCookie);

    String authUrl = issuerUrl + "/protocol/openid-connect/auth"
        + "?client_id=" + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
        + "&redirect_uri=" + URLEncoder.encode(redirectUri, StandardCharsets.UTF_8)
        + "&response_type=code"
        + "&scope=openid+email+profile"
        + "&state=" + stateValue;

    response.sendRedirect(authUrl);
  }
}
