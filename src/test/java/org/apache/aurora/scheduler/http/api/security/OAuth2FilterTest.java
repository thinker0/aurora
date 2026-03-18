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

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.scheduler.http.api.security.HttpSecurityModule.Options;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyLong;
import static org.easymock.EasyMock.eq;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;

public class OAuth2FilterTest extends EasyMockTest {

  private static final String ISSUER_URL = "https://auth.example.com/realms/test";
  private static final String CLIENT_ID = "aurora-client";
  private static final String CLIENT_SECRET = "secret";
  private static final String REDIRECT_URI = "https://aurora.example.com/oauth2/callback";
  private static final String SESSION_TOKEN = "valid.session.token";
  private static final String DISCOVERY_JSON =
      "{\"authorization_endpoint\":\"https://auth.example.com/auth\","
          + "\"token_endpoint\":\"https://auth.example.com/token\","
          + "\"userinfo_endpoint\":\"https://auth.example.com/userinfo\"}";

  private HttpServletRequest request;
  private HttpServletResponse response;
  private FilterChain chain;
  private OAuth2SessionManager sessionManager;
  private HttpClient httpClient;
  private OAuth2Filter filter;

  @Before
  public void setUp() {
    request = createMock(HttpServletRequest.class);
    response = createMock(HttpServletResponse.class);
    chain = createMock(FilterChain.class);
    sessionManager = createMock(OAuth2SessionManager.class);
    httpClient = createMock(HttpClient.class);

    Options options = new Options();
    options.oauth2IssuerUrl = ISSUER_URL;
    options.oauth2ClientId = CLIENT_ID;
    options.oauth2ClientSecret = CLIENT_SECRET;
    options.oauth2RedirectUri = REDIRECT_URI;
    options.oauth2ExcludePaths = Arrays.asList("/api", "/vars", "/health");
    options.oauth2CookieName = "aurora_token";
    options.oauth2JwtSecret = "test-secret-32-chars-minimum-length!";
    options.oauth2SessionTimeoutSecs = 3600L;

    filter = new OAuth2Filter(options, sessionManager, httpClient);
    expect(request.isSecure()).andStubReturn(true);
    expect(request.getAttribute("originalPath")).andStubReturn(null);
  }

  @Test
  public void testExcludedPathPrefixPassesThrough() throws Exception {
    expect(request.getRequestURI()).andReturn("/api/scheduler");
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testExactExcludedPathPassesThrough() throws Exception {
    expect(request.getRequestURI()).andReturn("/health");
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testValidSessionCookiePassesThrough() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs");
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("aurora_token", SESSION_TOKEN)});
    expect(sessionManager.validate(SESSION_TOKEN))
        .andReturn(Optional.of(Map.of("sub", "user123")));
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testNullCookiesRedirectsToLogin() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs").anyTimes();
    expect(request.getCookies()).andReturn(null);
    expectDiscoverySuccess();
    expect(request.getQueryString()).andReturn(null);
    response.addCookie(anyObject(Cookie.class)); // state cookie
    response.sendRedirect(anyObject(String.class));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testExpiredSessionRedirectsToLogin() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs").anyTimes();
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("aurora_token", SESSION_TOKEN)});
    expect(sessionManager.validate(SESSION_TOKEN)).andReturn(Optional.empty());
    expectDiscoverySuccess();
    expect(request.getQueryString()).andReturn("tab=active");
    response.addCookie(anyObject(Cookie.class)); // state cookie
    response.sendRedirect(anyObject(String.class));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testInitiateLoginRedirectUrlContainsClientId() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs").anyTimes();
    expect(request.getCookies()).andReturn(null);
    expectDiscoverySuccess();
    expect(request.getQueryString()).andReturn(null);
    response.addCookie(anyObject(Cookie.class));

    // Capture the redirect URL to verify it contains the client_id
    final String[] capturedUrl = new String[1];
    response.sendRedirect(anyObject(String.class));
    expectLastCall().andAnswer(() -> {
      capturedUrl[0] = (String) org.easymock.EasyMock.getCurrentArguments()[0];
      return null;
    });

    control.replay();
    filter.doFilter(request, response, chain);

    // Verify the redirect URL contains expected OAuth2 parameters
    org.junit.Assert.assertTrue(capturedUrl[0].contains("client_id=aurora-client"));
    org.junit.Assert.assertTrue(capturedUrl[0].contains("response_type=code"));
    org.junit.Assert.assertTrue(capturedUrl[0].contains("openid"));
  }

  @Test
  public void testInitiateLoginUsesOriginalPathAttributeWhenPresent() throws Exception {
    expect(request.getRequestURI()).andReturn("/assets/index.html").anyTimes();
    expect(request.getAttribute("originalPath")).andReturn("/scheduler/overview");
    expect(request.getCookies()).andReturn(null);
    expectDiscoverySuccess();
    expect(request.getQueryString()).andReturn("a=1");
    response.addCookie(anyObject(Cookie.class));

    final String[] capturedUrl = new String[1];
    response.sendRedirect(anyObject(String.class));
    expectLastCall().andAnswer(() -> {
      capturedUrl[0] = (String) org.easymock.EasyMock.getCurrentArguments()[0];
      return null;
    });

    control.replay();
    filter.doFilter(request, response, chain);

    String state = capturedUrl[0].split("state=", 2)[1];
    String encodedOriginal = new String(
        Base64.getUrlDecoder().decode(URLDecoder.decode(state, StandardCharsets.UTF_8)),
        StandardCharsets.UTF_8);
    org.junit.Assert.assertTrue(encodedOriginal.startsWith("/scheduler/overview?a=1|"));
  }

  @Test
  public void testCallbackMissingCodeReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn(null);
    expect(request.getParameter("state")).andReturn("somestate");
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing code or state");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testCallbackMissingStateReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(null);
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Missing code or state");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testCallbackStateMismatchReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn("state-A");
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", "state-B")});
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "State mismatch (CSRF check failed)");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testCallbackMissingStateCookieReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn("state-A");
    expect(request.getCookies()).andReturn(null); // no cookies at all
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "State mismatch (CSRF check failed)");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackTokenExchangeFailureReturns500() throws Exception {
    String stateValue = stateFor("/ui/jobs");
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("badcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    // statusCode() called twice: once for the 200-check, once in the warn log
    expect(tokenResp.statusCode()).andReturn(401).times(2);
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    response.sendError(
        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Token exchange failed");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackUserInfoFailureReturns500() throws Exception {
    String stateValue = stateFor("/ui/jobs");
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"access-tok\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    // statusCode() called twice: once for the 200-check, once in the warn log
    expect(userInfoResp.statusCode()).andReturn(403).times(2);
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    response.sendError(
        HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "UserInfo fetch failed");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackSuccessCreatesSessionAndRedirects() throws Exception {
    String stateValue = stateFor("/ui/jobs");
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"access-tok\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body())
        .andReturn("{\"sub\":\"user123\",\"email\":\"user@example.com\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    expect(sessionManager.create(eq("user123"), eq("user@example.com"), anyLong()))
        .andReturn("new.session.token");

    response.addCookie(anyObject(Cookie.class)); // session cookie
    response.addCookie(anyObject(Cookie.class)); // clear state cookie
    response.sendRedirect("/ui/jobs");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackSuccessRedirectsToRootWhenStateUnparseable() throws Exception {
    // State that cannot be base64-decoded to a valid URL falls back to "/"
    String stateValue = "!!!invalid-base64!!!";
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body())
        .andReturn("{\"sub\":\"u\",\"email\":\"u@x.com\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    expect(sessionManager.create(anyObject(), anyObject(), anyLong()))
        .andReturn("tok");

    response.addCookie(anyObject(Cookie.class));
    response.addCookie(anyObject(Cookie.class));
    response.sendRedirect("/"); // fallback to root

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackNormalizesAssetsIndexToSchedulerRoot() throws Exception {
    String stateValue = stateFor("/assets/index.html");
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expectDiscoverySuccess();
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body())
        .andReturn("{\"sub\":\"u\",\"email\":\"u@x.com\"}");
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    expect(sessionManager.create(anyObject(), anyObject(), anyLong()))
        .andReturn("tok");

    response.addCookie(anyObject(Cookie.class));
    response.addCookie(anyObject(Cookie.class));
    response.sendRedirect("/scheduler/");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testAllowsHttpForLocalhostConfig() {
    Options options = new Options();
    options.oauth2IssuerUrl = "http://localhost:8081/issuer";
    options.oauth2ClientId = CLIENT_ID;
    options.oauth2ClientSecret = CLIENT_SECRET;
    options.oauth2RedirectUri = "http://127.0.0.1:8080/oauth2/callback";
    options.oauth2ExcludePaths = Arrays.asList("/api");
    options.oauth2CookieName = "aurora_token";
    options.oauth2JwtSecret = "test-secret-32-chars-minimum-length!";
    options.oauth2SessionTimeoutSecs = 3600L;
    control.replay();
    new OAuth2Filter(options, sessionManager, httpClient);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testRejectsHttpForRemoteConfig() {
    Options options = new Options();
    options.oauth2IssuerUrl = "http://auth.example.com/issuer";
    options.oauth2ClientId = CLIENT_ID;
    options.oauth2ClientSecret = CLIENT_SECRET;
    options.oauth2RedirectUri = REDIRECT_URI;
    options.oauth2ExcludePaths = Arrays.asList("/api");
    options.oauth2CookieName = "aurora_token";
    options.oauth2JwtSecret = "test-secret-32-chars-minimum-length!";
    options.oauth2SessionTimeoutSecs = 3600L;
    control.replay();
    new OAuth2Filter(options, sessionManager, httpClient);
  }

  /** Encodes an original URL into the base64url state value the filter expects. */
  private static String stateFor(String originalUrl) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString((originalUrl + "|testnonce").getBytes(StandardCharsets.UTF_8));
  }

  @SuppressWarnings("unchecked")
  private void expectDiscoverySuccess() throws Exception {
    HttpResponse<String> discoveryResp = createMock(HttpResponse.class);
    expect(discoveryResp.statusCode()).andReturn(200);
    expect(discoveryResp.body()).andReturn(DISCOVERY_JSON);
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(discoveryResp);
  }
}
