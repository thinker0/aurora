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
import java.io.PrintWriter;
import java.io.StringWriter;
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

  private static final String DISCOVERY_JSON_WITH_DEVICE =
      "{\"authorization_endpoint\":\"https://auth.example.com/auth\","
          + "\"token_endpoint\":\"https://auth.example.com/token\","
          + "\"userinfo_endpoint\":\"https://auth.example.com/userinfo\","
          + "\"device_authorization_endpoint\":\"https://auth.example.com/device\"}";

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
    options.oauth2ExcludePaths = Arrays.asList("/vars", "/health", "/leaderhealth");
    options.oauth2CookieName = "aurora_token";
    options.oauth2JwtSecret = "test-secret-32-chars-minimum-length!";
    options.oauth2SessionTimeoutSecs = 3600L;

    filter = new OAuth2Filter(options, sessionManager, httpClient);
    expect(request.isSecure()).andStubReturn(true);
    expect(request.getAttribute("originalPath")).andStubReturn(null);
    // Bearer and cookie checks now run for all paths (including excluded ones).
    expect(request.getHeader("Authorization")).andStubReturn(null);
    expect(request.getCookies()).andStubReturn(null);
  }

  @Test
  public void testExcludedPathPrefixPassesThrough() throws Exception {
    expect(request.getRequestURI()).andReturn("/vars/uptime");
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

  // -------------------------------------------------------------------------
  // Bearer token tests
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testBearerTokenValidPassesThrough() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs");
    expect(request.getHeader("Authorization")).andReturn("Bearer valid.access.token");
    expectDiscoverySuccess();

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body()).andReturn("{\"sub\":\"user123\",\"email\":\"user@example.com\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testBearerTokenInvalidReturns401() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs");
    expect(request.getHeader("Authorization")).andReturn("Bearer bad.token");
    expectDiscoverySuccess();

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(401).times(2);
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Bearer token");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testSessionWithMissingClaimsRedirectsToLogin() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs").anyTimes();
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("aurora_token", SESSION_TOKEN)});
    // Validate returns claims with no email or sub
    expect(sessionManager.validate(SESSION_TOKEN))
        .andReturn(Optional.of(Map.of("iat", 1234, "exp", 9999999999L)));
    expectDiscoverySuccess();
    expect(request.getQueryString()).andReturn(null);
    response.addCookie(anyObject(Cookie.class));
    response.sendRedirect(anyObject(String.class));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // /oauth2/device-authorize tests
  // -------------------------------------------------------------------------

  @Test
  public void testDeviceAuthorizeGetMethodReturns405() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("GET");
    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceAuthorizeDiscoveryFailedReturns500() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("POST");

    HttpResponse<String> discoveryResp = createMock(HttpResponse.class);
    // statusCode called twice in ensureEndpoints(): != 200 check + LOG.warn
    expect(discoveryResp.statusCode()).andReturn(503).times(2);
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(discoveryResp);

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceAuthorizeNoEndpointReturns501() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("POST");
    // DISCOVERY_JSON has no device_authorization_endpoint → deviceAuthorizationEndpoint = null
    expectDiscoverySuccess();

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_NOT_IMPLEMENTED);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceAuthorizeOidcErrorForwarded() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    // statusCode called: (1) != 200 check, (2) LOG.warn, (3) forwardOidcError argument
    expect(devAuthResp.statusCode()).andReturn(400).times(3);
    expect(devAuthResp.body())
        .andReturn("{\"error\":\"invalid_client\",\"error_description\":\"bad creds\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);

    StringWriter sw = new StringWriter();
    response.setContentType("application/json");
    response.setStatus(400);
    expect(response.getWriter()).andReturn(new PrintWriter(sw));

    control.replay();
    filter.doFilter(request, response, chain);

    org.junit.Assert.assertTrue(sw.toString().contains("invalid_client"));
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceAuthorizeSuccess() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    expect(devAuthResp.statusCode()).andReturn(200);
    expect(devAuthResp.body()).andReturn(
        "{\"device_code\":\"real-dc\",\"user_code\":\"ABC-123\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);

    expect(sessionManager.createProxyDeviceToken("real-dc")).andReturn("proxy.sig");

    StringWriter sw = new StringWriter();
    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_OK);
    expect(response.getWriter()).andReturn(new PrintWriter(sw));

    control.replay();
    filter.doFilter(request, response, chain);

    org.junit.Assert.assertTrue(sw.toString().contains("proxy_device_code"));
    org.junit.Assert.assertTrue(sw.toString().contains("proxy.sig"));
  }

  // -------------------------------------------------------------------------
  // /oauth2/device-token tests
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenGetMethodReturns405() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("GET");
    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenMissingParamReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expectDiscoverySuccess();
    expect(request.getParameter("proxy_device_code")).andReturn(null);

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenInvalidHmacReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expectDiscoverySuccess();
    expect(request.getParameter("proxy_device_code")).andReturn("bad.hmac");

    expect(sessionManager.extractVerifiedDeviceCode("bad.hmac")).andReturn(Optional.empty());

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenExpiredCacheReturns400() throws Exception {
    // HMAC signature is valid but proxy code is not in issuedProxyCodes cache (expired/replayed)
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expectDiscoverySuccess();
    expect(request.getParameter("proxy_device_code")).andReturn("expired.code");

    expect(sessionManager.extractVerifiedDeviceCode("expired.code"))
        .andReturn(Optional.of("real-dc"));
    // issuedProxyCodes cache does NOT contain "expired.code"

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenSuccessReturnsAuroraToken() throws Exception {
    // Phase 1: /oauth2/device-authorize — populates issuedProxyCodes cache
    HttpServletRequest authReq = createMock(HttpServletRequest.class);
    HttpServletResponse authResp = createMock(HttpServletResponse.class);

    expect(authReq.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(authReq.getMethod()).andReturn("POST");
    expect(authReq.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthOidcResp = createMock(HttpResponse.class);
    expect(devAuthOidcResp.statusCode()).andReturn(200);
    expect(devAuthOidcResp.body()).andReturn(
        "{\"device_code\":\"dc-abc\",\"user_code\":\"XY-ZW\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthOidcResp);

    expect(sessionManager.createProxyDeviceToken("dc-abc")).andReturn("prx.abc");
    authResp.setContentType("application/json");
    authResp.setStatus(HttpServletResponse.SC_OK);
    expect(authResp.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    // Phase 2: /oauth2/device-token — uses cached proxy code
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("proxy_device_code")).andReturn("prx.abc");

    expect(sessionManager.extractVerifiedDeviceCode("prx.abc")).andReturn(Optional.of("dc-abc"));

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body()).andReturn("{\"access_token\":\"at-xyz\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body()).andReturn("{\"sub\":\"u1\",\"email\":\"u@x.com\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    expect(sessionManager.create(eq("u1"), eq("u@x.com"), anyLong())).andReturn("aurora.tok");
    expect(sessionManager.getSessionTimeoutSecs()).andReturn(3600L);

    StringWriter tokenSw = new StringWriter();
    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_OK);
    expect(response.getWriter()).andReturn(new PrintWriter(tokenSw));

    control.replay();

    filter.doFilter(authReq, authResp, chain);    // phase 1: populates cache
    filter.doFilter(request, response, chain);    // phase 2: returns aurora_token

    org.junit.Assert.assertTrue(tokenSw.toString().contains("aurora_token"));
    org.junit.Assert.assertTrue(tokenSw.toString().contains("aurora.tok"));
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenOidcPendingForwarded() throws Exception {
    // Phase 1: device-authorize to populate cache
    HttpServletRequest authReq = createMock(HttpServletRequest.class);
    HttpServletResponse authResp = createMock(HttpServletResponse.class);

    expect(authReq.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(authReq.getMethod()).andReturn("POST");
    expect(authReq.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthOidcResp = createMock(HttpResponse.class);
    expect(devAuthOidcResp.statusCode()).andReturn(200);
    expect(devAuthOidcResp.body()).andReturn(
        "{\"device_code\":\"dc-pend\",\"user_code\":\"PEND\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthOidcResp);

    expect(sessionManager.createProxyDeviceToken("dc-pend")).andReturn("prx.pend");
    authResp.setContentType("application/json");
    authResp.setStatus(HttpServletResponse.SC_OK);
    expect(authResp.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    // Phase 2: device-token with authorization_pending error
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("proxy_device_code")).andReturn("prx.pend");

    expect(sessionManager.extractVerifiedDeviceCode("prx.pend")).andReturn(Optional.of("dc-pend"));

    HttpResponse<String> pendingResp = createMock(HttpResponse.class);
    // statusCode called: (1) != 200 check, (2) forwardOidcError argument
    expect(pendingResp.statusCode()).andReturn(400).times(2);
    expect(pendingResp.body())
        .andReturn("{\"error\":\"authorization_pending\","
            + "\"error_description\":\"User has not yet authorized\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(pendingResp);

    StringWriter sw = new StringWriter();
    response.setContentType("application/json");
    response.setStatus(400);
    expect(response.getWriter()).andReturn(new PrintWriter(sw));

    control.replay();

    filter.doFilter(authReq, authResp, chain);
    filter.doFilter(request, response, chain);

    org.junit.Assert.assertTrue(sw.toString().contains("authorization_pending"));
  }

  // -------------------------------------------------------------------------
  // Bearer token cache / sub-only tests
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testBearerTokenCacheHitPassesThrough() throws Exception {
    // First call: validates via userinfo endpoint and caches
    expect(request.getRequestURI()).andReturn("/ui/jobs").times(2);
    expect(request.getHeader("Authorization")).andReturn("Bearer cached.token").times(2);
    expectDiscoverySuccess();

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body()).andReturn("{\"sub\":\"u1\",\"email\":\"u@x.com\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    // Second call: cached — no httpClient.send for userinfo
    chain.doFilter(request, response);
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain); // primes cache
    filter.doFilter(request, response, chain); // cache hit
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testBearerTokenSubOnlyPassesThrough() throws Exception {
    expect(request.getRequestURI()).andReturn("/ui/jobs");
    expect(request.getHeader("Authorization")).andReturn("Bearer sub.only.token");
    expectDiscoverySuccess();

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    // No email field — sub is used as username
    expect(userInfoResp.body()).andReturn("{\"sub\":\"user-sub-only\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // shouldUseSecureCookies — X-Forwarded-Proto: https
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testInitiateLoginWithXForwardedProtoHttps() throws Exception {
    // Override the stubReturn(true) for isSecure set in setUp
    Options options = new Options();
    options.oauth2IssuerUrl = ISSUER_URL;
    options.oauth2ClientId = CLIENT_ID;
    options.oauth2ClientSecret = CLIENT_SECRET;
    options.oauth2RedirectUri = REDIRECT_URI;
    options.oauth2ExcludePaths = Arrays.asList("/vars", "/health");
    options.oauth2CookieName = "aurora_token";
    options.oauth2JwtSecret = "test-secret-32-chars-minimum-length!";
    options.oauth2SessionTimeoutSecs = 3600L;

    HttpServletRequest req2 = createMock(HttpServletRequest.class);
    HttpServletResponse resp2 = createMock(HttpServletResponse.class);
    OAuth2Filter filter2 = new OAuth2Filter(options, sessionManager, httpClient);

    expect(req2.getRequestURI()).andReturn("/ui/jobs").anyTimes();
    expect(req2.getAttribute("originalPath")).andReturn(null);
    expect(req2.getHeader("Authorization")).andReturn(null);
    expect(req2.getCookies()).andReturn(null);
    expect(req2.isSecure()).andReturn(false);
    expect(req2.getHeader("X-Forwarded-Proto")).andReturn("https");
    expect(req2.getQueryString()).andReturn(null);
    expectDiscoverySuccess();

    resp2.addCookie(anyObject(Cookie.class));
    resp2.sendRedirect(anyObject(String.class));

    control.replay();
    filter2.doFilter(req2, resp2, chain);
  }

  // -------------------------------------------------------------------------
  // ensureEndpoints — discoveryComplete=true skips re-fetch
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testDiscoveryAlreadyCompleteIsReused() throws Exception {
    // First request primes discoveryComplete=true; second reuses cached endpoints (no re-fetch).
    // getRequestURI() is called twice per doFilter (outer + getOriginalRequestPath)
    expect(request.getRequestURI()).andReturn("/ui/jobs").anyTimes();
    expectDiscoverySuccess(); // only one httpClient.send for discovery
    expect(request.getQueryString()).andReturn(null).times(2);
    response.addCookie(anyObject(Cookie.class));
    expectLastCall().times(2);
    response.sendRedirect(anyObject(String.class));
    expectLastCall().times(2);

    control.replay();
    filter.doFilter(request, response, chain); // primes discoveryComplete
    filter.doFilter(request, response, chain); // reuses cached endpoints (if branch = true)
  }

  // -------------------------------------------------------------------------
  // isLoopbackHost — IPv6 [::1]
  // -------------------------------------------------------------------------

  @Test
  public void testAllowsHttpForIPv6Loopback() {
    Options options = new Options();
    options.oauth2IssuerUrl = "http://[::1]:8080/realms/test";
    options.oauth2ClientId = CLIENT_ID;
    options.oauth2ClientSecret = CLIENT_SECRET;
    options.oauth2RedirectUri = "http://[::1]:8080/callback";
    options.oauth2ExcludePaths = Arrays.asList("/vars");
    options.oauth2CookieName = "aurora_token";
    options.oauth2JwtSecret = "test-secret-32-chars-minimum-length!";
    options.oauth2SessionTimeoutSecs = 3600L;
    control.replay();
    new OAuth2Filter(options, sessionManager, httpClient); // must not throw
  }

  // -------------------------------------------------------------------------
  // handleCallback — additional uncovered paths
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackDiscoveryFailureReturns500() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn("somestate");

    HttpResponse<String> discoveryResp = createMock(HttpResponse.class);
    expect(discoveryResp.statusCode()).andReturn(503).times(2);
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(discoveryResp);

    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackMissingAccessTokenReturns500() throws Exception {
    String stateValue = stateFor("/ui/jobs");
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expectDiscoverySuccess();
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body()).andReturn("{}"); // no access_token field
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "No access_token received");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackSubAndEmailNonStringReturns500() throws Exception {
    String stateValue = stateFor("/ui/jobs");
    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expectDiscoverySuccess();
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"access-tok\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    // sub and email are integers (non-String) → cast fails → empty string → error
    expect(userInfoResp.body()).andReturn("{\"sub\":123,\"email\":456}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
        "UserInfo missing required claims");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCallbackCliFlowRedirectsToLocalhost() throws Exception {
    // CLI state: "cli:12345|<nonce>" base64url-encoded
    String cliStateData = "cli:12345|testnonce";
    String stateValue = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(cliStateData.getBytes(java.nio.charset.StandardCharsets.UTF_8));

    expect(request.getRequestURI()).andReturn("/oauth2/callback");
    expect(request.getParameter("code")).andReturn("authcode");
    expect(request.getParameter("state")).andReturn(stateValue);
    expectDiscoverySuccess();
    expect(request.getCookies())
        .andReturn(new Cookie[]{new Cookie("oauth2_state", stateValue)});

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"access-tok\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body()).andReturn("{\"sub\":\"u1\",\"email\":\"u@x.com\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    expect(sessionManager.create(anyObject(), anyObject(), anyLong())).andReturn("aurora.tok");

    response.addCookie(anyObject(Cookie.class)); // session cookie
    response.addCookie(anyObject(Cookie.class)); // clear state cookie
    // Redirect to localhost:<port>/callback?aurora_token=...
    response.sendRedirect(anyObject(String.class));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // handleDeviceAuthorize — network error and missing device_code
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceAuthorizeNetworkErrorReturns502() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andThrow(new java.io.IOException("connection refused"));

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceAuthorizeMissingDeviceCodeReturns502() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    expect(devAuthResp.statusCode()).andReturn(200);
    expect(devAuthResp.body()).andReturn("{\"user_code\":\"ABC-123\",\"expires_in\":600}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // handleDeviceToken — empty proxy_device_code, network error, missing access_token,
  //                     sub/email non-String
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenEmptyProxyCodeReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expectDiscoverySuccess();
    expect(request.getParameter("proxy_device_code")).andReturn(""); // empty string

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenNetworkErrorReturns502() throws Exception {
    // Phase 1: device-authorize to populate issuedProxyCodes cache
    HttpServletRequest authReq = createMock(HttpServletRequest.class);
    HttpServletResponse authResp = createMock(HttpServletResponse.class);

    expect(authReq.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(authReq.getMethod()).andReturn("POST");
    expect(authReq.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    expect(devAuthResp.statusCode()).andReturn(200);
    expect(devAuthResp.body()).andReturn(
        "{\"device_code\":\"dc-net\",\"user_code\":\"NET\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);
    expect(sessionManager.createProxyDeviceToken("dc-net")).andReturn("prx.net");
    authResp.setContentType("application/json");
    authResp.setStatus(HttpServletResponse.SC_OK);
    expect(authResp.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    // Phase 2: device-token — httpClient.send throws IOException
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("proxy_device_code")).andReturn("prx.net");
    expect(sessionManager.extractVerifiedDeviceCode("prx.net")).andReturn(Optional.of("dc-net"));

    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andThrow(new java.io.IOException("network error"));

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(authReq, authResp, chain); // phase 1: populates cache
    filter.doFilter(request, response, chain); // phase 2: network error
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenMissingAccessTokenReturns502() throws Exception {
    // Phase 1: populate cache
    HttpServletRequest authReq = createMock(HttpServletRequest.class);
    HttpServletResponse authResp = createMock(HttpServletResponse.class);

    expect(authReq.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(authReq.getMethod()).andReturn("POST");
    expect(authReq.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    expect(devAuthResp.statusCode()).andReturn(200);
    expect(devAuthResp.body()).andReturn(
        "{\"device_code\":\"dc-noat\",\"user_code\":\"NOAT\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);
    expect(sessionManager.createProxyDeviceToken("dc-noat")).andReturn("prx.noat");
    authResp.setContentType("application/json");
    authResp.setStatus(HttpServletResponse.SC_OK);
    expect(authResp.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    // Phase 2: token response 200 but no access_token
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("proxy_device_code")).andReturn("prx.noat");
    expect(sessionManager.extractVerifiedDeviceCode("prx.noat")).andReturn(Optional.of("dc-noat"));

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body()).andReturn("{}"); // no access_token
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(authReq, authResp, chain);
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testDeviceTokenSubAndEmailNonStringReturns500() throws Exception {
    // Phase 1: populate cache
    HttpServletRequest authReq = createMock(HttpServletRequest.class);
    HttpServletResponse authResp = createMock(HttpServletResponse.class);

    expect(authReq.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(authReq.getMethod()).andReturn("POST");
    expect(authReq.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    expect(devAuthResp.statusCode()).andReturn(200);
    expect(devAuthResp.body()).andReturn(
        "{\"device_code\":\"dc-ns\",\"user_code\":\"NS\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);
    expect(sessionManager.createProxyDeviceToken("dc-ns")).andReturn("prx.ns");
    authResp.setContentType("application/json");
    authResp.setStatus(HttpServletResponse.SC_OK);
    expect(authResp.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    // Phase 2: sub/email are integers → treated as empty → error
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("proxy_device_code")).andReturn("prx.ns");
    expect(sessionManager.extractVerifiedDeviceCode("prx.ns")).andReturn(Optional.of("dc-ns"));

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    expect(tokenResp.statusCode()).andReturn(200);
    expect(tokenResp.body())
        .andReturn("{\"access_token\":\"at-ns\",\"token_type\":\"Bearer\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body()).andReturn("{\"sub\":123,\"email\":456}"); // non-String
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    response.setContentType("application/json");
    response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
    expect(response.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    control.replay();
    filter.doFilter(authReq, authResp, chain);
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // forwardOidcError — non-JSON upstream body
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testForwardOidcErrorNonJsonBodyReturnsGenericError() throws Exception {
    // Phase 1: populate cache
    HttpServletRequest authReq = createMock(HttpServletRequest.class);
    HttpServletResponse authResp = createMock(HttpServletResponse.class);

    expect(authReq.getRequestURI()).andReturn("/oauth2/device-authorize");
    expect(authReq.getMethod()).andReturn("POST");
    expect(authReq.getParameter("scope")).andReturn(null);
    expectDiscoveryWithDeviceSuccess();

    HttpResponse<String> devAuthResp = createMock(HttpResponse.class);
    expect(devAuthResp.statusCode()).andReturn(200);
    expect(devAuthResp.body()).andReturn(
        "{\"device_code\":\"dc-njson\",\"user_code\":\"NJSON\","
            + "\"verification_uri\":\"https://auth.example.com/activate\","
            + "\"expires_in\":600,\"interval\":5}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(devAuthResp);
    expect(sessionManager.createProxyDeviceToken("dc-njson")).andReturn("prx.njson");
    authResp.setContentType("application/json");
    authResp.setStatus(HttpServletResponse.SC_OK);
    expect(authResp.getWriter()).andReturn(new PrintWriter(new StringWriter()));

    // Phase 2: token polling returns non-JSON body
    expect(request.getRequestURI()).andReturn("/oauth2/device-token");
    expect(request.getMethod()).andReturn("POST");
    expect(request.getParameter("proxy_device_code")).andReturn("prx.njson");
    expect(sessionManager.extractVerifiedDeviceCode("prx.njson"))
        .andReturn(Optional.of("dc-njson"));

    HttpResponse<String> tokenResp = createMock(HttpResponse.class);
    // statusCode() is called twice: once in != 200 check, once as arg to forwardOidcError
    expect(tokenResp.statusCode()).andReturn(400).times(2);
    expect(tokenResp.body()).andReturn("not-json-at-all"); // non-JSON triggers catch + safe.isEmpty
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(tokenResp);

    StringWriter sw = new StringWriter();
    response.setContentType("application/json");
    response.setStatus(400);
    expect(response.getWriter()).andReturn(new PrintWriter(sw));

    control.replay();
    filter.doFilter(authReq, authResp, chain);
    filter.doFilter(request, response, chain);

    org.junit.Assert.assertTrue(sw.toString().contains("upstream_error"));
  }

  // -------------------------------------------------------------------------
  // extractUsername empty-string branches + validateBearerToken username==null
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testBearerTokenEmptySubAndEmailReturns401() throws Exception {
    // Covers: extractUsername email isEmpty()=true, sub isEmpty()=true, validateBearerToken username==null
    expect(request.getRequestURI()).andReturn("/ui/jobs");
    expect(request.getHeader("Authorization")).andReturn("Bearer empty.user.token");
    expectDiscoverySuccess();

    HttpResponse<String> userInfoResp = createMock(HttpResponse.class);
    expect(userInfoResp.statusCode()).andReturn(200);
    expect(userInfoResp.body()).andReturn("{\"email\":\"\",\"sub\":\"\"}");
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(userInfoResp);

    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid Bearer token");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // initiateLogin — discovery failure
  // -------------------------------------------------------------------------

  @Test
  @SuppressWarnings("unchecked")
  public void testInitiateLoginDiscoveryFailureReturns500() throws Exception {
    // Covers: initiateLogin !ensureEndpoints()=true branch
    expect(request.getRequestURI()).andReturn("/ui/jobs").anyTimes();

    HttpResponse<String> discoveryResp = createMock(HttpResponse.class);
    expect(discoveryResp.statusCode()).andReturn(503).times(2);
    expect(httpClient.send(anyObject(HttpRequest.class), anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(discoveryResp);

    response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "OIDC discovery failed");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // /oauth2/cli-authorize tests
  // -------------------------------------------------------------------------

  @Test
  public void testCliAuthorizeMissingPortReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/cli-authorize");
    expect(request.getParameter("local_port")).andReturn(null);
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "local_port parameter required");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testCliAuthorizeInvalidPortReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/cli-authorize");
    expect(request.getParameter("local_port")).andReturn("not-a-number");
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid local_port");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  public void testCliAuthorizePortOutOfRangeReturns400() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/cli-authorize");
    expect(request.getParameter("local_port")).andReturn("99999");
    response.sendError(HttpServletResponse.SC_BAD_REQUEST, "local_port out of range");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCliAuthorizeSuccess() throws Exception {
    expect(request.getRequestURI()).andReturn("/oauth2/cli-authorize");
    expect(request.getParameter("local_port")).andReturn("12345");
    expectDiscoverySuccess();
    response.addCookie(anyObject(Cookie.class)); // state cookie
    response.sendRedirect(anyObject(String.class));

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /** Encodes an original URL into the base64url state value the filter expects. */
  private static String stateFor(String originalUrl) {
    return Base64.getUrlEncoder().withoutPadding()
        .encodeToString((originalUrl + "|testnonce").getBytes(StandardCharsets.UTF_8));
  }

  @SuppressWarnings("unchecked")
  private void expectDiscoveryWithDeviceSuccess() throws Exception {
    HttpResponse<String> discoveryResp = createMock(HttpResponse.class);
    expect(discoveryResp.statusCode()).andReturn(200);
    expect(discoveryResp.body()).andReturn(DISCOVERY_JSON_WITH_DEVICE);
    expect(httpClient.send(
        anyObject(HttpRequest.class),
        anyObject(HttpResponse.BodyHandler.class)))
        .andReturn(discoveryResp);
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
