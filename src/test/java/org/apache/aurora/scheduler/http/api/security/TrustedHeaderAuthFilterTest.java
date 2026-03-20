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

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ThreadContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;

public class TrustedHeaderAuthFilterTest extends EasyMockTest {

  private HttpServletRequest request;
  private HttpServletResponse response;
  private FilterChain chain;
  private Subject mockSubject;

  @Before
  public void setUp() {
    request = createMock(HttpServletRequest.class);
    response = createMock(HttpServletResponse.class);
    chain = createMock(FilterChain.class);
    mockSubject = createMock(Subject.class);
    ThreadContext.bind(mockSubject);
  }

  @After
  public void tearDownShiro() {
    ThreadContext.unbindSubject();
  }

  // Covers: X-Forwarded-User non-null/non-empty → user.isPresent()=true → login success
  @Test
  public void testXForwardedUserLoginSuccess() throws Exception {
    TrustedHeaderAuthFilter filter = new TrustedHeaderAuthFilter();
    expect(request.getHeader("X-Forwarded-User")).andReturn("alice");
    mockSubject.login(anyObject());
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // Covers: user.isPresent()=true → login throws → sendError(401)
  @Test
  public void testXForwardedUserLoginFailsReturns401() throws Exception {
    TrustedHeaderAuthFilter filter = new TrustedHeaderAuthFilter();
    expect(request.getHeader("X-Forwarded-User")).andReturn("alice");
    mockSubject.login(anyObject());
    expectLastCall().andThrow(new AuthenticationException("bad credentials"));
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // Covers: X-Forwarded-User=null → fallback to X-Auth-Request-User non-empty → login success
  @Test
  public void testXAuthRequestUserFallbackSuccess() throws Exception {
    TrustedHeaderAuthFilter filter = new TrustedHeaderAuthFilter();
    expect(request.getHeader("X-Forwarded-User")).andReturn(null);
    expect(request.getHeader("X-Auth-Request-User")).andReturn("bob");
    mockSubject.login(anyObject());
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // Covers: both headers null → user.isPresent()=false + permissive=false → sendError(401)
  @Test
  public void testBothHeadersNullStrictReturns401() throws Exception {
    TrustedHeaderAuthFilter filter = new TrustedHeaderAuthFilter();
    expect(request.getHeader("X-Forwarded-User")).andReturn(null);
    expect(request.getHeader("X-Auth-Request-User")).andReturn(null);
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication");

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // Covers: both headers null → user.isPresent()=false + permissive=true → chain.doFilter
  @Test
  public void testBothHeadersNullPermissivePassesThrough() throws Exception {
    TrustedHeaderAuthFilter filter = new TrustedHeaderAuthFilter(true);
    expect(request.getHeader("X-Forwarded-User")).andReturn(null);
    expect(request.getHeader("X-Auth-Request-User")).andReturn(null);
    chain.doFilter(request, response);

    control.replay();
    filter.doFilter(request, response, chain);
  }

  // Covers: X-Forwarded-User="" (empty) → fallback → X-Auth-Request-User="" → strict → 401
  @Test
  public void testXForwardedUserEmptyXAuthEmptyStrictReturns401() throws Exception {
    TrustedHeaderAuthFilter filter = new TrustedHeaderAuthFilter();
    expect(request.getHeader("X-Forwarded-User")).andReturn("");
    expect(request.getHeader("X-Auth-Request-User")).andReturn("");
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication");

    control.replay();
    filter.doFilter(request, response, chain);
  }
}
