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
package org.apache.aurora.scheduler.http;

import java.util.Arrays;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.http.HttpServletRequest;

import com.google.common.base.Function;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.net.HostAndPort;
import com.google.gson.Gson;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.scheduler.app.ServiceGroupMonitor;
import org.apache.aurora.scheduler.app.ServiceGroupMonitor.MonitorException;
import org.apache.aurora.scheduler.discovery.ServiceInstance;
import org.apache.aurora.scheduler.discovery.ServiceInstance.Endpoint;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class LeaderRedirectTest extends EasyMockTest {

  private static final int HTTP_PORT = 500;

  private static final Function<HostAndPort, ServiceInstance> CREATE_INSTANCE =
      endpoint -> new ServiceInstance(
          new Endpoint(endpoint.getHost(), endpoint.getPort()),
          ImmutableMap.of());

  private AtomicReference<ImmutableSet<ServiceInstance>> schedulers;
  private ServiceGroupMonitor serviceGroupMonitor;
  private LeaderRedirect leaderRedirector;

  @Before
  public void setUp() throws MonitorException {
    schedulers = new AtomicReference<>(ImmutableSet.of());
    serviceGroupMonitor = createMock(ServiceGroupMonitor.class);

    HttpService http = createMock(HttpService.class);
    expect(http.getAddress()).andStubReturn(HostAndPort.fromParts("localhost", HTTP_PORT));

    leaderRedirector = new LeaderRedirect(http, serviceGroupMonitor);
  }

  private void replayAndMonitor() throws Exception {
    serviceGroupMonitor.start();
    expectLastCall();
    expect(serviceGroupMonitor.get()).andAnswer(() -> schedulers.get()).anyTimes();
    control.replay();
    leaderRedirector.monitor();
  }

  private HttpServletRequest mockRequest(String attributeValue, String queryString) {
    HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    expect(mockRequest.getScheme()).andReturn("http");
    expect(mockRequest.getAttribute(JettyServerModule.ORIGINAL_PATH_ATTRIBUTE_NAME))
        .andReturn(attributeValue);
    expect(mockRequest.getRequestURI()).andReturn("/some/path");
    expect(mockRequest.getQueryString()).andReturn(queryString);
    return mockRequest;
  }

  @Test
  public void testResolveLeaderActionLeading() throws Exception {
    HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    // LEADING path returns early without invoking any request methods.
    replayAndMonitor();
    publishSchedulers(localPort(HTTP_PORT));

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertTrue(resolution.isLeading());
    assertFalse(resolution.isNoLeader());
    assertEquals(Optional.empty(), resolution.getRedirectUrl());
  }

  @Test
  public void testResolveLeaderActionNoLeader() throws Exception {
    HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    // NO_LEADER path returns early without invoking any request methods.
    replayAndMonitor();
    // no schedulers published → empty host set

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertFalse(resolution.isLeading());
    assertTrue(resolution.isNoLeader());
  }

  @Test
  public void testResolveLeaderActionMultipleSchedulers() throws Exception {
    HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    replayAndMonitor();
    publishSchedulers(HostAndPort.fromParts("foobar", 500), HostAndPort.fromParts("baz", 800));

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertFalse(resolution.isLeading());
    assertTrue(resolution.isNoLeader());
  }

  @Test
  public void testResolveLeaderActionNullEndpoint() throws Exception {
    HttpServletRequest mockRequest = createMock(HttpServletRequest.class);
    serviceGroupMonitor.start();
    expectLastCall();
    // Simulate a malformed ZK node (null serviceEndpoint) via Gson deserialization,
    // which uses the package-private no-arg constructor that allows null serviceEndpoint.
    ServiceInstance instanceWithNullEndpoint = new Gson().fromJson("{}", ServiceInstance.class);
    expect(serviceGroupMonitor.get())
        .andReturn(ImmutableSet.of(instanceWithNullEndpoint))
        .anyTimes();
    control.replay();
    leaderRedirector.monitor();

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertFalse(resolution.isLeading());
    assertTrue(resolution.isNoLeader());
  }

  @Test
  public void testResolveLeaderActionRedirect() throws Exception {
    HttpServletRequest mockRequest = mockRequest(null, null);
    replayAndMonitor();

    HostAndPort remote = HostAndPort.fromParts("foobar", HTTP_PORT);
    publishSchedulers(remote);

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertFalse(resolution.isLeading());
    assertFalse(resolution.isNoLeader());
    assertEquals(Optional.of("http://foobar:500/some/path"), resolution.getRedirectUrl());
  }

  @Test
  public void testResolveLeaderActionRedirectWithQueryString() throws Exception {
    HttpServletRequest mockRequest = mockRequest(null, "foo=bar");
    replayAndMonitor();

    HostAndPort remote = HostAndPort.fromParts("foobar", HTTP_PORT);
    publishSchedulers(remote);

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertFalse(resolution.isLeading());
    assertFalse(resolution.isNoLeader());
    assertEquals(Optional.of("http://foobar:500/some/path?foo=bar"), resolution.getRedirectUrl());
  }

  @Test
  public void testResolveLeaderActionRedirectWithOriginalPath() throws Exception {
    HttpServletRequest mockRequest = mockRequest("/original/path", null);
    replayAndMonitor();

    HostAndPort remote = HostAndPort.fromParts("foobar", HTTP_PORT);
    publishSchedulers(remote);

    LeaderRedirect.LeaderResolution resolution = leaderRedirector.resolveLeaderAction(mockRequest);
    assertFalse(resolution.isLeading());
    assertFalse(resolution.isNoLeader());
    assertEquals(Optional.of("http://foobar:500/original/path"), resolution.getRedirectUrl());
  }

  private void publishSchedulers(HostAndPort... schedulerHttpEndpoints) {
    publishSchedulers(ImmutableSet.copyOf(Iterables.transform(Arrays.asList(schedulerHttpEndpoints),
        CREATE_INSTANCE)));
  }

  private void publishSchedulers(ImmutableSet<ServiceInstance> instances) {
    schedulers.set(instances);
  }

  private static HostAndPort localPort(int port) {
    return HostAndPort.fromParts("localhost", port);
  }
}
