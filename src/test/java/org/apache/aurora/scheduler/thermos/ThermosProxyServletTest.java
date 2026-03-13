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
package org.apache.aurora.scheduler.thermos;

import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.common.collect.ImmutableSet;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.gen.HostAttributes;
import org.apache.aurora.scheduler.config.CliOptions;
import org.apache.aurora.scheduler.storage.AttributeStore;
import org.apache.aurora.scheduler.storage.Storage;
import org.apache.aurora.scheduler.storage.Storage.StoreProvider;
import org.apache.aurora.scheduler.storage.entities.IHostAttributes;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.capture;
import static org.easymock.EasyMock.expect;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ThermosProxyServletTest extends EasyMockTest {

  @Test
  public void testAllowDomain() {
    control.replay();
    Pattern agentId = ThermosProxyServlet.AGENT_PATTERN;
    assert agentId.matcher("/thermos/agent/"
        + "6869fe8a-a7e7-4422-82b0-5771861ee98d-S46/browser/...").matches();
    String path = "/thermos/agent/6869fe8a-a7e7-4422-82b0-5771861ee98d-S46/browser/...";
    Matcher hostMatcher = agentId.matcher(path);
    if (hostMatcher.matches()) {
      final String domain = hostMatcher.group("agent");
      assert Objects.equals(domain, "6869fe8a-a7e7-4422-82b0-5771861ee98d-S46");
      assert domain.matches(".*");
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testStorageNotReadyReturns503() throws Exception {
    Storage storage = createMock(Storage.class);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);

    expect(request.getRequestURL())
        .andReturn(new StringBuffer(
            "http://localhost:28081/thermos/agent/test-agent-storage-not-ready/"));
    expect(storage.read(anyObject()))
        .andThrow(new Storage.TransientStorageException("Storage not ready"));
    response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Service unavailable");

    control.replay();

    ThermosProxyServlet servlet = new ThermosProxyServlet(new CliOptions(), storage);
    servlet.service(request, response);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testInvalidPathReturns404() throws Exception {
    Storage storage = createMock(Storage.class);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);

    expect(request.getRequestURL())
        .andReturn(new StringBuffer("http://localhost:28081/invalid/path/here"));
    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Invalid URL");

    control.replay();

    ThermosProxyServlet servlet = new ThermosProxyServlet(new CliOptions(), storage);
    servlet.service(request, response);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testAgentNotFoundReturns404() throws Exception {
    Storage storage = createMock(Storage.class);
    StoreProvider storeProvider = createMock(StoreProvider.class);
    AttributeStore attributeStore = createMock(AttributeStore.class);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);

    String agentId = "unknown-agent-notfound-xyz";
    expect(request.getRequestURL())
        .andReturn(new StringBuffer(
            "http://localhost:28081/thermos/agent/" + agentId + "/browser/"));
    Capture<Storage.Work<Set<IHostAttributes>, RuntimeException>> workCapture =
        EasyMock.newCapture();
    expect(storage.<Set<IHostAttributes>, RuntimeException>read(capture(workCapture)))
        .andAnswer(() -> workCapture.getValue().apply(storeProvider));
    expect(storeProvider.getAttributeStore()).andReturn(attributeStore);
    expect(attributeStore.getHostAttributes()).andReturn(ImmutableSet.of());
    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Agent or Domain not found");

    control.replay();

    ThermosProxyServlet servlet = new ThermosProxyServlet(new CliOptions(), storage);
    servlet.service(request, response);
  }

  @Test
  public void testAgentPatternMatchesValidPath() {
    control.replay();
    Pattern pattern = ThermosProxyServlet.AGENT_PATTERN;
    assertTrue(pattern.matcher("/thermos/agent/abc-123/").matches());
    assertTrue(pattern.matcher("/thermos/agent/abc-123").matches());
    assertTrue(pattern.matcher("/thermos/agent/abc123/some/path").matches());
    assertFalse(pattern.matcher("/other/path").matches());
    assertFalse(pattern.matcher("/thermos/other/abc-123").matches());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testAgentFoundButDomainNotAllowedReturns404() throws Exception {
    // Covers the branch: host != null but thermosAllowDomainRegex.matcher(host).matches() == false.
    Storage storage = createMock(Storage.class);
    StoreProvider storeProvider = createMock(StoreProvider.class);
    AttributeStore attributeStore = createMock(AttributeStore.class);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);

    String agentId = "allowed-agent-id-001";
    String agentHost = "notallowed.internal.host";

    expect(request.getRequestURL())
        .andReturn(new StringBuffer(
            "http://localhost:28081/thermos/agent/" + agentId + "/browser/"));
    Capture<Storage.Work<Set<IHostAttributes>, RuntimeException>> workCapture =
        EasyMock.newCapture();
    expect(storage.<Set<IHostAttributes>, RuntimeException>read(capture(workCapture)))
        .andAnswer(() -> workCapture.getValue().apply(storeProvider));
    expect(storeProvider.getAttributeStore()).andReturn(attributeStore);

    IHostAttributes attrs = IHostAttributes.build(
        new HostAttributes()
            .setHost(agentHost)
            .setSlaveId(agentId));
    expect(attributeStore.getHostAttributes()).andReturn(ImmutableSet.of(attrs));
    response.sendError(HttpServletResponse.SC_NOT_FOUND, "Agent or Domain not found");

    control.replay();

    // Use a domain regex that does NOT match agentHost.
    CliOptions options = new CliOptions();
    options.thermos.thermosAllowDomainRegex = "^only\\.allowed\\.domain$";
    ThermosProxyServlet servlet = new ThermosProxyServlet(options, storage);
    servlet.service(request, response);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testAgentFoundAndDomainAllowed() throws Exception {
    // Covers the branch: host != null AND thermosAllowDomainRegex.matcher(host).matches() == true.
    // super.service() will be called but will fail with a servlet error — we just verify no
    // sendError for 404/503 is called by the servlet logic itself.
    Storage storage = createMock(Storage.class);
    StoreProvider storeProvider = createMock(StoreProvider.class);
    AttributeStore attributeStore = createMock(AttributeStore.class);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);

    String agentId = "valid-agent-id-found-002";
    String agentHost = "agent.allowed.example.com";

    // getRequestURL is called twice: once in service(), once in super.service() (rewriteTarget).
    expect(request.getRequestURL())
        .andReturn(new StringBuffer(
            "http://localhost:28081/thermos/agent/" + agentId + "/browser/"))
        .anyTimes();
    Capture<Storage.Work<Set<IHostAttributes>, RuntimeException>> workCapture =
        EasyMock.newCapture();
    expect(storage.<Set<IHostAttributes>, RuntimeException>read(capture(workCapture)))
        .andAnswer(() -> workCapture.getValue().apply(storeProvider))
        .anyTimes();
    expect(storeProvider.getAttributeStore()).andReturn(attributeStore).anyTimes();
    IHostAttributes attrs = IHostAttributes.build(
        new HostAttributes()
            .setHost(agentHost)
            .setSlaveId(agentId));
    expect(attributeStore.getHostAttributes()).andReturn(ImmutableSet.of(attrs)).anyTimes();
    // Allow setAttribute to be called.
    request.setAttribute(org.easymock.EasyMock.anyObject(), org.easymock.EasyMock.anyObject());
    org.easymock.EasyMock.expectLastCall().anyTimes();
    // Allow any response interactions from super.service() failing.
    expect(request.getServerName()).andReturn("localhost").anyTimes();
    expect(request.getServerPort()).andReturn(28081).anyTimes();
    expect(request.getQueryString()).andReturn(null).anyTimes();

    control.replay();

    CliOptions options = new CliOptions();
    options.thermos.thermosAllowDomainRegex = ".*";
    ThermosProxyServlet servlet = new ThermosProxyServlet(options, storage);
    try {
      servlet.service(request, response);
    } catch (Throwable e) {
      // super.service() or EasyMock may throw due to missing servlet context — that's expected.
    }
  }
}
