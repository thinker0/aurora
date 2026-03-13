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

import java.io.Closeable;
import java.io.IOException;
import java.util.Optional;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Iterables;
import com.google.common.net.HostAndPort;

import org.apache.aurora.scheduler.app.ServiceGroupMonitor;
import org.apache.aurora.scheduler.app.ServiceGroupMonitor.MonitorException;
import org.apache.aurora.scheduler.discovery.ServiceInstance;
import org.apache.aurora.scheduler.discovery.ServiceInstance.Endpoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

/**
 * Redirect logic for finding the leading scheduler in the event that this process is not the
 * leader.
 */
class LeaderRedirect implements Closeable {

  private static final Logger LOG = LoggerFactory.getLogger(LeaderRedirect.class);

  private final HttpService httpService;
  private final ServiceGroupMonitor serviceGroupMonitor;

  @Inject
  LeaderRedirect(HttpService httpService, ServiceGroupMonitor serviceGroupMonitor) {
    this.httpService = requireNonNull(httpService);
    this.serviceGroupMonitor = requireNonNull(serviceGroupMonitor);
  }

  /**
   * Initiates the monitor that will watch the scheduler host set.
   *
   * @throws MonitorException If monitoring failed to initialize.
   */
  public void monitor() throws MonitorException {
    serviceGroupMonitor.start();
  }

  @Override
  public void close() throws IOException {
    try {
      serviceGroupMonitor.close();
    } catch (Throwable e) {
      LOG.warn("Error closing serviceGroupMonitor. {}", e.getMessage(), e);
    }
  }

  private Optional<HostAndPort> getLocalHttp() {
    HostAndPort localHttp = httpService.getAddress();
    return (localHttp == null) ? Optional.empty()
        : Optional.of(HostAndPort.fromParts(localHttp.getHost(), localHttp.getPort()));
  }

  /**
   * Resolves the leader filter action in a single atomic ZK read, avoiding race conditions
   * that would arise from separate status checks and redirect target lookups.
   *
   * @param req HTTP request.
   * @return A {@link LeaderResolution} indicating LEADING (serve request), NO_LEADER (503), or
   *         a redirect resolution containing the target URL of the current leader.
   */
  LeaderResolution resolveLeaderAction(HttpServletRequest req) {
    Optional<ServiceInstance> leadingScheduler = getLeader();
    if (!leadingScheduler.isPresent()) {
      return LeaderResolution.NO_LEADER;
    }

    Endpoint leaderEndpoint = leadingScheduler.get().getServiceEndpoint();
    if (leaderEndpoint == null) {
      LOG.warn("Leader service instance has no service endpoint.");
      return LeaderResolution.NO_LEADER;
    }

    HostAndPort leaderHttp =
        HostAndPort.fromParts(leaderEndpoint.getHost(), leaderEndpoint.getPort());
    Optional<HostAndPort> localHttp = getLocalHttp();

    if (localHttp.isPresent() && leaderHttp.equals(localHttp.get())) {
      return LeaderResolution.LEADING;
    }

    // If Jetty rewrote the path, redirect to the original path so the UI route is preserved.
    String path = Optional.ofNullable(
        (String) req.getAttribute(JettyServerModule.ORIGINAL_PATH_ATTRIBUTE_NAME))
        .orElse(req.getRequestURI());
    StringBuilder redirectUrl = new StringBuilder()
        .append(req.getScheme())
        .append("://")
        .append(leaderHttp.getHost())
        .append(':')
        .append(leaderHttp.getPort())
        .append(path);
    String queryString = req.getQueryString();
    if (queryString != null) {
      redirectUrl.append('?').append(queryString);
    }
    return new LeaderResolution(redirectUrl.toString());
  }

  static final class LeaderResolution {
    static final LeaderResolution LEADING = new LeaderResolution(null, true, false);
    static final LeaderResolution NO_LEADER = new LeaderResolution(null, false, true);

    private final String redirectUrl;
    private final boolean leading;
    private final boolean noLeader;

    private LeaderResolution(String redirectUrl) {
      this(redirectUrl, false, false);
    }

    private LeaderResolution(String redirectUrl, boolean leading, boolean noLeader) {
      this.redirectUrl = redirectUrl;
      this.leading = leading;
      this.noLeader = noLeader;
    }

    boolean isLeading() { return leading; }
    boolean isNoLeader() { return noLeader; }
    Optional<String> getRedirectUrl() { return Optional.ofNullable(redirectUrl); }
  }

  private Optional<ServiceInstance> getLeader() {
    ImmutableSet<ServiceInstance> hostSet = serviceGroupMonitor.get();
    switch (hostSet.size()) {
      case 0:
        LOG.warn("No scheduler in host set, will not redirect despite not being leader.");
        return Optional.empty();
      case 1:
        LOG.debug("Found leader scheduler at {}", hostSet);
        return Optional.of(Iterables.getOnlyElement(hostSet));
      default:
        LOG.error("Multiple schedulers detected, will not redirect: {}", hostSet);
        return Optional.empty();
    }
  }
}
