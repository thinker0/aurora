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
package org.apache.aurora.scheduler.app;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.concurrent.TimeoutException;

import com.google.common.net.HostAndPort;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;

import org.apache.aurora.GuavaUtils.ServiceManagerIface;
import org.apache.aurora.common.application.Lifecycle;
import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.common.zookeeper.SingletonService;
import org.apache.aurora.common.zookeeper.SingletonService.LeadException;
import org.apache.aurora.common.zookeeper.SingletonService.LeadershipListener;
import org.apache.aurora.scheduler.AppStartup;
import org.apache.aurora.scheduler.SchedulerLifecycle;
import org.apache.aurora.scheduler.app.SchedulerMain.Options;
import org.apache.aurora.scheduler.http.HttpService;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.expectLastCall;

public class SchedulerMainTest extends EasyMockTest {

  private SingletonService schedulerService;
  private HttpService httpService;
  private SchedulerLifecycle schedulerLifecycle;
  // Lifecycle has final methods (awaitShutdown, shutdown) — use a real instance
  // pre-triggered to return immediately from awaitShutdown().
  private Lifecycle appLifecycle;
  private ServiceManagerIface startupServices;

  @Before
  public void setUp() {
    schedulerService = createMock(SingletonService.class);
    httpService = createMock(HttpService.class);
    schedulerLifecycle = createMock(SchedulerLifecycle.class);
    // Lifecycle.awaitShutdown() is final — EasyMock cannot proxy it.
    // Use a real Lifecycle with a no-op command.
    appLifecycle = new Lifecycle(() -> { });
    startupServices = createMock(ServiceManagerIface.class);
  }

  private SchedulerMain createSchedulerMain() {
    Injector injector = Guice.createInjector(new AbstractModule() {
      @Override
      protected void configure() {
        bind(SingletonService.class).toInstance(schedulerService);
        bind(HttpService.class).toInstance(httpService);
        bind(SchedulerLifecycle.class).toInstance(schedulerLifecycle);
        bind(Lifecycle.class).toInstance(appLifecycle);
        bind(ServiceManagerIface.class)
            .annotatedWith(AppStartup.class)
            .toInstance(startupServices);
      }
    });
    SchedulerMain main = new SchedulerMain();
    injector.injectMembers(main);
    return main;
  }

  private Options defaultOptions() {
    Options options = new Options();
    options.serversetEndpointName = "http";
    return options;
  }

  private void expectStopSequence() throws TimeoutException {
    expect(startupServices.stopAsync()).andReturn(startupServices);
    startupServices.awaitStopped(5L, java.util.concurrent.TimeUnit.SECONDS);
    expectLastCall();
  }

  /**
   * Covers the catch(LeadException) branch in run().
   */
  @Test(expected = IllegalStateException.class)
  public void testRunLeadExceptionThrows() throws Exception {
    HostAndPort httpAddr = HostAndPort.fromParts("localhost", 8080);
    LeadershipListener listener = createMock(LeadershipListener.class);

    expect(startupServices.startAsync()).andReturn(startupServices);
    startupServices.awaitHealthy();
    expectLastCall();
    expect(schedulerLifecycle.prepare()).andReturn(listener);
    expect(httpService.getAddress()).andReturn(httpAddr);
    expect(httpService.getAdvertiserAddress()).andReturn(Optional.empty());
    schedulerService.lead(
        anyObject(InetSocketAddress.class),
        anyObject(),
        anyObject(LeadershipListener.class));
    expectLastCall().andThrow(new LeadException("test", null));
    expectStopSequence();

    control.replay();

    appLifecycle.shutdown();

    SchedulerMain main = createSchedulerMain();
    main.run(defaultOptions());
  }

  /**
   * Covers the advertiserAddress.isPresent() == false branch.
   */
  @Test
  public void testRunWithoutAdvertiserAddress() throws Exception {
    HostAndPort httpAddr = HostAndPort.fromParts("localhost", 8080);
    LeadershipListener listener = createMock(LeadershipListener.class);

    expect(startupServices.startAsync()).andReturn(startupServices);
    startupServices.awaitHealthy();
    expectLastCall();
    expect(schedulerLifecycle.prepare()).andReturn(listener);
    expect(httpService.getAddress()).andReturn(httpAddr);
    expect(httpService.getAdvertiserAddress()).andReturn(Optional.empty());
    schedulerService.lead(
        anyObject(InetSocketAddress.class),
        anyObject(),
        anyObject(LeadershipListener.class));
    expectLastCall();
    expectStopSequence();

    control.replay();

    // Pre-trigger shutdown so awaitShutdown() returns immediately.
    appLifecycle.shutdown();

    SchedulerMain main = createSchedulerMain();
    main.run(defaultOptions());
  }

  /**
   * Covers the advertiserAddress.isPresent() == true branch.
   */
  @Test
  public void testRunWithAdvertiserAddress() throws Exception {
    HostAndPort httpAddr = HostAndPort.fromParts("localhost", 8080);
    HostAndPort advertiserAddr = HostAndPort.fromParts("public.host", 9090);
    LeadershipListener listener = createMock(LeadershipListener.class);

    expect(startupServices.startAsync()).andReturn(startupServices);
    startupServices.awaitHealthy();
    expectLastCall();
    expect(schedulerLifecycle.prepare()).andReturn(listener);
    expect(httpService.getAddress()).andReturn(httpAddr);
    expect(httpService.getAdvertiserAddress()).andReturn(Optional.of(advertiserAddr));
    schedulerService.lead(
        anyObject(InetSocketAddress.class),
        anyObject(),
        anyObject(LeadershipListener.class));
    expectLastCall();
    expectStopSequence();

    control.replay();

    // Pre-trigger shutdown so awaitShutdown() returns immediately.
    appLifecycle.shutdown();

    SchedulerMain main = createSchedulerMain();
    main.run(defaultOptions());
  }
}
