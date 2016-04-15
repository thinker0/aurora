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
package org.apache.aurora.scheduler.discovery;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;

import com.google.common.base.Optional;
import com.google.common.base.Throwables;
import com.google.common.collect.ImmutableList;
import com.google.common.io.Files;
import com.google.common.util.concurrent.AbstractIdleService;
import com.google.inject.AbstractModule;
import com.google.inject.Inject;
import com.google.inject.Key;
import com.google.inject.PrivateModule;
import com.google.inject.Provider;
import com.google.inject.Singleton;

import org.apache.aurora.common.application.ShutdownRegistry;
import org.apache.aurora.common.inject.Bindings.KeyFactory;
import org.apache.aurora.common.zookeeper.ZooKeeperClient;
import org.apache.aurora.common.zookeeper.testing.ZooKeeperTestServer;
import org.apache.aurora.scheduler.SchedulerServicesModule;

import static com.google.common.base.Preconditions.checkNotNull;

/**
 * A guice binding module that configures and binds a {@link ZooKeeperClient} instance.
 */
public class ZooKeeperClientModule extends AbstractModule {
  private final KeyFactory keyFactory;
  private final ZooKeeperConfig config;

  /**
   * Creates a new ZK client module from the provided configuration.
   *
   * @param config Configuration parameters for the client.
   */
  public ZooKeeperClientModule(ZooKeeperConfig config) {
    this(KeyFactory.PLAIN, config);
  }

  /**
   * Creates a new ZK client module from the provided configuration, using a key factory to
   * qualify any bindings.
   *
   * @param keyFactory Factory to use when creating any exposed bindings.
   * @param config Configuration parameters for the client.
   */
  public ZooKeeperClientModule(KeyFactory keyFactory, ZooKeeperConfig config) {
    this.keyFactory = checkNotNull(keyFactory);
    this.config = checkNotNull(config);
  }

  @Override
  protected void configure() {
    Key<ZooKeeperClient> clientKey = keyFactory.create(ZooKeeperClient.class);
    if (config.inProcess) {
      File tempDir = Files.createTempDir();
      bind(ZooKeeperTestServer.class).toInstance(new ZooKeeperTestServer(tempDir, tempDir));

      install(new PrivateModule() {
        @Override
        protected void configure() {
          requireBinding(ShutdownRegistry.class);
          // Bound privately to give the local provider access to configuration settings.
          bind(ZooKeeperConfig.class).toInstance(config);
          bind(clientKey).toProvider(LocalClientProvider.class).in(Singleton.class);
          expose(clientKey);
        }
      });
      SchedulerServicesModule.addAppStartupServiceBinding(binder()).to(TestServerService.class);
    } else {
      bind(clientKey).toInstance(new ZooKeeperClient(
          config.sessionTimeout,
          config.credentials,
          config.chrootPath,
          config.servers));
    }
  }

  /**
   * A service to wrap ZooKeeperTestServer.  ZooKeeperTestServer is not a service itself because
   * some tests depend on stop/start routines that do not no-op, like startAsync and stopAsync may.
   */
  private static class TestServerService extends AbstractIdleService {
    private final ZooKeeperTestServer testServer;

    @Inject
    TestServerService(ZooKeeperTestServer testServer) {
      this.testServer = checkNotNull(testServer);
    }

    @Override
    protected void startUp() {
      // We actually start the test server on-demand rather than with the normal lifecycle.
      // This is because a ZooKeeperClient binding is needed before scheduler services are started.
    }

    @Override
    protected void shutDown() {
      testServer.stop();
    }
  }

  private static class LocalClientProvider implements Provider<ZooKeeperClient> {
    private final ZooKeeperConfig config;
    private final ZooKeeperTestServer testServer;

    @Inject
    LocalClientProvider(ZooKeeperConfig config, ZooKeeperTestServer testServer) {
      this.config = checkNotNull(config);
      this.testServer = checkNotNull(testServer);
    }

    @Override
    public ZooKeeperClient get() {
      try {
        testServer.startNetwork();
      } catch (IOException | InterruptedException e) {
        throw Throwables.propagate(e);
      }
      return new ZooKeeperClient(
          config.sessionTimeout,
          config.credentials,
          Optional.absent(), // chrootPath
          ImmutableList.of(InetSocketAddress.createUnresolved("localhost", testServer.getPort())));
    }
  }

}