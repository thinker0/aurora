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

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.ImmutableList;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;

import org.apache.aurora.common.application.ShutdownRegistry;
import org.apache.aurora.common.application.ShutdownRegistry.ShutdownRegistryImpl;
import org.apache.aurora.common.quantity.Amount;
import org.apache.aurora.common.quantity.Time;
import org.apache.aurora.common.stats.StatsProvider;
import org.apache.aurora.common.testing.TearDownTestCase;
import org.apache.aurora.common.zookeeper.Credentials;
import org.apache.aurora.common.zookeeper.ZooKeeperUtils;
import org.apache.aurora.scheduler.testing.FakeStatsProvider;
import org.apache.zookeeper.data.ACL;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ServiceDiscoveryModuleTest extends TearDownTestCase {

  private static final InetSocketAddress ZK_SERVER =
      InetSocketAddress.createUnresolved("localhost", 2181);

  /**
   * Covers the else-branch in configure(): zooKeeperConfig.isInProcess() == false,
   * uses toInstance(servers) binding.
   * Also covers provideAcls() with no credentials (OPEN_ACL_UNSAFE branch).
   */
  @Test
  public void testNotInProcessNoCredentials() {
    ZooKeeperConfig zkConfig = ZooKeeperConfig.create(ImmutableList.of(ZK_SERVER));

    ShutdownRegistryImpl shutdownRegistry = new ShutdownRegistryImpl();
    addTearDown(shutdownRegistry::execute);

    Injector injector = Guice.createInjector(
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(StatsProvider.class).toInstance(new FakeStatsProvider());
            bind(ShutdownRegistry.class).toInstance(shutdownRegistry);
          }
        },
        new ServiceDiscoveryModule(zkConfig, "/aurora/scheduler"));

    // Verify the ZOO_KEEPER_ACL_KEY binding resolves to OPEN_ACL_UNSAFE.
    @SuppressWarnings("unchecked")
    List<ACL> acls = (List<ACL>) injector
        .getBinding(ServiceDiscoveryBindings.ZOO_KEEPER_ACL_KEY)
        .getProvider()
        .get();
    assertEquals(ZooKeeperUtils.OPEN_ACL_UNSAFE, acls);

    // Verify the cluster binding resolves to the provided server list.
    @SuppressWarnings("unchecked")
    Iterable<InetSocketAddress> cluster = (Iterable<InetSocketAddress>) injector
        .getBinding(ServiceDiscoveryBindings.ZOO_KEEPER_CLUSTER_KEY)
        .getProvider()
        .get();
    assertNotNull(cluster);
  }

  /**
   * Covers provideAcls() with credentials present: returns EVERYONE_READ_CREATOR_ALL.
   */
  @Test
  public void testNotInProcessWithCredentials() {
    ZooKeeperConfig zkConfig = ZooKeeperConfig
        .create(ImmutableList.of(ZK_SERVER))
        .withCredentials(Credentials.digestCredentials("user", "pass"));

    ShutdownRegistryImpl shutdownRegistry = new ShutdownRegistryImpl();
    addTearDown(shutdownRegistry::execute);

    Injector injector = Guice.createInjector(
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(StatsProvider.class).toInstance(new FakeStatsProvider());
            bind(ShutdownRegistry.class).toInstance(shutdownRegistry);
          }
        },
        new ServiceDiscoveryModule(zkConfig, "/aurora/scheduler"));

    @SuppressWarnings("unchecked")
    List<ACL> acls = (List<ACL>) injector
        .getBinding(ServiceDiscoveryBindings.ZOO_KEEPER_ACL_KEY)
        .getProvider()
        .get();
    assertEquals(ZooKeeperUtils.EVERYONE_READ_CREATOR_ALL, acls);
  }
}
