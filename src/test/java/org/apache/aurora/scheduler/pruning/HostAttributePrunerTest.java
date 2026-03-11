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
package org.apache.aurora.scheduler.pruning;

import com.google.common.collect.ImmutableSet;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;

import org.apache.aurora.common.quantity.Amount;
import org.apache.aurora.common.quantity.Time;
import org.apache.aurora.common.stats.StatsProvider;
import org.apache.aurora.common.util.Clock;
import org.apache.aurora.common.util.testing.FakeClock;
import org.apache.aurora.gen.Attribute;
import org.apache.aurora.gen.HostAttributes;
import org.apache.aurora.gen.MaintenanceMode;
import org.apache.aurora.scheduler.pruning.HostAttributePruner.PrunerSettings;
import org.apache.aurora.scheduler.storage.Storage;
import org.apache.aurora.scheduler.storage.Storage.MutateWork.NoResult;
import org.apache.aurora.scheduler.storage.entities.IHostAttributes;
import org.apache.aurora.scheduler.storage.mem.MemStorageModule;
import org.apache.aurora.scheduler.testing.FakeStatsProvider;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HostAttributePrunerTest {

  private static final Amount<Long, Time> THRESHOLD = Amount.of(30L, Time.DAYS);
  private static final Amount<Long, Time> INTERVAL = Amount.of(1L, Time.HOURS);

  private FakeClock clock;
  private Storage storage;
  private HostAttributePruner pruner;
  private FakeStatsProvider statsProvider;

  private static IHostAttributes makeAttrs(String host, String slaveId) {
    return IHostAttributes.build(
        new HostAttributes(host, ImmutableSet.<Attribute>of())
            .setSlaveId(slaveId)
            .setMode(MaintenanceMode.NONE));
  }

  @Before
  public void setUp() {
    clock = new FakeClock();
    clock.setNowMillis(1_000_000L);
    statsProvider = new FakeStatsProvider();

    Injector injector = Guice.createInjector(
        new MemStorageModule(),
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(StatsProvider.class).toInstance(statsProvider);
            bind(Clock.class).toInstance(clock);
          }
        });

    storage = injector.getInstance(Storage.class);
    storage.prepare();

    pruner = new HostAttributePruner(
        clock,
        storage,
        new PrunerSettings(INTERVAL, THRESHOLD),
        statsProvider);
  }

  private void saveAttrs(IHostAttributes attrs) {
    storage.write((NoResult.Quiet) sp -> sp.getAttributeStore().saveHostAttributes(attrs));
  }

  @Test
  public void testNoStaleHosts() {
    IHostAttributes hostA = makeAttrs("hostA", "slaveA");
    saveAttrs(hostA);

    // No time has passed - host was just saved
    pruner.runForTest();

    assertEquals(1, storage.read(sp -> sp.getAttributeStore().getHostAttributes()).size());
    assertEquals(0L, statsProvider.getLongValue(HostAttributePruner.HOSTS_PRUNED));
  }

  @Test
  public void testPruneStaleHosts() {
    IHostAttributes hostA = makeAttrs("hostA", "slaveA");
    IHostAttributes hostB = makeAttrs("hostB", "slaveB");

    saveAttrs(hostA);
    saveAttrs(hostB);

    // Advance past pruning threshold
    clock.advance(THRESHOLD);
    clock.advance(Amount.of(1L, Time.MILLISECONDS));

    pruner.runForTest();

    assertTrue(storage.read(sp -> sp.getAttributeStore().getHostAttributes()).isEmpty());
    assertEquals(2L, statsProvider.getLongValue(HostAttributePruner.HOSTS_PRUNED));
  }

  @Test
  public void testPartialPrune() {
    IHostAttributes hostA = makeAttrs("hostA", "slaveA");
    saveAttrs(hostA);

    // Advance past threshold
    clock.advance(THRESHOLD);
    clock.advance(Amount.of(1L, Time.MILLISECONDS));

    // Save hostB now (fresh - its lastSeenMs is now past the old time)
    IHostAttributes hostB = makeAttrs("hostB", "slaveB");
    saveAttrs(hostB);

    pruner.runForTest();

    // hostA should be pruned, hostB should remain
    assertEquals(1, storage.read(sp -> sp.getAttributeStore().getHostAttributes()).size());
    assertTrue(storage.read(
        sp -> sp.getAttributeStore().getHostAttributes("hostB")).isPresent());
    assertEquals(1L, statsProvider.getLongValue(HostAttributePruner.HOSTS_PRUNED));
  }

  @Test
  public void testHostsWithZeroLastSeenMsNotPruned() {
    // Simulate a host with lastSeenMs = 0 (e.g., edge case where clock is at epoch).
    // MemAttributeStore stamps 0 when clock.nowMillis() == 0.
    // The pruner's filter requires lastSeenMs > 0, so these hosts must never be pruned.
    clock.setNowMillis(0L);
    saveAttrs(makeAttrs("hostA", "slaveA"));

    // Advance well past threshold with a normal clock value
    clock.setNowMillis(1_000_000L);
    clock.advance(THRESHOLD);
    clock.advance(Amount.of(1L, Time.MILLISECONDS));

    pruner.runForTest();

    // Host with lastSeenMs = 0 must NOT be pruned
    assertEquals(1, storage.read(sp -> sp.getAttributeStore().getHostAttributes()).size());
    assertEquals(0L, statsProvider.getLongValue(HostAttributePruner.HOSTS_PRUNED));
  }

  @Test
  public void testUpgradeScenarioPreservesTimestamp() {
    // Simulate WAL replay: attrs with a non-zero lastSeenMs (e.g., from a new-format WAL
    // entry) should have their timestamp preserved rather than overwritten by clock.
    clock.setNowMillis(5_000L);
    saveAttrs(makeAttrs("hostA", "slaveA"));

    // Verify lastSeenMs was stamped at save time
    long savedTs = storage.read(
        sp -> sp.getAttributeStore().getHostAttributes("hostA"))
        .map(IHostAttributes::getLastSeenMs)
        .orElse(-1L);
    assertEquals(5_000L, savedTs);

    // Simulate replay with a different clock: save attrs that already carry a timestamp
    clock.setNowMillis(9_000L);
    IHostAttributes attrsWithTs = IHostAttributes.build(
        makeAttrs("hostA", "slaveA").newBuilder().setLastSeenMs(5_000L));
    storage.write((NoResult.Quiet) sp -> sp.getAttributeStore().saveHostAttributes(attrsWithTs));

    // lastSeenMs must be preserved as 5_000L, not overwritten with 9_000L
    long replayedTs = storage.read(
        sp -> sp.getAttributeStore().getHostAttributes("hostA"))
        .map(IHostAttributes::getLastSeenMs)
        .orElse(-1L);
    assertEquals(5_000L, replayedTs);
  }
}
