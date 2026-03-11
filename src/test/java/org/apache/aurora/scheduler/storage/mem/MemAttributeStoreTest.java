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
package org.apache.aurora.scheduler.storage.mem;

import java.util.Optional;

import com.google.inject.AbstractModule;
import com.google.inject.Module;
import com.google.inject.util.Modules;

import org.apache.aurora.common.stats.StatsProvider;
import org.apache.aurora.common.util.Clock;
import org.apache.aurora.common.util.testing.FakeClock;
import org.apache.aurora.scheduler.storage.AbstractAttributeStoreTest;
import org.apache.aurora.scheduler.storage.Storage.MutateWork.NoResult;
import org.apache.aurora.scheduler.storage.entities.IHostAttributes;
import org.apache.aurora.scheduler.testing.FakeStatsProvider;
import org.junit.Test;

import static org.apache.aurora.scheduler.storage.mem.MemAttributeStore.ATTRIBUTE_STORE_SIZE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class MemAttributeStoreTest extends AbstractAttributeStoreTest {

  private FakeStatsProvider statsProvider;
  private FakeClock fakeClock;

  @Override
  protected Module getStorageModule() {
    statsProvider = new FakeStatsProvider();
    fakeClock = new FakeClock();
    fakeClock.setNowMillis(1000L);
    return Modules.combine(
        new MemStorageModule(),
        new AbstractModule() {
          @Override
          protected void configure() {
            bind(StatsProvider.class).toInstance(statsProvider);
            bind(Clock.class).toInstance(fakeClock);
          }
        });
  }

  @Test
  public void testStoreSize() {
    assertEquals(0L, statsProvider.getLongValue(ATTRIBUTE_STORE_SIZE));
    insert(HOST_A_ATTRS);
    assertEquals(1L, statsProvider.getLongValue(ATTRIBUTE_STORE_SIZE));
    insert(HOST_B_ATTRS);
    assertEquals(2L, statsProvider.getLongValue(ATTRIBUTE_STORE_SIZE));
    truncate();
    assertEquals(0L, statsProvider.getLongValue(ATTRIBUTE_STORE_SIZE));
  }

  @Test
  public void testLastSeenMsSetOnSave() {
    fakeClock.setNowMillis(5000L);
    insert(HOST_A_ATTRS);
    assertTrue(
        injector.getInstance(org.apache.aurora.scheduler.storage.Storage.class)
            .read(sp -> sp.getAttributeStore().getHostAttributes(HOST_A_ATTRS.getHost()))
            .map(a -> a.getLastSeenMs() == 5000L)
            .orElse(false));
  }

  @Test
  public void testLastSeenMsPreservedIfAlreadySet() {
    // Simulate WAL replay: attrs that already carry a lastSeenMs must not have
    // their timestamp overwritten by the clock (Option B preservation).
    fakeClock.setNowMillis(5000L);
    insert(HOST_A_ATTRS);

    // Save again with a non-zero lastSeenMs (simulates WAL replay with stored value)
    fakeClock.setNowMillis(9000L);
    long replayTs = 3000L;
    IHostAttributes attrsWithTs = IHostAttributes.build(
        HOST_A_ATTRS.newBuilder().setLastSeenMs(replayTs));
    injector.getInstance(org.apache.aurora.scheduler.storage.Storage.class).write(
        (NoResult.Quiet) sp -> sp.getAttributeStore().saveHostAttributes(attrsWithTs));

    // lastSeenMs must be 3000L (preserved), not 9000L (overwritten by clock)
    assertTrue(
        injector.getInstance(org.apache.aurora.scheduler.storage.Storage.class)
            .read(sp -> sp.getAttributeStore().getHostAttributes(HOST_A_ATTRS.getHost()))
            .map(a -> a.getLastSeenMs() == replayTs)
            .orElse(false));
  }

  @Test
  public void testDeleteSingleHost() {
    insert(HOST_A_ATTRS);
    insert(HOST_B_ATTRS);
    injector.getInstance(org.apache.aurora.scheduler.storage.Storage.class).write(
        (NoResult.Quiet) sp ->
            sp.getAttributeStore().deleteHostAttributes(HOST_A_ATTRS.getHost()));
    assertEquals(
        Optional.empty(),
        injector.getInstance(org.apache.aurora.scheduler.storage.Storage.class)
            .read(sp -> sp.getAttributeStore().getHostAttributes(HOST_A_ATTRS.getHost())));
    assertTrue(
        injector.getInstance(org.apache.aurora.scheduler.storage.Storage.class)
            .read(sp -> sp.getAttributeStore().getHostAttributes(HOST_B_ATTRS.getHost()))
            .isPresent());
  }
}
