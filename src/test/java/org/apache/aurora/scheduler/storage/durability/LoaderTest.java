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
package org.apache.aurora.scheduler.storage.durability;

import java.util.stream.Stream;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.gen.storage.Op;
import org.apache.aurora.gen.storage.SaveFrameworkId;
import org.apache.aurora.scheduler.base.TaskTestUtil;
import org.apache.aurora.scheduler.storage.SchedulerStore;
import org.apache.aurora.scheduler.storage.Storage.MutableStoreProvider;
import org.apache.aurora.scheduler.storage.durability.Persistence.Edit;
import org.junit.Test;

import static org.easymock.EasyMock.expect;

/**
 * Tests for {@link Loader}.
 */
public class LoaderTest extends EasyMockTest {

  /**
   * Verifies that a WAL op whose field ID is unknown (i.e. written by a newer version of the
   * scheduler) is silently skipped rather than causing a NullPointerException.
   *
   * When an old scheduler reads a WAL entry whose Op union field ID it does not recognise,
   * Apache Thrift's TUnion deserialization skips the raw bytes and leaves
   * {@code op.getSetField()} as {@code null}.  A plain {@code switch(null)} in Java throws
   * a NullPointerException, so Loader must guard against this before entering the switch.
   */
  @Test
  public void testUnknownOpIsSkipped() {
    MutableStoreProvider stores = createMock(MutableStoreProvider.class);
    // No store methods should be called for an unrecognised op.
    control.replay();

    // new Op() leaves setField_ unset → getSetField() returns null,
    // simulating what Thrift produces when it encounters an unknown union field ID.
    Op unknownOp = new Op();
    Loader.load(stores, TaskTestUtil.THRIFT_BACKFILL, Stream.of(Edit.op(unknownOp)));
  }

  /**
   * Verifies that a known op type is correctly routed to the appropriate store method.
   *
   * Note: the {@code default:} branch in the switch (which throws IllegalArgumentException) is
   * unreachable at runtime. Thrift's TUnion deserialization returns {@code null} (not a new enum
   * constant) for unknown field IDs, and the null case is handled by the null guard above the
   * switch. All non-null _Fields values are explicitly handled in the switch.
   */
  @Test
  public void testSaveFrameworkIdOp() {
    MutableStoreProvider stores = createMock(MutableStoreProvider.class);
    SchedulerStore.Mutable schedulerStore = createMock(SchedulerStore.Mutable.class);
    expect(stores.getSchedulerStore()).andReturn(schedulerStore);
    schedulerStore.saveFrameworkId("test-framework-id");
    control.replay();

    Op op = Op.saveFrameworkId(new SaveFrameworkId("test-framework-id"));
    Loader.load(stores, TaskTestUtil.THRIFT_BACKFILL, Stream.of(Edit.op(op)));
  }
}
