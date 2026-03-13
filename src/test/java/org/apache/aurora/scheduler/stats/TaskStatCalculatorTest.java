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
package org.apache.aurora.scheduler.stats;

import java.util.Collections;
import java.util.concurrent.atomic.AtomicLong;

import com.google.common.collect.ImmutableList;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.scheduler.resources.ResourceBag;
import org.apache.aurora.scheduler.stats.ResourceCounter.Metric;
import org.apache.aurora.scheduler.stats.ResourceCounter.MetricType;
import org.apache.aurora.scheduler.storage.Storage.StorageException;
import org.junit.Before;
import org.junit.Test;

import static org.easymock.EasyMock.anyObject;
import static org.easymock.EasyMock.anyString;
import static org.easymock.EasyMock.expect;

public class TaskStatCalculatorTest extends EasyMockTest {

  private ResourceCounter resourceCounter;
  private CachedCounters counters;
  private TaskStatCalculator calculator;

  @Before
  public void setUp() {
    resourceCounter = createMock(ResourceCounter.class);
    counters = createMock(CachedCounters.class);
    calculator = new TaskStatCalculator(resourceCounter, counters);
  }

  @Test
  public void testRunSuccessful() throws Exception {
    Metric totalMetric = new Metric(MetricType.TOTAL_CONSUMED, ResourceBag.EMPTY);
    expect(resourceCounter.computeConsumptionTotals())
        .andReturn(ImmutableList.of(totalMetric));
    for (MetricType type : MetricType.values()) {
      expect(resourceCounter.computeAggregates(anyObject(), anyObject(), anyObject()))
          .andReturn(Collections.emptyMap());
    }
    expect(resourceCounter.computeQuotaAllocationTotals())
        .andReturn(new Metric(MetricType.TOTAL_CONSUMED, ResourceBag.EMPTY));
    expect(resourceCounter.computeQuotaAllocationByRole())
        .andReturn(Collections.emptyMap());
    expect(counters.get(anyString())).andReturn(new AtomicLong()).anyTimes();

    control.replay();

    calculator.run();
  }

  @Test
  public void testRunHandlesStorageException() throws Exception {
    expect(resourceCounter.computeConsumptionTotals())
        .andThrow(new StorageException("Storage not ready"));

    control.replay();

    // Should not throw — StorageException is caught and logged.
    calculator.run();
  }
}
