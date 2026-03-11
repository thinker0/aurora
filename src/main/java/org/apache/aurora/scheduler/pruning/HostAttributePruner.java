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

import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import javax.inject.Inject;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.util.concurrent.AbstractScheduledService;

import org.apache.aurora.common.inject.TimedInterceptor.Timed;
import org.apache.aurora.common.quantity.Amount;
import org.apache.aurora.common.quantity.Time;
import org.apache.aurora.common.stats.StatsProvider;
import org.apache.aurora.common.util.Clock;
import org.apache.aurora.scheduler.storage.Storage;
import org.apache.aurora.scheduler.storage.Storage.MutateWork.NoResult;
import org.apache.aurora.scheduler.storage.entities.IHostAttributes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

/**
 * Prunes host attributes for hosts that have not been seen for a configurable threshold.
 */
class HostAttributePruner extends AbstractScheduledService {
  private static final Logger LOG = LoggerFactory.getLogger(HostAttributePruner.class);

  @VisibleForTesting
  static final String HOSTS_PRUNED = "host_attributes_pruned";

  private final Clock clock;
  private final Storage storage;
  private final PrunerSettings settings;
  private final AtomicLong prunedCount;

  static class PrunerSettings {
    private final Amount<Long, Time> pruneInterval;
    private final Amount<Long, Time> pruningThreshold;

    PrunerSettings(
        Amount<Long, Time> pruneInterval,
        Amount<Long, Time> pruningThreshold) {

      this.pruneInterval = requireNonNull(pruneInterval);
      this.pruningThreshold = requireNonNull(pruningThreshold);
      Preconditions.checkArgument(
          pruneInterval.as(Time.MILLISECONDS) > 0,
          "pruneInterval must be positive");
      Preconditions.checkArgument(
          pruningThreshold.as(Time.MILLISECONDS) > 0,
          "pruningThreshold must be positive");
    }
  }

  @Inject
  HostAttributePruner(
      Clock clock,
      Storage storage,
      PrunerSettings settings,
      StatsProvider statsProvider) {

    this.clock = requireNonNull(clock);
    this.storage = requireNonNull(storage);
    this.settings = requireNonNull(settings);
    this.prunedCount = statsProvider.makeCounter(HOSTS_PRUNED);
  }

  @Override
  protected Scheduler scheduler() {
    return Scheduler.newFixedDelaySchedule(
        settings.pruneInterval.as(Time.MILLISECONDS),
        settings.pruneInterval.as(Time.MILLISECONDS),
        TimeUnit.MILLISECONDS);
  }

  @VisibleForTesting
  void runForTest() {
    runOneIteration();
  }

  @Timed("host_attribute_store_prune")
  @Override
  protected void runOneIteration() {
    storage.write((NoResult.Quiet) storeProvider -> {
      long cutoff = clock.nowMillis() - settings.pruningThreshold.as(Time.MILLISECONDS);
      Set<String> toPrune = storeProvider.getAttributeStore()
          .getHostAttributes()
          .stream()
          .filter(a -> a.getLastSeenMs() > 0 && a.getLastSeenMs() < cutoff)
          .map(IHostAttributes::getHost)
          .collect(Collectors.toSet());

      toPrune.forEach(host -> storeProvider.getAttributeStore().deleteHostAttributes(host));
      prunedCount.addAndGet(toPrune.size());

      if (toPrune.isEmpty()) {
        LOG.debug("No stale host attributes to prune.");
      } else {
        LOG.info("Pruned stale host attributes for {} host(s): {}", toPrune.size(), toPrune);
      }
    });
  }
}
