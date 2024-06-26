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
package org.apache.aurora.scheduler;

import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableMap;

/**
 * Defines common task tier traits and behaviors.
 */
public final class TierInfo {

  private final boolean preemptible;
  private final boolean revocable;

  @JsonCreator
  public TierInfo(
      @JsonProperty("preemptible") boolean preemptible,
      @JsonProperty("revocable") boolean revocable) {

    this.preemptible = preemptible;
    this.revocable = revocable;
  }

  /**
   * Checks if this tier intends to run tasks as preemptible.
   *
   * @return {@code true} if this tier will result in tasks being run as preemptible, {@code false}
   * otherwise.
   */
  public boolean isPreemptible() {
    return preemptible;
  }

  /**
   * Checks if this tier intends to run with Mesos revocable resource offers.
   *
   * @return {@code true} if this tier requires revocable resource offers, {@code false} otherwise.
   */
  public boolean isRevocable() {
    return revocable;
  }

  /**
   * Checks if this tier meets the requirements to be considered a production tier:
   * Tier must not be running on revocable resources and must not be preemptable.
   *
   * @return {@code true} if this tier is a production tier, {@code false} otherwise.
   */
  @JsonIgnore
  public boolean isProduction() {
    return !(revocable || preemptible);
  }

  /**
   * Gets the map of tier attribute names to values.
   *
   * @return A readonly view of all tier attributes.
   */
  public Map<String, String> toMap() {
    return ImmutableMap.of(
        "preemptible", String.valueOf(preemptible),
        "revocable", String.valueOf(revocable)
    );
  }

  @Override
  public int hashCode() {
    return Objects.hash(preemptible, revocable);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof TierInfo)) {
      return false;
    }

    TierInfo other = (TierInfo) obj;
    return Objects.equals(preemptible, other.preemptible)
        && Objects.equals(revocable, other.revocable);
  }

  @Override
  public String toString() {
    return MoreObjects.toStringHelper(this)
        .add("preemptible", preemptible)
        .add("revocable", revocable)
        .toString();
  }
}
