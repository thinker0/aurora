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
package org.apache.aurora.scheduler.configuration.executor;

import java.util.List;

import com.google.common.collect.ImmutableList;

import org.apache.mesos.v1.Protos.CommandInfo;
import org.apache.mesos.v1.Protos.ExecutorID;
import org.apache.mesos.v1.Protos.ExecutorInfo;
import org.apache.mesos.v1.Protos.Volume;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

public class ExecutorConfigTest {

  private static final ExecutorInfo EXECUTOR = ExecutorInfo.newBuilder()
      .setExecutorId(ExecutorID.newBuilder().setValue("executor-id"))
      .setCommand(CommandInfo.newBuilder().setValue("echo hello"))
      .build();

  private static final List<Volume> VOLUMES = ImmutableList.of();

  // equals: non-ExecutorConfig object (false branch)
  @Test
  public void testEqualsNonInstance() {
    ExecutorConfig config = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    assertNotEquals(config, "not an ExecutorConfig");
  }

  // equals: equal configs (true branch)
  @Test
  public void testEqualsEqual() {
    ExecutorConfig c1 = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    ExecutorConfig c2 = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    assertEquals(c1, c2);
  }

  // equals: different executor (false branch)
  @Test
  public void testEqualsDifferentExecutor() {
    ExecutorInfo otherExecutor = ExecutorInfo.newBuilder()
        .setExecutorId(ExecutorID.newBuilder().setValue("other-id"))
        .setCommand(CommandInfo.newBuilder().setValue("echo world"))
        .build();
    ExecutorConfig c1 = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    ExecutorConfig c2 = new ExecutorConfig(otherExecutor, VOLUMES, "prefix-");
    assertNotEquals(c1, c2);
  }

  // equals: different task prefix
  @Test
  public void testEqualsDifferentPrefix() {
    ExecutorConfig c1 = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    ExecutorConfig c2 = new ExecutorConfig(EXECUTOR, VOLUMES, "other-");
    assertNotEquals(c1, c2);
  }

  // hashCode consistency
  @Test
  public void testHashCode() {
    ExecutorConfig c1 = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    ExecutorConfig c2 = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    assertEquals(c1.hashCode(), c2.hashCode());
  }

  // getters
  @Test
  public void testGetters() {
    ExecutorConfig config = new ExecutorConfig(EXECUTOR, VOLUMES, "prefix-");
    assertEquals(EXECUTOR, config.getExecutor());
    assertEquals(VOLUMES, config.getVolumeMounts());
    assertEquals("prefix-", config.getTaskPrefix());
  }
}
