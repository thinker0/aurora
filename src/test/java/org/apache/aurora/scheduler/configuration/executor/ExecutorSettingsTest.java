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

import java.util.Optional;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.gen.TaskConfig;
import org.apache.aurora.scheduler.storage.entities.ITaskConfig;
import org.apache.mesos.v1.Protos.CommandInfo;
import org.apache.mesos.v1.Protos.ExecutorID;
import org.apache.mesos.v1.Protos.ExecutorInfo;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ExecutorSettingsTest extends EasyMockTest {

  private static final ExecutorInfo EXECUTOR = ExecutorInfo.newBuilder()
      .setExecutorId(ExecutorID.newBuilder().setValue("executor-id"))
      .setCommand(CommandInfo.newBuilder().setValue("echo hello"))
      .build();

  @Test
  public void testGetExecutorConfigPresent() {
    control.replay();
    ExecutorConfig config = new ExecutorConfig(EXECUTOR, ImmutableList.of(), "thermos-");
    ExecutorSettings settings = new ExecutorSettings(
        ImmutableMap.of("myExecutor", config), false);
    Optional<ExecutorConfig> result = settings.getExecutorConfig("myExecutor");
    assertTrue(result.isPresent());
    assertEquals(config, result.get());
  }

  @Test
  public void testGetExecutorConfigAbsent() {
    control.replay();
    ExecutorSettings settings = new ExecutorSettings(ImmutableMap.of(), false);
    Optional<ExecutorConfig> result = settings.getExecutorConfig("missing");
    assertFalse(result.isPresent());
  }

  @Test
  public void testShouldPopulateDiscoveryInfoTrue() {
    control.replay();
    ExecutorSettings settings = new ExecutorSettings(ImmutableMap.of(), true);
    assertTrue(settings.shouldPopulateDiscoverInfo());
  }

  @Test
  public void testShouldPopulateDiscoveryInfoFalse() {
    control.replay();
    ExecutorSettings settings = new ExecutorSettings(ImmutableMap.of(), false);
    assertFalse(settings.shouldPopulateDiscoverInfo());
  }

  @Test
  public void testGetExecutorOverheadNoExecutorConfig() {
    control.replay();
    // A TaskConfig without executorConfig set (isSetExecutorConfig() == false)
    ITaskConfig task = ITaskConfig.build(new TaskConfig());
    ExecutorSettings settings = new ExecutorSettings(ImmutableMap.of(), false);
    assertEquals(
        org.apache.aurora.scheduler.resources.ResourceBag.EMPTY,
        settings.getExecutorOverhead(task));
  }

  @Test
  public void testGetExecutorOverheadUnknownExecutorName() {
    control.replay();
    ExecutorConfig config = new ExecutorConfig(EXECUTOR, ImmutableList.of(), "thermos-");
    org.apache.aurora.gen.ExecutorConfig genExecConfig = new org.apache.aurora.gen.ExecutorConfig();
    genExecConfig.setName("unknownExecutor");
    genExecConfig.setData("{}");
    TaskConfig tc = new TaskConfig();
    tc.setExecutorConfig(genExecConfig);
    ITaskConfig task = ITaskConfig.build(tc);

    ExecutorSettings settings = new ExecutorSettings(
        ImmutableMap.of("knownExecutor", config), false);
    assertEquals(
        org.apache.aurora.scheduler.resources.ResourceBag.EMPTY,
        settings.getExecutorOverhead(task));
  }

  @Test
  public void testEqualsAndHashCode() {
    control.replay();
    ExecutorConfig config = new ExecutorConfig(EXECUTOR, ImmutableList.of(), "thermos-");
    ExecutorSettings s1 = new ExecutorSettings(ImmutableMap.of("e", config), false);
    ExecutorSettings s2 = new ExecutorSettings(ImmutableMap.of("e", config), false);
    assertEquals(s1, s2);
    assertEquals(s1.hashCode(), s2.hashCode());
  }

  @Test
  public void testNotEqualsOtherType() {
    control.replay();
    ExecutorSettings settings = new ExecutorSettings(ImmutableMap.of(), false);
    assertFalse(settings.equals("not an ExecutorSettings"));
  }
}
