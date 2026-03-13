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
package org.apache.aurora.scheduler.events;

import com.google.common.collect.ImmutableSet;

import org.apache.aurora.gen.HostAttributes;
import org.apache.aurora.gen.ScheduleStatus;
import org.apache.aurora.scheduler.base.TaskTestUtil;
import org.apache.aurora.scheduler.events.PubsubEvent.HostAttributesChanged;
import org.apache.aurora.scheduler.events.PubsubEvent.TasksDeleted;
import org.apache.aurora.scheduler.storage.entities.IHostAttributes;
import org.apache.aurora.scheduler.storage.entities.IScheduledTask;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

public class PubsubEventTest {

  private static final IScheduledTask TASK = TaskTestUtil.makeTask("task1", TaskTestUtil.JOB);

  // TasksDeleted: equals same object (both branches covered)
  @Test
  public void testTasksDeletedEqualsSame() {
    TasksDeleted event = new TasksDeleted(ImmutableSet.of(TASK));
    assertEquals(event, event);
  }

  // TasksDeleted: equals non-TasksDeleted object (false branch)
  @Test
  public void testTasksDeletedEqualsNonTasksDeleted() {
    TasksDeleted event = new TasksDeleted(ImmutableSet.of(TASK));
    assertNotEquals(event, "not a TasksDeleted");
  }

  // TasksDeleted: equals equal TasksDeleted (true branch)
  @Test
  public void testTasksDeletedEqualsEqual() {
    TasksDeleted event1 = new TasksDeleted(ImmutableSet.of(TASK));
    TasksDeleted event2 = new TasksDeleted(ImmutableSet.of(TASK));
    assertEquals(event1, event2);
  }

  // TasksDeleted: equals different TasksDeleted
  @Test
  public void testTasksDeletedEqualsDifferent() {
    IScheduledTask task2 = TaskTestUtil.makeTask("task2", TaskTestUtil.JOB);
    TasksDeleted event1 = new TasksDeleted(ImmutableSet.of(TASK));
    TasksDeleted event2 = new TasksDeleted(ImmutableSet.of(task2));
    assertNotEquals(event1, event2);
  }

  // TasksDeleted: hashCode and getTasks
  @Test
  public void testTasksDeletedHashCodeAndGet() {
    ImmutableSet<IScheduledTask> tasks = ImmutableSet.of(TASK);
    TasksDeleted event = new TasksDeleted(tasks);
    assertEquals(tasks, event.getTasks());
    assertEquals(event.hashCode(), new TasksDeleted(tasks).hashCode());
  }

  // HostAttributesChanged: equals non-HostAttributesChanged (false branch)
  @Test
  public void testHostAttributesChangedEqualsNonInstance() {
    IHostAttributes attrs = IHostAttributes.build(new HostAttributes().setHost("h1").setSlaveId("s1"));
    HostAttributesChanged event = new HostAttributesChanged(attrs);
    assertNotEquals(event, "not an event");
  }

  // HostAttributesChanged: equals same attributes (true branch)
  @Test
  public void testHostAttributesChangedEqualsEqual() {
    IHostAttributes attrs = IHostAttributes.build(new HostAttributes().setHost("h1").setSlaveId("s1"));
    HostAttributesChanged event1 = new HostAttributesChanged(attrs);
    HostAttributesChanged event2 = new HostAttributesChanged(attrs);
    assertEquals(event1, event2);
  }
}
