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
package org.apache.aurora.scheduler.thrift.aop;

import java.util.Arrays;
import java.util.Collections;

import com.google.common.collect.ImmutableSet;

import org.apache.aurora.gen.ConfigGroup;
import org.apache.aurora.gen.ConfigSummary;
import org.apache.aurora.gen.ConfigSummaryResult;
import org.apache.aurora.gen.GetJobUpdateDetailsResult;
import org.apache.aurora.gen.GetJobUpdateSummariesResult;
import org.apache.aurora.gen.GetJobsResult;
import org.apache.aurora.gen.GetPendingReasonResult;
import org.apache.aurora.gen.Identity;
import org.apache.aurora.gen.JobConfiguration;
import org.apache.aurora.gen.JobKey;
import org.apache.aurora.gen.JobSummary;
import org.apache.aurora.gen.JobSummaryResult;
import org.apache.aurora.gen.JobUpdateDetails;
import org.apache.aurora.gen.JobUpdateKey;
import org.apache.aurora.gen.JobUpdateSummary;
import org.apache.aurora.gen.PendingReason;
import org.apache.aurora.gen.Result;
import org.apache.aurora.gen.RoleSummary;
import org.apache.aurora.gen.RoleSummaryResult;
import org.apache.aurora.gen.ScheduleStatusResult;
import org.apache.aurora.gen.ScheduledTask;
import org.apache.aurora.gen.TaskConfig;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ThriftWorkloadCounterImplTest {

  private ThriftWorkload.ThriftWorkloadCounterImpl counter;

  @Before
  public void setUp() {
    counter = new ThriftWorkload.ThriftWorkloadCounterImpl();
  }

  @Test
  public void testNoneSet() {
    Result result = new Result();
    assertEquals(Integer.valueOf(0), counter.apply(result));
  }

  @Test
  public void testScheduleStatusResult() {
    ScheduledTask t1 = new ScheduledTask();
    ScheduledTask t2 = new ScheduledTask();
    t1.setAssignedTask(new org.apache.aurora.gen.AssignedTask().setTaskId("t1"));
    t2.setAssignedTask(new org.apache.aurora.gen.AssignedTask().setTaskId("t2"));
    ScheduleStatusResult statusResult = new ScheduleStatusResult();
    statusResult.setTasks(Arrays.asList(t1, t2));
    Result result = new Result();
    result.setScheduleStatusResult(statusResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testScheduleStatusResultEmpty() {
    ScheduleStatusResult statusResult = new ScheduleStatusResult();
    statusResult.setTasks(Collections.emptyList());
    Result result = new Result();
    result.setScheduleStatusResult(statusResult);
    assertEquals(Integer.valueOf(0), counter.apply(result));
  }

  @Test
  public void testGetPendingReasonResult() {
    PendingReason r1 = new PendingReason();
    r1.setTaskId("task1");
    r1.setReason("reason1");
    PendingReason r2 = new PendingReason();
    r2.setTaskId("task2");
    r2.setReason("reason2");
    GetPendingReasonResult pendingResult = new GetPendingReasonResult();
    pendingResult.setReasons(ImmutableSet.of(r1, r2));
    Result result = new Result();
    result.setGetPendingReasonResult(pendingResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testConfigSummaryResult() {
    TaskConfig tc1 = new TaskConfig();
    tc1.setOwner(new Identity().setUser("user1"));
    TaskConfig tc2 = new TaskConfig();
    tc2.setOwner(new Identity().setUser("user2"));
    ConfigGroup g1 = new ConfigGroup();
    g1.setConfig(tc1);
    ConfigGroup g2 = new ConfigGroup();
    g2.setConfig(tc2);
    ConfigSummary summary = new ConfigSummary();
    summary.setGroups(ImmutableSet.of(g1, g2));
    ConfigSummaryResult configResult = new ConfigSummaryResult();
    configResult.setSummary(summary);
    Result result = new Result();
    result.setConfigSummaryResult(configResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testRoleSummaryResult() {
    RoleSummary rs1 = new RoleSummary();
    rs1.setRole("role1");
    RoleSummary rs2 = new RoleSummary();
    rs2.setRole("role2");
    RoleSummaryResult roleResult = new RoleSummaryResult();
    roleResult.setSummaries(ImmutableSet.of(rs1, rs2));
    Result result = new Result();
    result.setRoleSummaryResult(roleResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testJobSummaryResult() {
    JobSummary js1 = new JobSummary();
    js1.setJob(new JobConfiguration().setKey(new JobKey("role1", "env", "job1")));
    JobSummary js2 = new JobSummary();
    js2.setJob(new JobConfiguration().setKey(new JobKey("role2", "env", "job2")));
    JobSummaryResult jobSummaryResult = new JobSummaryResult();
    jobSummaryResult.setSummaries(ImmutableSet.of(js1, js2));
    Result result = new Result();
    result.setJobSummaryResult(jobSummaryResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testGetJobsResult() {
    JobConfiguration j1 = new JobConfiguration().setKey(new JobKey("role1", "env", "job1"));
    JobConfiguration j2 = new JobConfiguration().setKey(new JobKey("role2", "env", "job2"));
    GetJobsResult getJobsResult = new GetJobsResult();
    getJobsResult.setConfigs(ImmutableSet.of(j1, j2));
    Result result = new Result();
    result.setGetJobsResult(getJobsResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testGetJobUpdateSummariesResult() {
    JobUpdateSummary s1 = new JobUpdateSummary();
    s1.setKey(new JobUpdateKey().setId("id1"));
    JobUpdateSummary s2 = new JobUpdateSummary();
    s2.setKey(new JobUpdateKey().setId("id2"));
    GetJobUpdateSummariesResult summariesResult = new GetJobUpdateSummariesResult();
    summariesResult.setUpdateSummaries(Arrays.asList(s1, s2));
    Result result = new Result();
    result.setGetJobUpdateSummariesResult(summariesResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }

  @Test
  public void testGetJobUpdateDetailsResult() {
    JobUpdateDetails d1 = new JobUpdateDetails();
    JobUpdateDetails d2 = new JobUpdateDetails();
    GetJobUpdateDetailsResult detailsResult = new GetJobUpdateDetailsResult();
    detailsResult.setDetailsList(Arrays.asList(d1, d2));
    Result result = new Result();
    result.setGetJobUpdateDetailsResult(detailsResult);
    assertEquals(Integer.valueOf(2), counter.apply(result));
  }
}
