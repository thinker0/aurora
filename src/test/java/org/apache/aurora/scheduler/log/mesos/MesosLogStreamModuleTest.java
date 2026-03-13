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
package org.apache.aurora.scheduler.log.mesos;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.util.Optional;

import com.google.common.collect.ImmutableList;

import org.apache.aurora.scheduler.discovery.ZooKeeperConfig;
import org.junit.Test;

public class MesosLogStreamModuleTest {

  private static MesosLogStreamModule.Options makeOptions(File logPath) {
    MesosLogStreamModule.Options options = new MesosLogStreamModule.Options();
    options.logPath = logPath;
    options.zkLogGroupPath = "/aurora/replicated-log";
    options.quorumSize = 1;
    return options;
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullLogPathThrows() throws IOException {
    MesosLogStreamModule.Options options = new MesosLogStreamModule.Options();
    options.logPath = null;
    options.zkLogGroupPath = "/aurora/replicated-log";
    ZooKeeperConfig zkConfig = ZooKeeperConfig.create(
        ImmutableList.of(InetSocketAddress.createUnresolved("localhost", 2181)));
    new MesosLogStreamModule(options, zkConfig);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullZkGroupPathThrows() throws IOException {
    File tempDir = Files.createTempDirectory("mesos-log-test").toFile();
    tempDir.deleteOnExit();
    MesosLogStreamModule.Options options = new MesosLogStreamModule.Options();
    options.logPath = new File(tempDir, "log");
    options.zkLogGroupPath = null;
    ZooKeeperConfig zkConfig = ZooKeeperConfig.create(
        ImmutableList.of(InetSocketAddress.createUnresolved("localhost", 2181)));
    new MesosLogStreamModule(options, zkConfig);
  }

}
