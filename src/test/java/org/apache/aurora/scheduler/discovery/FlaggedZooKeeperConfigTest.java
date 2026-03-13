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
package org.apache.aurora.scheduler.discovery;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.Optional;

import com.google.common.collect.ImmutableList;

import org.apache.aurora.common.quantity.Amount;
import org.apache.aurora.common.quantity.Time;
import org.apache.aurora.scheduler.config.types.TimeAmount;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class FlaggedZooKeeperConfigTest {

  private static FlaggedZooKeeperConfig.Options buildOptions(
      String chrootPath,
      String digestCredentials) {

    FlaggedZooKeeperConfig.Options opts = new FlaggedZooKeeperConfig.Options();
    opts.zkEndpoints = ImmutableList.of(InetSocketAddress.createUnresolved("localhost", 2181));
    opts.chrootPath = chrootPath;
    opts.digestCredentials = digestCredentials;
    return opts;
  }

  // chrootPath present branch
  @Test
  public void testCreateWithChrootPath() {
    FlaggedZooKeeperConfig.Options opts = buildOptions("/aurora", null);
    ZooKeeperConfig config = FlaggedZooKeeperConfig.create(opts);
    assertTrue(config.getChrootPath().isPresent());
    assertEquals("/aurora", config.getChrootPath().get());
  }

  // chrootPath absent branch
  @Test
  public void testCreateWithoutChrootPath() {
    FlaggedZooKeeperConfig.Options opts = buildOptions(null, null);
    ZooKeeperConfig config = FlaggedZooKeeperConfig.create(opts);
    assertFalse(config.getChrootPath().isPresent());
  }

  // digestCredentials present branch
  @Test
  public void testCreateWithDigestCredentials() {
    FlaggedZooKeeperConfig.Options opts = buildOptions(null, "user:pass");
    ZooKeeperConfig config = FlaggedZooKeeperConfig.create(opts);
    assertTrue(config.getCredentials().isPresent());
  }

  // digestCredentials absent branch
  @Test
  public void testCreateWithoutDigestCredentials() {
    FlaggedZooKeeperConfig.Options opts = buildOptions(null, null);
    ZooKeeperConfig config = FlaggedZooKeeperConfig.create(opts);
    assertFalse(config.getCredentials().isPresent());
  }
}
