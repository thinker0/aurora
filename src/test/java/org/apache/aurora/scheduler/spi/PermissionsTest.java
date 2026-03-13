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
package org.apache.aurora.scheduler.spi;

import java.util.Optional;

import org.apache.aurora.scheduler.spi.Permissions.Domain;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PermissionsTest {

  // Domain.fromString: found branch (THRIFT_AURORA_SCHEDULER_MANAGER)
  @Test
  public void testDomainFromStringManagerFound() {
    Optional<Domain> result = Domain.fromString("thrift.AuroraSchedulerManager");
    assertTrue(result.isPresent());
    assertEquals(Domain.THRIFT_AURORA_SCHEDULER_MANAGER, result.get());
  }

  // Domain.fromString: found branch (THRIFT_AURORA_ADMIN)
  @Test
  public void testDomainFromStringAdminFound() {
    Optional<Domain> result = Domain.fromString("thrift.AuroraAdmin");
    assertTrue(result.isPresent());
    assertEquals(Domain.THRIFT_AURORA_ADMIN, result.get());
  }

  // Domain.fromString: not-found branch
  @Test
  public void testDomainFromStringNotFound() {
    Optional<Domain> result = Domain.fromString("unknown.domain");
    assertFalse(result.isPresent());
  }

  // Domain.toString
  @Test
  public void testDomainToString() {
    assertEquals("thrift.AuroraSchedulerManager",
        Domain.THRIFT_AURORA_SCHEDULER_MANAGER.toString());
    assertEquals("thrift.AuroraAdmin", Domain.THRIFT_AURORA_ADMIN.toString());
  }
}
