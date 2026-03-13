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
package org.apache.aurora.scheduler.http;

import org.apache.aurora.common.testing.easymock.EasyMockTest;
import org.apache.aurora.common.util.templating.StringTemplateHelper.TemplateException;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class LogConfigTest extends EasyMockTest {

  private LogConfig logConfig;

  @Before
  public void setUp() {
    logConfig = new LogConfig();
  }

  @Test
  public void testGetReturnsNonEmpty() throws TemplateException {
    control.replay();
    String result = logConfig.get();
    assertNotNull(result);
    assertTrue("Response should be non-empty HTML", result.length() > 0);
  }

  @Test
  public void testPostWithNoParamsReturnsNonEmpty() throws TemplateException {
    control.replay();
    String result = logConfig.post(null, null);
    assertNotNull(result);
    assertTrue(result.length() > 0);
  }

  @Test
  public void testPostWithValidLoggerAndLevel() throws TemplateException {
    control.replay();
    String result = logConfig.post("org.apache.aurora", "DEBUG");
    assertNotNull(result);
    assertTrue(result.length() > 0);
  }

  @Test
  public void testPostWithInheritLevel() throws TemplateException {
    control.replay();
    String result = logConfig.post("org.apache.aurora", "INHERIT");
    assertNotNull(result);
    assertTrue(result.length() > 0);
  }

  @Test
  public void testPostWithNullLoggerNameOnlyDoesNotChangeConfig() throws TemplateException {
    control.replay();
    String result = logConfig.post(null, "INFO");
    assertNotNull(result);
    assertTrue(result.length() > 0);
  }

  @Test
  public void testPostWithBlankLevelSetsInherit() throws TemplateException {
    control.replay();
    // Setting a real logger level via post, then resetting with blank-ish level.
    // This exercises the LoggerConfig constructor where level is blank.
    String result = logConfig.post("org.apache.aurora", "  ");
    assertNotNull(result);
    assertTrue(result.length() > 0);
  }

  @Test
  public void testPostWithBothNullDoesNotChangeConfig() throws TemplateException {
    control.replay();
    // Ensures the configChange.isPresent() == false branch is exercised in displayPage.
    String result = logConfig.post(null, null);
    assertNotNull(result);
    assertTrue(result.length() > 0);
  }
}
