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
package org.apache.aurora.scheduler.thermos;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

public class ThermosProxyServletTest {

  @Test
  public void testAllowDomain() {
    Pattern agentId = ThermosProxyServlet.AGENT_PATTERN;
    assert agentId.matcher("/thermos/agent/"
        + "6869fe8a-a7e7-4422-82b0-5771861ee98d-S46/browser/...").matches();
    String path = "/thermos/agent/6869fe8a-a7e7-4422-82b0-5771861ee98d-S46/browser/...";
    Matcher hostMatcher = agentId.matcher(path);
    if (hostMatcher.matches()) {
      final String domain = hostMatcher.group("agent");
      assert Objects.equals(domain, "6869fe8a-a7e7-4422-82b0-5771861ee98d-S46");
      assert domain.matches(".*");
    }
  }
}
