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

import java.util.Optional;

import com.google.inject.Guice;
import com.google.inject.Injector;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class WebhookModuleTest {

  // WebhookModule.configure: webhookConfig absent branch (configure is a no-op)
  @Test
  public void testConfigureWithNoWebhookConfig() {
    WebhookModule module = new WebhookModule(Optional.empty());
    Injector injector = Guice.createInjector(module);
    assertNotNull(injector);
  }

  // WebhookModule.parseWebhookConfig: verify the present branch path is reachable by parsing
  @Test
  public void testParseWebhookConfig() {
    String config = "{\n"
        + "  \"headers\": {\"Content-Type\": \"application/json\"},\n"
        + "  \"targetURL\": \"http://localhost:8080/\",\n"
        + "  \"timeoutMsec\": 5000\n"
        + "}\n";

    WebhookInfo info = WebhookModule.parseWebhookConfig(config);
    assertNotNull(info);
    assertNotNull(info.getTargetURI());
  }
}
