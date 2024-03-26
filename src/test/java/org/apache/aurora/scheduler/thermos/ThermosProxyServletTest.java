package org.apache.aurora.scheduler.thermos;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

public class ThermosProxyServletTest {

  @Test
  public void testAllowDomain() {
    Pattern agentId = ThermosProxyServlet.agentPattern;
    assert agentId.matcher("/thermos/agent/6869fe8a-a7e7-4422-82b0-5771861ee98d-S46/browser/...").matches();
    String path = "/thermos/agent/6869fe8a-a7e7-4422-82b0-5771861ee98d-S46/browser/...";
    Matcher hostMatcher = agentId.matcher(path);
    if (hostMatcher.matches()) {
      final String domain = hostMatcher.group("agent");
      assert domain.equals("6869fe8a-a7e7-4422-82b0-5771861ee98d-S46");
      assert domain.matches(".*");
    }
  }
}
