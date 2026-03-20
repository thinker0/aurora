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
package org.apache.aurora.scheduler.http.api.security;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;

import org.apache.aurora.scheduler.http.api.security.HttpSecurityModule.Options;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class OAuth2SessionManagerTest {

  private static final String SECRET = "test-secret-key-for-hmac-sha256-min32chars!";
  private static final long TIMEOUT_SECS = 3600L;

  private OAuth2SessionManager manager;

  @Before
  public void setUp() {
    Options options = new Options();
    options.oauth2JwtSecret = SECRET;
    options.oauth2SessionTimeoutSecs = TIMEOUT_SECS;
    manager = new OAuth2SessionManager(options);
  }

  @Test
  public void testCreateReturnsThreePartToken() {
    long now = System.currentTimeMillis() / 1000L;
    String token = manager.create("user123", "user@example.com", now);
    assertNotNull(token);
    assertEquals(3, token.split("\\.").length);
  }

  @Test
  public void testCreateAndValidateReturnsPayload() {
    long now = System.currentTimeMillis() / 1000L;
    String token = manager.create("user123", "user@example.com", now);

    Optional<Map<String, Object>> result = manager.validate(token);
    assertTrue(result.isPresent());
    assertEquals("user123", result.get().get("sub"));
    assertEquals("user@example.com", result.get().get("email"));
  }

  @Test
  public void testPayloadContainsIatAndExp() {
    long now = System.currentTimeMillis() / 1000L;
    String token = manager.create("sub-val", "email@test.com", now);

    Optional<Map<String, Object>> result = manager.validate(token);
    assertTrue(result.isPresent());
    Map<String, Object> payload = result.get();
    assertTrue(payload.containsKey("iat"));
    long exp = ((Number) payload.get("exp")).longValue();
    assertEquals(now + TIMEOUT_SECS, exp);
  }

  @Test
  public void testValidateExpiredTokenReturnsEmpty() {
    // iat is in the past such that exp is already past
    long pastTime = (System.currentTimeMillis() / 1000L) - TIMEOUT_SECS - 1;
    String token = manager.create("user123", "user@example.com", pastTime);

    assertFalse(manager.validate(token).isPresent());
  }

  @Test
  public void testValidateTamperedSignatureReturnsEmpty() {
    long now = System.currentTimeMillis() / 1000L;
    String token = manager.create("user123", "user@example.com", now);
    String[] parts = token.split("\\.");
    String tampered = parts[0] + "." + parts[1] + ".invalidsignature";

    assertFalse(manager.validate(tampered).isPresent());
  }

  @Test
  public void testValidateTamperedPayloadReturnsEmpty() {
    long now = System.currentTimeMillis() / 1000L;
    String token = manager.create("user123", "user@example.com", now);
    String[] parts = token.split("\\.");

    // Swap in a different payload — original signature no longer matches
    long futureExp = now + TIMEOUT_SECS + 9999L;
    String fakePayload = Base64.getUrlEncoder().withoutPadding().encodeToString(
        ("{\"sub\":\"attacker\",\"email\":\"evil@x.com\","
            + "\"iat\":" + now + ",\"exp\":" + futureExp + "}")
            .getBytes(StandardCharsets.UTF_8));
    String tampered = parts[0] + "." + fakePayload + "." + parts[2];

    assertFalse(manager.validate(tampered).isPresent());
  }

  @Test
  public void testValidateMalformedTokenReturnsEmpty() {
    assertFalse(manager.validate("notavalidtoken").isPresent());
    assertFalse(manager.validate("only.two").isPresent());
    assertFalse(manager.validate("").isPresent());
  }

  @Test
  public void testGetSessionTimeoutSecs() {
    assertEquals(TIMEOUT_SECS, manager.getSessionTimeoutSecs());
  }

  @Test
  public void testProxyDeviceTokenCreateAndExtract() {
    String deviceCode = "urn:ietf:params:oauth:device_code:12345-abcde";
    String proxyToken = manager.createProxyDeviceToken(deviceCode);
    assertNotNull(proxyToken);
    assertTrue(proxyToken.contains("."));

    Optional<String> result = manager.extractVerifiedDeviceCode(proxyToken);
    assertTrue(result.isPresent());
    assertEquals(deviceCode, result.get());
  }

  @Test
  public void testExtractVerifiedDeviceCodeTamperedReturnsEmpty() {
    String proxyToken = manager.createProxyDeviceToken("real-device-code");
    // Replace the HMAC signature part with garbage
    String tampered = proxyToken.substring(0, proxyToken.lastIndexOf('.')) + ".invalidsig";

    assertFalse(manager.extractVerifiedDeviceCode(tampered).isPresent());
  }

  @Test
  public void testExtractVerifiedDeviceCodeMalformedReturnsEmpty() {
    // Token without a dot separator
    assertFalse(manager.extractVerifiedDeviceCode("nodots").isPresent());
    assertFalse(manager.extractVerifiedDeviceCode("").isPresent());
  }

  @Test
  public void testValidateWithWrongSecretReturnsEmpty() {
    long now = System.currentTimeMillis() / 1000L;
    String token = manager.create("user", "user@x.com", now);

    Options options2 = new Options();
    options2.oauth2JwtSecret = "completely-different-secret-min32chars!";
    options2.oauth2SessionTimeoutSecs = TIMEOUT_SECS;
    OAuth2SessionManager manager2 = new OAuth2SessionManager(options2);

    assertFalse(manager2.validate(token).isPresent());
  }
}
