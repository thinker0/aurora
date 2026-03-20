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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import static java.util.Objects.requireNonNull;

/**
 * Manages OAuth2 session cookies using compact HMAC-SHA256 signed JWTs.
 *
 * <p>Token structure:
 * {@code base64url(header) . base64url(payload) . base64url(HMAC-SHA256(header.payload, secret))}
 *
 * <p>Payload fields: {@code sub}, {@code email}, {@code iat}, {@code exp}.
 */
public class OAuth2SessionManager {

  private static final String HMAC_ALGO = "HmacSHA256";
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final String HEADER =
      B64.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

  private final byte[] secret;
  private final long sessionTimeoutSecs;

  @Inject
  OAuth2SessionManager(HttpSecurityModule.Options options) {
    requireNonNull(options);
    this.secret = requireNonNull(options.oauth2JwtSecret, "oauth2_jwt_secret is required")
        .getBytes(StandardCharsets.UTF_8);
    this.sessionTimeoutSecs = options.oauth2SessionTimeoutSecs;
  }

  public String create(String sub, String email, long nowSecs) {
    try {
      Map<String, Object> payload = new HashMap<>();
      payload.put("sub", sub);
      payload.put("email", email);
      payload.put("iat", nowSecs);
      payload.put("exp", nowSecs + sessionTimeoutSecs);

      String payloadB64 = B64.encodeToString(
          MAPPER.writeValueAsBytes(payload));
      String signingInput = HEADER + "." + payloadB64;
      return signingInput + "." + sign(signingInput);
    } catch (Exception e) {
      throw new RuntimeException("Failed to create session token", e);
    }
  }

  public Optional<Map<String, Object>> validate(String token) {
    try {
      String[] parts = token.split("\\.", 3);
      if (parts.length != 3) {
        return Optional.empty();
      }
      String signingInput = parts[0] + "." + parts[1];
      if (!sign(signingInput).equals(parts[2])) {
        return Optional.empty();
      }
      Map<String, Object> payload = MAPPER.readValue(
          B64_DEC.decode(parts[1]),
          new TypeReference<Map<String, Object>>() { });
      long exp = ((Number) payload.get("exp")).longValue();
      if (exp < System.currentTimeMillis() / 1000L) {
        return Optional.empty();
      }
      return Optional.of(payload);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  /**
   * Creates a proxy device token that hides the real OIDC device_code from the CLI client.
   * Format: {@code base64url(deviceCode).HMAC-SHA256("proxy_device:" + deviceCode)}
   */
  public String createProxyDeviceToken(String deviceCode) {
    try {
      String input = "proxy_device:" + deviceCode;
      return B64.encodeToString(deviceCode.getBytes(StandardCharsets.UTF_8))
          + "." + sign(input);
    } catch (Exception e) {
      throw new RuntimeException("Failed to create proxy device token", e);
    }
  }

  /**
   * Verifies the HMAC signature of a proxy device token and extracts the real device_code.
   *
   * @return the real device_code, or empty if the token is invalid or tampered.
   */
  public Optional<String> extractVerifiedDeviceCode(String proxyToken) {
    try {
      String[] parts = proxyToken.split("\\.", 2);
      if (parts.length != 2) {
        return Optional.empty();
      }
      String deviceCode = new String(B64_DEC.decode(parts[0]), StandardCharsets.UTF_8);
      String expected = sign("proxy_device:" + deviceCode);
      if (!expected.equals(parts[1])) {
        return Optional.empty();
      }
      return Optional.of(deviceCode);
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  public long getSessionTimeoutSecs() {
    return sessionTimeoutSecs;
  }

  private String sign(String input) throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = Mac.getInstance(HMAC_ALGO);
    mac.init(new SecretKeySpec(secret, HMAC_ALGO));
    return B64.encodeToString(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
  }
}
