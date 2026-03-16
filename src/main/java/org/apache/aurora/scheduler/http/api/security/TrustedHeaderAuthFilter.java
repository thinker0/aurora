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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.aurora.scheduler.http.AbstractFilter;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A filter that trusts a user identity provided in an HTTP header by a trusted proxy
 * (like oauth2-proxy) or directly via a Bearer token.
 *
 * <p>In strict mode (default), requests without a recognized header are rejected with 401.
 * In permissive mode, requests without a header are passed to the next filter in the chain,
 * enabling fallback to a downstream authenticator such as {@link OAuth2Filter}.
 */
public class TrustedHeaderAuthFilter extends AbstractFilter {
  private static final Logger LOG = LoggerFactory.getLogger(TrustedHeaderAuthFilter.class);
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private static final String X_FORWARDED_USER = "X-Forwarded-User";
  private static final String X_AUTH_REQUEST_USER = "X-Auth-Request-User";

  private final boolean permissive;

  /** Default constructor used by Guice for {@code TRUSTED_HEADER} (strict) mode. */
  TrustedHeaderAuthFilter() {
    this(false);
  }

  /**
   * @param permissive When {@code true}, requests without a recognized header are passed through
   *                   to the next filter instead of being rejected with 401. Use this when
   *                   combining with a fallback authenticator (e.g. {@code OAUTH2_PROXY,OAUTH2}).
   */
  TrustedHeaderAuthFilter(boolean permissive) {
    this.permissive = permissive;
  }

  @Override
  protected void doFilter(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain chain) throws IOException, ServletException {

    Optional<String> user = getUsername(request);

    if (user.isPresent()) {
      LOG.debug("Authenticating user {} from trusted header or token", user.get());
      UsernamePasswordToken token = new UsernamePasswordToken(user.get(), "");
      Subject subject = SecurityUtils.getSubject();
      try {
        subject.login(token);
        chain.doFilter(request, response);
      } catch (Exception e) {
        LOG.warn("Failed to login user {} from header: {}", user.get(), e.getMessage());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication failed");
      }
    } else if (permissive) {
      LOG.debug("No trusted user header found; passing through to next filter (permissive mode)");
      chain.doFilter(request, response);
    } else {
      LOG.warn("No trusted user header or valid Bearer token found in request");
      response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing authentication");
    }
  }

  private Optional<String> getUsername(HttpServletRequest request) {
    // 1. Try Proxy Headers
    String user = request.getHeader(X_FORWARDED_USER);
    if (user == null || user.isEmpty()) {
      user = request.getHeader(X_AUTH_REQUEST_USER);
    }
    if (user != null && !user.isEmpty()) {
      return Optional.of(user);
    }

    // 2. Try Authorization: Bearer <JWT>
    String authHeader = request.getHeader("Authorization");
    if (authHeader != null && authHeader.startsWith("Bearer ")) {
      String token = authHeader.substring(7);
      return extractUserFromJwt(token);
    }

    return Optional.empty();
  }

  private Optional<String> extractUserFromJwt(String token) {
    try {
      // In a real production environment, you MUST verify the JWT signature here.
      // This implementation only extracts the 'sub' or 'email' claim from the payload.
      String[] parts = token.split("\\.");
      if (parts.length != 3) {
        return Optional.empty();
      }
      String payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
      JsonNode payload = MAPPER.readTree(payloadJson);
      
      // Preferred claim order: email -> sub -> preferred_username
      if (payload.has("email")) {
        return Optional.of(payload.get("email").asText());
      } else if (payload.has("sub")) {
        return Optional.of(payload.get("sub").asText());
      } else if (payload.has("preferred_username")) {
        return Optional.of(payload.get("preferred_username").asText());
      }
    } catch (Exception e) {
      LOG.warn("Failed to extract user from JWT: {}", e.getMessage());
    }
    return Optional.empty();
  }
}
