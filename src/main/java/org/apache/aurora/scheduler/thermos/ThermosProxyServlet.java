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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.util.concurrent.UncheckedExecutionException;

import org.apache.aurora.scheduler.base.JobKeys;
import org.apache.aurora.scheduler.base.Query;
import org.apache.aurora.scheduler.config.CliOptions;
import org.apache.aurora.scheduler.storage.Storage;
import org.apache.aurora.scheduler.storage.entities.IHostAttributes;
import org.apache.aurora.scheduler.storage.entities.IJobKey;
import org.apache.aurora.scheduler.storage.entities.IScheduledTask;
import org.eclipse.jetty.client.api.Request;
import org.eclipse.jetty.client.api.Response;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.proxy.AfterContentTransformer;
import org.eclipse.jetty.proxy.AsyncMiddleManServlet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;

public class ThermosProxyServlet extends AsyncMiddleManServlet {
  private static final Logger LOG = LoggerFactory.getLogger(ThermosProxyServlet.class);
  private final CliOptions options;
  private final Storage storage;
  private static final String THERMOS_TASK_PATH = "THERMOS_TASK_PATH";
  private static final String X_FORWARDED_USER = "X-Forwarded-User";
  private static final String X_AUTH_REQUEST_USER = "X-Auth-Request-User";
  private static final String HMAC_ALGO = "HmacSHA256";
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64_DEC = Base64.getUrlDecoder();
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private final Pattern thermosAllowDomainRegex;

  @Parameters(separators = "=")
  public static class Options {
    public static final int DEFAULT_THERMOS_PORT = 1338;
    @Parameter(names = "-thermos_port",
        description =
            "The port to start an HTTP server on.  Default value will choose a random port.")
    public int thermosPort = DEFAULT_THERMOS_PORT;
    @Parameter(names = "-thermos_allow_domain_regex",
        description =
            "The port to start an HTTP server on.  Default value will choose a random port.")
    public String thermosAllowDomainRegex = ".*";
  }

  @Inject
  public ThermosProxyServlet(CliOptions options, Storage storage) {
    this.options = requireNonNull(options);
    this.storage = requireNonNull(storage);
    this.thermosAllowDomainRegex = Pattern.compile(options.thermos.thermosAllowDomainRegex);
  }

  static final Pattern AGENT_PATTERN = Pattern.compile(
      "^/thermos/agent/(?<agent>[a-zA-Z0-9-]+)/?(?<path>.*)");
  private static final Cache<String, String> CACHE_AGENT_ID =
      CacheBuilder.newBuilder()
                  .maximumSize(1000L)
                  .expireAfterWrite(Duration.ofMinutes(10))
                  .build();

  @Override
  protected void service(final HttpServletRequest request, final HttpServletResponse response)
      throws ServletException, IOException {
    final URL url = new URL(request.getRequestURL().toString()); // Extract agent from URL
    final String path = url.getPath();
    final Matcher hostMatcher = AGENT_PATTERN.matcher(path);
    if (hostMatcher.matches()) {
      final String agentId = hostMatcher.group("agent");
      final String host;
      try {
        host = getHostFromAgentId(agentId);
      } catch (Storage.TransientStorageException e) {
        LOG.debug("Storage not ready for thermos agent lookup: {}", agentId);
        response.sendError(HttpServletResponse.SC_SERVICE_UNAVAILABLE, "Service unavailable");
        return;
      }
      if (host == null || !thermosAllowDomainRegex.matcher(host).matches()) {
        LOG.debug("Invalid AgentId or not allowed domains: {}:{}", agentId, host);
        response.sendError(HttpServletResponse.SC_NOT_FOUND, "Agent or Domain not found");
        return;
      }
      request.setAttribute(THERMOS_TASK_PATH, String.format("agent/%s", agentId));
      LOG.debug("Valid agents {}:{}", agentId, host);
      super.service(request, response);
    } else {
      LOG.debug("Invalid path: {}", path);
      response.sendError(HttpServletResponse.SC_NOT_FOUND, "Invalid URL");
    }
  }

  private @Nullable String getHostFromAgentId(String agentId) {
    try {
      return CACHE_AGENT_ID.get(agentId, () -> {
        for (IHostAttributes attributes : getHostAttributes()) {
          if (attributes.getSlaveId().equals(agentId)) {
            return attributes.getHost();
          }
        }
        throw new ExecutionException("Agent not found: " + agentId, null);
      });
    } catch (UncheckedExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Storage.TransientStorageException) {
        throw (Storage.TransientStorageException) cause;
      }
      LOG.warn("Failed to get host for agentId: {}", agentId, e);
    } catch (Exception e) {
      LOG.warn("Failed to get host for agentId: {}", agentId, e);
    }
    return null;
  }

  private Storage getStorage() {
    return this.storage;
  }

  @Override
  protected String rewriteTarget(HttpServletRequest clientRequest) {
    if (!validateDestination(clientRequest.getServerName(), clientRequest.getServerPort())) {
      LOG.debug("Invalid clientRequest: {}:{}",
              clientRequest.getServerName(), clientRequest.getServerPort());
      return null;
    }
    // build url
    final URL url;
    try {
      url = new URL(clientRequest.getRequestURL().toString()); // Extract agent from URL
    } catch (MalformedURLException e) {
      _log.warn("Failed to parse URL, {}", e.getMessage(), e);
      return null;
    }
    final String path = url.getPath();
    final Matcher hostMatcher = AGENT_PATTERN.matcher(path);
    if (hostMatcher.matches()) {
      final String agentId = hostMatcher.group("agent");
      final String pPath = hostMatcher.group("path");
      final String host = getHostFromAgentId(agentId);
      if (host == null || !thermosAllowDomainRegex.matcher(host).matches()) {
        // Configured domain not allowed
        LOG.debug("Invalid AgentId or not allowed domains: {}:{}", agentId, host);
        return null;
      }
      final URI upstream = UriBuilder
            .fromPath(pPath)
            .scheme("http") // TODO: Use the scheme from the client request
            .host(host)
            .port(options.thermos.thermosPort)
            .replaceQuery(clientRequest.getQueryString()).build();
      LOG.debug("Valid URL: {}", upstream);
      return upstream.toString();
    }
    return null;
  }

  protected IScheduledTask getTask(IJobKey jobKey, int instanceId) {
    return Iterables.getOnlyElement(
        Storage.Util.fetchTasks(getStorage(),
                                Query.instanceScoped(jobKey, instanceId).active()),
        null);
  }

  private Iterable<IHostAttributes> getHostAttributes() {
    return getStorage().read(storeProvider ->
            storeProvider.getAttributeStore().getHostAttributes());
  }

  @VisibleForTesting
  Optional<String> getTrustedUser(HttpServletRequest request) {
    String cookieName = options.httpSecurity.oauth2CookieName;
    String secret = options.httpSecurity.oauth2JwtSecret;
    if (cookieName == null || cookieName.isEmpty() || secret == null || secret.isEmpty()) {
      return Optional.empty();
    }
    return getCookieValue(request, cookieName).flatMap(token -> validateAndExtractUser(token, secret));
  }

  private static Optional<String> getCookieValue(HttpServletRequest request, String cookieName) {
    Cookie[] cookies = request.getCookies();
    if (cookies == null) {
      return Optional.empty();
    }
    for (Cookie cookie : cookies) {
      if (cookieName.equals(cookie.getName())) {
        return Optional.ofNullable(cookie.getValue());
      }
    }
    return Optional.empty();
  }

  private static Optional<String> validateAndExtractUser(String token, String secret) {
    try {
      String[] parts = token.split("\\.", 3);
      if (parts.length != 3) {
        return Optional.empty();
      }

      String signingInput = parts[0] + "." + parts[1];
      if (!sign(signingInput, secret).equals(parts[2])) {
        return Optional.empty();
      }

      Map<String, Object> payload = MAPPER.readValue(
          B64_DEC.decode(parts[1]),
          new TypeReference<Map<String, Object>>() { });
      Object exp = payload.get("exp");
      if (!(exp instanceof Number) || ((Number) exp).longValue() < System.currentTimeMillis() / 1000L) {
        return Optional.empty();
      }

      Optional<String> email = asNonEmptyString(payload.get("email"));
      if (email.isPresent()) {
        return email;
      }
      return asNonEmptyString(payload.get("sub"));
    } catch (Exception e) {
      return Optional.empty();
    }
  }

  private static Optional<String> asNonEmptyString(Object value) {
    if (!(value instanceof String)) {
      return Optional.empty();
    }
    String normalized = ((String) value).trim();
    return normalized.isEmpty() ? Optional.empty() : Optional.of(normalized);
  }

  private static String sign(String input, String secret)
      throws NoSuchAlgorithmException, InvalidKeyException {
    Mac mac = Mac.getInstance(HMAC_ALGO);
    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), HMAC_ALGO));
    return B64.encodeToString(mac.doFinal(input.getBytes(StandardCharsets.UTF_8)));
  }

  protected IScheduledTask getTask(String role, String env, String job, int instanceId) {
    return getTask(JobKeys.from(role, env, job), instanceId);
  }

  @Override
  protected void sendProxyRequest(
      HttpServletRequest clientRequest,
      HttpServletResponse proxyResponse,
      Request proxyRequest) {

    getTrustedUser(clientRequest).ifPresent(user -> {
      proxyRequest.header(X_FORWARDED_USER, user);
      proxyRequest.header(X_AUTH_REQUEST_USER, user);
    });

    super.sendProxyRequest(clientRequest, proxyResponse, proxyRequest);
  }

  @Override
  protected String filterServerResponseHeader(HttpServletRequest clientRequest,
      Response serverResponse, String headerName, String headerValue) {
    if (HttpHeader.DATE.is(headerName)
        || HttpHeader.SERVER.is(headerName)
        || HttpHeader.SET_COOKIE.is(headerName)
        || HttpHeader.SET_COOKIE2.is(headerName)
        || "x-powered-by".equalsIgnoreCase(headerName)) {
      return null;
    }
    return super.filterServerResponseHeader(clientRequest, serverResponse, headerName, headerValue);
  }

  @Override
  protected void onServerResponseHeaders(HttpServletRequest clientRequest,
      HttpServletResponse proxyResponse, Response serverResponse) {
    super.onServerResponseHeaders(clientRequest, proxyResponse, serverResponse);
    String protocol = clientRequest.getProtocol();
    String httpVersion = protocol.startsWith("HTTP/") ? protocol.substring(5) : "1.1";
    String viaEntry = httpVersion + " " + getViaHost();
    String existing = proxyResponse.getHeader(HttpHeader.VIA.asString());
    if (existing != null) {
      proxyResponse.setHeader(HttpHeader.VIA.asString(), existing + ", " + viaEntry);
    } else {
      proxyResponse.addHeader(HttpHeader.VIA.asString(), viaEntry);
    }
  }

  @Override
  protected ContentTransformer newServerResponseContentTransformer(HttpServletRequest clientRequest,
         HttpServletResponse proxyResponse,
         Response serverResponse) {
    String contentType = proxyResponse.getHeader("Content-Type");
    // Only: 'Content-Type: text/html; charset=UTF-8'
    if (contentType != null
        && contentType.startsWith("text/html")
        && proxyResponse.getStatus() == 200
        && clientRequest.getAttribute(THERMOS_TASK_PATH) != null) {
      String taskPath = (String) clientRequest.getAttribute(THERMOS_TASK_PATH);
      return new ThermosContentTransformer("/thermos/" + taskPath, 1024 * 10);
    } else {
      return ContentTransformer.IDENTITY;
    }
  }

  static class ThermosContentTransformer extends AfterContentTransformer {
    private final Map<ByteBuffer, ByteBuffer> replacements;
    private final Set<Byte> keyByte = Sets.newTreeSet();
    private final String thermosPath;
    private final int bufferSize;

    ThermosContentTransformer(String thermosPath, int bufferSize) {
      this.bufferSize = bufferSize;
      this.replacements = Maps.newHashMap();
      this.thermosPath = thermosPath;
      setReplacements();
    }

    static ByteBuffer wrap(String s) {
      return ByteBuffer.wrap(s.getBytes(StandardCharsets.UTF_8));
    }

    private void setReplacements() {
      // 'data-url="m' to 'data-url="/thermos/agent/xxxx/m'
      replacements.put(wrap("data-url=\"m"), wrap("data-url=\"" + thermosPath + "/m"));
      replacements.put(wrap("data-url=\"/"), wrap("data-url=\"" + thermosPath + "/"));
      // 'href="a' to 'href="/thermos/agent/xxxx/a'
      replacements.put(wrap("href=\"a"), wrap("href=\"" + thermosPath + "/a"));
      // 'src="a' to 'src="/thermos/agent/xxxx/a'
      replacements.put(wrap("src=\"a"), wrap("src=\"" + thermosPath + "/a"));

      // 'href=["']/...' to 'href="/thermos/agent/xxxx/...'
      replacements.put(wrap("href=\"/"), wrap("href=\"" + thermosPath + "/"));
      replacements.put(wrap("href='/"), wrap("href='" + thermosPath + "/"));
      // 'src=["']/...' to 'src="/thermos/agent/xxxx/...'
      replacements.put(wrap("src=\"/"), wrap("src=\"" + thermosPath + "/"));
      replacements.put(wrap("src='/"), wrap("src='" + thermosPath + "/"));
      // 'var url = "/logdata/' to 'var url = "/thermos/agent/xxxx/logdata/'
      replacements.put(wrap("var url = \"/"), wrap("var url = \"" + thermosPath + "/"));
      replacements.put(wrap("var url = '/"), wrap("var url = '" + thermosPath + "/"));
      replacements.forEach((key, value) -> keyByte.add(key.get(0)));
    }

    @Override
    public boolean transform(Source source, Sink sink) throws IOException {
      final byte[] buffer = new byte[bufferSize];
      int read = 0;
      try (InputStream s = source.getInputStream();
           OutputStream o = sink.getOutputStream()) {
        while ((read = s.read(buffer)) != -1) {
          parseAndExchange(buffer, read, o);
        }
      } catch (IOException e) {
        LOG.error("Failed to transform content", e);
        return false;
      }
      return true;
    }

    void parseAndExchange(final byte[] buffer, final int read, OutputStream o) throws IOException {
      final ByteBuffer bb = ByteBuffer.wrap(buffer, 0, read);
      int pos = 0;
      int start = 0;
      while (pos < read) {
        if (keyByte.contains(bb.get(pos))) {
          if (pos > start) {
            o.write(buffer, start, pos - start);
            start = pos;
          }
          for (Map.Entry<ByteBuffer, ByteBuffer> entry : replacements.entrySet()) {
            final ByteBuffer from = entry.getKey();
            final ByteBuffer to = entry.getValue();
            final int fromLen = from.remaining();
            if (fromLen <= read - pos) {
              boolean match = true;
              for (int i = 0; i < fromLen; i++) {
                if (from.get(i) != bb.get(pos + i)) {
                  match = false;
                  break;
                }
              }
              if (match) {
                o.write(to.array());
                pos += fromLen;
                start = pos;
                break;
              }
            }
          }
        }
        pos++;
      }
      if (pos > start) {
        o.write(buffer, start, pos - start);
      }
    }

    @VisibleForTesting
    void parserAndExchange(String s, OutputStream o) {
      final byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
      try {
        parseAndExchange(bytes, bytes.length, o);
      } catch (IOException e) {
        LOG.error("Failed to transform content", e);
      }
    }

  }

}
