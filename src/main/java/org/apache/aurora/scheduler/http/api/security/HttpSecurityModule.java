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

import java.lang.reflect.Method;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import javax.inject.Singleton;
import javax.servlet.Filter;
import javax.servlet.ServletContext;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.inject.AbstractModule;
import com.google.inject.Key;
import com.google.inject.Module;
import com.google.inject.Provides;
import com.google.inject.TypeLiteral;
import com.google.inject.binder.AnnotatedBindingBuilder;
import com.google.inject.matcher.Matcher;
import com.google.inject.matcher.Matchers;
import com.google.inject.name.Names;
import com.google.inject.servlet.RequestScoped;
import com.google.inject.servlet.ServletModule;

import org.aopalliance.intercept.MethodInterceptor;
import org.apache.aurora.GuiceUtils;
import org.apache.aurora.gen.AuroraAdmin;
import org.apache.aurora.gen.AuroraSchedulerManager;
import org.apache.aurora.scheduler.app.MoreModules;
import org.apache.aurora.scheduler.config.CliOptions;
import org.apache.aurora.scheduler.config.splitters.CommaSplitter;
import org.apache.aurora.scheduler.http.api.security.HttpSecurityModule.Options.HttpAuthenticationMechanism;
import org.apache.aurora.scheduler.thrift.aop.AnnotatedAuroraAdmin;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.guice.aop.ShiroAopModule;
import org.apache.shiro.guice.web.ShiroWebModule;
import org.apache.shiro.session.mgt.DefaultSessionManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.Subject;

import static java.util.Objects.requireNonNull;

import static org.apache.aurora.scheduler.http.api.ApiModule.API_PATH;
import static org.apache.aurora.scheduler.spi.Permissions.Domain.THRIFT_AURORA_ADMIN;
import static org.apache.shiro.guice.web.ShiroWebModule.guiceFilterModule;
import static org.apache.shiro.web.filter.authc.AuthenticatingFilter.PERMISSIVE;

/**
 * Provides HTTP Basic Authentication using Apache Shiro. When enabled, prevents unauthenticated
 * access to write APIs and configured servlets. Write API access must also be authorized, with
 * permissions configured in a shiro.ini file. For an example of this file, see the test resources
 * included with this package.
 */
public class HttpSecurityModule extends ServletModule {
  private static final String HTTP_REALM_NAME = "Apache Aurora Scheduler";

  private static final String ALL_PATTERN = "/**";
  private static final Key<? extends Filter> K_PERMISSIVE =
      Key.get(ShiroKerberosPermissiveAuthenticationFilter.class);

  @Parameters(separators = "=")
  public static class Options {
    @Parameter(names = "-shiro_realm_modules",
        description = "Guice modules for configuring Shiro Realms.",
        splitter = CommaSplitter.class)
    @SuppressWarnings("rawtypes")
    public List<Class> shiroRealmModule = ImmutableList.of(IniShiroRealmModule.class);

    @Parameter(names = "-shiro_after_auth_filter",
        description = "Fully qualified class name of the servlet filter to be applied after the"
            + " shiro auth filters are applied.")
    public Class<? extends Filter> shiroAfterAuthFilter;

    public enum HttpAuthenticationMechanism {
      /**
       * No security.
       */
      NONE,

      /**
       * HTTP Basic Authentication, produces {@link org.apache.shiro.authc.UsernamePasswordToken}s.
       */
      BASIC,

      /**
       * Use GSS-Negotiate. Only Kerberos and SPNEGO-with-Kerberos GSS mechanisms are supported.
       */
      NEGOTIATE,

      /**
       * OAuth2 Authorization Code Flow (Keycloak / OIDC compatible).
       * Protects Web UI paths; /api and other excluded paths bypass authentication.
       */
      OAUTH2,

      /**
       * Trust user identity from HTTP headers (e.g. X-Forwarded-User).
       */
      TRUSTED_HEADER,
    }

    @Parameter(names = "-oauth2_issuer_url",
        description = "OIDC issuer URL (e.g. https://keycloak.example.com/realms/myrealm)")
    public String oauth2IssuerUrl;

    @Parameter(names = "-oauth2_client_id",
        description = "OAuth2 client ID registered in the identity provider")
    public String oauth2ClientId;

    @Parameter(names = "-oauth2_client_secret",
        description = "OAuth2 client secret")
    public String oauth2ClientSecret;

    @Parameter(names = "-oauth2_redirect_uri",
        description = "Callback URL registered in the identity provider "
            + "(e.g. https://aurora.example.com/oauth2/callback)")
    public String oauth2RedirectUri;

    @Parameter(names = "-oauth2_exclude_paths",
        description = "Comma-separated path prefixes excluded from OAuth2 authentication",
        splitter = CommaSplitter.class)
    public List<String> oauth2ExcludePaths =
        ImmutableList.of("/api", "/vars", "/health", "/apiclient");

    @Parameter(names = "-oauth2_jwt_secret",
        description = "HMAC-SHA256 secret for signing session cookies (min 32 chars)")
    public String oauth2JwtSecret;

    @Parameter(names = "-oauth2_cookie_name",
        description = "Name of the session cookie set after successful OAuth2 login")
    public String oauth2CookieName = "aurora_token";

    @Parameter(names = "-oauth2_session_timeout_secs",
        description = "Session cookie validity in seconds (default: 8 hours)")
    public long oauth2SessionTimeoutSecs = 28800L;

    @Parameter(names = "-http_authentication_mechanism",
        description = "HTTP Authentication mechanism to use.",
        splitter = CommaSplitter.class)
    public List<HttpAuthenticationMechanism> httpAuthenticationMechanisms =
        ImmutableList.of(HttpAuthenticationMechanism.NONE);
  }

  @VisibleForTesting
  static final Matcher<Method> AURORA_SCHEDULER_MANAGER_SERVICE =
      GuiceUtils.interfaceMatcher(AuroraSchedulerManager.Iface.class, true);

  @VisibleForTesting
  static final Matcher<Method> AURORA_ADMIN_SERVICE =
      GuiceUtils.interfaceMatcher(AuroraAdmin.Iface.class, true);

  private final List<HttpAuthenticationMechanism> mechanisms;
  private final Set<Module> shiroConfigurationModules;
  private final Optional<Key<? extends Filter>> shiroAfterAuthFilterKey;
  private final Options options;
  private final ServletContext servletContext;

  public HttpSecurityModule(CliOptions options, ServletContext servletContext) {
    this(
        options.httpSecurity.httpAuthenticationMechanisms,
        MoreModules.instantiateAll(options.httpSecurity.shiroRealmModule, options),
        Optional.ofNullable(options.httpSecurity.shiroAfterAuthFilter).map(Key::get).orElse(null),
        options.httpSecurity,
        servletContext);
  }

  @VisibleForTesting
  public HttpSecurityModule(
      Module shiroConfigurationModule,
      Key<? extends Filter> shiroAfterAuthFilterKey,
      ServletContext servletContext) {

    this(ImmutableList.of(HttpAuthenticationMechanism.BASIC),
        ImmutableSet.of(shiroConfigurationModule),
        shiroAfterAuthFilterKey,
        new Options(),
        servletContext);
  }

  private HttpSecurityModule(
      List<HttpAuthenticationMechanism> mechanisms,
      Set<Module> shiroConfigurationModules,
      Key<? extends Filter> shiroAfterAuthFilterKey,
      Options options,
      ServletContext servletContext) {

    this.mechanisms = requireNonNull(mechanisms);
    this.shiroConfigurationModules = requireNonNull(shiroConfigurationModules);
    this.shiroAfterAuthFilterKey = Optional.ofNullable(shiroAfterAuthFilterKey);
    this.options = options;
    this.servletContext = requireNonNull(servletContext);
  }

  @Override
  protected void configureServlets() {
    bind(Options.class).toInstance(options);
    
    if (mechanisms.size() == 1 && mechanisms.contains(HttpAuthenticationMechanism.NONE)) {
      bind(new TypeLiteral<Optional<Subject>>() { }).toInstance(Optional.empty());
    } else {
      doConfigureServlets();
    }

    if (mechanisms.contains(HttpAuthenticationMechanism.TRUSTED_HEADER)) {
      bind(TrustedHeaderAuthFilter.class).in(Singleton.class);
      filter("/*").through(TrustedHeaderAuthFilter.class);
    }
    if (mechanisms.contains(HttpAuthenticationMechanism.OAUTH2)) {
      bind(OAuth2SessionManager.class).in(Singleton.class);
      bind(OAuth2Filter.class).in(Singleton.class);
      filter("/*").through(OAuth2Filter.class);
    }
  }

  private void doConfigureServlets() {
    bind(Subject.class).toProvider(SecurityUtils::getSubject).in(RequestScoped.class);
    install(new AbstractModule() {
      @Override protected void configure() {}
      @Provides Optional<Subject> provideOptionalSubject(Subject subject) { return Optional.of(subject); }
    });
    install(guiceFilterModule(API_PATH));
    install(new ShiroWebModule(servletContext) {
      @Override protected void bindSessionManager(AnnotatedBindingBuilder<SessionManager> bind) {
        bind.to(DefaultSessionManager.class).asEagerSingleton();
      }

      @Override
      @SuppressWarnings("unchecked")
      protected void configureShiroWeb() {
        for (Module module : shiroConfigurationModules) { install(module); }

        for (HttpAuthenticationMechanism mechanism : mechanisms) {
          switch (mechanism) {
            case BASIC:
              addFilterChainWithAfterAuthFilter(filterConfig(AUTHC_BASIC, PERMISSIVE));
              break;
            case NEGOTIATE:
              addFilterChainWithAfterAuthFilter(filterConfig(Key.get(ShiroKerberosPermissiveAuthenticationFilter.class)));
              break;
            default: break;
          }
        }
      }

      private void addFilterChainWithAfterAuthFilter(FilterConfig<? extends Filter> filter) {
        if (shiroAfterAuthFilterKey.isPresent()) {
          addFilterChain(ALL_PATTERN, filterConfig(NO_SESSION_CREATION), filter, filterConfig(shiroAfterAuthFilterKey.get()));
        } else {
          addFilterChain(ALL_PATTERN, filterConfig(NO_SESSION_CREATION), filter);
        }
      }
    });

    bindConstant().annotatedWith(Names.named("shiro.applicationName")).to(HTTP_REALM_NAME);
    install(new ShiroAopModule());

    MethodInterceptor interceptor = new ShiroAuthenticatingThriftInterceptor();
    requestInjection(interceptor);
    bindInterceptor(Matchers.subclassesOf(AuroraSchedulerManager.Iface.class),
        AURORA_SCHEDULER_MANAGER_SERVICE.or(AURORA_ADMIN_SERVICE),
        interceptor);

    MethodInterceptor apiInterceptor = new ShiroAuthorizingParamInterceptor();
    requestInjection(apiInterceptor);
    bindInterceptor(Matchers.subclassesOf(AuroraSchedulerManager.Iface.class),
        AURORA_SCHEDULER_MANAGER_SERVICE,
        apiInterceptor);

    MethodInterceptor adminInterceptor = new ShiroAuthorizingInterceptor(THRIFT_AURORA_ADMIN);
    requestInjection(adminInterceptor);
    bindInterceptor(Matchers.subclassesOf(AnnotatedAuroraAdmin.class),
        AURORA_ADMIN_SERVICE,
        adminInterceptor);
  }
}