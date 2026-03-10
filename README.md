![Aurora Logo](docs/images/aurora_logo.png)

![Build Status](https://github.com/aurora-scheduler/aurora/workflows/CI/badge.svg?branch=master)

[Aurora Scheduler](https://aurora-scheduler.github.io/) lets you use an [Apache Mesos](http://mesos.apache.org)
cluster as a private cloud. It supports running long-running services, cron jobs, and ad-hoc jobs.
Aurora aims to make it extremely quick and easy to take a built application and run it on machines
in a cluster, with an emphasis on reliability. It provides basic operations to manage services
running in a cluster, such as rolling upgrades.

To very concisely describe Aurora, it is like a distributed monit or distributed supervisord that
you can instruct to do things like _run 100 of these, somewhere, forever_.

### What this project is and what it is not
Aurora Scheduler is a reboot of Apache Aurora that seeks to continue its development after the latter entered the [Apache Attic](https://lists.apache.org/thread.html/reee926fceea75b7cc25110abb9deb3c41921c1585157a7f45c814419%40%3Cdev.aurora.apache.org%3E).
That having been said, the project is largely in maintenance mode. We will continue to try to provide
quality of life updates to the codebase but we don't anticipate any new large features being landed.

Furthermore, as a result of the decreased amount of contributors available, focus will be turned to the scheduler.
Anyone who depends on tooling outside of the scheduler should look at taking up maintenance of those tools.

Changes made to the scheduler will always strive to be compatible with existing tools but compatibility is _not_ guaranteed.
More importantly, in many cases we will not be testing against such tools so it is
up to users to report incompatible changes. **Tools in this case also include the [original Python2 client](https://github.com/aurora-scheduler/client).**

## Features

Aurora is built for users _and_ operators.

* User-facing Features:
  - Management of [long-running services](docs/features/services.md)
  - [Cron jobs](docs/features/cron-jobs.md)
  - [Resource quotas](docs/features/multitenancy.md): provide guaranteed resources for specific
    applications
  - [Rolling job updates](docs/features/job-updates.md), with automatic rollback
  - [Multi-user support](docs/features/multitenancy.md)
  - Sophisticated [DSL](docs/reference/configuration-tutorial.md): supports templating, allowing you to
    establish common patterns and avoid redundant configurations
  - [Dedicated machines](docs/features/constraints.md#dedicated-attribute):
    for things like stateful services that must always run on the same machines
  - [Service registration](docs/features/service-discovery.md): announce services in
    [ZooKeeper](http://zookeeper.apache.org/) for discovery by [various clients](docs/additional-resources/tools.md)
  - [Scheduling constraints](docs/features/constraints.md)
    to run on specific machines, or to mitigate impact of issues like machine and rack failure

* Under the hood, to help you rest easy:
  - [Preemption](docs/features/multitenancy.md): important services can 'steal' resources when they need it
  - High-availability: resists machine failures and disk failures
  - Scalable: proven to work in data center-sized clusters, with hundreds of users and thousands of
    jobs
  - Instrumented: a wealth of information makes it easy to [monitor](docs/operations/monitoring.md)
    and debug

### When and when not to use Aurora
Aurora can take over for most uses of software like monit and chef.  Aurora can manage applications,
while these tools are still useful to manage Aurora and Mesos themselves.

However, if you have very specific scheduling requirements, or are building a system that looks like a
scheduler itself, you may want to explore developing your own
[framework](http://mesos.apache.org/documentation/latest/app-framework-development-guide).


## Authentication

Aurora supports multiple HTTP authentication mechanisms controlled by the `-http_authentication_mechanism` flag.

### OAuth2 / OIDC (Keycloak)

The Web UI can be protected using OAuth2 Authorization Code Flow with any OIDC-compatible provider (e.g. Keycloak, Okta, Auth0).

**How it works:**

1. Unauthenticated browser requests to the Web UI are redirected to the identity provider login page.
2. After successful login the provider redirects back to `/oauth2/callback`.
3. The scheduler exchanges the authorization code for tokens, fetches the user's `sub` and `email` from the userinfo endpoint, and issues a signed HMAC-SHA256 session cookie (`aurora_token` by default).
4. Subsequent requests carry the session cookie and are admitted without another round-trip to the provider.
5. Paths listed in `-oauth2_exclude_paths` (default: `/api`, `/vars`, `/health`, `/apiclient`) bypass OAuth2 entirely, so Thrift API clients and monitoring probes continue to work without browser credentials.

**Required flags:**

| Flag | Description |
|------|-------------|
| `-http_authentication_mechanism=OAUTH2` | Enable OAuth2 mode |
| `-oauth2_issuer_url` | OIDC issuer base URL, e.g. `https://keycloak.example.com/realms/myrealm` |
| `-oauth2_client_id` | Client ID registered in the identity provider |
| `-oauth2_client_secret` | Client secret |
| `-oauth2_redirect_uri` | Callback URL registered in the provider, e.g. `https://aurora.example.com/oauth2/callback` |
| `-oauth2_jwt_secret` | Random string (≥ 32 chars) used to sign session cookies with HMAC-SHA256 |

**Optional flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-oauth2_exclude_paths` | `/api,/vars,/health,/apiclient` | Comma-separated path prefixes that bypass OAuth2 |
| `-oauth2_cookie_name` | `aurora_token` | Name of the session cookie |
| `-oauth2_session_timeout_secs` | `28800` (8 hours) | Session cookie validity in seconds |

**Example startup flags:**

```
-http_authentication_mechanism=OAUTH2
-oauth2_issuer_url=https://keycloak.example.com/realms/myrealm
-oauth2_client_id=aurora-scheduler
-oauth2_client_secret=<secret>
-oauth2_redirect_uri=https://aurora.example.com/oauth2/callback
-oauth2_jwt_secret=<random-string-at-least-32-chars>
```

**Keycloak client configuration checklist:**

- Client protocol: `openid-connect`
- Access type: `confidential`
- Valid redirect URIs: must include your `-oauth2_redirect_uri` value
- Scopes: `openid`, `email`, `profile`

**Notes:**

- No new external libraries are required. Token exchange and userinfo calls use the Java 11 built-in `java.net.http.HttpClient`. Session cookies use `javax.crypto.Mac` (HmacSHA256).
- The OIDC endpoints are derived from the issuer URL using the standard Keycloak path convention (`/protocol/openid-connect/token`, `/protocol/openid-connect/userinfo`, `/protocol/openid-connect/auth`). For non-Keycloak providers, ensure these paths match or adjust accordingly.
- When OAUTH2 is active, Shiro-based authentication (BASIC / NEGOTIATE) is **not** installed. The Thrift API paths are excluded from OAuth2 by default and rely on network-level security.

## Getting Help
If you have questions that aren't answered in our [documentation](https://aurora-scheduler.github.io/documentation/latest/),
you can reach out to the maintainers via Slack: #aurora on [mesos.slack.com](http://mesos.slack.com).
Invites to our slack channel may be requested via [mesos-slackin.herokuapp.com](https://mesos-slackin.herokuapp.com/)

You can also file bugs/issues in our [Github](https://github.com/aurora-scheduler/aurora/issues) repo.


## License
Except as otherwise noted this software is licensed under the
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0.html)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
