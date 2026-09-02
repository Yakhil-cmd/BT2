### Title
Thread-local GitHub API client cache is shared across organizations, causing GITHUB_TOKEN cross-organization leakage - (File: `lib/shipit/github_app.rb`)

### Summary
`GitHubApp#api` memoizes its Octokit client in `Thread.current[:github_client]`, a key that is global to the thread and not scoped to the `GitHubApp` instance/organization that created it. Because Rails/Puma reuse worker threads across unrelated requests, and because Shipit supports multiple GitHub organizations each with their own domain/token (`Shipit.github(organization:)`), a client created for one organization's endpoint gets reused — with only its `access_token` swapped — for a completely different organization's API calls. This breaks the binding "the organization whose GitHub App is authenticated" == "the endpoint that actually receives the token", letting one organization's `GITHUB_TOKEN` be sent to another organization's (potentially attacker-operated Enterprise) endpoint.

### Finding Description
`GitHubApp#api` is: [1](#0-0) 

```ruby
def api
  client = (Thread.current[:github_client] ||= new_client(access_token: token))
  client.access_token = token if client.access_token != token
  client
end
```

`new_client` bakes the organization-specific `api_endpoint`/`web_endpoint` into the Octokit client at creation time, based on that `GitHubApp` instance's `domain`: [2](#0-1) 

Each organization has its own `GitHubApp` instance (with its own `@domain`, `@config`, token), created and cached per-organization in `Shipit.github`: [3](#0-2) 

However, `api`'s memoization key `Thread.current[:github_client]` is **not namespaced by organization** — it is a single slot per Ruby thread, shared by every `GitHubApp` instance that happens to run `.api` on that thread. The first call on a thread builds the Octokit client with that organization's `api_endpoint`/`web_endpoint` (its Faraday connection `url_prefix`), and every subsequent call on the same thread — for any other organization — reuses that same client object, mutating only `access_token`. The connection endpoint from the first organization remains in place.

Since application servers reuse a fixed pool of threads across many unrelated requests (webhooks, background jobs, controller actions), and Shipit explicitly supports multiple organizations with independent GitHub Apps/domains (`github_organizations`, `github_app_config`), this equality is broken:

`organization whose GITHUB_TOKEN is being used` == `organization/domain the request is actually sent to`

### Impact Explanation
If Organization A configures a custom/Enterprise `domain` in its GitHub App config, and Organization B (default github.com, or another Enterprise) shares the same Shipit instance, any interleaving of API calls for A and B on the same worker thread causes B's freshly-fetched installation/OAuth token to be sent as the `Authorization` header to A's endpoint (or vice versa, depending on ordering) instead of the intended GitHub host. Operators of Organization A's endpoint can passively capture Organization B's `GITHUB_TOKEN` from their own server's access logs — a credential exfiltration that requires no privileged Shipit access, `ApiClient` token, or `webhook_secret`, only ordinary use of Shipit as an already-onboarded organization. This matches the Critical-severity impact of "exfiltration of GITHUB_TOKEN" and can further enable unauthorized cross-repository actions once the leaked token is replayed against the correct GitHub host.

### Likelihood Explanation
This requires only the documented, supported multi-organization configuration (`secrets.github` with multiple orgs, at least one using a custom `domain`) and ordinary concurrent traffic hitting a shared thread pool — no attacker-side code execution, session, or Shipit credential is needed. The only "attacker" precondition is administering one of the legitimately configured organizations, which is an unprivileged position relative to Shipit itself. Because thread reuse under Puma/Rails is the normal deployment model, the race condition triggers naturally under load rather than requiring an unusual attack setup.

### Recommendation
Scope the memoized Octokit client per `GitHubApp` instance (e.g., store it in an instance variable protected by the existing `@mutex`, or key the thread-local cache by organization/domain) instead of a single global `Thread.current[:github_client]` slot, e.g.:

```ruby
def api
  @api_client ||= new_client(access_token: token)
  @api_client.access_token = token if @api_client.access_token != token
  @api_client
end
```

so that each organization's client keeps its own endpoint configuration for the lifetime of that `GitHubApp` instance, and add multi-organization regression tests (analogous to the report's recommendation for multi-day simulations) verifying that concurrent/interleaved API calls for different organizations never cross endpoints or tokens.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.github`: `orgA` with `domain: github.example.com` (Enterprise, attacker-operated), and `orgB` using default `github.com`.
2. On a given Puma worker thread, trigger any Shipit action that calls `Shipit.github(organization: 'orgA').api` first (e.g., a webhook or sync job for an `orgA` repository) — this caches an Octokit client in `Thread.current[:github_client]` with `api_endpoint`/`web_endpoint` pointing at `github.example.com`.
3. Immediately after, on the same worker thread, trigger an action for `orgB` (e.g., `Shipit.github(organization: 'orgB').api` via a deploy/sync job) — `api` reuses the cached client object, only overwriting `access_token` to `orgB`'s fresh token, per [1](#0-0) .
4. The subsequent Octokit API call for `orgB` is sent to `github.example.com` (orgA's domain) carrying `orgB`'s `GITHUB_TOKEN` in the `Authorization` header.
5. The operator of `github.example.com` (orgA) captures `orgB`'s token from server access logs, achieving credential exfiltration without any Shipit-side privilege.

### Citations

**File:** lib/shipit/github_app.rb (L63-67)
```ruby
    def api
      client = (Thread.current[:github_client] ||= new_client(access_token: token))
      client.access_token = token if client.access_token != token
      client
    end
```

**File:** lib/shipit/github_app.rb (L140-162)
```ruby
    def api_endpoint
      url('/api/v3/') if enterprise?
    end

    def web_endpoint
      url if enterprise?
    end

    def enterprise?
      domain != DOMAIN
    end

    def new_client(options = {})
      if enterprise?
        options = options.reverse_merge(
          api_endpoint:,
          web_endpoint:
        )
      end
      client = Octokit::Client.new(options)
      client.middleware = faraday_stack
      client
    end
```

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```
