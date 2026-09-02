This confirms the multi-tenant setup: `Shipit.github(organization:)` creates a distinct `GitHubApp` instance per organization key, each with its own `@domain`, `@webhook_secret`, `app_id`, `installation_id`, and `private_key` [1](#0-0) . But inside `GitHubApp#api`, the actual Octokit client object is memoized in `Thread.current[:github_client]` — a key scoped only to the current thread, not to `self` (the specific `GitHubApp`/organization instance) [2](#0-1) .### Title
Cross-organization GitHub API client/token reuse via unindexed `Thread.current[:github_client]` cache - ([File: lib/shipit/github_app.rb])

### Summary
In multi-organization Shipit deployments, each organization gets its own `GitHubApp` instance keyed by organization name, holding organization-specific `domain`, `app_id`, `installation_id`, `private_key`, and `webhook_secret` [1](#0-0) . However, the actual Octokit HTTP client used to talk to GitHub is memoized in `Thread.current[:github_client]`, a key scoped only to the current thread and shared by every `GitHubApp` instance that happens to execute in that thread — it is never indexed by organization/instance identity [2](#0-1) .

### Finding Description
This is the same bug class as the report: a value that should be partitioned by a tenant/context key (`marketIndex` in the original report, `organization`/`GitHubApp` instance here) is instead stored behind a single shared index (a global per-thread slot), so two logically independent contexts collide and overwrite each other's state.

`GitHubApp#api` does:
```ruby
def api
  client = (Thread.current[:github_client] ||= new_client(access_token: token))
  client.access_token = token if client.access_token != token
  client
end
``` [2](#0-1) 

`new_client` bakes in enterprise-specific connection settings (`api_endpoint`, `web_endpoint`, derived from `domain`/`enterprise?`) **only at client-construction time** [3](#0-2) . Once a client object is created for organization A in a given thread, every subsequent call to `.api` on a *different* `GitHubApp` instance (organization B) in that same thread reuses the exact same client object and only mutates `access_token`. The `api_endpoint`/`web_endpoint` (i.e., which GitHub host the requests are sent to) is never refreshed.

Multi-org configuration is an explicitly supported mode: `Shipit.github_organizations`, `Shipit.github_app_config(organization)`, and per-organization `@github[organization] ||= GitHubApp.new(...)` memoization all exist to support several distinct organizations (potentially including on-prem GitHub Enterprise Server domains alongside github.com) sharing a single Shipit install [4](#0-3) .

The binding that should hold is:
`GitHubApp(org).domain/api_endpoint used for a request == GitHubApp(org).token attached to that request`

But because the client cache key is `Thread.current[:github_client]` (indexed only by "current OS thread"), not by organization, after two different organizations' `GitHubApp#api` are invoked on the same worker thread (Puma/Sidekiq threads are reused across requests/jobs for different stacks/organizations), the equality breaks: the endpoint from the first org's `GitHubApp` persists while the token gets overwritten with the second org's token.

### Impact Explanation
When one organization is on `github.com` and another is configured with a distinct GitHub Enterprise Server `domain`, thread reuse causes org B's freshly-minted installation access token to be sent to org A's `api_endpoint`/`web_endpoint` (or vice-versa). This is a direct analog of "an organization authenticated versus the repository that is written": the credential fetched for org B ends up being transmitted to, and usable against, org A's GitHub host/repositories, i.e. cross-organization `GITHUB_TOKEN`-equivalent (installation token) leakage and the potential for cross-repository API writes performed with the wrong org's identity.

### Likelihood Explanation
This requires a multi-organization Shipit deployment (`secrets.github` configured with multiple org keys, at least one of which is a GHE domain differing from `github.com`) and normal thread-pool reuse across organizations' stacks/jobs, which is the default execution model for Puma web workers and Sidekiq jobs handling multiple stacks. A user with access to trigger GitHub-API-touching actions for their own (less-trusted) organization's stack (e.g., syncing/refreshing a stack, which is a normal authenticated action, not privileged) can increase the chance of interleaving with another organization's request on the same thread. This is not a common single-tenant configuration, so likelihood is limited to multi-org enterprise deployments, but the trust boundary crossed matches the rules' criteria (organization-scoped credential vs. destination it is actually applied to).

### Recommendation
Key the cached Octokit client by organization/`GitHubApp` identity (or the `domain`) instead of a bare `Thread.current[:github_client]` slot, e.g. `Thread.current[:github_clients] ||= {}; Thread.current[:github_clients][@organization] ||= new_client(...)`, and refresh `api_endpoint`/`web_endpoint` together with the token whenever the underlying `GitHubApp` instance differs, so a client is never reused across organizations with different domains/credentials.

### Proof of Concept
1. Configure Shipit with two organizations: `orgA` on `github.com` and `orgB` with `domain: github.example-enterprise.com`.
2. In the same worker thread, first trigger any action that calls `Shipit.github(organization: 'orgA').api` (e.g. a stack refresh for an orgA stack) — this creates and caches `Thread.current[:github_client]` pointed at `github.com`.
3. On the same thread, trigger an action for `orgB` (e.g. `Shipit.github(organization: 'orgB').api`) — per `lib/shipit/github_app.rb:63-67`, the cached client object (still targeting `github.com`'s endpoint) has its `access_token` overwritten with orgB's freshly fetched installation token, and subsequent API calls made through this client send orgB's token to `github.com` rather than to `github.example-enterprise.com`.

### Citations

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

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
