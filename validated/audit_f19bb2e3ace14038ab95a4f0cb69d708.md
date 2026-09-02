### Title
Cross-organization GitHub API client/token confusion via unscoped thread-local cache - ([File: lib/shipit/github_app.rb])

### Finding Description
`GitHubApp#api` memoizes the Octokit client in a **global, thread-local slot** that is not scoped to the calling `GitHubApp` instance/organization: [1](#0-0) 

```ruby
def api
  client = (Thread.current[:github_client] ||= new_client(access_token: token))
  client.access_token = token if client.access_token != token
  client
end
```

`new_client` sets enterprise-specific `api_endpoint`/`web_endpoint` at creation time only, based on the *first* `GitHubApp` instance that populates the cache on that thread: [2](#0-1) 

Shipit supports multiple GitHub organizations, each with its own `GitHubApp` instance/config (domain, webhook secret, credentials) — this is how `Shipit.github(organization: repository_owner)` is looked up per-request in `WebhooksController#verify_signature` [3](#0-2) , and it underlies the credentials used for all GitHub API calls made through `.api` (used pervasively for syncing repos, statuses, deploys, etc.).

Because `Thread.current[:github_client]` is keyed only by the fixed symbol `:github_client` with no organization/domain component, if a single worker thread ever serves two different `GitHubApp` instances in sequence (e.g. an Enterprise-configured organization followed by a github.com organization, or vice versa, within the same Puma/Sidekiq thread), the code only refreshes `access_token` on cache hit — it never re-evaluates `api_endpoint`/`web_endpoint`. The result: the **second** organization's access token is attached to a client still pointed at the **first** organization's API host.

This is structurally the same class of bug as the Lighthouse report: a value (the custody-column/API-endpoint configuration) is computed once at "startup"/first-use and then relied upon by later requests without being recomputed for the new context, breaking the intended binding between "the organization whose token is being used" and "the GitHub host that token is sent to."

### Impact Explanation
If exploitable across two configured organizations sharing worker threads, this breaks the binding of "an organization authenticated" (the token/credentials being used) versus "the repository/host the request is actually sent to" — an org B GitHub App installation token could be transmitted to org A's (potentially attacker-influenced, if org A is a GitHub Enterprise Server domain configured by a lower-trust tenant) API host, i.e., SSRF carrying the app's GitHub credentials to an unintended host, satisfying the report's "High" impact bucket.

### Likelihood Explanation
This requires a specific multi-organization Shipit deployment (mixing at least one GitHub Enterprise-domain org with at least one github.com org, or two Enterprise orgs on different domains) and thread reuse across those organizations within the same process — a configuration/operational precondition, not something a single unprivileged external actor can trigger directly through a single request. I was not able to fully verify, within the available tool budget, exactly how many organizations a single Shipit deployment typically configures via `lib/shipit.rb` (`Shipit.github`) or whether request routing guarantees per-organization thread affinity; this bounds my confidence in real-world reachability.

### Recommendation
Scope the thread-local (or better, use a per-`GitHubApp`-instance memoized client instead of `Thread.current`) cache key by organization/domain, e.g. `Thread.current[:github_clients] ||= {}; Thread.current[:github_clients][@organization] ||= new_client(...)`, and always refresh `api_endpoint`/`web_endpoint` (not just `access_token`) on every call, or simply avoid a globally-keyed thread-local entirely and memoize on the `GitHubApp` instance.

### Proof of Concept
Conceptual reproduction (not confirmed end-to-end due to tool limitations):
1. Configure two organizations in Shipit: `org-enterprise` (domain: `github.example.com`) and `org-public` (default `github.com`).
2. On a given worker thread, trigger any code path invoking `Shipit.github(organization: 'org-enterprise').api` (e.g. a webhook or sync job for a repo under `org-enterprise`) — this populates `Thread.current[:github_client]` with `api_endpoint: https://github.example.com/api/v3/`.
3. On the same thread, trigger a code path for `org-public` (`Shipit.github(organization: 'org-public').api`) — the cached client is reused, `access_token` is swapped to `org-public`'s token, but `api_endpoint` still points at `github.example.com`.
4. Subsequent API calls intended for `github.com` on behalf of `org-public` are sent to `github.example.com` carrying `org-public`'s installation token. [1](#0-0)

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

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```
