### Title
Webhook signature verification is keyed on `repository.owner.login`/`organization.login` while event handlers act on the unrelated `repository.full_name` field, allowing a valid webhook secret for one configured GitHub organization to be replayed to control stacks belonging to a different organization - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to validate the HMAC signature against using an untrusted field read straight out of the JSON body, then hands the *entire* untrusted payload to event handlers, which independently resolve the target `Repository`/`Stack` from a *different* untrusted field in the same body. Because the two fields are never cross-checked, a caller who possesses (or forges knowledge of) the webhook secret configured for organization A can craft a payload whose signature-selection field says "A" while its stack-resolution field says "B", causing Shipit to act on organization B's stacks using organization A's trust.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App config to check the signature against via: [1](#0-0) [2](#0-1) 

`repository_owner` is taken directly from the unauthenticated JSON body (`params.dig('repository','owner','login')` or `organization.login`) before the signature has been checked. `Shipit.github(organization: repository_owner)` looks up a per-organization `webhook_secret` (see the multi-org config in `test/dummy/config/secrets_double_github_app.yml`, where distinct organizations each get an independent `app_id`/`webhook_secret`). `GitHubApp#verify_webhook_signature` only proves that *some* configured secret matches the raw body - it never asserts that the organization whose secret matched is the same organization the payload subsequently claims to modify.

Once the signature check passes, the full raw payload is dispatched unmodified to handlers: [3](#0-2) 

Every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, `MembershipHandler`, `pull_request/*`) inherits from the base `Handler`, which resolves the target repository/stack from a **separate, unrelated field**: [4](#0-3) 

`Repository.from_github_repo_name` splits `owner/name` straight out of `repository.full_name` and does a direct DB lookup with no relationship back to the `repository.owner.login`/`organization.login` value that was used to select the verifying secret: [5](#0-4) 

`PushHandler#process` then acts on whatever stacks were resolved this way, enqueueing a GitHub sync with an attacker-supplied `expected_head_sha`: [6](#0-5) 

**The broken binding, stated as an equality that should hold but doesn't:**
`organization used to authenticate the webhook (repository.owner.login / organization.login)` == `organization whose repository/stack the handler mutates (repository.full_name)`

Before the attacker's request: for a legitimate GitHub-originated webhook, GitHub always signs a payload where `repository.owner.login` and `repository.full_name`'s owner segment refer to the same repository, so the two fields are implicitly consistent.

After the attacker's request: the attacker directly POSTs to the shared `/github/webhooks` endpoint (this is a single Rails route, not scoped per-organization) with `repository.owner.login = "OrgA"` (so the signature check selects and validates against `OrgA`'s `webhook_secret`, which the attacker knows) but `repository.full_name = "OrgB/some-private-repo"`. The signature check passes because it is computed over the raw body against `OrgA`'s secret, and the attacker fully controls that raw body. The handler then resolves and mutates `OrgB`'s `Repository`/`Stack` records, even though `OrgB` never authenticated this request.

### Impact Explanation
This breaks the intended tenant isolation between GitHub organizations configured in a single Shipit deployment (as explicitly supported/documented by the multi-org `github:` config format). An entity holding only one organization's webhook secret can:
- Force `PushHandler` to enqueue `GithubSyncJob`/resync operations against a stack that belongs to an unrelated organization [6](#0-5) .
- Since `StatusHandler` and `CheckSuiteHandler` share the identical `Handler#repository_name`/`#stacks` resolution path, the same confusion lets a holder of one organization's secret post/spoof commit statuses or check-suite results against commits in a different organization's stack. If that target stack has continuous deployment enabled and depends on `status`/`check_suite` webhooks to satisfy `ci.require` gating (see `shipit.yml` `ci.require`), this can be used to fraudulently mark a commit "green" and cause Shipit to trigger an **unauthorized deploy** for a repository the attacker never authenticated against.

This lands in the Critical bucket ("unauthorized deploy") to at least the High bucket ("unauthenticated ... task streams" via forced sync/state changes), depending on the specific handler exercised.

### Likelihood Explanation
Exploitation requires only knowledge of a single valid webhook secret for *any one* of the organizations configured on the Shipit instance (an unprivileged attacker relative to the *other* organizations) and the ability to POST directly to the shared webhooks endpoint - no GitHub App installation, `ApiClient` token, or repository write access to the target organization is required. The webhook endpoint is intentionally public/unauthenticated apart from the HMAC check, so this is directly reachable.

### Recommendation
Do not select the verification secret from an untrusted field that is also used later to determine the mutation target. Concretely:
- Bind the signature verification to the same value used for resolving the stack (e.g., require `repository.full_name`'s owner segment to match the organization whose secret validated the signature, and reject mismatches with `422`), or
- Verify the signature against the secret associated with the resolved `Repository`'s owner (derived from `full_name`) rather than the raw, independently-sourced `owner.login`/`organization.login` field, so a single equality is always enforced between "who authenticated" and "what gets written."

### Proof of Concept
Given a Shipit instance configured with two organizations as in `test/dummy/config/secrets_double_github_app.yml` (`OrgOne` secret `S1`, `OrgTwo` secret `S2`), and a stack `OrgTwo/private-repo` on branch `main`:

```
POST /github/webhooks
X-Github-Event: push
X-Hub-Signature: sha1=<HMAC-SHA1(S1, body)>

body = {
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgOne" },      // selects OrgOne's secret S1 for verification
    "full_name": "OrgTwo/private-repo"   // used by PushHandler to pick the target stack
  }
}
```

- `WebhooksController#verify_signature` computes `Shipit.github(organization: "OrgOne")` and validates the signature with `S1` -> passes, because the attacker signed with `S1`, a secret they legitimately hold for `OrgOne`.
- `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `repository_name` reads `payload.dig('repository','full_name')` = `"OrgTwo/private-repo"`.
- `Repository.from_github_repo_name("OrgTwo/private-repo")` resolves `OrgTwo`'s stack, and `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` is invoked against a repository the attacker never authenticated for.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
