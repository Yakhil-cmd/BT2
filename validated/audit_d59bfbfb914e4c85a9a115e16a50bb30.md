### Title
Webhook signature is validated against the payload's `repository.owner.login`, but every handler acts on `repository.full_name` - allowing a party who controls one organization's webhook secret to forge events for stacks belonging to a different repository/organization - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate the HMAC signature against using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (or `organization.login`) [1](#0-0) [2](#0-1) . Once the signature check passes, every `Shipit::Webhooks::Handlers::Handler` subclass resolves the actually-affected stack via a completely different field: `payload.dig('repository', 'full_name')`, looked up with `Repository.from_github_repo_name` [3](#0-2) [4](#0-3) . The signature check binds trust to "owner.login" while the mutating action is bound to "full_name" — an equality that is never actually enforced (owner.login == full_name.split('/').first).

### Finding Description
This is structurally identical to the audited DeFi bug: one code path (increasing position) checks a coarse/weaker condition while a different code path (decreasing/closing) checks a different, unsynchronized condition, letting the attacker exploit the mismatch between the two. Here:

- The **authentication decision** (`verify_signature`) picks the webhook secret keyed by `repository_owner` = `repository.owner.login` (or `organization.login`) [1](#0-0) .
- The **write/action decision** made by every handler (`PushHandler`, `StatusHandler`, `CheckSuiteHandler`, pull-request handlers, etc.) is based on `repository.full_name`, an entirely separate JSON field in the same payload [5](#0-4) .

Because `Shipit.github(organization:)` is looked up per-organization and each organization can have its own `webhook_secret` (see `docs/setup.md` config example) [6](#0-5) , an entity that legitimately controls (or can source) the webhook secret for **one** organization's GitHub App installation can craft an arbitrary raw JSON body, sign it correctly for that organization (satisfying `verify_webhook_signature`, which is a pure HMAC-over-raw-body check with no binding between the signing org and content of `repository.full_name`) [7](#0-6) , but set `repository.full_name` to point at a completely different repository/organization tracked by this Shipit instance.

Because the code never checks that `owner.login` (the value used to select/verify the secret) matches the owner encoded in `full_name` (the value used to resolve the target `Repository`/`Stack`), the two "trust bindings" — "which organization's secret authenticated this request" and "which repository is being mutated" — are never required to be equal.

### Impact Explanation
Exploiting the mismatch lets the forged payload:
- Trigger `Repository.from_github_repo_name(full_name)` → resolves stacks belonging to a repository under a *different* organization than the one whose secret validated the request, then queue `GithubSyncJob`/`stack.sync_github` for that unrelated stack via `PushHandler#process` [8](#0-7) .
- Inject arbitrary commit statuses on commits belonging to other repositories via `StatusHandler#process`, which can influence deployability gating (`ci.require`) and thus which commits become eligible for automatic/continuous deploys on stacks the attacker does not own [9](#0-8) .

This crosses the "cross-repository writes" / "unauthorized deploy" impact bucket in scope, since it lets a party outside the true owning organization influence commit/deploy state for a stack under a different repository, using only their own org's webhook credential.

### Likelihood Explanation
Likelihood is limited primarily by the precondition: the attacker needs *a* valid webhook secret for *some* organization configured on this Shipit install (e.g. because they legitimately administer their own GitHub App installation pointed at the same Shipit instance, in a multi-tenant Shipit deployment as documented in `docs/setup.md`). Given that precondition, forging the rest of the JSON body (including an arbitrary `repository.full_name`) is trivial and entirely under attacker control, since `verify_webhook_signature` only checks the HMAC of the raw body against the secret — it performs no structural validation tying signer identity to declared repository [7](#0-6) .

### Recommendation
After signature verification succeeds, assert that the organization implied by `repository.full_name` (or `organization.login`) equals the `repository_owner` value that was actually used to select/verify the webhook secret, rejecting the request (422) on mismatch. Equivalently, verify the signature using the secret associated with `repository.full_name`'s owner rather than `repository.owner.login`/`organization.login` computed independently, so the two derived values used for authentication and for the write action are provably the same field.

### Proof of Concept
1. Attacker administers (or otherwise possesses the `webhook_secret` for) GitHub organization `attacker-org`, configured on the shared Shipit instance.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org secret, raw_body)` and POSTs to `/github/webhooks`.
4. `WebhooksController#verify_signature` computes `repository_owner = "attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and the signature validates successfully [1](#0-0) .
5. `Shipit::Webhooks.for_event('push')` dispatches to `PushHandler`, whose `repository_name` resolves to `"victim-org/victim-repo"` from `full_name`, looking up and acting on the victim's `Repository`/`Stack` [3](#0-2) [8](#0-7) , even though the request was authenticated only against `attacker-org`'s secret.

Note: full confirmation that this Shipit deployment is configured multi-tenant (multiple orgs/secrets in `Shipit.github_apps`) and that no additional guard exists elsewhere was limited by index coverage of `lib/shipit.rb`'s full contents; a Devin session with full file access would be needed to double check the `Shipit.github` lookup implementation exhaustively.

### Citations

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

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
