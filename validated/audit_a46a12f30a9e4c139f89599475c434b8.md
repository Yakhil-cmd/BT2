### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but the stack that gets mutated is resolved from the independent `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` picks the `GitHubApp`/`webhook_secret` used to authenticate an inbound webhook by reading `repository.owner.login` (or `organization.login`) out of the untrusted JSON body, while every `Handlers::Handler` subclass resolves the `Repository`/`Stack` to mutate by reading the separate `repository.full_name` field from that same body. Nothing ties these two independently-parsed fields together, so a payload can be signed with Organization A's secret while acting on Organization B's stacks.

### Finding Description
`repository_owner` is computed purely from attacker-supplied JSON, and is used to select which `GitHubApp` config (and therefore which `webhook_secret`) verifies the HMAC signature: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` resolves to per-organization config, and `verify_webhook_signature` only checks the HMAC over the raw body using the `webhook_secret` associated with whichever organization the caller named: [3](#0-2) [4](#0-3) 

Once signature verification passes, every handler resolves the target `Repository`/`Stack` using a *different* field, `repository.full_name`, taken from the same JSON body: [5](#0-4) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the affected stacks) are two independent keys in the same attacker-controlled JSON, an actor who legitimately knows/controls the `webhook_secret` configured for their own organization (e.g., because they configured the GitHub webhook delivery for their own org's repo into this Shipit instance) can sign a payload with `repository.owner.login = "OrgA"` but `repository.full_name = "OrgB/victim-repo"`. The signature check succeeds against Org A's secret, yet the handler acts on Org B's repository/stacks — breaking the binding `organization authenticated == repository written`.

This directly mirrors the reported smart-contract analog: `pool.collectFees()` is trusted based on one condition (`amount0/1 > 1`) while the caller (`CLGauge`) checks a different condition (`claimed0/1 > 0`), so the two sides of the check drift apart. Here, the "check" (signature verification keyed by `owner.login`) and the "effect" (stack mutation keyed by `full_name`) are similarly decoupled fields from the same payload.

### Impact Explanation
Downstream handlers act on the mismatched target repository/stack:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` on the forged stack. [6](#0-5) 
- `StatusHandler#process` creates a forged commit status (`commit.create_status_from_github!`) for any known commit SHA, which feeds into Shipit's deployability/CI-gating logic used to authorize deploys. [7](#0-6) 
- `CheckSuiteHandler#process` forges check-run refresh triggers for arbitrary stacks/commits. [8](#0-7) 

Forged "success" statuses/check-suite state can satisfy the deployability checks Shipit relies on before allowing a deploy, enabling an attacker outside the target organization to unlock or trigger an unauthorized deploy path for a stack they do not own — matching the "unauthorized deploy" Critical-impact category.

### Likelihood Explanation
This requires the attacker to control the `webhook_secret` of *some* organization onboarded to the Shipit instance (a realistic scenario in multi-tenant/multi-org Shipit deployments, where each org's admins configure their own webhook secret and could reuse this exact endpoint against another org's repo). No access to the victim organization's GitHub App, session, or `ApiClient` token is needed — only knowledge of one legitimate (even low-privilege, self-controlled) org secret. Likelihood is Medium: it depends on the deployment hosting more than one organization's webhook secret, which is an explicitly supported configuration (`lib/shipit/github_app.rb` config is per-organization).

### Recommendation
Bind signature verification and stack resolution to the same, single source of truth: derive both the verifying organization and the acted-upon repository from the identical field (e.g., always use `repository.full_name`, and cross-check that its owner segment equals the `owner.login`/`organization.login` used for secret lookup) before dispatching to any handler in `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/handler.rb`.

### Proof of Concept
1. Attacker is an admin of GitHub organization `attacker-org`, which has a Shipit `webhook_secret` configured (`Shipit.github(organization: 'attacker-org')`).
2. Attacker crafts a JSON payload for the `push` event:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeef...",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(attacker-org-secret, payload)` and POSTs to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` to `"attacker-org"`, fetches `attacker-org`'s `webhook_secret`, and the HMAC matches → request is accepted. [9](#0-8) 
5. `PushHandler` (via `Handler#stacks`) resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `sync_github(expected_head_sha: "deadbeef...")` on that stack, despite the attacker never having proven control of `victim-org`. [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/webhooks/handlers/check_suite_handler.rb (L13-17)
```ruby
        def process
          stacks.where(branch: params.check_suite.head_branch).each do |stack|
            stack.commits.where(sha: params.check_suite.head_sha).each(&:schedule_refresh_check_runs!)
          end
        end
```
