### Title
Unscoped `Commit.where(sha:)` lookup in `StatusHandler` allows cross-repository status forgery once *any* organization's webhook signature check passes - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) purely by `sha`, with no scoping to the repository/stack that produced the webhook's `X-Hub-Signature`. Because `GitHubApp#verify_webhook_signature` trivially returns `true` for any organization that has no `webhook_secret` configured, an attacker who owns (or creates) such an org can forge a `status` event whose `sha` matches a commit belonging to an entirely different, victim stack, and force a status onto that victim's commit—flipping `blocked?` on a `blocking_statuses`-configured stack.

### Finding Description
The broken binding: the code assumes `authenticated_repository_owner == repository_that_owns(Commit.where(sha: params.sha))`, but nothing enforces this equality.

- `Shipit::WebhooksController#verify_signature` calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, keyed only by `repository_owner` taken from the attacker-supplied JSON body [1](#0-0) [2](#0-1) .
- `GitHubApp#verify_webhook_signature` short-circuits to `true` for any organization with no configured `webhook_secret` (`return true unless webhook_secret`), before any signature parsing happens [3](#0-2) . For secret-configured orgs, `signature.split("=", 2)` on a header with no `=` yields `algorithm` = the whole header and `signature = nil`; this only reaches `SecureCompare.secure_compare` if the attacker's raw header literally equals `"sha1"`, and comparing `nil` against a real HMAC hex digest is not a realistic bypass path (it either raises or returns `false` in any conventional constant-time compare) — this specific "malformed split" trick is not independently confirmed exploitable. The definition of `SecureCompare` is not present in this codebase (it comes from an external gem), so its exact behavior on `nil` could not be verified further; I could not find its source.
- Once *any* signature check passes (trivially for a no-secret org), `Shipit::Webhooks.for_event('status')` routes to `StatusHandler#process`, which runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` with no `stack_id`/repository filter whatsoever [4](#0-3) .
- `Commit#create_status_from_github!` uses the **commit's own** `stack_id` (not the authenticating org's) when writing the status: `statuses.replicate_from_github!(stack_id, github_status)` [5](#0-4) . So the status is written against whichever real stack happens to own a commit with that `sha`, regardless of which org's secret (or lack thereof) authenticated the webhook.
- `Commit#blocked?` depends on `stack.blocking_statuses` and whether any commit in range `has any?(&:blocking?)`, i.e., a forged status can flip this and gate `deployable?` on the victim stack [6](#0-5) .

Exploit flow: attacker registers/controls an org with no `webhook_secret` in `Shipit.github` config (or otherwise gets any signature check to pass), learns/guesses a `sha` present in the victim's stack (commit SHAs are frequently public — via the Shipit UI, GitHub, or shared git history/forks), and POSTs a `status` webhook with `repository.owner.login` = attacker's own org and `sha` = victim's commit SHA. `verify_signature` passes because the attacker's own org has no secret. `StatusHandler` then finds the victim's `Commit` (globally, by `sha` alone) and creates a status on it, mutating the victim stack's blocking/deployable state.

Existing guards fail because: `verify_signature` only proves the payload was authenticated *for some organization*, never that the payload's `repository`/`sha`/content actually belongs to that organization; and `StatusHandler` performs no cross-check between the authenticated `repository_owner` and the `stack`/`repository` that owns the matched `Commit`.

### Impact Explanation
An attacker who authenticates as any organization (including a trivially owned org with no `webhook_secret` configured) can write forged CI `status` records onto commits belonging to unrelated victim stacks, as long as they can name a `sha` present in that stack (commit SHAs are not secret). On stacks with `blocking_statuses` configured, this directly manipulates `Commit#blocked?`, gating or unblocking deploys — a payload from one (attacker-controlled) repository mutating another repository's/stack's state. This matches the "Critical — a payload for one repository mutating another's stack, commit, task or team" impact category. The attack is repeatable against any stack/commit combination the attacker can enumerate a valid `sha` for.

### Likelihood Explanation
Preconditions: (1) at least one Shipit-configured organization with no `webhook_secret` set (or any other way to make `verify_signature` return `true`) — this is a configuration detail outside attacker control but common in smaller/simpler deployments; (2) attacker needs to know a `sha` belonging to the victim stack, which is generally public for open-source repos or discoverable via the Shipit UI. No Shipit session, API token, or GitHub credentials are required. The `status` payload is trivial to construct (`sha`, `state`, `context`, etc., per `StatusHandler`'s `ExplicitParameters` schema). This is directly repeatable per request. The specific "malformed X-Hub-Signature split" trick against secret-configured orgs is not confirmed as an independent working bypass (nil vs. real HMAC digest comparison is unlikely to evaluate true), so it should not be relied upon as the entry point; the no-secret-org path is the confirmed, simpler route to the same impact.

### Recommendation
Scope `StatusHandler` (and any other unscoped-by-sha handler) to the repository that authenticated the webhook: pass the authenticated `repository_owner`/`repository.full_name` through to the handler and filter `Commit.joins(:stack).where(sha: params.sha, shipit_stacks: { repository_owner: ..., repository_name: ... })` (or equivalent) instead of a bare `Commit.where(sha: params.sha)`. Additionally, treat an org with no configured `webhook_secret` as unable to authenticate any webhook that claims to belong to a *different* org's repository, and fix `verify_webhook_signature` so malformed/missing `X-Hub-Signature` values cannot reach `SecureCompare.secure_compare` with `nil`.

### Proof of Concept
```ruby
# test/models/webhooks/status_handler_test.rb (conceptual, no live GitHub)
test "status event is not applied to a commit belonging to a different, unauthenticated stack" do
  victim_stack = shipit_stacks(:shipit)
  victim_stack.update!(deploy_spec_cache: { blocking_statuses: ['ci/attacker-forged'] }.to_yaml) # or via DeploySpec fixture
  victim_commit = victim_stack.commits.create!(sha: 'a' * 40, message: 'victim commit')

  # Simulate an attacker-authenticated request for a DIFFERENT (no-secret) org's repository,
  # but reusing the victim's sha in the status payload.
  params = Shipit::Webhooks::Handlers::StatusHandler::Params.new(
    sha: victim_commit.sha,
    state: 'failure',
    context: 'ci/attacker-forged'
  )

  Shipit::Webhooks::Handlers::StatusHandler.new.call(params)

  victim_commit.reload
  # BROKEN BINDING: authenticated_repository_owner (attacker's org) != victim_stack.repository
  # yet victim_commit now has the forged status, and blocked? flips:
  assert victim_commit.statuses.exists?(context: 'ci/attacker-forged', state: 'failure')
  assert victim_stack.commits.last.blocked? # deploys on victim_stack are now gated by attacker's forged status
end
```
The assertion `victim_commit.statuses.exists?(context: 'ci/attacker-forged')` succeeding for a request never authenticated by `victim_stack`'s own repository/organization demonstrates the cross-tenant write.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```
