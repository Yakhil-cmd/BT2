### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` in `StatusHandler#process` broadcasts attacker-controlled content onto victim stack's public Pubsubstub channel - ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits to attach a forged GitHub Status to using a global, repository-unscoped `Commit.where(sha: params.sha)` query, even though the base `Handler` class already exposes a repository-scoped `stacks` helper meant for exactly this purpose. Any webhook sender whose signature is accepted for *some* organization/repository can attach a `Status` (with attacker-controlled `description`/`target_url`/`context`) to a `Commit` belonging to a completely different stack, which then triggers `after_commit :broadcast_update` and publishes attacker-authored content on that victim stack's public Pubsubstub channel (`stack.#{stack.id}`).

### Finding Description
The claimed binding is: `stack.id used as the broadcast channel key == the stack the payload's webhook_secret authorized`.

Tracing the code:
- `WebhooksController#verify_signature` resolves the signing key via `Shipit.github(organization: repository_owner)` where `repository_owner = params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) [2](#0-1) . This authenticates the *organization* named in the attacker-supplied payload, not a specific stack/repository — it only proves the payload is validly signed by whichever entity owns that org's webhook secret.
- Once verified, `create` dispatches to `Shipit::Webhooks.for_event(event)` handlers with the raw parsed JSON [3](#0-2) .
- `Handler` already defines a repository-scoped accessor, `stacks`, derived from `payload.dig('repository','full_name')` [4](#0-3) , intended to constrain handler logic to stacks actually belonging to the authenticated repository.
- `StatusHandler#process`, however, ignores `stacks` entirely and instead does:
```ruby
Commit.where(sha: params.sha).each do |commit|
  commit.create_status_from_github!(params)
end
``` [5](#0-4) 
This matches *every* `Commit` row across *every* stack in the entire installation that happens to share the given `sha` — not just commits belonging to the repository named in the payload.
- `create_status_from_github!` creates a `Status` via `statuses.replicate_from_github!`, copying `state`, `description`, `target_url`, `context` verbatim from the attacker-supplied payload [6](#0-5) [7](#0-6) .
- `Status` has `after_commit :schedule_continuous_delivery, :broadcast_update, on: :create`, and `broadcast_update` is delegated to `commit` → `stack`, i.e. the stack that actually owns the matched `Commit` row (the victim's), regardless of which organization's webhook secret authorized the request [8](#0-7) [9](#0-8) [10](#0-9) .

Root cause: `sha` values are globally unique per-repository content hashes but are **not globally unique across repositories/forks** (identical commits — e.g. shared history between a fork and its upstream, or cherry-picked/duplicated commits — produce identical SHAs). `StatusHandler` never checks that the matched `Commit`'s stack belongs to the repository named in (and authenticated for) the incoming payload, so any sha collision across tenants lets a webhook validly signed for repository A silently mutate and broadcast onto a stack belonging to repository B.

Why existing guards don't catch this: `verify_signature` only proves org-level authenticity of the payload, not that the `sha`/`repository` fields inside that payload refer to a commit actually owned by that org's repositories; `ExplicitParameters` (`StatusHandler.params`) validates field *types*, not their relationship to `stacks`; and the `stacks` scoping helper exists in the base class but is simply unused by this handler.

### Impact Explanation
An attacker who controls (or whose webhook signature is validly accepted for) any repository/organization onboarded to the Shipit instance can, by referencing a `sha` that also exists as a `Commit` on a victim stack (trivial via forks/shared git history, or simply because commit hashes are public information on public repos), inject a `Status` record with attacker-chosen `description`, `target_url`, and `context` that gets attached to the victim's `Commit` and immediately broadcast over the victim stack's public Pubsubstub channel (`stack.#{stack.id}`), readable by any unauthenticated viewer of that stack's page. Beyond the read-side content injection, the forged `Status` also feeds `Commit#schedule_continuous_delivery`, influencing the victim stack's deployability/CI state — a payload for one repository mutating another's commit/stack state. This is repeatable against any stack whose commits share (or can be made to share) a sha with a repository the attacker can emit signed webhooks for.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce a validly-signed webhook for *some* org/repo (their own, or one sharing an org-level GitHub App/webhook secret with the victim's stack — common in multi-repo/multi-team single-org Shipit deployments) and on being able to name a `sha` that also exists as a `Commit` row for the victim's stack. Both are realistic for shared-history scenarios (forks, cherry-picks, monorepo-style multi-team orgs onboarded to one Shipit instance), making this a credible, repeatable cross-tenant issue rather than a purely theoretical one, though it does depend on Shipit installation topology (single GitHub App/secret shared across multiple stacks/orgs).

### Recommendation
Scope `StatusHandler#process` to the authenticated repository, e.g. replace the global lookup with the already-available `stacks` helper: `stacks.flat_map(&:commits).select { |c| c.sha == params.sha }` (or a `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` query), so a Status can only be attached to commits belonging to stacks of the repository named in the verified payload.

### Proof of Concept
```ruby
test "status webhook for repo A cannot broadcast onto repo B's stack channel" do
  victim_stack = shipit_stacks(:shipit)
  victim_commit = victim_stack.commits.create!(sha: "a" * 40, message: "victim commit")

  attacker_stack = create_stack(repository: create_repository(owner: "attacker-org", name: "attacker-repo"))
  # attacker's own repo happens to contain a commit with the same sha (fork/shared history)
  attacker_stack.commits.create!(sha: victim_commit.sha, message: "attacker commit")

  payload = {
    "sha" => victim_commit.sha,
    "state" => "success",
    "description" => "PWNED - injected by attacker",
    "target_url" => "https://evil.example/",
    "repository" => { "full_name" => attacker_stack.repository.github_repo_name, "owner" => { "login" => "attacker-org" } }
  }

  Shipit::Pubsubstub.expects(:publish).with("stack.#{victim_stack.id}", anything, has_entries(description: "PWNED - injected by attacker"))

  # simulate authenticated (validly signed for attacker-org) webhook dispatch
  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert_equal "PWNED - injected by attacker", victim_commit.reload.statuses.last.description
end
```
Assertion binds: channel key used by `Pubsubstub.publish` == `"stack.#{victim_stack.id}"`, while the payload's `repository.owner.login`/`repository.full_name` (what the signature authorized) == `attacker-org`/`attacker-stack.repository`. These differ, proving the equality claimed in the question is false.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** app/models/shipit/commit.rb (L21-21)
```ruby
    after_commit { broadcast_update }
```

**File:** app/models/shipit/commit.rb (L57-58)
```ruby
    delegate :broadcast_update, :github_repo_name, :hidden_statuses, :required_statuses, :blocking_statuses,
             :soft_failing_statuses, to: :stack
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/status.rb (L18-21)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create

    delegate :broadcast_update, to: :commit
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```
