### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` lookup enabling unauthorized deploy trigger - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` records solely by `sha`, with no scoping to the repository that actually emitted the webhook. Any GitHub `status` event that passes org-level HMAC verification can therefore write a `Status` onto a `Commit` belonging to a completely unrelated `Stack`, as long as the two commits share a SHA (trivially achievable by forking/duplicating the victim's commit history within the same GitHub App installation).

### Finding Description
The binding the codebase should enforce is: `payload['repository']['full_name'] == commit.stack.repository.full_name` for every `Commit` mutated by a `status` webhook. This binding is never checked.

`WebhooksController#verify_signature` only proves the request came from GitHub for the organization named in the payload (`repository_owner`), using that org's configured `webhook_secret`: [1](#0-0) [2](#0-1) 

It does not verify that the specific repository or SHA in the payload belongs to a stack owned by that organization. Compare `PushHandler`, which explicitly scopes to stacks matching the repository/branch context (`stacks.not_archived.where(branch:)`): [3](#0-2) 

`StatusHandler#process`, by contrast, performs a completely global lookup with no repository/stack scoping at all: [4](#0-3) 

`Commit.where(sha: params.sha)` searches the entire `commits` table across every `Stack` in the Shipit instance, since `Commit#belongs_to :stack` is not filtered here: [5](#0-4) 

Any matched commit gets `create_status_from_github!(params)` invoked, unconditionally writing the forged status: [6](#0-5) 

**Attack flow**: An attacker who has push/CI-posting rights on some repository sharing the same GitHub organization/App installation as the victim's stack (webhook secrets in this engine are configured per-organization, not per-repository - see `GitHubApp#verify_webhook_signature`) forks or otherwise reproduces the victim's commit so it carries an identical SHA in the attacker's own repository. The attacker then uses their own repository's legitimate GitHub integration/CI to post an arbitrary commit `status` (state, context, target_url, created_at) for that SHA via the real GitHub API. GitHub relays this as a genuinely-signed `status` webhook to Shipit. `verify_signature` passes because the HMAC is computed by GitHub itself using the organization's real secret. `StatusHandler#process` then matches the colliding SHA against the victim's `Commit` row (in a stack the attacker never interacted with) and writes a `Status`.

If the victim `Stack` relies solely on CI state (`Shipit.deployment_checks` empty, no additional `checks?`), this forged status can flip `Commit#deployable?` / `Stack#deployment_checks_passed?` to true: [7](#0-6) [8](#0-7) 

which feeds `Stack#should_delay_continuous_delivery?` / `#should_resume_continuous_delivery?`: [9](#0-8) 

and ultimately `Stack#trigger_continuous_delivery`, which calls `trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)` with no attacker-supplied env required: [10](#0-9) 

No existing guard (`verify_signature`, `drop_unhandled_event`, the `ExplicitParameters` schema on `StatusHandler`) checks repository identity against the matched `Commit`'s stack, so the divergence is real.

### Impact Explanation
The forged status write is a record mutation on a `Commit`/`Status` belonging to a repository/stack the attacker's webhook never authenticated for, and it can be the sole trigger condition for `Stack#trigger_continuous_delivery` to fire an unauthorized deploy on the victim stack. The deploy is attributed to `Shipit.user` rather than any accountable human, defeating auditability. This is repeatable against any stack sharing the attacker's GitHub App/organization installation whose commit SHAs the attacker can reproduce (e.g., any stack tracking a repository the attacker can fork within that org), so the blast radius spans every tenant stack under the same webhook_secret/organization. This matches the "unauthorized deploy" Critical impact category.

### Likelihood Explanation
Preconditions: the attacker needs push/CI-posting capability on some repository within the same GitHub organization/App installation as the victim (since `webhook_secret` in this engine is configured per organization via `GitHubApp`), and the victim stack must gate `deployable?`/`deployment_checks_passed?` purely on CI status with `Shipit.deployment_checks` unset. Producing a colliding SHA is cheap - forking the victim's repository preserves identical SHAs for shared history. No Shipit credentials, sessions, or API tokens are required; the only requirement is a legitimately-signed GitHub webhook from a repository the attacker controls within the shared org, which is well within the attacker capability model described (fork owner, webhook emitter). This makes the attack realistically repeatable, though scoped to attacker-and-victim sharing the same org-level webhook secret.

### Recommendation
Scope `StatusHandler#process` to only touch commits belonging to stacks whose tracked repository matches the webhook's `repository.full_name` (or organization), mirroring the pattern used in `PushHandler`'s `stacks` scoping - e.g., join through `Stack` and filter by repository owner/name derived from the payload before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`, illustrative):
```ruby
test "status handler does not update a Commit belonging to a different repository" do
  victim_stack = shipit_stacks(:shipit) # repository "shopify/shipit-engine"
  attacker_stack = shipit_stacks(:some_other_repo_same_org) # different repository, same org/webhook_secret

  colliding_sha = "deadbeef" * 5
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, ...)
  attacker_commit = attacker_stack.commits.create!(sha: colliding_sha, ...)

  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci/attacker',
    'created_at' => Time.now.iso8601,
    'repository' => { 'full_name' => attacker_stack.github_repo_name, 'owner' => { 'login' => attacker_stack.repository.owner } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.new(payload).process
  end
end
```
This asserts the equality `payload['repository']['full_name'] == commit.stack.repository.full_name` is (or should be) enforced: currently it is not, and the test would fail against the existing `StatusHandler#process` implementation, demonstrating the cross-stack write.

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

**File:** app/models/shipit/commit.rb (L11-12)
```ruby
    belongs_to :stack
    has_many :statuses, -> { order(created_at: :desc) }, dependent: :destroy, inverse_of: :commit
```

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/stack.rb (L210-229)
```ruby
    def trigger_continuous_delivery
      return if cached_deploy_spec.blank?

      commit = next_commit_to_deploy

      if should_resume_continuous_delivery?(commit)
        continuous_delivery_resumed!
        return
      end

      if should_delay_continuous_delivery?(commit)
        continuous_delivery_delayed!
        return
      end

      begin
        trigger_deploy(commit, Shipit.user, env: cached_deploy_spec.default_deploy_env)
      rescue Task::ConcurrentTaskRunning
      end
    end
```

**File:** app/models/shipit/stack.rb (L627-631)
```ruby
    def deployment_checks_passed?
      return true unless deployment_checks?

      Shipit.deployment_checks.call(self)
    end
```

**File:** app/models/shipit/stack.rb (L701-713)
```ruby
    def should_resume_continuous_delivery?(commit)
      (deployment_checks_passed? && !deployable?) ||
        deployed_too_recently? ||
        commit.nil? ||
        commit.deployed?
    end

    def should_delay_continuous_delivery?(commit)
      commit.deploy_failed? ||
        (checks? && !EphemeralCommitChecks.new(commit).run.success?) ||
        !deployment_checks_passed? ||
        commit.recently_pushed?
    end
```
