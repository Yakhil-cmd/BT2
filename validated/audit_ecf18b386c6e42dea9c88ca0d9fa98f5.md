### Title
StatusHandler applies GitHub `status` webhooks to any commit with a matching SHA across all stacks/repositories, without verifying the webhook's repository owns that commit - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits purely by `sha` (`Commit.where(sha: params.sha)`), unlike every other webhook handler in the engine, which first resolves `stacks` scoped to the reporting `repository.full_name` from the payload. This lets a validly-signed status webhook for repository A attach a `Status` row to a `Commit` belonging to an unrelated repository/stack B, as long as the SHA values collide, feeding both `Commit#status` (`Status::Group.compact`) and therefore `MergeRequest#all_status_checks_passed?` / `Stack#branch_status`.

### Finding Description
The broken binding: `status.commit.stack.repository.full_name` should equal `payload.dig('repository', 'full_name')` for every `Status` created from a webhook, but `StatusHandler` never enforces this.

Compare the handlers:
- `Handler#stacks` (app/models/shipit/webhooks/handlers/handler.rb:32-38) resolves `Repository.from_github_repo_name(repository_name)&.stacks`, scoping all lookups to the repository named in the payload. `PushHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s use this `stacks` scope before mutating any record.
- `StatusHandler#process` (app/models/shipit/webhooks/handlers/status_handler.rb:20-24) instead does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This queries `Commit` globally by `sha` only. The `Commit` table's uniqueness/index is `(stack_id, sha)` (see `db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb`), i.e. the same SHA is expected to legitimately exist in multiple stacks (forks, mirrors, shared history, or attacker-duplicated commit content since git SHA-1 is a pure function of commit content — an attacker can trivially reproduce an identical SHA by pushing byte-identical commit content, which is knowable from a victim's public repository, into a repository the attacker owns). Nothing in `StatusHandler` filters by `repository_name`/`stacks`, so any commit anywhere in the Shipit install sharing that SHA gets the forged `Status` row via `commit.create_status_from_github!(params)` → `add_status` (app/models/shipit/commit.rb:366-386).

Once written, `Commit#status` (app/models/shipit/commit.rb:304-306) resolves via `Status::Group.compact(self, statuses_and_check_runs)`, which is exactly what feeds `Stack#branch_status`/`merge_status` and `MergeRequest#all_status_checks_passed?` (app/models/shipit/merge_request.rb:193-197), using the victim stack's own `required_statuses`/`merge_request_required_statuses` from `stack.cached_deploy_spec` to decide which contexts satisfy the gate — contexts the attacker can read directly from the victim's public `shipit.yml`.

**Why existing guards fail to close this**: `verify_signature` (app/controllers/shipit/webhooks_controller.rb:24-49) only validates the HMAC over the payload against the webhook secret configured for `repository_owner` (i.e., keyed by GitHub organization, via `Shipit.github(organization: repository_owner)`), not against the specific repository or stack being mutated. It never checks that the `sha`/commit being updated actually belongs to the repository whose signature was verified. `drop_unhandled_event` and the `ExplicitParameters` schema (`sha`, `state`, `context`, etc.) only validate payload shape, not ownership. There is no `require_permission!`/`User#authorized?` check on webhook ingestion at all (by design, webhooks aren't user-authenticated) — the missing control is specifically the per-repository scoping that every sibling handler performs via `Handler#stacks` and that `StatusHandler` alone omits.

### Impact Explanation
An attacker who can trigger a genuinely-signed `status` webhook for *some* repository under the same signing scope (e.g., a repository they own that shares the same GitHub organization/webhook secret configuration as the victim, or any org for which no `webhook_secret` is configured, in which case `GitHubApp#verify_webhook_signature` returns `true` unconditionally — lib/shipit/github_app.rb:76-77) can forge `context`/`state` combinations that get attached to a victim commit whose SHA they've reproduced. This can:
- Flip `MergeRequest#all_status_checks_passed?` to `true` for the victim's PR, satisfying `reject_unless_mergeable!`'s CI gate and enabling an **unauthorized merge** the attacker doesn't otherwise have permission to trigger.
- Flip `Stack#branch_status`/`Commit#deployable?` to green, enabling **continuous delivery/deploy** of a commit that never actually passed the victim's real CI.

This is a cross-tenant/cross-repository record-mutation vulnerability: a payload for one (attacker) repository mutates state (`Status` rows) attributed to another (victim) stack/commit, matching the "Critical" impact category (unauthorized merge / unauthorized deploy via forged CI status not sourced from the victim's authenticated GitHub relationship).

### Likelihood Explanation
Preconditions: attacker needs (a) a validly-signed `status` webhook path into Shipit (own repo under a covered/no-secret org, or an org with `webhook_secret` unset), and (b) a commit SHA collision with the victim commit, which is trivially achievable because Git SHA-1s are deterministic over commit content — the attacker can copy the victim's public commit (same tree, parents, author/committer identities and timestamps, message) into their own repository to get an identical SHA. The victim's required-status context names are directly readable from their public `shipit.yml` (`ci.require`, `merge.require`, etc., parsed by `DeploySpec#required_statuses`/`merge_request_required_statuses`, app/models/shipit/deploy_spec.rb:194-217). This is a purely code-level flaw (missing repository scoping in `StatusHandler`) reachable with only a `POST /webhooks` request whose signature they can legitimately produce for their own repo/org — no Shipit session, API token, or GitHub App key needed.

### Recommendation
Scope `StatusHandler#process` to the reporting repository exactly like every other handler, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
using `Handler#stacks` (repository-scoped via `repository_name`) instead of an unscoped `Commit.where(sha:)`.

### Proof of Concept
```ruby
# test/models/webhooks/handlers/status_handler_test.rb (conceptual)
test "status webhook must not attach to a same-sha commit belonging to a different repository/stack" do
  victim_stack = shipit_stacks(:shipit) # repository e.g. "shopify/shipit-engine"
  attacker_stack = shipit_stacks(:cyclimse) # different repository, e.g. "attacker/evil-repo"

  colliding_sha = 'a' * 40
  victim_commit = victim_stack.commits.create!(sha: colliding_sha, message: 'x')
  attacker_commit = attacker_stack.commits.create!(sha: colliding_sha, message: 'x')

  victim_stack.update!(cached_deploy_spec: DeploySpec.new('ci' => { 'require' => ['ci/test'] }))

  payload = {
    'sha' => colliding_sha,
    'state' => 'success',
    'context' => 'ci/test',
    'repository' => { 'full_name' => attacker_stack.repository.full_name,
                       'owner' => { 'login' => attacker_stack.repository.owner } }
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  # Binding under test: victim_commit.statuses must be empty because the webhook
  # was signed/scoped for attacker_stack's repository, not victim_stack's.
  assert_equal 0, victim_commit.reload.statuses.count
  refute victim_commit.status.success?
end
```
With the current implementation (`Commit.where(sha: params.sha)`), this test fails: `victim_commit.statuses.count` becomes `1` and `victim_commit.status.success?` becomes `true`, demonstrating that a webhook scoped to `attacker_stack`'s repository forges a passing required status on `victim_stack`'s commit purely via SHA collision. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/models/shipit/commit.rb (L366-386)
```ruby
    def add_status
      already_deployed = deployed?

      previous_status = status
      yield
      reload # to get the statuses into the right order (since sorted :desc)
      new_status = status

      unless already_deployed
        payload = { commit: self, stack:, status: new_status.state }
        Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status)) if previous_status != new_status
      end

      if previous_status.simple_state != new_status.simple_state
        if !already_deployed && (!new_status.pending? || previous_status.unknown?)
          Hook.emit(:deployable_status, stack, payload.merge(deployable_status: new_status))
        end
        stack.schedule_merges if new_status.pending? || new_status.success?
      end
      new_status
    end
```

**File:** app/models/shipit/merge_request.rb (L193-206)
```ruby
    def all_status_checks_passed?
      return false unless head

      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).success?
    end

    def any_status_checks_failed?
      status = StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec)
      status.failure? || status.error?
    end

    def any_status_checks_missing?
      StatusChecker.new(head, head.statuses_and_check_runs, stack.cached_deploy_spec).missing?
    end
```

**File:** app/models/shipit/deploy_spec.rb (L194-217)
```ruby
    def required_statuses
      (Array.wrap(config('ci', 'require')) + blocking_statuses).uniq
    end

    def soft_failing_statuses
      Array.wrap(config('ci', 'allow_failures'))
    end

    def blocking_statuses
      Array.wrap(config('ci', 'blocking'))
    end

    def merge_request_merge_method
      method = config('merge', 'method')
      method if %w[merge rebase squash].include?(method)
    end

    def merge_request_required_statuses
      if config('merge', 'require') || config('merge', 'ignore')
        Array.wrap(config('merge', 'require'))
      else
        required_statuses
      end
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
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
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
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
