### Title
`StatusHandler` updates commit statuses for any repository sharing a SHA, ignoring the webhook's `repository` field entirely - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves target commits with a global, unscoped `Commit.where(sha: params.sha)` query instead of scoping the lookup to the repository that emitted the webhook, unlike every `PullRequest::*Handler` and the base `Handler#stacks` helper. Because `StatusHandler.param_parser` never requires or validates `repository.full_name`, an authenticated status webhook from repository A silently mutates commit status/state for any other stack in the Shipit instance whose commits happen to share the same SHA (a common occurrence for forks/mirrors of the same repository history).

### Finding Description
The intended binding is: `payload.dig('repository','full_name') == Handler#repository_name`, and the commits touched by a handler should be constrained to `stacks` derived from that name, exactly as `Handler#stacks` does at [1](#0-0) . `StatusHandler`'s param schema only requires `:sha` and `:state` [2](#0-1) , and `process` never consults `repository_name` or `stacks`, instead running `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` [3](#0-2) . `Commit` has no uniqueness constraint on `sha` alone (only `sha` is looked up, not `stack_id`), so this query returns every commit row across every stack in the database whose SHA matches, regardless of which repository the webhook actually originated from.

`WebhooksController#verify_signature` only uses `repository.owner.login` to pick the GitHub App/secret used for HMAC verification [4](#0-3)  and then discards it; the value is never checked against the commit(s) actually mutated. So even a fully legitimate, correctly-signed `status` webhook — sent by any account with push/webhook-triggering access to any repository whose git history is shared with a target repository (a fork, a mirror, a repo imported/rebased from the same upstream) — will cause `create_status_from_github!` to run against every stack's commit sharing that SHA, not just the sender's own repository's stack.

This directly matches the described critical class of bug: "a payload for one repository mutating another's stack, commit ... status" — because commit-status mutation feeds `Commit#add_status`, which can flip `blocked?`/`deployable?` state and trigger `stack.schedule_merges`, `ContinuousDeliveryJob`, and `Hook.emit(:deployable_status, ...)`, i.e. it can influence deploy/merge automation for a stack the attacker's webhook was never authorized against [5](#0-4) .

Existing guards do not catch this: `verify_signature` authenticates the sender's organization/repo, not the scope of records touched; `ExplicitParameters` only validates the declared schema (which omits `repository`); and `Handler#stacks`/`repository_name` — the mechanism that would enforce scoping — is defined on the base class but simply never called by `StatusHandler`.

### Impact Explanation
A webhook legitimately signed for repository A can alter commit status/state (`Commit#create_status_from_github!` → `Status` records, `deployable?`, `blocked?`) for any other stack B whose commits happen to share a SHA with repository A's commits (forks, imported mirrors, shared monorepo history). This can unblock or block deploys, and trigger `stack.schedule_merges` / `ContinuousDeliveryJob` for stack B, which the sender was never authorized to affect — a cross-tenant stack mutation, matching the Critical "payload for one repository mutating another's stack/commit" category.

### Likelihood Explanation
Requires only: (1) the attacker/sender's own repository already has a webhook wired to this Shipit instance with a valid signature (any repository the attacker owns or can push to that is onboarded to Shipit or shares an org-level webhook secret), and (2) SHA collision across repositories, which is routine for forks/mirrors/rebased history rather than needing a hash collision attack. No special privilege in `Shipit.github_teams`, no maintainer role on the target stack, and no secrets are needed beyond what is already required to trigger any webhook at all.

### Recommendation
Add `requires :repository do; requires :full_name, String; end` to `StatusHandler.param_parser` and scope the lookup through `stacks`/`repository_name`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring how `PullRequest::*Handler` classes enforce `repository.full_name`.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/status_handler_test.rb
test "StatusHandler mutates commits in unrelated stacks sharing a sha" do
  stack_a = shipit_stacks(:shipit)
  stack_b = create_stack! # different repository
  shared_sha = 'a' * 40

  commit_a = stack_a.commits.create!(sha: shared_sha, message: 'x')
  commit_b = stack_b.commits.create!(sha: shared_sha, message: 'x')

  payload = {
    'sha' => shared_sha,
    'state' => 'success',
    'repository' => { 'full_name' => stack_a.github_repo_name } # only A's repo claimed
  }

  Shipit::Webhooks::Handlers::StatusHandler.call(payload)

  assert commit_b.reload.statuses.exists?(state: 'success'), 
    "commit belonging to unrelated stack_b was mutated by a webhook scoped to stack_a"
end
```
This demonstrates that `StatusHandler` lacks a `repository.full_name == Handler#repository_name` equality check before mutating `Commit` records, confirmed by `Commit.where(sha: params.sha)` at [3](#0-2)  versus the scoped `stacks` helper at [1](#0-0) .

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-18)
```ruby
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
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
