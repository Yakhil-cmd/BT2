### Title
Cross-repository CI status forgery via unscoped SHA lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the commit(s) to update purely by `Commit.where(sha: params.sha)`, with no scoping to the repository/stack that authenticated the incoming webhook. Any GitHub `status` webhook that passes `verify_signature` for *some* trusted organization can therefore mutate the CI status of, and fire `Hook.emit(:commit_status, ...)` for, a commit belonging to an entirely different stack, as long as that commit's SHA also exists in the database (which is routine for shared git history between a fork and its upstream, or between repos in the same org).

### Finding Description
The broken binding, stated as an equality that should hold but does not:
`webhook_authenticated_repository(params.dig('repository','full_name'))` == `commit.stack.repository` for every `commit` mutated by `StatusHandler#process`.

Code path:
1. `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) validates the HMAC signature against `Shipit.github(organization: repository_owner)`, where `repository_owner` is read straight from the JSON payload (`params.dig('repository','owner','login')`). This only proves the request was signed with the webhook secret configured for *that organization* — it says nothing about which specific repository/stack should receive the event.
2. `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`):
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
This query has **no repository/stack filter** — it matches every `Commit` row in the entire database with that SHA, across every stack tracked by the Shipit instance.
3. `Commit#create_status_from_github!` → `Commit#add_status` (`app/models/shipit/commit.rb`) builds `payload = { commit: self, stack:, status: new_status.state }` using `stack` = `commit.stack` (the real owning/victim stack) and calls `Hook.emit(:commit_status, stack, payload.merge(commit_status: new_status))`, confirmed by the existing test helper `expect_hook_emit(commit, :commit_status, expected_status_attributes)` in `test/models/commits_test.rb:703`.

Exploit flow: an attacker who owns/forks a repository sharing commit history with a victim's tracked repository (a routine situation for any fork, or for sibling repos in the same GitHub org, both of which are within the "own a repo, push to a fork" attacker capability) can configure or trigger a `status` webhook on their own repository with an arbitrary `state`/`description`/`context` for a SHA that is also present in the victim's stack's commit history. `verify_signature` only checks that the payload's signature matches the webhook secret for the organization named in the payload — it never confirms that this organization is authorized for the specific commit/stack being mutated. `StatusHandler#process` then looks up that SHA globally and invokes `Hook.emit` on the victim stack with attacker-authored status fields, reaching the victim's configured `internal_hook_receivers`/external hooks (Slack, paging, auto-rollback automation, etc.).

None of the existing guards prevent this: `verify_signature` authenticates an organization, not a repository-to-stack binding; `ExplicitParameters` in `StatusHandler.params` only validates the shape of `sha`/`state`/etc., not their origin repository; there is no `stack_id`/`repository` filter anywhere in `Commit.where(sha: params.sha)`.

### Impact Explanation
This is a payload for one (attacker-controlled) repository mutating another (victim) repository's stack/commit/hook state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attacker can inject fabricated CI signal (`state`, `description`, `target_url`, `context`) into a victim's commit record and trigger `Hook.emit(:commit_status, victim_stack, ...)`, causing any downstream automation configured by the victim (Slack notifications, paging, or host-application `Hook` receivers implementing auto-rollback/auto-notify logic) to run based on entirely attacker-authored content. This is repeatable against any commit SHA shared between an attacker-controlled repo and a victim's tracked repo, and is not limited to a single stack — any stack whose commit history overlaps with a repository the attacker can push a signed webhook from is affected.

### Likelihood Explanation
Preconditions: (1) the victim stack has configured `Hook`s/`internal_hook_receivers` for `commit_status`/`deploy_status` (stated as a given precondition), and (2) there exists a commit SHA shared between the attacker's own repository and the victim's tracked repository — trivially true for forks (all commits prior to divergence) and common in monorepo/org-wide setups. The attacker only needs the ability to push/trigger a webhook from a repository whose owning organization is already trusted by Shipit (i.e., a `Shipit.github(organization:)` config exists) — no access to the victim's specific repository, stack, or secrets is required. This is a low-cost, fully repeatable attack (one crafted status event per target SHA).

### Recommendation
Scope the commit lookup in `StatusHandler#process` to the repository that authenticated the webhook, not merely by SHA. E.g., resolve the commit only within stacks whose `repository` matches `params.dig('repository', 'full_name')` (or an equivalent repository identifier carried in the webhook payload), so `Commit.where(sha: params.sha, stack: Stack.where(repository: incoming_repository))` (or filtering by `commit.stack.repository == incoming_repository` before calling `create_status_from_github!`). Reject/ignore matches for stacks belonging to a different repository.

### Proof of Concept
Minitest plan (`test/models/webhooks/handlers/status_handler_test.rb` conceptually):
```ruby
test "status event authenticated for repo A must not update or emit hooks for a commit belonging to repo B's stack" do
  victim_stack = shipit_stacks(:shipit) # repository = "shopify/shipit-engine"
  attacker_repo_full_name = "attacker/unrelated-fork"

  shared_sha = shipit_commits(:cyclimse_first).sha
  victim_commit = Commit.find_by(sha: shared_sha, stack: victim_stack)

  # Binding under test: authenticated_repository == commit.stack.repository
  assert_not_equal attacker_repo_full_name, victim_stack.repository

  params = ExplicitParameters described from
    { sha: shared_sha, state: 'success', description: 'forged', context: 'ci/attacker' }

  Hook.expects(:emit).with(:commit_status, victim_stack, has_entries(commit: victim_commit)).never
  # or, to demonstrate the vulnerability exists today:
  Hook.expects(:emit).with(:commit_status, victim_stack, has_entries(commit: victim_commit)).once

  Shipit::Webhooks::Handlers::StatusHandler.new(params).process
end
```
The test would assert that `Hook.emit` fires with `victim_stack` even though nothing in the request establishes that the caller is authorized for `victim_stack`'s repository — demonstrating the broken binding. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** app/models/shipit/commit.rb (L165-169)
```ruby
    def create_status_from_github!(github_status)
      add_status do
        statuses.replicate_from_github!(stack_id, github_status)
      end
    end
```

**File:** test/models/commits_test.rb (L683-710)
```ruby
        test "#add_status #{action} for status from #{initial_state} to #{new_state}" do
          commit = shipit_commits(:cyclimse_first)
          assert commit.stack.hooks.where(events: ['deploy_status']).size >= 1
          refute commit.stack.ignore_ci
          commit.statuses.destroy_all
          commit.reload
          unless initial_state == 'unknown'
            attrs = initial_status_attributes.merge(
              stack_id: commit.stack_id,
              created_at: 10.days.ago.to_formatted_s(:db)
            )
            commit.statuses.create!(attrs)
          end
          assert_equal initial_state, commit.state

          expected_status_attributes = { state: new_state, description: initial_state, context: 'ci/travis' }
          add_status = lambda do
            attrs = expected_status_attributes.merge(created_at: 1.day.ago.to_formatted_s(:db))
            commit.create_status_from_github!(OpenStruct.new(attrs))
          end
          expect_hook_emit(commit, :commit_status, expected_status_attributes) do
            if should_fire
              expect_hook_emit(commit, :deployable_status, expected_status_attributes, &add_status)
            else
              expect_no_hook(:deployable_status, &add_status)
            end
          end
        end
```
