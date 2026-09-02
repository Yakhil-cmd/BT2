### Title
Cross-repository status webhook mutates commits/blocking status of unrelated stacks - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` looks up commits by SHA alone across the entire `commits` table, ignoring the repository that authenticated the webhook, while `Commit#blocked?` in `app/models/shipit/commit.rb` trusts whatever status rows exist on a stack's commits. An attacker who owns `attacker/repoA` can send a valid, correctly-signed `status` webhook for a commit SHA that happens to also exist in `victim/repoB` (e.g. a shared base commit, cherry-pick, or common ancestor), and that status is written onto **every** commit row sharing that SHA, including `victim/repoB`'s, which can flip `blocked?` to `true` for the victim's stack.

### Finding Description
Binding claimed to hold: `stack_that_authenticated_webhook (attacker/repoA, verified via repository_owner in webhooks_controller.rb) == stack_whose_blocking_statuses/commit_state_is_mutated`. Tracing the code shows this binding is broken specifically in `StatusHandler`.

- `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) only validates that the payload's signature matches the GitHub organization owning `repository_owner` (`params.dig('repository','owner','login')`). This proves the request came from GitHub for *that* organization/repo — it says nothing about which `Stack`/`Commit` rows may be touched.
- The generic `Handler` base class exposes a `stacks` helper (`app/models/shipit/webhooks/handlers/handler.rb:32-38`) that correctly scopes lookups via `Repository.from_github_repo_name(repository_name)&.stacks`, and most handlers (`pull_request/*`, `push_handler.rb`, etc.) use this scoping.
- `StatusHandler#process` does **not** use this scoping. It does:
```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
``` [1](#0-0) 
This queries the global `commits` table by `sha` only. Since `commits` has a unique index on `(sha, stack_id)` rather than a global unique index on `sha`, the same SHA can legitimately exist as distinct rows for multiple stacks/repositories (shared history, forks, cherry-picks, or a base commit both `repoA` and `repoB` happened to include). [2](#0-1) 
- `create_status_from_github!` unconditionally writes a `Status` row scoped to that commit's own `stack_id` (`app/models/shipit/commit.rb:165-169`), so a single attacker-controlled webhook fans out a `failure` status write to every stack sharing the SHA — including `victim/repoB`, which never authenticated this request.
- `Commit#blocked?` then reads `stack.commits.reachable...any?(&:blocking?)` (`app/models/shipit/commit.rb:231-237`) — if `victim/repoB`'s `blocking_statuses` config matches the attacker's `context` string, the injected failing status makes `blocking?` true for the victim's commit, flipping `blocked?` to true and blocking the victim's otherwise-healthy deploy pipeline.

Existing guards do not catch this: `verify_signature` validates only the attacker's own org's signature; `ExplicitParameters` schema in `StatusHandler` only validates types, not repository scope; there is no `stacks`/repository filter applied before the `Commit.where(sha:)` lookup.

### Impact Explanation
A single crafted, correctly-signed `status` webhook from a repository the attacker owns can write `Status` rows onto commit records belonging to unrelated stacks/repositories, provided a SHA collision (shared commit) exists between the two. If the victim stack's `blocking_statuses` deploy-spec config matches the attacker-chosen `context`, this directly blocks the victim's legitimate deploys — a cross-tenant stack mutation caused by a payload that never authenticated against the victim's repository. This matches the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any pair of stacks that happen to share a commit SHA (common in monorepo forks, shared upstream branches, or vendored histories).

### Likelihood Explanation
Preconditions: the victim stack's `blocking_statuses` deploy spec must include a context string the attacker can produce (attacker fully controls `context` in their own status webhook), and a commit SHA must be shared between attacker's and victim's commit tables (realistic for forks/common ancestors/cherry-picked commits, or simply any commit sha the attacker can get into their own repo's history that is also present in the victim's tracked branch, e.g., a widely known/public base commit). Attacker cost is a single unauthenticated-by-Shipit HTTP webhook delivery from their own GitHub repo (which they legitimately control), requiring no Shipit credentials. This is fully repeatable and requires no timing race.

### Recommendation
Scope `StatusHandler#process` by the repository that emitted the webhook, mirroring the pattern used by other handlers via the `stacks` helper, e.g.:
```ruby
def process
  stacks.each do |stack|
    stack.commits.where(sha: params.sha).each do |commit|
      commit.create_status_from_github!(params)
    end
  end
end
```
This ensures only commits belonging to stacks whose repository matches `payload['repository']['full_name']` can be mutated by the webhook.

### Proof of Concept
Minitest plan (under `test/models/shipit/webhooks/handlers/status_handler_test.rb`, no live GitHub calls):
1. Create two stacks backed by two different `Repository` records, `attacker/repoA` and `victim/repoB`, each with `blocking_statuses` deploy spec configured to match context `"ci/build"` (stub `cached_deploy_spec`/`blocking_statuses` as done in existing `deploy_spec_test.rb`/`commits_test.rb`).
2. Create a `Commit` with the same `sha` (e.g. `"deadbeef"`) under both stacks (`stack_a.commits.create!(sha: "deadbeef", ...)` and `stack_b.commits.create!(sha: "deadbeef", ...)`), and mark `stack_b`'s commit as `success` beforehand so `blocked?` is initially `false`.
3. Build the webhook payload as if from `attacker/repoA`: `{"repository" => {"full_name" => "attacker/repoA"}, "sha" => "deadbeef", "state" => "failure", "context" => "ci/build"}`.
4. Assert binding before: `assert_equal false, stack_b_commit.blocked?`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert binding after (bug reproduced): `assert stack_b_commit.reload.blocking?` and `assert stack_b_commit.blocked?` even though the webhook's `repository.full_name` was `attacker/repoA`, not `victim/repoB` — i.e., the equality `stack_that_authenticated_webhook == stack_whose_state_mutated` is broken.
7. After applying the recommended fix (scoping via `stacks`), re-run and assert `stack_b_commit.reload.blocked?` remains `false`. [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-28)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
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

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
    end
  end
end
```

**File:** db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb (L1-5)
```ruby
class IndexCommitsOnStackIdAndSha < ActiveRecord::Migration[5.1]
  def change
    add_index :commits, %i(sha stack_id), unique: true
  end
end
```

**File:** app/models/shipit/commit.rb (L231-237)
```ruby
    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
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
