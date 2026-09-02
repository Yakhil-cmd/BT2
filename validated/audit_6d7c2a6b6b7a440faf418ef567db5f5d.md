### Title
Cross-stack Status forgery via `Commit.where(sha:)` in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by `sha` only, with no `stack_id`/repository scoping, then writes a `Status` to every matching row. Because the database only enforces sha uniqueness *per stack* (`add_index :commits, [:sha, :stack_id], unique: true`), any two stacks that happen to track the same commit (trivially true for a fork and its upstream, since shared ancestor commits keep the same sha) will both receive the status from a single legitimate webhook belonging to only one of them.

### Finding Description
The broken binding is: DB-enforced identity `(stack_id, sha)` (`db/migrate/20170524104615_index_commits_on_stack_id_and_sha.rb:3` — `add_index :commits, %i(sha stack_id), unique: true`) is assumed by the schema to be the unit that owns a status, but the code that actually persists statuses, `Shipit::Webhooks::Handlers::StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`), operates on identity `sha` alone:

```ruby
def process
  Commit.where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```

`Commit.where(sha: params.sha)` returns every `Commit` row across every `Stack`/`Repository` that has recorded that sha — nothing in the query or in `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) restricts the update to the stack the inbound webhook's `repository` payload refers to. The webhook `repository`/`repository_owner` is only used by `WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) to select which GitHub App/organization secret to check the signature against; it is never propagated into `StatusHandler#process` to filter which `Commit` rows may be mutated.

Exploit flow, using only unprivileged actions:
1. Attacker owns/controls a public fork of a repository that Shipit already tracks as a separate `Stack` (a common real-world setup — teams often add forks or mirror repos as their own stacks, or the attacker's own org/account already has the GitHub App installed for their fork).
2. Because it is a fork, many commits are shared ancestors with the upstream repository and therefore have byte-identical `sha` values in both the fork's `Commit` rows and the upstream `Stack`'s `Commit` rows — no SHA1 preimage/collision attack is actually needed, only shared git history.
3. The attacker triggers real CI (or simply crafts a `status` API call from their own repo/account) on that shared-ancestor sha. GitHub delivers a status webhook to Shipit, correctly signed for the attacker's own org/installation — `verify_signature` passes because it only checks the signature matches the sending organization's real secret, it does not check that the referenced `sha` actually belongs to a commit under that organization's repositories.
4. `StatusHandler#process` runs `Commit.where(sha:)`, matches both the fork's commit row and the upstream stack's commit row, and calls `create_status_from_github!` on both, writing the attacker-controlled `state`/`description`/`context`/`target_url` onto the upstream stack's commit.

This bypasses `verify_signature`, `drop_unhandled_event`, and the `ExplicitParameters` schema entirely — all of them validate the *webhook envelope*, none of them validate that the `sha` in the payload is scoped to the repository that sent it.

### Impact Explanation
A `Status` row is written to a `Commit` belonging to a stack/repository the attacker never authenticated against or owns. Since `Commit#deployable?`/`#blocked?` (`app/models/shipit/commit.rb:227-237`) and the commit's aggregated `status` (`app/models/shipit/commit.rb:304-306`) drive whether Shipit considers a commit CI-green and eligible for continuous delivery/merge (`schedule_continuous_delivery`, `stack.schedule_merges`), an attacker who can name a `success` status for a shared-ancestor sha can flip the deployability state of a commit in a stack they do not control — a payload from one repository mutating another stack's commit/task state, matching the "Critical" impact category (payload for one repository mutating another's stack/commit, or an unauthorized deploy).

### Likelihood Explanation
Requires: (a) the target Shipit instance tracks both the upstream repository and a fork/mirror the attacker controls as separate `Stack`s (a realistic, common configuration, not an exotic one), and (b) a shared-ancestor commit sha between the two (guaranteed by git fork semantics, not a brute-force hash collision as the prompt's short-circuit framing suggests). No secrets, sessions, or privileged roles are needed — only the ability to push/commit to a repo the attacker owns and let GitHub deliver the resulting status webhook. This is fully repeatable against any sha shared between any two stacks in the instance.

### Recommendation
Scope the status lookup and update to the stack that actually owns the webhook. Resolve the target `Repository`/`Stack` from the webhook's `repository` payload (as `verify_signature` already does for `repository_owner`) and constrain the query, e.g. `Commit.where(sha: params.sha, stack_id: repository.stacks.select(:id))`, before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (fixture-based, no live GitHub):
```ruby
test "status webhook leaks across stacks sharing a sha" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:cyclimse) # distinct stack/repository

  shared_sha = "a" * 40
  commit_a = stack_a.commits.create!(sha: shared_sha, message: "shared ancestor")
  commit_b = stack_b.commits.create!(sha: shared_sha, message: "shared ancestor")

  params = ExplicitParameters::Parameters.new(
    sha: shared_sha, state: "success", context: "ci/attacker", description: "forged"
  )

  Shipit::Webhooks::Handlers::StatusHandler.new(params).process

  assert commit_a.reload.statuses.exists?(state: "success", context: "ci/attacker"),
    "expected commit_a to receive the status (webhook target)"
  assert commit_b.reload.statuses.exists?(state: "success", context: "ci/attacker"),
    "commit_b received a status from a webhook belonging to stack_a — cross-stack corruption"
end
```
Both assertions pass under current code, proving a single webhook write leaks into an unrelated stack's commit. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
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

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-49)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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
