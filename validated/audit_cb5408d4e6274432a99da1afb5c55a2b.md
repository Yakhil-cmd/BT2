### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` — ([File: app/models/shipit/webhooks/handlers/status_handler.rb])

### Summary
`StatusHandler#process` looks up commits purely by bare SHA across the entire `commits` table and writes a GitHub status onto every matching record, without checking that the SHA belongs to the repository that authenticated the webhook. Since `Commit#blocked?`/`#deployable?` derive from `Status::Group` over `commit.statuses`, and stacks configure `blocking_statuses`/`required_statuses`, a legitimately-signed status webhook from one repository can flip the block/deploy state of a commit belonging to a completely different stack/repository if the SHA is shared (e.g., forked history, cherry-picks, or coincidental identical commits).

### Finding Description
The broken binding: the code assumes `commit.stack.github_repo_name == payload['repository']['full_name']` for every `Commit` matched by SHA, but this is never checked.

- `Shipit::WebhooksController#create` (`app/controllers/shipit/webhooks_controller.rb:10-15`) dispatches the parsed JSON payload to `Shipit::Webhooks.for_event(event)` handlers after `verify_signature`, which validates the HMAC using `Shipit.github(organization: repository_owner)` — i.e., it proves the payload was signed by *some* org's GitHub App/webhook secret for the repository named in the payload, not that the SHA "belongs" to that repository.
- `Handler` (`app/models/shipit/webhooks/handlers/handler.rb`) provides a `stacks` helper that scopes lookups via `Repository.from_github_repo_name(repository_name)` — the mechanism intended to enforce repo scoping.
- `StatusHandler#process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) does **not** use `stacks`/`repository_name` at all; it runs `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`, matching every commit row in the database with that SHA, across every stack/repository.
- `Commit#create_status_from_github!` (`app/models/shipit/commit.rb:165-169`) calls `add_status`, which recomputes `status` (`Status::Group.compact`), fires `Hook.emit(:commit_status/:deployable_status, ...)`, and calls `stack.schedule_merges` if the new status is `pending?`/`success?`.
- `Commit#blocked?` (`app/models/shipit/commit.rb:231-237`) and `#deployable?` (`:227-229`) depend on `stack.blocking_statuses`/`status.blocking?`, which are driven by the `statuses` records just mutated.

Exploit flow: An attacker who controls their own GitHub repository (own org/installation, hence a validly-signed webhook) pushes a commit that shares a SHA with a victim's tracked repository (achievable via a fork sharing history with an upstream commit, or otherwise arranging a shared SHA). The attacker then creates a GitHub Status on that SHA in their own repo with `context: ci/circleci`, `state: success` (or `failure`/`error`). GitHub sends a `status` webhook, correctly signed for the attacker's own org, to `POST /webhooks`. `verify_signature` passes because it only validates that the payload matches the signing org's secret, not that the referenced SHA is confined to that org's stacks. `StatusHandler#process` then matches the victim's `Commit` row with the same `sha` (in a completely unrelated stack) and applies the attacker's status to it, flipping `blocked?`/`deployable?` for the victim stack and potentially triggering `stack.schedule_merges`/continuous deployment.

Existing guards do not prevent this: `verify_signature` scopes by *signing organization*, not by the SHA/commit ownership; `drop_unhandled_event` and `ExplicitParameters` only validate presence/shape of expected params (`sha`, `state`, `context`, etc.), not repository ownership; there is no `Repository`/`Stack` scoping performed anywhere in `StatusHandler`.

### Impact Explanation
A payload legitimately signed for repository A can write status records (and, transitively, flip `blocked?`/`deployable?`/trigger merges or continuous deployment) for a `Commit` belonging to repository B's stack, whenever the two repositories share a commit SHA. This is a cross-tenant/cross-repository state manipulation matching the "Critical" category: "a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy, rollback or merge." It is repeatable against any stack whose commit SHAs happen to coincide with SHAs the attacker can produce/control (most realistically via forks sharing history with the same shared commits present across multiple Shipit-tracked stacks, e.g. a monorepo mirrored under two names, or shared library repos tracked twice).

### Likelihood Explanation
Preconditions: the attacker needs (a) a repository whose webhooks are validly signed for some org configured in Shipit (i.e., their own onboarded/forked repository), and (b) a commit SHA that also exists as a `Commit` row in a victim stack. SHA collision is not automatically achievable for arbitrary victims — it requires either a shared ancestor commit (fork scenario) or the victim independently tracking the same commit under a second `Stack`/`Repository` record (which occurs, e.g., for repos mirrored/tracked with multiple Shipit stack configs, or the same GitHub repo tracked with multiple environments/stacks — quite common in Shipit's model, since one `Repository` maps to many `Stack`s and `Commit`s are per-stack but sha values are duplicated across all stacks for the same repository/branch). Given Shipit's data model (`Stack belongs_to :repository`, multiple stacks per repository, `Commit belongs_to :stack`), the same underlying commit SHA will typically exist as separate `Commit` rows in *every* stack tracking that repository (e.g., staging/production stacks) — this is the most trivial and highly likely trigger, requiring no forking at all: the attacker only needs write/CI access to one repo tracked by multiple Shipit stacks, or a forked repo with shared history against any second Shipit-tracked repo. Attacker cost is low (send one CI status), and the action is fully repeatable/scriptable against any observed shared SHA.

### Recommendation
Scope `StatusHandler#process` to only the commits belonging to the repository that authenticated the webhook, mirroring the `stacks` helper already defined in `Handler`:
```ruby
def process
  stacks.flat_map(&:commits).where(sha: params.sha).each do |commit|
    commit.create_status_from_github!(params)
  end
end
```
or equivalently join through `Stack`/`Repository` using `payload.dig('repository', 'full_name')` so that only commits under stacks whose repository matches the authenticated payload's repository are updated.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb`):
1. Create `repository_a` and `repository_b` (or two `Stack`s under the same `Repository`), each with its own `Stack` (`stack_a`, `stack_b`), where `stack_b` has `blocking_statuses` configured requiring `ci/circleci` (via `DeploySpec`/`.shipit.yml` stub as used elsewhere in `deploy_spec_test.rb`).
2. Create `commit_a` under `stack_a` and `commit_b` under `stack_b` with the **same** `sha` value (`"deadbeef" * 5`).
3. Assert the binding before: `commit_b.blocked?` reflects no status yet (e.g., `assert_not commit_b.deployable?` if no success status recorded, per its normal state), and `commit_b.stack_id != commit_a.stack_id`.
4. Build a `status` webhook payload with `repository: { full_name: repository_a.full_name (or an attacker-controlled/unrelated repo) }`, `sha: commit_a.sha`, `context: 'ci/circleci'`, `state: 'success'`.
5. Call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
6. Assert `commit_b.reload.statuses.exists?(context: 'ci/circleci', state: 'success')` is `true` even though the payload's `repository` never named `stack_b`'s repository — proving the write crossed repository boundaries.
7. Assert `commit_b.blocked?`/`commit_b.deployable?` changed as a result (e.g., toggled from blocked to unblocked, or vice versa), demonstrating the ship/block gate was manipulated by a payload that did not authenticate for that repository. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
