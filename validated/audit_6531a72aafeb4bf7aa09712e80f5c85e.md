### Title
`ci/circleci` status webhook is applied to every `Commit` sharing a SHA across all repositories, not scoped to the authenticated repository - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves target commits with a bare, global `Commit.where(sha: params.sha)`, unlike the base `Handler` class's `stacks` helper that scopes lookups to the repository that authenticated the webhook. This lets an attacker who controls any repository with a valid Shipit webhook (their own repo/org) push a `status` event whose SHA is shared with an unrelated victim stack (e.g. via a fork sharing commit history), and have that status recorded against the victim's commit.

### Finding Description
The broken binding: the invariant `status.repository == commit.stack.repository` (a `ci/circleci` status should only ever affect the repository that authenticated the webhook) does **not hold** in this code path.

- `WebhooksController#verify_signature` only checks that the webhook signature is valid for `repository_owner`/`organization.login` taken from the **payload**, i.e. it authenticates "this request really came from GitHub for org X's app config," not "the SHA in this payload belongs to org X's repository." [1](#0-0) 
- The base `Handler` class provides a `stacks` helper explicitly meant to scope lookups to `Repository.from_github_repo_name(repository_name)`, derived from `payload.dig('repository', 'full_name')`. [2](#0-1) 
- `StatusHandler#process`, however, ignores this scoping entirely and does a bare, cross-tenant lookup: `Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }`. [3](#0-2) 
- `create_status_from_github!` then writes a new `Status` row and recomputes `status`/`deployable?`/`blocked?` for that commit's stack via `add_status`, which can emit `deployable_status` hooks and call `stack.schedule_merges`. [4](#0-3) [5](#0-4) [6](#0-5) 

Exploit flow: an attacker who owns any GitHub repository wired to the same Shipit instance (or any org whose webhook secret they can satisfy) sends `POST /webhooks` with `X-Github-Event: status`, payload `{"sha": "<victim_sha>", "context": "ci/circleci", "state": "failure", "repository": {"full_name": "attacker/repo", "owner": {"login": "attacker-org"}}}`. `verify_signature` succeeds because the signature is valid for the attacker's own org/app config. `StatusHandler` then matches `Commit.where(sha: victim_sha)` across **all** stacks in the database — including the victim's — and writes the `failure` status onto the victim's commit row, independent of which repository the request claims to be from.

For this to hit a specific victim commit, the SHA must exist in the victim's `commits` table. Git SHAs are content-addressed; the most realistic way an attacker obtains a shared SHA is if the attacker's own repository is a fork of (or shares history with) the victim's repository — a routine, unprivileged action any GitHub user can perform. Existing guards do not close this gap: `verify_signature` validates the sender's identity/secret, not the SHA-to-repository binding; `drop_unhandled_event` only filters unknown event types; the `ExplicitParameters` schema in `StatusHandler.params` validates types, not repository ownership; and `Commit#stack`/`Repository` model validations do not constrain cross-stack SHA collisions.

### Impact Explanation
A payload authenticated for repository A can flip the CI status (`ci/circleci`, `failure`) of a commit belonging to stack/repository B, changing `Commit#deployable?`/`#blocked?` for B's production environment stack without B's repository ever emitting that webhook. This is a "payload for one repository mutating another's stack/commit," directly forcing a production stack toward blocking (denying legitimate deploys) or, depending on `required_statuses`/`blocking_statuses` configuration, altering merge/deploy eligibility computed from status state. The blast radius is any Shipit instance hosting multiple repositories/orgs and any commit SHA an attacker can arrange to share with a victim stack (trivially achievable via forking). This matches the Critical category: "a payload for one repository mutating another's stack, commit, task or team."

### Likelihood Explanation
Preconditions: the attacker needs a repository/org with a valid webhook configuration pointed at the shared Shipit instance (achievable by any GitHub user who can add a webhook to their own repo/fork, or any org onboarded to the same Shipit deployment), and a SHA that is present in both their own commit history and the victim's `commits` table — trivially satisfied by forking the victim repository, since shared ancestor commits retain identical SHAs. No Shipit session, API token, or GitHub secret belonging to the victim is required. The attack is fully repeatable and requires only one crafted HTTP POST per target commit/status flip.

### Recommendation
Scope `StatusHandler#process` the same way other handlers scope via `Handler#stacks`: restrict the `Commit` lookup to commits belonging to stacks under `Repository.from_github_repo_name(payload.dig('repository', 'full_name'))`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` to `Stack`/`Repository` and filtering by the authenticated repository's `full_name`, before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (no live GitHub):
1. Create `repository_a` (`full_name: "attacker/repo"`) and `repository_b` (`full_name: "victim/repo"`), each with its own `stack` (`stack_b` configured as the production environment requiring `ci/circleci`).
2. Create a `Commit` with `sha: "deadbeef..."` under `stack_b` (simulating a SHA shared via fork/shared history) with an existing passing/pending `ci/circleci` status so `stack_b.commits.last.deployable?` is `true` beforehand.
3. Assert the binding before the exploit: `assert_equal true, commit_b.reload.deployable?`.
4. Invoke `Shipit::Webhooks::Handlers::StatusHandler.call(payload)` directly with a payload whose `repository.full_name` is `"attacker/repo"` (not `"victim/repo"`), `sha: "deadbeef..."`, `context: "ci/circleci"`, `state: "failure"` — bypassing controller-level signature verification to isolate the handler logic (or drive it through `WebhooksController` with a valid signature for `attacker/repo`'s configured secret).
5. Assert the binding after: `assert_equal false, commit_b.reload.deployable?` and that a new `Status` row with `state: "failure"` was created on `commit_b` even though the payload's `repository.full_name` was `"attacker/repo"`, proving `commit_b.stack_id != Repository.from_github_repo_name("attacker/repo").stacks.first&.id`.
6. This demonstrates `StatusHandler` wrote a status for repository B despite the request only authenticating repository A, confirming the cross-tenant mutation.

### Citations

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
