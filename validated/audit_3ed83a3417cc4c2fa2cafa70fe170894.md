### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup in `StatusHandler#process` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` looks up commits by bare SHA with no repository/stack scoping, unlike sibling handlers such as `PushHandler` which explicitly filter via `stacks` derived from the payload's `repository.full_name`. Any attacker who can get a validly-signed `status` webhook delivered for their own repository, referencing a SHA that also exists as a `Commit` row belonging to a victim's stack (e.g. by pushing/cherry-picking the identical Git object into their own repo, since commit SHAs are content-addressed and repo-independent), will have their forged `state`/`context` written onto the victim's commit.

### Finding Description
The broken binding: the handler should enforce `commit.stack.repository.full_name == payload.dig('repository', 'full_name')` before writing a status, but instead the code enforces nothing of the sort: [1](#0-0) 

Compare with `PushHandler`, which correctly resolves the target scope from the payload's own repository before acting: [2](#0-1) [3](#0-2) 

`StatusHandler` never calls the `stacks`/`repository_name` helper at all; it queries `Commit.where(sha: params.sha)` globally across every stack in the installation, then calls `commit.create_status_from_github!(params)` on each match: [4](#0-3) 

`create_status_from_github!` records the new status and, if it changes the commit's `simple_state`, triggers deploy-affecting side effects, including scheduling merges when the new status is `success`: [5](#0-4) 

`deployable?` for the commit is directly a function of `success?` and `blocked?`, both of which are derived from the `statuses` association populated by this unscoped write: [6](#0-5) 

Signature verification only proves that the request was validly signed for the attacker's own organization/repository (`Shipit.github(organization: repository_owner)` keyed off the attacker's own `repository.owner.login`), it says nothing about which `sha` values the payload is allowed to reference: [7](#0-6) 

Exploit flow: the attacker owns/controls a GitHub repository connected to the same Shipit instance (satisfying the "unprivileged, no Shipit session/secrets" constraint — they only need their own repo's valid GitHub App/webhook wiring, which the question's preconditions grant as "attacker repo stack"). They obtain an identical commit SHA to one already present in the victim's stack — trivial since Git commit hashes are content-derived and repo-independent (e.g., cherry-pick/fork the exact commit object, or force-push it into their own repo). They send GitHub a state/status update (or synthesize the webhook delivery for their own repo) with `context: ci/e2e`, `state: success`, `sha: <shared sha>`. `verify_signature` passes because it validates against the attacker's own repository/organization credentials. `StatusHandler#process` then matches **every** `Commit` row across **every stack** with that `sha`, including the victim's, and writes a `success` status onto it, potentially flipping `deployable?` to true and triggering `stack.schedule_merges`, causing an unauthorized deploy/merge of the victim's stack.

No existing guard closes this: `verify_signature` only proves authenticity for the attacker's own repo, `drop_unhandled_event` and `ExplicitParameters` only validate payload shape, and there is no `Repository`/`Stack` scoping anywhere in `StatusHandler` or `Commit.create_status_from_github!`.

### Impact Explanation
A payload authenticated for repository A can write a `success` (or any) CI status onto a `Commit` belonging to repository B's stack, directly matching the "Critical: a payload for one repository mutating another's stack/commit" category. Because `deployable?`/`blocked?` and `schedule_merges` are downstream of this write, the attacker can force an unauthorized ship or block of a victim's release pipeline without any access to the victim's repository, Shipit session, or API token. This is repeatable against any victim commit whose SHA the attacker can reproduce, and scales to any number of stacks sharing the queried SHA.

### Likelihood Explanation
The attacker needs: (1) a GitHub repository wired into the same Shipit instance so a validly-signed `status` webhook can be delivered (which the question's scenario explicitly grants — "attacker repo stack"), and (2) a commit SHA collision with the victim, achievable deterministically by re-creating/cherry-picking the exact same Git commit object (same tree, parents, author, committer, timestamps, message) into their own repository — a low-cost, fully attacker-controlled operation, not a cryptographic SHA-1 collision. Given these, the exploit is a single webhook POST, fully repeatable, with no rate limiting or additional authorization required.

### Recommendation
Scope `StatusHandler#process` by repository, mirroring `PushHandler`: resolve `stacks` (or equivalent) from `payload.dig('repository', 'full_name')`, and only update `Commit` records belonging to stacks whose repository matches the authenticated payload's repository, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or joining `Commit` to `Stack`/`Repository` and filtering by `repository_id`/`full_name` before calling `create_status_from_github!`.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/status_handler_test.rb`:
1. Create `victim_stack` (repository `victim/repo`) and `attacker_stack` (repository `attacker/repo`), each requiring status context `ci/e2e`.
2. Create a `Commit` on `victim_stack` and a `Commit` on `attacker_stack` with the identical `sha` value (simulating a shared Git object).
3. Assert baseline: `victim_commit.deployable?` is `false` (no successful `ci/e2e` status yet). Equality to check: `victim_commit.status.state != 'success'`.
4. Build a webhook payload for `attacker/repo` with `sha: shared_sha, context: 'ci/e2e', state: 'success'`, and call `Shipit::Webhooks::Handlers::StatusHandler.call(payload)`.
5. Reload `victim_commit` and assert `victim_commit.status.state == 'success'` and/or `victim_commit.deployable?` became `true`, proving that a payload authenticated only for `attacker/repo` mutated `victim/repo`'s commit state — the two sides of the equality (`payload repository == commit's repository`) diverge, confirming the vulnerability.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
