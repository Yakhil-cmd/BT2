### Title
Repository-unscoped SHA lookup in `StatusHandler#process` lets a verified webhook for one repository mutate commit status/`blocked?` state on unrelated stacks sharing the same commit SHA - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target commit purely by `Commit.where(sha: params.sha)` with no repository/stack scoping, unlike other handlers (e.g. `PushHandler`) which restrict to `stacks` derived from the payload's repository/organization. Because `Commit` rows are keyed by `stack_id` and multiple `Stack` records (different environments of the same repository, or repositories sharing commit history) can hold rows with an identical `sha`, a genuinely-signed status webhook for one stack's repository can write a status onto every commit row across the fleet that shares that SHA, and `Commit#blocked?`/`deployable?` will then react to that forced status.

### Finding Description
The broken binding: the code should enforce `commit.stack.repository == webhook.repository`, but `StatusHandler#process` only enforces `commit.sha == params.sha`: [1](#0-0) 

Compare with `PushHandler#process`, which correctly narrows to `stacks` (the repository/organization-scoped stack relation) before acting: [2](#0-1) 

`StatusHandler` has no equivalent scoping — it iterates over `Commit.where(sha: params.sha)` for the entire installation and calls `commit.create_status_from_github!(params)` on each match: [3](#0-2) 

`create_status_from_github!` writes the status and reruns commit-state evaluation via `add_status`, which can trigger `Hook.emit(:deployable_status, ...)` and `stack.schedule_merges`: [4](#0-3) [5](#0-4) 

Downstream, `Commit#blocked?` inspects `stack.blocking_statuses` and the reachable range of commits for that same stack, and any commit whose `status.blocking?` is true (i.e. matches a configured blocking context/state such as `buildkite/deploy`) will force `blocked? == true` for the whole stack, gating `deployable?` and therefore continuous delivery/merge queue behavior: [6](#0-5) 

Signature verification (`verify_signature`) is keyed on `repository_owner` taken from the webhook payload's own `repository`/`organization` object, so it correctly proves the request came from GitHub for *that* repository/org — it says nothing about which `Commit` rows in the database get mutated: [7](#0-6) 

Because `Commit` belongs to `stack` rather than `repository` directly, and a single GitHub repository can back multiple `Stack` rows (distinct environments, each with its own `commits` table rows for shared history), or repositories with overlapping/shared commit history (mirrors, forks kept in sync, shared merge-base commits before branches diverge) can end up with identical `sha` values in different stacks' `commits` tables. A correctly-signed status webhook from the attacker's own legitimately-integrated repository, for a SHA that also happens to exist in a victim stack's `commits` table, will flip the victim's cached status/`blocked?` computation via this shared-SHA path, since `StatusHandler` never checks `commit.stack.repository` against the requesting repository.

### Impact Explanation
An attacker who owns/controls one Shipit-integrated repository (or its GitHub status/CI integration) can, with a validly signed webhook for their own repo, write a `Status` record onto `Commit` rows belonging to a **different** stack whenever that stack's `commits` table contains the same `sha`. If the victim stack has `blocking_statuses` configured to require `buildkite/deploy`, forcing that context to `failure`/`error` sets `blocked? == true` stack-wide (blocking deploys/merges), or forcing it to `success` can clear a legitimate block, both without the attacker ever authenticating to that stack. This is a payload from one repository's webhook mutating another stack's commit/status/gating record — matching the Critical category ("payload for one repository mutating another's stack, commit ... an unauthorized deploy ... or block").

### Likelihood Explanation
Exploitation requires two preconditions beyond attacker control of their own repo/webhook: (1) the target stack must have `blocking_statuses` configured for a context the attacker can also emit statuses for (e.g. `buildkite/deploy`), and (2) a `sha` collision — i.e., a commit that is genuinely present (same 40-byte SHA1) in both the attacker's authorized repository's stack and the victim stack. Because git SHAs are content-addressed and not attacker-forgeable at will, this is only practically reachable in shared-history situations (multiple environment stacks tracking the same underlying repository, mirrored/forked repositories, or shared merge-base commits before branch divergence) — this is a realistic, not purely theoretical, Shipit deployment topology (multiple `Stack` rows per repository per environment is an explicitly supported first-class feature), but it is not "any arbitrary victim SHA on demand."

### Recommendation
Scope `StatusHandler#process` to commits belonging to stacks for the requesting repository, mirroring `PushHandler`'s use of the `stacks` helper, e.g. restrict to `stacks.commits.where(sha: params.sha)` (or otherwise filter by `commit.stack.repository == webhook repository/organization`) before calling `create_status_from_github!`.

### Proof of Concept
Minitest plan (schematic, no live GitHub required):
1. Create `Repository` A/`Stack` A1 and `Repository` B/`Stack` B1 (`blocking_statuses: ['buildkite/deploy']` configured on B1's deploy spec).
2. Insert a `Commit` in `A1.commits` and a `Commit` in `B1.commits` sharing the identical `sha` value (simulating shared history), with `B1`'s commit currently `success?`/`deployable? == true` and `blocked? == false`.
3. Build a status webhook payload `{ sha: <shared_sha>, context: 'buildkite/deploy', state: 'failure', repository: { owner: { login: <A's owner> } } }` and invoke `Shipit::Webhooks::Handlers::StatusHandler.new(payload).call` (or POST through the controller with a valid signature for A's org).
4. Assert: `Commit.where(sha: shared_sha).count == 2` and both received the new status — i.e. `B1_commit.reload.blocked? == true` and `B1.deployable? == false` — even though the webhook only authenticated repository A.
5. Equality check: before, `commit_B1.stack.repository != webhook.repository` while the status was still applied — proving the missing binding `commit.stack.repository == payload.repository` is never enforced in `StatusHandler#process`.

### Citations

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L7-24)
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
