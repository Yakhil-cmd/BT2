### Title
Cross-repository CI status forgery via unscoped `sha` lookup in `StatusHandler` - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` binds a webhook payload to a *repository owner/organization's* secret, but the handler that actually mutates state, `Shipit::Webhooks::Handlers::StatusHandler`, never re-checks that binding: it updates commit CI status purely by matching a raw `sha` string, with no scoping to the repository/organization whose secret validated the request.

### Finding Description
`WebhooksController#verify_signature` selects the GitHub App/secret to validate against using `repository_owner`, itself read straight out of the payload (`params.dig('repository', 'owner', 'login')`), and only proves that *some* registered organization's webhook secret produced a valid HMAC over the raw body: [1](#0-0) [2](#0-1) 

Once verified, the parsed payload is dispatched to handlers without any further tie to the authenticated organization/repository: [3](#0-2) 

The base `Handler` class does expose a repository-scoped helper (`stacks`, keyed off `payload.dig('repository', 'full_name')`), and `PushHandler` correctly uses it to scope which stacks it can touch: [4](#0-3) [5](#0-4) 

`StatusHandler`, however, ignores this scoping entirely and updates *any* `Commit` row in the whole Shipit instance whose `sha` matches the payload's `sha` field, regardless of which repository/stack that commit actually belongs to: [6](#0-5) 

This breaks the trust binding: "the organization whose webhook secret authenticated the request" ≠ "the repository/stack whose commit is written." The signature only proves the sender controls webhook credentials for organization A; it proves nothing about whether the `sha` in the payload actually belongs to a commit tracked under organization A's repositories. Any onboarded organization's status event can update the CI status of a commit belonging to a completely different, unrelated stack/organization tracked by the same Shipit instance, as long as the `sha` strings collide (which is realistic for forks, mirrors, or shared/cherry-picked history across repositories tracked by the same instance).

That written status feeds directly into deploy gating: `Commit#deployable?` and `Stack#deployable?`/`#trigger_continuous_delivery` rely on `Commit#status`/`#success?`, which is derived from `Status::Group.compact(self, statuses_and_check_runs)` — i.e., from rows written by `StatusHandler`: [7](#0-6) [8](#0-7) [9](#0-8) 

### Impact Explanation
An attacker who legitimately owns/controls a repository already onboarded on the same Shipit instance (a normal, unprivileged webhook sender for their own repo — no Shipit session, API token, or extra credential required) can send a forged/legitimate `status` GitHub event for a `sha` that also exists in another organization's tracked stack (e.g. via forks/mirrors/shared history), setting it to `success`. If that other stack has continuous deployment or manual deploy gated on CI status, this can unblock/trigger an unauthorized deploy for a repository the attacker does not control — satisfying the "unauthorized deploy" Critical-impact criterion, achieved purely by exploiting the repository↔organization binding gap, not by compromising any secret.

### Likelihood Explanation
Likelihood is **low-to-medium** because it depends on a real SHA collision between a commit the attacker can trigger a webhook for and a commit tracked by a victim stack — feasible for common patterns like forked/mirrored repos or shared upstream commits ingested by multiple Shipit-tracked repositories, but not a generic "any attacker, any target" primitive. It requires no privileged Shipit access, matching the report's "unprivileged attacker" framing, and directly mirrors the analog bug class (`Governance.revokeVotes` acting on data not actually covered by the intended check).

### Recommendation
Scope `StatusHandler#process` to only update commits belonging to stacks whose repository matches `payload.dig('repository', 'full_name')`, mirroring the `stacks` helper already used by `PushHandler`, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` instead of unscoped `Commit.where(sha: params.sha)`.

### Proof of Concept
1. Organization A and Organization B are both onboarded on the same Shipit instance, each with its own GitHub App/webhook secret.
2. Organization B's repository shares a commit `sha` with Organization A's tracked stack (fork, mirror, or cherry-pick).
3. Attacker (who only controls Organization B's repo, e.g. via a CI integration they own) triggers/sends a `status` webhook event signed with Organization B's valid webhook secret, referencing the shared `sha` with `state: success`.
4. `WebhooksController#verify_signature` validates the signature against Organization B's secret and passes.
5. `StatusHandler#process` executes `Commit.where(sha: params.sha)`, matching the `Commit` row that actually belongs to Organization A's stack, and calls `create_status_from_github!`, marking it `success`.
6. If Organization A's stack has continuous deployment enabled and was blocked on CI, `Stack#trigger_continuous_delivery` / `Commit#deployable?` now sees the commit as deployable, potentially triggering an unauthorized deploy for a stack the attacker never had access to. [6](#0-5) [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L304-306)
```ruby
    def status
      @status ||= Status::Group.compact(self, statuses_and_check_runs)
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
