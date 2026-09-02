### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`StatusHandler#process` resolves the target commit(s) for a GitHub `status` webhook purely by SHA, with no filter on the repository named in the same payload. Any owner of a Shipit-registered repository can send a validly-signed status webhook naming their own repo but with a `sha` copied from a public/victim repository's commit, and Shipit will write the forged status onto every `Commit` row sharing that SHA across all stacks.

### Finding Description
Broken binding: for a payload with `repository.full_name = R` and `sha = S`, the row mutated by `StatusHandler#process` must satisfy `commit.stack.repository.full_name == R`. Instead, the code executes: [1](#0-0) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` — this queries `Commit` globally by `sha` only, with no `stack_id`/`repository` predicate. The base `Handler` class actually provides a `stacks` helper that scopes by `repository_name` (`Repository.from_github_repo_name(repository_name)&.stacks`) [2](#0-1) , but `StatusHandler#process` never uses it.

`verify_signature` in `WebhooksController` only checks that the HMAC signature matches the `webhook_secret` of the org named by `repository_owner` in the payload [3](#0-2) ; it authenticates *who sent the payload* (attacker's own org), not that the `sha` inside the payload belongs to that org's repository. Since Shipit allows any organization to register its own stack/webhook_secret, an attacker who owns `attacker/repo` (registered as a Shipit Stack) can:

1. Copy a well-known `sha` from a victim's public commit (already present as a `Commit` row under a victim `Stack`, e.g. from a shared upstream/fork history).
2. POST `/webhooks` with `X-Github-Event: status`, a body naming `repository.full_name = attacker/repo`, `sha = <victim sha>`, `state = success`, signed with `attacker`'s own valid `webhook_secret`.
3. `verify_signature` passes (attacker's own secret matches attacker's own org).
4. `StatusHandler#process` runs `Commit.where(sha: victim_sha)`, which returns the **victim's** `Commit` row (and any other stack sharing that sha), and calls `create_status_from_github!(params)` on it, writing a forged `success` status via `statuses.replicate_from_github!` [4](#0-3) .

No existing guard (`ExplicitParameters` schema, `drop_unhandled_event`, `verify_signature`) checks that the resolved `Commit` belongs to a stack/repository matching the payload's `repository` field.

### Impact Explanation
A forged `success`/`error`/`failure` CI status is written onto a commit belonging to a stack the attacker does not control, potentially satisfying `stack.blocking_statuses`/`required_statuses` checks used by `Commit#deployable?` and `schedule_continuous_delivery`, which can unblock or trigger an unauthorized deploy on the victim's stack [5](#0-4) [6](#0-5) . This is a cross-repository/cross-tenant write reachable by any repository owner able to register a Shipit stack and know/guess a shared sha, matching the "payload for one repository mutating another's stack/commit" Critical category. It is repeatable against any stack whose commits' shas the attacker can predict (forks of public repos, cherry-picks, shared upstream history).

### Likelihood Explanation
Preconditions are modest but require some coincidence: the attacker must control a Shipit-registered stack (registering one's own repo/org is within an "unprivileged" attacker's reach per the threat model), and the victim commit's `sha` must already exist as a `Commit` row for a real, distinguishable-in-advance sha — which is realistic for forks/mirrors sharing git history with an upstream repo also deployed via Shipit. The attack costs one HTTP POST correctly signed with the attacker's own secret; no victim secret or session is needed.

### Recommendation
Scope the commit lookup in `StatusHandler#process` by the repository named in the verified payload, e.g. `stacks.flat_map(&:commits).where(sha: params.sha)` or `Commit.where(sha: params.sha, stack_id: stacks.select(:id))`, mirroring the `stacks`/`repository_name` helper already defined on `Handler`.

### Proof of Concept
In a minitest file under `test/`:
1. Create `stack_a` (repo `attacker/repo`) and `stack_b` (repo `victim/repo`), each with `webhook_secret` configured for their respective orgs.
2. Create `commit_b = shipit_commits(:stack_b, sha: 'deadbeef...')` under `stack_b`.
3. Also create a `commit_a` under `stack_a` with the **same** `sha` (simulating the shared-sha precondition), or simply assert the global query behavior directly: call `Shipit::Webhooks::Handlers::StatusHandler.call(params_with_repository_attacker_repo_and_sha_matching_commit_b)` and assert `commit_b.reload.statuses.last.state == 'success'` even though the payload's `repository.full_name` was `attacker/repo`, not `victim/repo`.
4. Assert the binding: `payload['repository']['full_name']` (`attacker/repo`) != `commit_b.stack.repository.full_name` (`victim/repo`), yet the status was written — proving the divergence.
5. Additionally send the request through `WebhooksController#create` signed with `attacker`'s own `webhook_secret` (computed via `OpenSSL::HMAC`) to show `verify_signature` passes and does not prevent this.

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

**File:** app/models/shipit/commit.rb (L227-229)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/commit.rb (L281-287)
```ruby
    def schedule_continuous_delivery
      return unless deployable? && stack.continuous_deployment? && stack.deployable?

      # This buffer is to allow for statuses and checks to be refreshed before evaluating if the commit is deployable
      # - e.g. if the commit was fast-forwarded with already passing CI.
      ContinuousDeliveryJob.set(wait: RECENT_COMMIT_THRESHOLD).perform_later(stack)
    end
```
