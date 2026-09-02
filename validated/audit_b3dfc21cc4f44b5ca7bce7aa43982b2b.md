### Title
Cross-repository status forgery via unscoped `Commit.where(sha:)` lookup enables unauthorized `trigger_continuous_delivery` on a victim stack - (File: app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
`WebhooksController#verify_signature` only proves that a webhook payload was signed by the GitHub App/org configuration named in the payload's `repository.owner.login` field, but `StatusHandler#process` then creates a `Status` for *any* `Commit` row matching the payload's `sha`, without checking that the commit's actual stack/repository corresponds to the organization that produced the valid signature. This breaks the binding `Shipit.github(organization: repository_owner)` (verifier) == owning organization of the `Stack` the resulting `Status` is attached to, letting a same-SHA status signed by one (attacker-controlled) org's webhook secret write a `success` status onto a commit that belongs to a completely different (victim) stack, which can then drive `Stack#trigger_continuous_delivery` into an unauthorized deploy.

### Finding Description
The binding the system is supposed to enforce is:
`org used in Shipit.github(organization: repository_owner)` (the org whose `webhook_secret` validated `X-Hub-Signature`) `== org that owns the Stack/Commit the Status write applies to`.

Tracing the code:
- `WebhooksController#verify_signature` resolves the GitHub App purely from the attacker-supplied JSON field `repository.owner.login` / `organization.login` and checks the HMAC against that org's `webhook_secret`: [1](#0-0) [2](#0-1) 
- Once the signature check passes for *that org*, `Shipit::Webhooks.for_event('status')` dispatches to `StatusHandler#process`, which looks up commits **purely by `sha`, with no scoping to the org/repository that was just verified**: [3](#0-2) 
- `Commit#create_status_from_github!` then creates a `Status` row keyed on `commit.stack_id` — i.e. whatever stack the matched commit actually belongs to, regardless of which org's secret signed the request: [4](#0-3) 
- `Status` creation triggers continuous delivery on the commit's real stack: [5](#0-4) [6](#0-5) 
- `Stack#trigger_continuous_delivery` picks the next deployable commit and calls `trigger_deploy(commit, Shipit.user, ...)` with no re-validation of which org/webhook produced the underlying status: [7](#0-6) [8](#0-7) 
- `Commit#deployable?` only inspects the aggregated `status` state, with no notion of which repository/org produced the underlying `Status` records: [9](#0-8) 

Exploit flow: an attacker who administers a separate GitHub organization that is also configured in Shipit's multi-org `github:` config (each org has its own independent `webhook_secret`, as documented) can:
1. Reproduce a byte-identical git commit (same tree/parents/author/committer/timestamps/message) as an undeployed commit in the victim's tracked (often public) repository, giving it the identical SHA.
2. Push a GitHub `status` event for that SHA from their own repository/org. This is correctly signed with the attacker's own org's `webhook_secret`, so `verify_signature` passes for the *attacker's own org*.
3. `StatusHandler#process` matches `Commit.where(sha: <same_sha>)`, which returns the *victim's* `Commit` (belonging to the victim's `Stack`), and writes a `success` `Status` scoped to `commit.stack_id` (the victim stack) — even though the signature was never verified against the victim org's secret.
4. This flips `Commit#deployable?` to true on the victim stack, and `Stack#trigger_continuous_delivery` (via `ContinuousDeliveryJob`) calls `trigger_deploy(commit, Shipit.user, ...)`, which builds and runs a real `Deploy`/`Task`, executing the victim stack's deploy `Command` via `PTY.spawn` with the victim's `GITHUB_TOKEN`/environment.

Existing guards (`verify_signature`, `drop_unhandled_event`, `ExplicitParameters` schema on `StatusHandler`) only validate the *format* of the payload and the *identity of the signing org*; none of them re-check that the `Commit`/`Stack` actually mutated belongs to that same signing org. `force_github_authentication`, `require_permission!`, and `Shipit.github_teams` are irrelevant here since webhook processing is not a session-based, permission-checked path.

### Impact Explanation
An attacker who controls only their own org's webhook credentials (never the victim's) can cause a `Status` record — and consequently a real unauthorized `Deploy`/`Task` — to be written against a victim's `Stack`, executing `Command`/`PTY.spawn` with the victim's deploy credentials (`GITHUB_TOKEN`, deploy env). This is a cross-tenant "payload for one repository mutating another's stack/commit" — squarely in the Critical bucket ("a payload for one repository mutating another's stack, commit, task or team, or an unauthorized deploy"). It is repeatable against any commit whose SHA the attacker can reproduce, and is not limited to a single victim stack if multiple stacks/orgs are hosted on the same Shipit instance.

### Likelihood Explanation
The attack requires: (1) the Shipit instance is configured with multiple independent GitHub App organizations, each with its own `webhook_secret` (a documented, supported configuration for multi-tenant Shipit installs), and (2) the attacker administers one of those configured orgs (their own, legitimately onboarded) while the victim's tracked repository is public (or otherwise has commit content the attacker can reproduce byte-for-byte to collide the SHA). Given those two preconditions — both plausible in shared/multi-tenant Shipit deployments tracking open-source repos — the attacker's cost is low: no victim secrets, sessions, or API tokens are needed, only their own org's legitimate webhook signing key and a copy of a public commit. In a strictly single-org Shipit deployment this specific chain is blocked because `Shipit.github(organization: repository_owner)` for an unrecognized org raises `GithubOrganizationUnknown` and returns 422, so the vulnerability's applicability is directly gated by the multi-org configuration.

### Recommendation
In `StatusHandler#process` (and analogous handlers such as check-run/check-suite handlers), scope the `Commit` lookup to commits belonging to a stack whose `repository.owner`/`full_name` matches the `repository_owner` (or the full `repository.full_name`) that was actually verified in `verify_signature`, e.g. `Commit.joins(stack: :repository).where(sha: params.sha, shipit_repositories: { owner: repository_owner })`, and pass the verified repository identity down from the controller into the handler context so it cannot be spoofed independently of the signature-verified org.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/status_handler_test.rb` or extend `test/controllers/webhooks_controller_test.rb`):
1. Set up two orgs in `Shipit.github` config stubs: `org_a` (victim) and `org_b` (attacker), each with distinct `webhook_secret`.
2. Create `stack_a` under `org_a` with an undeployed `commit` (sha `SHA_X`) that currently has no passing status (`refute_predicate commit, :deployable?`).
3. Create `stack_b` under `org_b` with its own commit sharing the same sha `SHA_X` (simulate SHA collision) — or simply stub `Commit.where(sha:)` to return `commit` regardless of caller context to demonstrate the missing scoping.
4. Post to `/webhooks` with `X-Github-Event: status`, a payload whose `repository.owner.login = "org_b"` and `sha: SHA_X`, `state: "success"`, correctly signed with `org_b`'s `webhook_secret` (`Shipit.github(organization: 'org_b').verify_webhook_signature` returns true; `Shipit.github(organization: 'org_a')` is never consulted).
5. Assert: `assert_difference('commit.statuses.count', 1) { post :create, body: payload, as: :json }` and `assert_predicate commit.reload, :deployable?` — proving org_b's signature created a status on org_a's commit.
6. `assert_enqueued_with(job: ContinuousDeliveryJob, args: [stack_a])`, then `perform_enqueued_jobs` and assert `assert_difference('Deploy.count', 1) { ... }`, with `Command.any_instance.expects(:start)` (or `PTY.expects(:spawn)`) invoked with `stack_a`'s env (e.g. `GITHUB_REPO_OWNER == 'org_a'`), confirming the deploy actually ran against the victim stack triggered solely by org_b's signature.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/commit.rb (L219-229)
```ruby
    delegate :pending?, :success?, :error?, :failure?, :blocking?, :state, to: :status

    def active?
      return false unless stack.active_task?

      stack.active_task.includes_commit?(self)
    end

    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end
```

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L42-44)
```ruby
    def schedule_continuous_delivery
      commit.schedule_continuous_delivery
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

**File:** app/models/shipit/stack.rb (L235-243)
```ruby
    def next_commit_to_deploy
      commits_to_deploy = commits.order(id: :asc).newer_than(last_deployed_commit).reachable.preload(:statuses)
      if maximum_commits_per_deploy
        commits_with_max_applied = commits_to_deploy.limit(maximum_commits_per_deploy)
        deployable_commits(commits_with_max_applied) || deployable_commits(commits_to_deploy)
      else
        deployable_commits(commits_to_deploy)
      end
    end
```
