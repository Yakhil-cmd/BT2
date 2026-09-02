### Title
Cross-repository Status forgery via unscoped `Commit.where(sha:)` lookup - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`StatusHandler#process` resolves the target `Commit` purely by matching the raw `sha` field from the webhook payload, with no check that the payload's `repository.full_name` corresponds to the stack that owns that commit. An attacker who can legitimately generate a validly-signed GitHub `status` webhook from a repository they own can attach an arbitrary, fully attacker-controlled `Status` (state, description, context, target_url, created_at) to any commit in Shipit's database that happens to share the same sha — including commits belonging to a completely different stack/tenant — as long as they can get a byte-identical commit object (same tree/parents/author/committer/message/timestamps) recorded in a repository they control.

### Finding Description
The claimed binding — the `Status` set consulted by `Commit#deployable?` equals the set that would exist if statuses only ever originated from `stack.github_api` scoped to that stack's own repository — is broken not just by the de-dup weakness described in the prompt, but by a more fundamental missing check upstream of it.

`Handler` base class exposes a `stacks` helper explicitly scoped by the payload's repository (`Repository.from_github_repo_name(repository_name)&.stacks`), used by other handlers such as `PushHandler`/`PullRequest` handlers: [1](#0-0) 

`StatusHandler#process`, however, never uses this scoping. It looks up commits globally by sha alone: [2](#0-1) 

This calls `Commit#create_status_from_github!`, which calls `add_status` and `statuses.replicate_from_github!`, persisting a `Status` keyed by `(stack_id, state, description, target_url, context, created_at)`: [3](#0-2) [4](#0-3) 

Because `find_or_create_by!` never overwrites or de-duplicates against an existing legitimate status with a different `description`/`created_at`, a forged row survives indefinitely, including across a subsequent `refresh_statuses!` call which pulls real GitHub statuses via `stack.github_api.statuses(...)`: [5](#0-4) 

`Status#after_create` immediately re-evaluates deployability and schedules continuous delivery: [6](#0-5) 

`Commit#deployable?` only checks `success? && !blocked?` against whichever `Status` rows exist for that commit — it has no notion of which repository a `Status` came from: [7](#0-6) 

**Attacker's exact path**: the attacker owns/controls a repository (a fork, or any repo where they can install/trigger the shared GitHub App per the ruleset's explicit "emit webhooks from a repository they own" capability). They obtain a byte-identical commit object to a victim commit (trivial for any public commit: `git fetch`/cherry-pick preserves the sha since it is a pure hash of tree/parents/message/author/committer timestamps) and push it into their own repo. They then use their own repo's legitimate write access to set a status via GitHub's real Statuses API (`state: success`, arbitrary `description`/`created_at`) on that sha. GitHub emits a real, correctly-signed `status` webhook (since `verify_webhook_signature` in `lib/shipit/github_app.rb:76-83` only checks the HMAC of the raw payload against the configured `webhook_secret` for the *organization derived from the payload*, which is the attacker's own repository's owner, and passes normally) — this is not a bypass of `verify_signature`, it is a legitimately signed webhook whose payload references an unrelated repository: [8](#0-7) [9](#0-8) 

`WebhooksController#create` dispatches strictly by event type, then `StatusHandler.call(params)` runs unconditionally against `Commit.where(sha: params.sha)` with zero repository binding: [10](#0-9) 

Existing guards do not stop this: `verify_signature` only authenticates that *some* configured GitHub organization sent the payload — it says nothing about whether that payload's commit belongs to the stack it is being applied to. `drop_unhandled_event` and `ExplicitParameters` schema validate payload shape, not repository ownership of the sha. `stacks`/`Repository.from_github_repo_name` scoping exists in the base `Handler` class but is simply not invoked by `StatusHandler`.

### Impact Explanation
A forged `success` status attached to a victim commit can flip `Commit#deployable?` to true for that commit in the victim's stack, enabling an unauthorized deploy path (directly, via `next_expected_commit_to_deploy`/continuous delivery scheduling triggered in `Status#after_commit :schedule_continuous_delivery`, or by satisfying `require_ci: true` on `POST /api/deploys`). This is a payload originating from one repository mutating another repository's stack/commit state — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team" / "an unauthorized deploy". Blast radius spans every stack in the Shipit instance sharing sha-space with attacker-reachable commits (i.e., any commit whose content the attacker can reproduce, which for open-source or forked repos is essentially every commit). It is fully repeatable — nothing in `find_or_create_by!` or `deployable?` invalidates or removes the forged row later, so it persists even after the legitimate refresh runs.

### Likelihood Explanation
The attacker needs: (1) a repository they own/control that is configured under the same Shipit GitHub App/org so a webhook from it passes `verify_webhook_signature`, and (2) the ability to push/replicate a commit object with an identical sha to the target and set an arbitrary status on it via GitHub's real API for their own repo — both are consistent with the ruleset's granted attacker capabilities ("push to a fork," "emit webhooks from a repository they own"). No Shipit secrets, sessions, or privileged roles are required. This is a low-cost, repeatable, one-webhook-per-target attack.

### Recommendation
In `StatusHandler#process`, scope the commit lookup to stacks associated with the payload's own repository (mirroring the `stacks` helper already used elsewhere), e.g. restrict to `Commit.where(sha: params.sha, stack_id: stacks.select(:id))` or verify `commit.stack.github_repo_name == repository_name` before calling `create_status_from_github!`. Additionally, consider de-duplicating/replacing statuses per `(stack_id, context)` rather than accumulating unbounded rows keyed by mutable fields like `created_at`/`description`.

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/status_handler_test.rb`:
```ruby
test "process does not attach a status to a commit belonging to a different repository's stack" do
  victim_stack = shipit_stacks(:shipit)          # e.g. repo "shopify/shipit-engine"
  victim_commit = shipit_commits(:cyclimse_first) # belongs to victim_stack, currently NOT deployable via forged data
  refute_predicate victim_commit, :deployable?

  forged_payload = {
    'sha' => victim_commit.sha,
    'state' => 'success',
    'description' => 'forged-ci',
    'context' => 'ci/forged',
    'created_at' => 1.minute.ago.iso8601,
    'branches' => [],
    'repository' => { 'full_name' => 'attacker/unrelated-repo', 'owner' => { 'login' => 'attacker' } }
  }

  assert_no_difference -> { victim_commit.statuses.count } do
    Shipit::Webhooks::Handlers::StatusHandler.call(forged_payload)
  end

  refute_predicate victim_commit.reload, :deployable?
end
```
This test currently FAILS against the present implementation (the forged status is created and `deployable?` becomes true), demonstrating the missing repository binding. A second assertion can additionally show the forged row surviving a subsequent `victim_commit.refresh_statuses!` call by stubbing `stack.github_api.statuses` to return only genuine (differently-keyed) statuses and asserting the forged row is still present and `deployable?` still returns `true`.

### Citations

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/status.rb (L18-19)
```ruby
    after_create :enable_ci_on_stack
    after_commit :schedule_continuous_delivery, :broadcast_update, on: :create
```

**File:** app/models/shipit/status.rb (L24-33)
```ruby
      def replicate_from_github!(stack_id, github_status)
        find_or_create_by!(
          stack_id:,
          state: github_status.state,
          description: github_status.description,
          target_url: github_status.target_url,
          context: github_status.context,
          created_at: github_status.created_at
        )
      end
```

**File:** app/models/shipit/commit.rb (L156-169)
```ruby
    def refresh_statuses!
      github_statuses = stack.handle_github_redirections do
        stack.github_api.statuses(github_repo_name, sha, per_page: 100)
      end
      github_statuses.each do |status|
        create_status_from_github!(status)
      end
    end

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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
