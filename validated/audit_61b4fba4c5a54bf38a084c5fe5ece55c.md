### Title
Fail-open webhook signature verification allows forged `pull_request action=labeled` events to archive/unarchive review stacks and re-enable auto-deploy - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` derives the signing organization purely from the attacker-supplied JSON body and delegates authentication to `GitHubApp#verify_webhook_signature`, which returns `true` unconditionally whenever that organization has no `webhook_secret` configured — a supported, documented configuration state. This lets any unauthenticated internet client forge a `pull_request`/`action=labeled` webhook that `LabeledHandler` trusts wholesale, archiving/unarchiving real review stacks, and — when the targeted stack has `continuous_deployment` enabled — re-enabling the normal green-commit auto-deploy path (`ContinuousDeliveryJob`) for that stack.

### Finding Description
The broken binding: the code assumes `verified == true` implies `repository_owner` (from the forged payload) authenticated the request, i.e. `verified → payload.repository.owner.login is trustworthy`. In reality:

- `repository_owner` is read straight out of the untrusted body: `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0) .
- `verify_signature` builds `Shipit.github(organization: repository_owner)` from that untrusted value and calls `verify_webhook_signature(signature, raw_post)` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` fails open: `return true unless webhook_secret` [3](#0-2) . If the targeted org's config has no `webhook_secret` set — which the engine's own setup instructions treat as optional (`webhook_secret:` left blank in the generated `secrets.yml`, and the test dummy config itself sets `"webhook_secret": null`) — any signature header (or none at all) is accepted.
- Past this check, `create` blindly dispatches the raw JSON to every registered handler for the event: `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` [4](#0-3) .
- `LabeledHandler` performs no independent verification against GitHub; it trusts `params.repository.full_name` to resolve a real `Shipit::Repository`/review-stack scope and mutates state solely from the forged fields (`action`, `pull_request.state`, `pull_request.labels`): `stack.archive!` / `stack.unarchive!` [5](#0-4) , gated only by `respond_to_label_change?` and `archive?`/`unarchive?`, all computed from the forged payload [6](#0-5) .

Exploit flow: attacker identifies (or targets broadly) an org whose Shipit deployment has not set `github.webhook_secret` (a valid documented state, see `template.rb`/`docs/setup.md`), crafts a `pull_request` JSON body naming that org/repo and any PR number/branch, sends `POST /webhooks` with `X-Github-Event: pull_request` and any `X-Hub-Signature` value (even absent), and the request is accepted as authentic. If the target repository has review stacks enabled with a provisioning label behavior, the forged event unarchives (or archives) a real `Stack` record. If that stack has `continuous_deployment` enabled, unarchiving removes the archived gating and the stack resumes normal green-commit auto-deploy machinery: on the next "success" status for the stack's branch, `Commit#schedule_continuous_delivery` enqueues `ContinuousDeliveryJob`, whose `perform` calls `stack.trigger_continuous_delivery` → `trigger_deploy` [7](#0-6) [8](#0-7) , deploying commits from the attacker's own PR branch.

No existing guard catches this: `verify_signature` is the only authentication gate and it is fail-open by design when no secret is configured; `drop_unhandled_event` and `ExplicitParameters` only validate shape, not provenance; `LabeledHandler` has no cross-check against the live GitHub PR/label state.

### Impact Explanation
An attacker gains the ability to flip archived/unarchived state on any review stack belonging to a repository under an org lacking a `webhook_secret`, without holding any Shipit credential, GitHub token, or webhook secret. Combined with `continuous_deployment` enabled on the affected stack, this re-enables automated deployment of commits on the attacker's own branch once CI reports success — an unauthorized deploy path driven entirely by a forged webhook. The attack is repeatable against any repository/org that has this documented-but-insecure configuration, and it is not scoped to the repository that "sent" the webhook — the attacker names the target repository/org in the payload themselves, so a payload nominally "from" any source can mutate a different org/repo's stack. This matches the Critical category "authentication bypass (forged webhook ... accepted)" / "an unauthorized deploy."

### Likelihood Explanation
Preconditions: the target org's Shipit `github.webhook_secret` must be unset (a supported configuration explicitly shown as optional/blank in `template.rb` and `docs/setup.md`, and used by the test fixtures themselves), and the target repository must have `review_stacks_enabled` with a provisioning-label behavior, with the stack having `continuous_deployment` enabled. Attacker cost is a single unauthenticated HTTP POST with no secrets required; the attack is trivially repeatable and scriptable against any number of repositories on such an org.

### Recommendation
Fail closed instead of open in `GitHubApp#verify_webhook_signature`: reject the webhook (return `false`/422) when no `webhook_secret` is configured, or make `webhook_secret` a mandatory, validated configuration value at boot so no org can be deployed without one. Additionally, do not treat `repository_owner`/`repository.full_name` from the raw JSON body as trusted for handler-level authorization decisions; verify it corresponds to the org that was actually cryptographically authenticated.

### Proof of Concept
1. In `test/controllers/webhooks_controller_test.rb` (or a new test), configure the dummy app's `shipit` org GitHub config with `webhook_secret: nil` (already the case per `test/dummy/config/secrets.test.json`).
2. Create a repository with `review_stacks_enabled = true`, `provisioning_behavior = :allow_with_label`, `provisioning_label_name = "deploy-me"`, and a pre-existing archived `Stack` with `continuous_deployment = true` for a PR branch/environment (`pr123`).
3. Build a `pull_request` JSON payload: `action: "labeled"`, `pull_request.state: "open"`, `pull_request.labels: [{name: "deploy-me"}]`, `repository.full_name` pointing at the target repo, `pull_request.head.ref` = attacker's branch.
4. `post :create, body: payload.to_json, as: :json`, setting `X-Github-Event: pull_request` and `X-Hub-Signature` to an arbitrary/garbage value (or omitted).
5. Assert: `response` is `:ok` (not `:unprocessable_entity`), and `stack.reload.archived?` is `false` (state changed) — proving the equality `verified == true` held despite `signature` never matching any HMAC over `webhook_secret` (because none exists), i.e., the binding "verified implies authenticated owner" is false.
6. Extend: push a commit + success status on the now-unarchived stack's branch and assert `ContinuousDeliveryJob` is enqueued/performs `trigger_deploy`, demonstrating the amplified downstream deploy effect, mirroring the pattern in `test/models/commits_test.rb:233-243`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L41-63)
```ruby
          def process
            return unless respond_to_label_change?

            handle
          end

          private

          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-97)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end
```

**File:** app/jobs/shipit/continuous_delivery_job.rb (L10-21)
```ruby
    def perform(stack)
      return unless stack.continuous_deployment?

      # If there is a schedule defined for this stack, make sure we are within a
      # deployment window before proceeding.
      return if stack.continuous_delivery_schedule && !stack.continuous_delivery_schedule.can_deploy?

      # checks if there are any tasks running, including concurrent tasks
      return if stack.occupied?

      stack.trigger_continuous_delivery
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
