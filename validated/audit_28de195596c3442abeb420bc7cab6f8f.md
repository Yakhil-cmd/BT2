### Title
Cross-repository `pull_request` label injection into a continuous_deployment-enabled ReviewStack via unbound signature-owner vs. lookup-owner divergence - ([File: app/controllers/shipit/webhooks_controller.rb], [File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb])

### Summary
`Shipit::WebhooksController#verify_signature` derives the HMAC-verification organization from `params.dig('repository','owner','login')`, while `LabelCapturingHandler#repository` looks up the target `Shipit::Repository` from a completely different field, `params.repository.full_name` [1](#0-0) [2](#0-1) . Because the entire JSON body is attacker-controlled and these two fields are never checked for consistency, an attacker who knows of any Shipit-configured GitHub organization with a blank `webhook_secret` (verification trivially returns `true` for blank secrets) can pass signature verification while targeting an arbitrary victim repository/stack via `full_name`.

### Finding Description
The broken binding is the implicit equality Shipit assumes but never enforces:
`params.dig('repository','owner','login')` (used to select the `GitHubApp`/secret for HMAC verification) == owner segment of `params.repository.full_name` (used to resolve the actual `Shipit::Repository`/stack that gets mutated).

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `repository.owner.login` (falling back to `organization.login`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [3](#0-2) .
2. `GitHubApp#verify_webhook_signature` returns `true` unconditionally `unless webhook_secret` — i.e., any org configured with no `webhook_secret` accepts an unsigned/forged body with no HMAC check at all [4](#0-3) . This "no-secret organization" config pattern is present in this codebase's own fixtures (`test/dummy/config/secrets_double_github_app.yml` shows multiple orgs each with `webhook_secret: # nil`).
3. On success, `create` parses the raw body and dispatches it unmodified to all handlers for the event, including `LabelCapturingHandler` [5](#0-4) .
4. `LabelCapturingHandler#repository` resolves the target repository from `params.repository.full_name`, not from `repository.owner.login` used in step 1 [2](#0-1) . The handler then finds the review stack by `environment: "pr#{number}"` under that repository via `ReviewStackAdapter` [6](#0-5) , and `capture_labels` persists attacker-chosen label names onto that stack's `PullRequest` [7](#0-6) .
5. `ReviewStack#env` turns each persisted label name into an uppercased environment variable set to `"true"`, merged on top of the stack's base env [8](#0-7) , which flows into `StackCommands#env` (`super.merge(@stack.env)`) and ultimately into any `Command`/`PTY.spawn` executed for that stack's tasks/deploys (confirmed by `test/lib/shipit/deploy_commands_test.rb` and `test/lib/shipit/task_commands_test.rb`, which assert labels become deploy/task env vars).
6. If the victim stack has `continuous_deployment` enabled, `ContinuousDeliveryJob#perform` calls `stack.trigger_continuous_delivery` whenever conditions are met (not occupied, no schedule block) [9](#0-8) , which triggers a deploy whose task commands inherit the now attacker-controlled label-derived env vars [10](#0-9) .

None of the existing guards prevent this: `drop_unhandled_event` only checks the event type exists, `verify_signature` only checks the HMAC against the org derived from `repository.owner.login` (not `full_name`), and the `LabelCapturingHandler` `ExplicitParameters` schema validates field *types*, not that `repository.owner.login` and `repository.full_name` refer to the same repository. There is no cross-check anywhere in the controller or handler that ties the org used to select the webhook secret to the org whose stack is ultimately mutated.

### Impact Explanation
The attacker can write arbitrary label-derived environment variable names/values (`params.pull_request.labels.map(&:name)` uppercased, always `"true"`) onto any victim repository's review-stack `PullRequest` record, without ever authenticating against that repository's secret — a payload authenticated for one repository (or no repository, since the secret is blank) mutates another repository's stack record. If the victim review stack has `continuous_deployment` enabled, this record write is amplified into an unauthorized deploy whose deploy-script environment is attacker-influenced, which can flip feature flags, skip safety checks, or otherwise alter deploy behavior depending on what the target's `shipit.yml`/deploy scripts key off environment variables named after labels. This matches the "payload for one repository mutating another's stack" and "unauthorized deploy" Critical categories. The attack is repeatable against any repository whose full_name the attacker can guess/know, is bound only by the existence of at least one Shipit-configured organization (any organization, not necessarily the victim's) with a blank `webhook_secret`.

### Likelihood Explanation
Preconditions: Shipit must be running the multi-org `github:` config schema with at least one configured organization lacking `webhook_secret` (a documented/supported configuration in this repo's own `docs/setup.md` and `config/secrets.development.example.yml`, which explicitly shows `webhook_secret: # nil` as an example), and a victim stack must exist with `continuous_deployment: true`. No knowledge of any secret, token, or credential is required — the attacker only needs to know (a) the name of one such no-secret org and (b) the victim's `owner/repo` full name and open PR number, both of which are typically public information. Cost is a single unauthenticated HTTP POST to `/webhooks` with a crafted JSON body and `X-Github-Event: pull_request`; fully repeatable and scriptable against many repositories in one request per attempt.

### Recommendation
In `WebhooksController#verify_signature`, do not derive the signature-selection organization from an unauthenticated field disjoint from the field used for repository lookup. At minimum: (1) after selecting the `GitHubApp`/secret via `repository.owner.login`, verify `params.repository.full_name` starts with that same owner (case-insensitively) before dispatching to handlers, rejecting mismatches with `422`; (2) treat a blank `webhook_secret` as a misconfiguration to be logged/rejected rather than silently trusted (`verify_webhook_signature` should not auto-pass unsigned payloads); (3) in each handler (e.g. `LabelCapturingHandler`), re-validate that the resolved `Shipit::Repository`'s owner matches the authenticated `repository_owner` context passed down from the controller instead of only trusting `params.repository.full_name`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`):
1. Configure `Shipit.stubs(:secrets)` (or use the existing `secrets_double_github_app.yml` fixture) with two orgs: `NoSecretOrg` (no `webhook_secret`) and the victim org `victim-org` (its own secret, irrelevant here).
2. Create `victim_stack = Shipit::Stack.create!(repository: shipit_repositories(:... victim-org/repo), environment: "pr1", continuous_deployment: true, ...)` and an associated `PullRequest` and open PR fixture (`environment: "pr1"`).
3. POST to `/webhooks` with headers `X-Github-Event: pull_request`, no valid `X-Hub-Signature`, and JSON body:
   ```json
   {
     "action": "labeled",
     "number": 1,
     "pull_request": { ... "labels": [{"name": "shipit_bypass"}] ... },
     "repository": { "owner": { "login": "NoSecretOrg" }, "full_name": "victim-org/repo" },
     "sender": { "login": "attacker" }
   }
   ```
4. Assert response is `200 OK` (signature check passed due to blank secret on `NoSecretOrg`).
5. Assert `victim_stack.pull_request.reload.labels` now includes `"shipit_bypass"`, and `victim_stack.env["SHIPIT_BYPASS"] == "true"` — a record write on `victim-org/repo`'s stack authenticated only by `NoSecretOrg`'s (non-)secret.
6. Optionally assert `ContinuousDeliveryJob` is enqueued/`trigger_continuous_delivery` invoked given `continuous_deployment: true`, demonstrating the deploy amplification path, e.g. `assert_enqueued_with(job: ContinuousDeliveryJob, args: [victim_stack])` following the commit-success path, or directly invoke `ContinuousDeliveryJob.new.perform(victim_stack)` and assert the resulting `Deploy#env`/`StackCommands#env` contains `"SHIPIT_BYPASS" => "true"`.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L10-17)
```ruby
          def initialize(params, scope: Shipit::ReviewStack)
            @params = params
            @scope = scope
          end

          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
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
