## Verdict: Vulnerability Confirmed

The claimed binding failure is real: the org used to **verify** a webhook's signature is *not necessarily* the org whose repository/stack the handler subsequently **mutates**.

### The broken binding

Expected invariant: `repository_owner_used_for_signature_verification == owner_of_repository_actually_mutated`.

In practice:
- Signature verification key comes from `params.dig('repository', 'owner', 'login')` [1](#0-0)  which selects the `GitHubApp` config via `Shipit.github(organization: repository_owner)` [2](#0-1) .
- The mutated repository/stack is resolved from `params.repository.full_name` independently: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [3](#0-2) .

Nothing ties these two fields together — an attacker can set `repository.owner.login` to an org whose `webhook_secret` is blank (or absent from `Shipit.github_teams` config), and `repository.full_name` to `"victim-org/victim-repo"`. `verify_webhook_signature` explicitly returns `true` when no `webhook_secret` is configured: `return true unless webhook_secret` [4](#0-3) , so the entire payload passes verification without any secret being known to the attacker, yet the payload's `full_name` drives all downstream repository/stack resolution used by every handler (`LabelCapturingHandler`, `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `AssignedHandler`, `EditedHandler` all resolve `repository` the same way) [5](#0-4) .

### Downstream effect for `LabelCapturingHandler`

For `action=reopened`, the handler requires `stack.present? && !stack.archived?` [6](#0-5) , resolved via `ReviewStackAdapter#stack = scope.find_by(environment: "pr#{params.number}")` scoped to `repository.review_stacks` (the victim's repo) [7](#0-6) [8](#0-7) . If it exists and is not archived, `capture_labels` overwrites `pull_request.update!(labels: params.pull_request.labels.map(&:name))` on the **victim's** `PullRequest` record [9](#0-8) . Those labels are later uppercased into deploy-time environment variables via `ReviewStack#env`: `labels.each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }` [10](#0-9) , confirmed by existing tests showing arbitrary label names become env keys, e.g. `SAFETY_DISABLED` in a deploy spec [11](#0-10) .

**Caveat on the "continuous_deployment enabled" premise**: `ReviewStack`s created via `ReviewStackAdapter#create!` are always created with `continuous_deployment: false` [12](#0-11) . For the `ContinuousDeliveryJob`/auto-deploy amplification to apply to a *review stack*, an operator would have had to manually flip that flag afterward — this isn't something the attacker's webhook payload can set. `ContinuousDeliveryJob#perform` itself only checks `stack.continuous_deployment?` and no ownership check [13](#0-12) , so if that precondition holds (a review stack that an operator enabled CD on), the forged label env vars would indeed reach `PTY.spawn` on the next green commit.

### Why existing guards don't stop this

`drop_unhandled_event`, `ExplicitParameters` schema validation, and `Repository`/`Stack` format validators [14](#0-13)  only validate structure/format of individual fields — none of them cross-checks that `repository.owner.login` (used for auth) matches the owner segment of `repository.full_name` (used for the actual write). `verify_signature` operates purely on `repository_owner` and never looks at `full_name` at all [15](#0-14) .

### Impact & Likelihood

An attacker who controls (or names) a GitHub org configured in Shipit without a `webhook_secret` can forge signed-looking webhooks for **any other org's repository** known to Shipit, writing to that victim repository's `PullRequest.labels` unauthenticated. This is a cross-tenant write ("a payload for one repository mutating another's stack") — Critical per the stated impact categories. It requires: (1) multi-org Shipit deployment, (2) at least one configured org lacking `webhook_secret`, (3) knowledge of/target on a victim repo+PR number with an existing non-archived review stack. The label-injection itself is trivially repeatable per request; the auto-deploy amplification additionally requires an operator having enabled `continuous_deployment` on that particular review stack, which is not attacker-controlled.

### Recommendation

In `Shipit::WebhooksController#verify_signature`, after successful signature verification, assert that the org used for verification (`repository_owner`) equals the owner segment parsed from `params.dig('repository','full_name')` (and `organization.login` if present); reject (422) on mismatch, in addition to (or instead of) allowing implicit success on orgs with no `webhook_secret` configured. [16](#0-15)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L70-72)
```ruby
          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L96-98)
```ruby
          def environment
            "pr#{params.number}"
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

**File:** test/lib/shipit/deploy_commands_test.rb (L6-15)
```ruby
  test "#env includes the stack's pull request labels" do
    stack = shipit_stacks(:review_stack)
    deploy = stack.trigger_continuous_delivery
    stack.pull_request.labels = ["wip", "bug"]

    env = Shipit::DeployCommands.new(deploy).env

    assert_equal env["WIP"], "true"
    assert_equal env["BUG"], "true"
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

**File:** app/models/shipit/repository.rb (L41-45)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }
```
