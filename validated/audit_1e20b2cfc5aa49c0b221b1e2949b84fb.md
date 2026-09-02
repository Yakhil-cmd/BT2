### Title
`ReopenedHandler#unarchive?` operator-precedence bug bypasses `review_stacks_enabled: false` for `allow_with_label`/`prevent_with_label` repos - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` combines `repository.review_stacks_enabled` with three provisioning-behavior disjuncts using `&&`/`||` without parentheses. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` only gates the `allow_all` branch; the `allow_with_label` and `prevent_with_label` branches fire independently of it. A repository owner who has disabled review stacks but left a stale `provisioning_behavior` can still trigger stack unarchival/provisioning by reopening a labeled PR.

### Finding Description
The claimed binding is: `unarchive? == true` should require `repository.review_stacks_enabled == true` for every provisioning behavior. The code in `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:70-75`:

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. Unlike `LabeledHandler#respond_to_label_change?` and `UnlabeledHandler#respond_to_label_change?`, which explicitly AND `repository.review_stacks_enabled` at the outer gating level (`app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:78-83`, `unlabeled_handler.rb:79-84`) [2](#0-1) [3](#0-2) , `ReopenedHandler#respond_to_pull_request_reopened?` relies solely on `unarchive?` for gating, with no outer `review_stacks_enabled` check:
```ruby
def respond_to_pull_request_reopened?
  params.action == "reopened" &&
    unarchive?
end
``` [4](#0-3) 

Exploit flow: repository has `review_stacks_enabled: false`, `provisioning_behavior: :allow_with_label`, `provisioning_label_name: "pull-requests-label"`. Attacker (any contributor/owner of that GitHub repo) opens a PR, adds the label, closes it, then reopens it. GitHub emits a legitimately-signed `pull_request` `reopened` webhook (signature verification in `WebhooksController#verify_signature` / `GithubApp#verify_webhook_signature` passes normally since this is a real GitHub-originated event, not a forged one) [5](#0-4) [6](#0-5) . `ReopenedHandler#process` calls `stack.unarchive!` on the `ReviewStackAdapter`, which for a missing stack calls `create!` (enqueuing `ReviewStackProvisioningQueue.add`) or for an archived stack unarchives it and enqueues `GithubSyncJob` [7](#0-6) , despite `review_stacks_enabled` being `false`. This bypasses the repository administrator's explicit decision to disable review-stack provisioning for that repo.

### Impact Explanation
A repository configured with `review_stacks_enabled: false` should never provision or unarchive review stacks regardless of `provisioning_behavior`. This bug allows any contributor able to label/reopen their own PR to force a stack into `awaiting_provision`, enqueuing `GithubSyncJob` and, eventually, task provisioning that executes `shipit.yml` commands from the attacker's branch via `Command#start`/`PTY.spawn`. This is scoped to the attacker's own repository/stack (not cross-tenant), but it defeats the intended kill-switch (`review_stacks_enabled = false`) that operators rely on to prevent exactly this kind of automatic command execution from PR branches.

### Likelihood Explanation
Preconditions: the repository must have `review_stacks_enabled: false` and `provisioning_behavior` set to `:allow_with_label` or `:prevent_with_label` (a plausible transitional/misconfigured state, e.g. an admin disables review stacks but leaves the behavior field set). The attacker only needs the ability to open/label/reopen a PR against that repository — normal contributor capability, no secrets needed. It is repeatable on every reopen event against that repository as long as the config remains in this state.

### Recommendation
Parenthesize the boolean expression so `review_stacks_enabled` gates all three disjuncts, matching `LabeledHandler`/`UnlabeledHandler`:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `OpenedHandler#provision?`, which has the identical precedence bug.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`:
```ruby
test "does NOT unarchive/provision stacks when review_stacks_enabled is false, even with allow_with_label + matching label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_enqueued_jobs only: GithubSyncJob do
    Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process
  end

  assert stack.reload.archived?, "Expected stack to remain archived because review_stacks_enabled is false"
end
```
Before the fix this assertion fails: `unarchive?` returns `true` (because `provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?` is `true` regardless of `review_stacks_enabled`), `stack.unarchive!` runs, `GithubSyncJob` is enqueued, and `stack.reload.archived?` is `false` — confirming the binding `review_stacks_enabled == false ⇒ unarchive? == false` is broken.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L65-83)
```ruby
          def respond_to_pull_request_reopened?
            params.action == "reopened" &&
              unarchive?
          end

          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-84)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-85)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end

          def user
            @user ||= Shipit::User.find_or_create_by_login!(params.sender["login"])
          end

          private

          attr_reader :params, :scope

          def action
            params.action
          end

          def repo_name
            params.repository["full_name"]
          end

          def pr_number
            params.number
          end

          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end
```
