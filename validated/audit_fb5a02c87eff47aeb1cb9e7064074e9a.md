### Title
Missing parentheses in `OpenedHandler#provision?` let `prevent_with_label` PRs create Review Stacks even when `review_stacks_enabled == false` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` is written as `A && B || C || D` instead of `A && (B || C || D)`. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` is only ANDed with the `allow_all?` disjunct, so the `prevent_with_label` disjunct is evaluated independently of `review_stacks_enabled`. A repository with `review_stacks_enabled == false` and `provisioning_behavior == prevent_with_label` will still create a `ReviewStack` and enqueue provisioning for any unlabeled pull request.

### Finding Description
The claimed binding is: `review_stacks_enabled == true` must hold for any provisioning decision. The code is: [1](#0-0) 
which Ruby parses as `(review_stacks_enabled && provisioning_behavior_allow_all?) || (provisioning_behavior_allow_with_label? && has_label) || (provisioning_behavior_prevent_with_label? && !has_label)`. The third disjunct never references `review_stacks_enabled`, so when `provisioning_behavior_prevent_with_label?` is true and the PR carries no matching label, `provision?` returns `true` regardless of `review_stacks_enabled`.

`process` calls `respond_to_pull_request_opened?` → `provision?`, and if true, invokes `ReviewStackAdapter#find_or_create!` [2](#0-1) , which creates a `ReviewStack` record and calls `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) , and `.add` calls `stack.enqueue_for_provisioning` [4](#0-3) .

Reaching this code path requires a genuine `pull_request` `opened` webhook dispatched by GitHub for a repository that (a) exists in Shipit as a `Repository` record and (b) has the Shipit GitHub App installed, so that `WebhooksController#verify_signature` — which checks `Shipit.github(organization: repository_owner).verify_webhook_signature` against the real GitHub-computed HMAC — passes [5](#0-4) . Any GitHub user who can open a PR against such a repository (e.g., a public/open-source repo where the app is installed) can trigger this legitimate, correctly-signed webhook without needing any Shipit secret — the payload just needs no label matching `provisioning_label_name` (the default, since attackers control their own PR's labels or simply add none). `ExplicitParameters` schema only validates payload shape, not business logic [6](#0-5) , and no other guard (`drop_unhandled_event`, model validations) checks `review_stacks_enabled` before dispatch. This same operator-precedence flaw is duplicated in `ReopenedHandler#unarchive?` [7](#0-6) , but `LabeledHandler`/`UnlabeledHandler` correctly guard with a separate top-level `repository.review_stacks_enabled &&` check [8](#0-7) , confirming the intended binding and that `OpenedHandler`/`ReopenedHandler` diverge from it.

### Impact Explanation
An operator who disabled review stacks (`review_stacks_enabled = false`) for a repository configured with `provisioning_behavior = prevent_with_label` will still have `ReviewStack` rows created and provisioning jobs queued whenever an unlabeled PR is opened by any external contributor. This is a cross-tenant-state write: an unauthenticated (to Shipit) party causes state creation for a repository whose owner explicitly opted out of the feature. Depending on the host application's registered `ProvisioningHandler`, this can trigger real infrastructure provisioning (e.g., Kubernetes namespace, Heroku app) for a repository/environment that should never be provisioned, and it is repeatable per-PR against every such misconfigured repository the attacker can open PRs against.

### Likelihood Explanation
Preconditions: a `Repository` exists in Shipit with `review_stacks_enabled == false` and `provisioning_behavior == prevent_with_label`, and the Shipit GitHub App is installed on that repository (so the webhook is genuine and signature verification passes). No Shipit credential is needed by the attacker — opening a PR (or a fork PR, if the app watches such events) is sufficient, and simply not applying the provisioning label (the default state for any external contributor) satisfies the condition. This is fully repeatable, one PR per triggering event, with essentially zero attacker cost beyond having a GitHub account.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the whole expression:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (existing pattern uses `configure_provisioning_behavior`):
```ruby
test "does not create stacks when review_stacks_enabled is false, even with prevent_with_label behavior and no label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "opt-out-label"
  )
  payload = payload_parsed(:pull_request_opened) # no labels present

  Shipit::ReviewStackProvisioningQueue.expects(:add).never
  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Binding checked: LHS `repository.review_stacks_enabled` == `false`; RHS (expected gate) requires this to be `true` for any stack creation. Current code allows `provision?` to return `true` and calls `ReviewStackProvisioningQueue.add`, causing the assertion to fail against the intended binding — demonstrating the divergence.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-70)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
```ruby
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
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

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
