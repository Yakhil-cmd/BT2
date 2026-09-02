### Title
`OpenedHandler#provision?` operator-precedence bug lets `review_stacks_enabled` be bypassed for `allow_with_label`/`prevent_with_label` repos - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` only ANDs `repository.review_stacks_enabled` with `provisioning_behavior_allow_all?`, due to Ruby's `&&`/`||` precedence, and never applies that flag to the `allow_with_label` or `prevent_with_label` branches. An operator who disables `review_stacks_enabled` while `provisioning_behavior` is still `allow_with_label` (or `prevent_with_label`) leaves the repository provisionable by any PR that carries (or omits) the configured label.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == false` **implies** `OpenedHandler#provision? == false` for every PR, for that repository, regardless of `provisioning_behavior`.

The actual code is:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

In Ruby, `&&` binds tighter than `||`, so this evaluates as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`.

`review_stacks_enabled` is only scoped to the first disjunct. If the repository has `provisioning_behavior = :allow_with_label` (or `:prevent_with_label`), the second/third disjuncts are evaluated **independently of `review_stacks_enabled`**, so `provision?` can return `true` even when `review_stacks_enabled` is `false`.

Exact reachable path: attacker opens a PR against the tracked repository with the configured provisioning label attached (or, for `prevent_with_label`, simply opens a PR without the label). GitHub delivers a `pull_request` `opened` webhook, which — after signature verification (out of scope of this bug) — is routed to `OpenedHandler#process`, which calls `respond_to_pull_request_opened?` → `provision?` [2](#0-1) . Since `provision?` returns `true` despite `review_stacks_enabled == false`, `ReviewStackAdapter#find_or_create!` creates a `ReviewStack` record and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) . The background queue worker then calls `stack.provision` for any stack found in `queued_stacks` with no additional `review_stacks_enabled` check [4](#0-3) , which drives the actual provisioning/deploy commands for attacker-controlled branch/environment content.

No existing guard prevents this: `respond_to_pull_request_opened?` only filters on `params.action == "opened"`; there is no repository-level check anywhere else in the pipeline (`ReviewStackAdapter`, `ReviewStackProvisioningQueue#provision`) that re-verifies `review_stacks_enabled` before creating or provisioning the stack. The existing test suite confirms this gap: `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`'s only `review_stacks_enabled: false` test uses `behavior: :allow_all` [5](#0-4) ; the `allow_with_label` and `prevent_with_label` tests never disable `review_stacks_enabled`, leaving the precedence bug untested [6](#0-5) .

### Impact Explanation
Any unprivileged actor able to open a pull request (and apply/omit the configured label) against a repository whose operator believes review stacks are fully disabled can force Shipit to create a `ReviewStack` and drive it through provisioning — running the repository's deploy/provision commands against attacker-controlled branch content. This is a write for a repository whose operator did not authorize provisioning (they explicitly disabled `review_stacks_enabled`), and provisioning ultimately executes commands on the deploy host, matching the Critical category ("a command running that should not... an unauthorized deploy"). The bug is repeatable for every PR opened against that specific repository as long as the misconfiguration (`review_stacks_enabled: false` + stale `provisioning_behavior`) persists; it does not cross repository tenant boundaries by itself but is a full authorization bypass of the per-repository opt-out control for that repository/tenant.

### Likelihood Explanation
Preconditions: the repository must have previously been configured with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, and an operator later flips `review_stacks_enabled` to `false` without resetting `provisioning_behavior` back to a neutral/disabled state — a plausible, low-effort operational mistake described in the question. No Shipit secrets, sessions, or GitHub App credentials are required by the attacker; they only need PR-opening capability (and, per the ground rules, the ability to label their own PR) against the target repository. This makes the exploit cheap and directly repeatable.

### Recommendation
Fix operator precedence so `review_stacks_enabled` gates all branches, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the equivalent fix to any other handler with the same expression pattern (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb` were flagged in the earlier grep as containing similar `provisioning_behavior`/`review_stacks_enabled` logic and should be audited for the same precedence mistake).

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (or equivalent minitest file):
```ruby
test "does not create stacks when review_stacks_enabled is false, even for allow_with_label with label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end

test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label with label absent" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Both assertions currently fail against the unpatched `provision?` implementation (a `Shipit::Stack`/`Shipit::ReviewStack` is created despite `review_stacks_enabled == false`), and pass once `provision?` is rewritten to gate all branches on `review_stacks_enabled`.

### Citations

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L17-37)
```ruby
    def work
      queued_stacks.find_each(&method(:provision))
    end

    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
    end

    private

    def provision(stack)
      if stack.provisioner.provision?
        stack.provision
      else
        Rails.logger.info(
          "Putting review ReviewStack<#{stack.id}> back into the provisioning queue - #provision? was falsey."
        )
      end
    end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L129-187)
```ruby
          test "creates stacks for repos that allow_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos that allow_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :allow_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "create stacks for repos what prevent_with_label when label is absent" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] = []

            assert_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end

          test "does not create stacks for repos what prevent_with_label when label is present" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              behavior: :prevent_with_label,
              label: "pull-requests-label"
            )
            payload = payload_parsed(:pull_request_opened)
            payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload).process
            end
          end
```
