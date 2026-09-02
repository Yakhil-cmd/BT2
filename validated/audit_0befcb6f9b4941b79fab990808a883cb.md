### Title
Operator precedence bug in `OpenedHandler#provision?` bypasses `review_stacks_enabled=false` for `allow_with_label`/`prevent_with_label` repositories - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` intends to enforce the binding `review_stacks_enabled_as_configured == review_stacks_enabled_as_enforced` — i.e., no review stack should ever be provisioned if `Repository#review_stacks_enabled` is `false`, regardless of `provisioning_behavior`. Because `&&` binds tighter than `||`, the `review_stacks_enabled` check only guards the `allow_all?` branch; the `allow_with_label?` and `prevent_with_label?` branches are unconditional disjuncts that ignore `review_stacks_enabled` entirely.

### Finding Description
The claimed binding: `repository.review_stacks_enabled == false` should imply `provision? == false` for every `provisioning_behavior`. The actual code is: [1](#0-0) 

Due to Ruby operator precedence this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So when `review_stacks_enabled == false`, `provisioning_behavior == "allow_with_label"`, and the PR carries the label matching `repository.provisioning_label_name`, the second disjunct alone evaluates to `true`, making `provision?` return `true`. The same happens for `prevent_with_label` when the label is absent. This directly contradicts the intended "kill switch" semantics of `review_stacks_enabled`.

Path: `respond_to_pull_request_opened?` calls `provision?` [2](#0-1) , and when true, `process` invokes `ReviewStackAdapter#find_or_create!`, which unconditionally creates a `ReviewStack` scoped to `repository.review_stacks` when none exists [3](#0-2) [4](#0-3) . Nowhere else in `ReviewStackAdapter#create!` or `Repository`/`NullRepository` is `review_stacks_enabled` re-checked as a second line of defense [5](#0-4) [6](#0-5) . Signature verification on the webhook controller only authenticates that the payload came from GitHub for the configured repository; it says nothing about whether the payload's *contents* (PR opened by an untrusted contributor, label attached) should authorize provisioning, so it does not close this gap.

Once created, the `ReviewStack`'s `branch` is taken directly from `params.pull_request.head.ref`, an attacker-controlled value, and the stack is queued into `ReviewStackProvisioningQueue`, from which downstream provisioning executes the repository's `shipit.yml`/deploy steps on the deploy host — i.e., the attacker's own PR content drives execution despite the operator explicitly disabling review stacks for that repository.

### Impact Explanation
For any `Repository` where an operator set `review_stacks_enabled=false` (intending to fully disable this feature) but left `provisioning_behavior` at `allow_with_label` (or `prevent_with_label`), an unprivileged PR author who can attach the configured label to their own PR triggers unauthorized `ReviewStack` creation and provisioning-queue enqueuing for a repository whose review-stack feature was supposed to be off. This leads to execution of attacker-authored branch content (via the provisioning/deploy pipeline) on the deploy host — Critical, matching "unauthorized deploy" / RCE via attacker-controlled repository content. The blast radius is scoped to repositories misconfigured this way (any tenant/repo with this specific flag combination), and is repeatable per PR/repo.

### Likelihood Explanation
Requires: (1) a `Repository` configured with `review_stacks_enabled=false` and `provisioning_behavior` in `{allow_with_label, prevent_with_label}` — a plausible operator configuration when partially rolling back the feature without changing the label policy; (2) the attacker must be able to open a PR and (for `allow_with_label`) apply the specific label, or (for `prevent_with_label`) simply not apply it (the default state), which is the lower-cost path requiring no special label permission at all. No secrets, tokens, or privileged roles are needed beyond normal PR-opening ability against a repo already integrated with Shipit.

### Recommendation
Fix operator precedence by explicitly parenthesizing so `review_stacks_enabled` gates all branches:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, illustrative — implementation left to the fix owner):
1. Create a `Repository` fixture/record with `review_stacks_enabled: false`, `provisioning_behavior: "allow_with_label"`, `provisioning_label_name: "deploy-preview"`.
2. Build `pull_request.opened` webhook params with `action: "opened"`, `pull_request.labels: [{name: "deploy-preview"}]`, `pull_request.head.ref` set to an attacker-chosen branch, and `repository.full_name` matching the fixture.
3. Assert, BEFORE fix: `OpenedHandler.new(params).send(:provision?) == true` even though `repository.review_stacks_enabled == false` (binding broken: `review_stacks_enabled_as_configured (false) != review_stacks_enabled_as_enforced (true)`).
4. Assert `OpenedHandler.new(params).process` results in `Shipit::ReviewStack.exists?(repository: repository, environment: "pr<number>")` being `true`.
5. AFTER fix: assert `provision? == false` and no `ReviewStack` row is created, restoring `review_stacks_enabled_as_configured == review_stacks_enabled_as_enforced`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-63)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-69)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L19-21)
```ruby
          def find_or_create!
            stack || create!
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
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

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** app/models/shipit/repository.rb (L17-31)
```ruby
    def review_stacks_enabled
      false
    end

    def provisioning_behavior_allow_all?
      false
    end

    def provisioning_behavior_allow_with_label?
      false
    end

    def provisioning_behavior_prevent_with_label?
      false
    end
```
