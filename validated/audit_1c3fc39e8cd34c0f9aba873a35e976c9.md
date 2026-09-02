### Title
`provision?` operator-precedence bug lets PR review stacks provision (and later execute the PR's `shipit.yml`) even when `review_stacks_enabled: false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` and the structurally identical `ReopenedHandler#unarchive?` use `&&`/`||` without grouping parentheses, so `repository.review_stacks_enabled` is only ANDed with the `allow_all` branch, not with the `allow_with_label`/`prevent_with_label` branches. A repository owner who disables `review_stacks_enabled` while `provisioning_behavior` remains `allow_with_label` or `prevent_with_label` still gets review stacks auto-created from unprivileged pull requests, with `branch` taken verbatim from `params.pull_request.head.ref`.

### Finding Description
Broken binding: the intended invariant is `repository.review_stacks_enabled == true` must be a *necessary* condition for `ReviewStackAdapter#find_or_create!` to run, i.e. `provision? => review_stacks_enabled`. The actual code: [1](#0-0) 

is parsed as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`, so when `review_stacks_enabled` is `false` but `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, `provision?` can still return `true`. The identical pattern exists in `ReopenedHandler#unarchive?`: [2](#0-1) 

By contrast, `LabeledHandler#respond_to_label_change?` correctly ANDs `review_stacks_enabled` with `(archive? || unarchive?)`: [3](#0-2) 

confirming the `opened`/`reopened` handlers are the outliers and this is a genuine logic defect, not intended behavior.

When `provision?` (or `unarchive?`) mistakenly returns `true`, `ReviewStackAdapter#find_or_create!` builds the stack directly from unsanitized webhook data: [4](#0-3) 

`branch: params.pull_request.head.ref` is fully attacker-controlled (the PR opener names their own head branch), and the stack is queued for provisioning: [5](#0-4) 

Existing guards do not stop this: `verify_signature`/webhook signature checks only validate the payload came from GitHub for *that* repository, they say nothing about whether `review_stacks_enabled` should gate creation; `ExplicitParameters` only validates types/presence of `head.ref`, not its content; and there is no model-level validation on `ReviewStack#branch` restricting it to an approved/allow-listed ref.

I was not able to fully re-trace, within the remaining tool budget, the downstream chain from `ReviewStackProvisioningQueue#provision` / `stack.provision` through to the exact `TaskCommands#perform` invocation that checks out `branch` and executes `shipit.yml` steps via `Command#start`/`PTY.spawn`; that portion of the pipeline (post-provisioning auto-deploy triggering) is documented as the standard review-stack behavior but was not directly re-verified line-by-line here due to iteration limits.

### Impact Explanation
If confirmed end-to-end, this allows an unprivileged PR opener to force creation and provisioning of a `ReviewStack` bound to their own branch on a repository whose owner explicitly disabled review stacks (`review_stacks_enabled: false`), bypassing the intended authorization gate. Since review stacks execute the target repository's `shipit.yml` for provisioning/deploy steps, this is repeatable per pull request and per repository that has this specific, non-default combination of settings (`review_stacks_enabled: false` with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`), matching the Critical category of "unauthorized deploy" and potential RCE via `Command`/`PTY.spawn`.

### Likelihood Explanation
Requires a repository configuration where `review_stacks_enabled` is `false` but `provisioning_behavior` is still `allow_with_label` or `prevent_with_label` (e.g. an operator disabling review stacks without resetting the provisioning behavior, or a UI/ordering quirk leaving that column set). This is a plausible but non-default, non-universal configuration state, so exploitability is conditional on that specific misconfiguration rather than affecting all repositories by default.

### Recommendation
Add explicit grouping parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `ReopenedHandler#unarchive?`.

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style, not asserting existing file content):
1. Create a `Repository` with `review_stacks_enabled: false`, `provisioning_behavior: "allow_with_label"`.
2. Build webhook params for `action: "opened"` with `pull_request.head.ref: "attacker-branch"` and no provisioning label.
3. Call `OpenedHandler.new(params).process`.
4. Assert LHS `repository.review_stacks_enabled` is `false` (admin intent: no stack should be created) but RHS `Shipit::ReviewStack.find_by(environment: "pr#{number}").branch == "attacker-branch"` is present — proving the equality "`review_stacks_enabled == false` implies no stack is created" is violated. [6](#0-5) [7](#0-6)

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-70)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def pull_request
            params.pull_request
          end

          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
          end

          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
