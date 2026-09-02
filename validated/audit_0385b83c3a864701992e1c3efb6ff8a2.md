### Title
`OpenedHandler#provision?` operator precedence bypasses `review_stacks_enabled` gate, allowing unauthenticated `ReviewStack` provisioning - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` is written as `a && b || (c && d) || (e && f)`, and Ruby's operator precedence binds `&&` tighter than `||`, so `review_stacks_enabled` only guards the `allow_all` disjunct and not the `allow_with_label`/`prevent_with_label` disjuncts. A repository with `review_stacks_enabled: false` but `provisioning_behavior: allow_with_label` will still have `provision?` return `true` when an attacker's PR carries the configured label, causing a `ReviewStack` to be created with `branch: params.pull_request.head.ref` from an attacker-controlled fork.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` must hold for any branch executed via that repository's review stack. Tracing `OpenedHandler#provision?` [1](#0-0) :

```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

Due to Ruby precedence (`&&` before `||`), this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So when `review_stacks_enabled == false` and `provisioning_behavior == allow_with_label`, the first term is `false`, but the second term `(allow_with_label? && has_label?)` evaluates independently of `review_stacks_enabled` and can be `true` if the PR has the configured label. This makes `respond_to_pull_request_opened?` return `true` [2](#0-1) , which triggers `ReviewStackAdapter#find_or_create!` → `create!`, writing a `ReviewStack` with `branch: params.pull_request.head.ref` taken directly from the webhook payload [3](#0-2) .

The `repository` is resolved purely from `params.repository.full_name` in the webhook payload, with no authentication tying the PR/head ref to a maintainer decision [4](#0-3) . The `repository_controller#update_params` permits any repo maintainer to set `provisioning_behavior` and `provisioning_label_name` independently of `review_stacks_enabled` [5](#0-4) , so a configuration where `review_stacks_enabled == false` but `provisioning_behavior == allow_with_label` is achievable through normal UI usage (e.g., an admin disabling review stacks but leaving other fields unchanged), and this bug then reactivates provisioning despite the disable flag.

Existing guards do not prevent this: `ExplicitParameters` only validates payload *shape*, not intent; webhook signature verification (out of scope of this specific bug) authenticates that GitHub sent the payload, but does not enforce the `review_stacks_enabled` invariant at all — the invariant is purely an application-logic bug in operator precedence. Comparing with `LabeledHandler#respond_to_label_change?`, which correctly ANDs `repository.review_stacks_enabled` with the whole `(archive? || unarchive?)` expression using proper grouping [6](#0-5) , confirms that `OpenedHandler` (and `ReopenedHandler`, which has the identical bug) is missing equivalent parenthesization.

### Impact Explanation
Any attacker who opens a pull request against a repository configured with `provisioning_behavior: allow_with_label` and a known `provisioning_label_name` — regardless of `review_stacks_enabled` — causes Shipit to create a `ReviewStack` and enqueue it for provisioning (`ReviewStackProvisioningQueue.add(stack)`) using `branch: params.pull_request.head.ref`, an attacker-controlled fork branch. Downstream provisioning executes `shipit.yml` deploy steps for that branch, which reach `Command#start`/`PTY.spawn`. This is unauthorized code execution triggered for a repository whose operator explicitly disabled review stacks, matching the Critical RCE category. The attack is repeatable against any repository sharing this misconfiguration pattern (`review_stacks_enabled: false`, `provisioning_behavior: allow_with_label`), and does not require any Shipit credentials — only the ability to open a PR and apply a label the attacker controls on their own fork's PR.

### Likelihood Explanation
This requires a specific repository configuration: `review_stacks_enabled: false` combined with `provisioning_behavior: allow_with_label` (and a set `provisioning_label_name`). This is a plausible real-world state — e.g., an operator who previously enabled review stacks with label-gating and later toggles `review_stacks_enabled` off expecting provisioning to stop, unaware the flag no longer fully gates the `allow_with_label`/`prevent_with_label` paths due to the precedence bug. Once that state exists, the attacker's cost is trivial: open a PR from a fork and add the matching label (labels can typically be applied by anyone with triage access, or the PR author if they have permissions on their own fork PR in certain repo settings) — no secrets or privileged Shipit role needed. It is fully repeatable per PR/repository matching this configuration.

### Recommendation
Add explicit parentheses in `OpenedHandler#provision?` (and the identical `ReopenedHandler#unarchive?`) so that `repository.review_stacks_enabled` gates the entire expression:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
1. Create a `Repository` with `review_stacks_enabled: false`, `provisioning_behavior: 'allow_with_label'`, `provisioning_label_name: 'deploy-preview'`.
2. Build `OpenedHandler` params with `action: 'opened'`, `pull_request.labels: [{name: 'deploy-preview'}]`, `pull_request.head.ref: 'attacker-branch'`.
3. Assert `OpenedHandler.new(params).send(:provision?)` returns `true` (violates the claimed binding `repository.review_stacks_enabled == true`, which is actually `false`).
4. Call `handler.process` (or trigger via webhook) and assert a `Shipit::ReviewStack` row is created with `branch: 'attacker-branch'` for that repository despite `review_stacks_enabled == false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-63)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-98)
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

          def environment
            "pr#{params.number}"
          end
```

**File:** app/controllers/shipit/repositories_controller.rb (L59-65)
```ruby
    def update_params
      params.require(:repository).permit(
        :review_stacks_enabled,
        :provisioning_behavior,
        :provisioning_label_name
      )
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
