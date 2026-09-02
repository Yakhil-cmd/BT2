### Title
Operator precedence bug in `provision?` bypasses `review_stacks_enabled` check - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` with the provisioning-behavior clauses using `&&`/`||` without parentheses, so Ruby operator precedence groups it as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`. As a result, when `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), the PR is provisioned regardless of `review_stacks_enabled`, even if it is `false`.

### Finding Description
The binding that should hold is: `repository.review_stacks_enabled == true` must gate *all* provisioning paths, i.e. `provision?` should equal `repository.review_stacks_enabled && (allow_all? || (allow_with_label? && label) || (prevent_with_label? && !label))`. Instead, the actual code is: [1](#0-0) 

Because `&&` binds tighter than `||`, this evaluates as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)` — the second and third disjuncts never reference `review_stacks_enabled` at all.

Path: `OpenedHandler#process` calls `respond_to_pull_request_opened?`, which calls `provision?` [2](#0-1) . If it returns true, `ReviewStackAdapter#find_or_create!` is invoked scoped to `repository.review_stacks`; since no matching stack exists yet, `create!` persists a new `ReviewStack` with `branch: params.pull_request.head.ref` (fully attacker-controlled) and `environment: "pr#{params.number}"`, then calls `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) . This enqueues the stack via `stack.enqueue_for_provisioning` [4](#0-3)  for later processing by `ReviewStackProvisioningQueue#work`, which calls `stack.provisioner.provision?` and `stack.provision` for queued stacks [5](#0-4) .

No existing guard prevents this divergence: `respond_to_pull_request_opened?` only checks `params.action == "opened"` before calling the buggy `provision?`; there is no separate `review_stacks_enabled` check anywhere else in this handler. The attacker only needs to open a same-org PR (webhook signature validity for the PR's own org is a given precondition per the question, not something the attacker needs to forge) and label it with the repo's configured `provisioning_label_name`.

### Impact Explanation
A `ReviewStack` record is created and enqueued for a repository whose owner explicitly set `review_stacks_enabled: false`, using an attacker-controlled `branch` value taken directly from `pull_request.head.ref`. This is an unauthorized record write for a repository configuration the owner disabled, and it feeds the provisioning queue which downstream can lead to execution of `shipit.yml`/provisioning tasks from the attacker's branch (via `stack.provision`, ultimately reaching `Command`/`PTY.spawn`), matching the "unauthorized deploy" / "record written for a repository that did not authorize it" impact categories. This is repeatable against any repository configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) that also happens to have `review_stacks_enabled: false` — a configuration state that is plausible if an operator disables review stacks after having configured a label-based behavior, or misconfigures the two independently since nothing in the UI/model enforces their consistency.

### Likelihood Explanation
Preconditions are narrow but realistic: `repository.review_stacks_enabled == false` AND `repository.provisioning_behavior` set to `allow_with_label` (attacker must also apply the configured label to their own PR — trivial since PR authors can label their own PRs in many repo configurations, or the labeled_handler path is separately reachable) or `prevent_with_label` (default state, no label needed). Attacker cost is a single PR open action from an account with PR-opening rights on the org's repo; no secrets, tokens, or elevated GitHub permissions are required. The bug is deterministic and fully repeatable for any repository in this misconfigured state.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire expression:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (
      repository.provisioning_behavior_allow_all? ||
      (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
      (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
    )
end
```

### Proof of Concept
Minitest integration test under `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (existing coverage in this file already tests analogous scenarios):
1. Create a `Repository` fixture with `review_stacks_enabled: false` and `provisioning_behavior: "allow_with_label"`, `provisioning_label_name: "deploy-preview"`.
2. Build `pull_request opened` webhook params with `labels: [{name: "deploy-preview"}]` and `head.ref` set to an attacker-chosen branch string.
3. Invoke `OpenedHandler.new(params).process` (or post through the webhooks endpoint).
4. Assert `Shipit::ReviewStack.find_by(environment: "pr#{number}")` is present (LHS: `repository.review_stacks_enabled` is `false`; RHS: a `ReviewStack` was nonetheless created — the two do not match, proving the binding violation), and assert it was enqueued via `awaiting_provision: true` / `enqueue_for_provisioning`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-63)
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
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
