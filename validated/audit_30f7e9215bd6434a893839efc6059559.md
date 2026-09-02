### Title
`OpenedHandler#provision?` creates and provisions a review stack even when `review_stacks_enabled` is `false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`OpenedHandler#provision?` is intended to gate review-stack creation on `repository.review_stacks_enabled`, but due to Ruby `&&`/`||` precedence, `review_stacks_enabled` only guards the `allow_all?` branch. When a repository is configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`, any freshly opened, unlabeled pull request satisfies the third disjunct and `provision?` returns `true`, causing a review stack to be created and queued for provisioning despite review stacks being disabled.

### Finding Description
The correct binding should be: `provision? == (review_stacks_enabled && (allow_all? || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)))`. The actual code in `provision?` is: [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`. `review_stacks_enabled` is only ANDed into the first disjunct; the second and third disjuncts are evaluated independently of it.

Any unprivileged GitHub user who can open a pull request against a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` opens a PR without the provisioning label (this is the default state of a brand-new PR — no one has to add anything). `pull_request_has_provisioning_label?` is `false`, `provisioning_behavior_prevent_with_label?` is `true`, so the third disjunct is `true`, making `provision?` return `true` regardless of `review_stacks_enabled`. [2](#0-1) 
`respond_to_pull_request_opened?` then permits `process` to call `ReviewStackAdapter#find_or_create!`, which creates a `ReviewStack` and immediately enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [3](#0-2) 

The provisioning queue worker will then call `stack.provision`, running the repository's provisioning/deploy logic for a repository that was explicitly configured with review stacks disabled: [4](#0-3) 

No other guard in the codebase re-checks `review_stacks_enabled` before this point — it is referenced only inside the sibling handlers' equivalent `provision?`/gating methods (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`), not in `ReviewStackAdapter`, `ReviewStackProvisioningQueue`, or `Stack`/`ReviewStack` models. `Repository#provisioning_behavior_prevent_with_label?` itself is a plain enum predicate and correctly reflects the stored setting; the bug is entirely in how `OpenedHandler#provision?` composes it with `review_stacks_enabled`.

### Impact Explanation
For any repository administrator who intentionally sets `review_stacks_enabled: false` (e.g., to disable the review-stack feature while still keeping `provisioning_behavior` set to `prevent_with_label` from prior configuration), an unprivileged contributor opening a normal, unlabeled pull request causes Shipit to create a `ReviewStack` record and run its provisioning/deploy pipeline — a deploy action that should not occur for that repository. This is repeatable on every new PR opened against such a repository and matches the "unauthorized deploy" Critical impact category. It does not cross tenant boundaries (the created stack belongs to the same repository), but it is an authorization bypass of the `review_stacks_enabled` control itself.

### Likelihood Explanation
Preconditions: a repository must be registered in Shipit with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false` — a configuration state reachable by a maintainer toggling `review_stacks_enabled` off without also resetting `provisioning_behavior`, or vice versa. Attacker cost is trivial: open a pull request (or push to a fork against the tracked repo) with no special label, which is the default state. No secrets, sessions, or elevated GitHub permissions are required. Given this configuration exists, the bypass triggers deterministically and repeatably on every opened PR.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire expression:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Audit the sibling handlers (`labeled_handler.rb`, `unlabeled_handler.rb`, `reopened_handler.rb`) for the identical precedence pattern.

### Proof of Concept
Minitest against `OpenedHandler#send(:provision?)` in isolation:
```ruby
test "provision? returns false when review_stacks_enabled is false even with prevent_with_label and no label" do
  repository = stub(
    review_stacks_enabled: false,
    provisioning_behavior_allow_all?: false,
    provisioning_behavior_allow_with_label?: false,
    provisioning_behavior_prevent_with_label?: true,
    provisioning_label_name: "ship-it"
  )
  handler = Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params_with_no_labels)
  handler.stubs(:repository).returns(repository)

  # Broken binding demonstrated: expected false (review_stacks_enabled == false must dominate),
  # actual current code returns true.
  assert_equal false, handler.send(:provision?)
end
```
Running this against the current implementation fails, returning `true` instead of the expected `false`, confirming the precedence bug and the unauthorized stack creation/provisioning it enables.

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L29-37)
```ruby
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
