### Title
`provision?` skips `review_stacks_enabled` gate for `allow_with_label`/`prevent_with_label` behaviors, allowing PR-triggered stack provisioning on repos with review stacks disabled - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` is written with `&&`/`||` precedence such that `repository.review_stacks_enabled` only gates the `provisioning_behavior_allow_all?` branch, not the `allow_with_label?` or `prevent_with_label?` branches. As a result, a repository with review stacks explicitly disabled but configured with `allow_with_label`/`prevent_with_label` will still have PR-triggered review stacks provisioned via `ReviewStackAdapter#find_or_create!`.

### Finding Description
Binding claimed: `repository.review_stacks_enabled == true` must hold for `provision?` to be `true` under any provisioning behavior. Actual code: [1](#0-0) 

Due to Ruby operator precedence (`&&` binds tighter than `||`), this parses as:

`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So when `review_stacks_enabled == false` and `provisioning_behavior_allow_with_label? == true` and the PR carries the provisioning label, `provision?` evaluates the second disjunct `(true && true)` and returns `true`, regardless of the first disjunct being `false`. This violates the claimed binding: the equality `review_stacks_enabled == true` is false, yet `provision?` still returns `true`.

`process` then unconditionally proceeds: [2](#0-1) 
calling `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, which creates a `ReviewStack` record with `branch: params.pull_request.head.ref` and provisions it via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [3](#0-2) 

Attacker flow: an unprivileged GitHub user opens a PR on a repository whose maintainer set `provisioning_behavior = allow_with_label` and disabled `review_stacks_enabled`, applies the provisioning label to their own PR (label application on one's own PR is attacker-controlled since they own the PR/fork), and the `opened` webhook fires. Existing guards (`verify_signature`, `ExplicitParameters` schema, `drop_unhandled_event`) validate webhook authenticity and payload shape but do not enforce the `review_stacks_enabled` precondition — that enforcement is exactly the buggy boolean expression in `provision?`, so none of them catch this divergence.

### Impact Explanation
This causes an unauthorized deploy-adjacent action: a `ReviewStack` for the attacker's branch/commit is created and queued for provisioning even though the repository maintainer explicitly disabled review stacks (`review_stacks_enabled: false`). This is a policy bypass — the maintainer's explicit "no review stacks" setting is ignored, leading to attacker-controlled code being scheduled for provisioning onto the deploy host infrastructure for that repository. Repeatable for every PR the attacker opens against any repository configured with `allow_with_label`/`prevent_with_label` + `review_stacks_enabled: false`. Blast radius is scoped to that single repository (not cross-tenant, since `repository` and `pull_request.head.ref` are derived from the authenticated webhook payload's own `repository.full_name`), but within that repository it grants provisioning of attacker code despite the review-stacks feature being turned off — matching the Critical category of "cross-boundary provisioning of attacker-controlled code onto the deploy host."

### Likelihood Explanation
Requires: a target repository configured with `provisioning_behavior_allow_with_label` (or `prevent_with_label`) AND `review_stacks_enabled: false` simultaneously — a plausible but non-default combination that depends on repository settings via `app/views/shipit/repositories/settings.html.erb` and `Repository` enum/flag. Attacker cost is trivial: open a PR from a controlled fork and apply a label they control on their own PR. No secrets or privileged roles needed — this is exactly the "unprivileged PR author" threat model. Fully repeatable per PR against the same repository.

### Recommendation
Fix operator precedence in `provision?` to apply `review_stacks_enabled` as a top-level gate for all behaviors, e.g.:

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
In a minitest (e.g. `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`), instantiate `OpenedHandler` with a params double/mock, stub `repository` to return an object where `review_stacks_enabled` returns `false`, `provisioning_behavior_allow_all?` returns `false`, `provisioning_behavior_allow_with_label?` returns `true`, `provisioning_behavior_prevent_with_label?` returns `false`, and stub `pull_request_has_provisioning_label?` (or the PR labels array) to return `true`. Assert:

```ruby
handler = OpenedHandler.new(params)
handler.stubs(:repository).returns(fake_repo) # review_stacks_enabled: false, allow_with_label?: true
assert_equal false, fake_repo.review_stacks_enabled
assert_equal true, handler.send(:provision?)  # binding violated: review_stacks_enabled=false but provision?=true
```

This demonstrates the equality `review_stacks_enabled == true` required by the documented binding is false, while `provision?` still returns `true`, confirming the vulnerability.

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
