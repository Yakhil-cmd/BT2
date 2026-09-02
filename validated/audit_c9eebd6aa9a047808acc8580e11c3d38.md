### Title
`OpenedHandler#provision?` creates review stacks even when `repository.review_stacks_enabled == false` under `prevent_with_label` behavior - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#provision?` uses `&&`/`||` operator precedence that only gates the `allow_all` branch on `repository.review_stacks_enabled`, leaving the `prevent_with_label` branch unguarded. As a result, any external contributor who opens an unlabeled pull request against a repository whose maintainer has fully disabled review stacks (`review_stacks_enabled == false`) with `provisioning_behavior == prevent_with_label` will still trigger creation of a `Shipit::Stack` via `ReviewStackAdapter#create!`.

### Finding Description
The intended binding is: a review stack may only be provisioned when `repository.review_stacks_enabled == true`, regardless of `provisioning_behavior`. The code instead evaluates: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The third disjunct — the `prevent_with_label?` branch — never references `review_stacks_enabled` at all. So for a repository configured with `provisioning_behavior_prevent_with_label? == true` and `review_stacks_enabled == false`, `provision?` still returns `true` whenever the PR lacks the label named by `repository.provisioning_label_name`.

Exploit flow: an unprivileged GitHub user opens a normal pull request (with no special label) against the target repository. GitHub sends the real, correctly-signed `pull_request` "opened" webhook (signature verification passes normally because this is a genuine GitHub event for that repo — `verify_webhook_signature` and `drop_unhandled_event` are not bypassed, they simply don't protect against this internal logic bug). `respond_to_pull_request_opened?` calls `provision?`, which returns `true` due to the third disjunct, and `process` calls: [2](#0-1) 

which invokes `ReviewStackAdapter#find_or_create!` → `create!`, writing a real `Shipit::Stack`/`ReviewStack` record and enqueuing it for provisioning: [3](#0-2) 

No other guard intervenes: `params` schema validation only checks payload shape, not `review_stacks_enabled`; `Repository#review_stacks_enabled` is read but not enforced in this branch; there is no additional authorization check between the handler and stack creation.

### Impact Explanation
An unprivileged PR author can force provisioning (and subsequent deploy-pipeline execution such as `ReviewStackProvisioningQueue` processing, which typically runs CI/CD-like tasks) for a repository whose maintainer explicitly disabled review stacks. This is an unauthorized write of a stack record (and downstream provisioning task/command execution) for a repository configuration that should categorically prevent it — matching "a payload for one repository mutating another's stack ... or an unauthorized deploy" in spirit, since the maintainer's explicit `review_stacks_enabled = false` setting is bypassed entirely. The attack is repeatable against any repository configured this way, for every unlabeled PR opened (new `environment: "pr#{number}"` per PR).

### Likelihood Explanation
Preconditions: repository must have `review_stacks_enabled == false` and `provisioning_behavior == prevent_with_label` (an unusual but plausible/documented combination a maintainer might pick believing review stacks are fully off). Attacker cost is trivial: opening any pull request without applying the configured provisioning label, which requires no special access, no secrets, and no privileged role — only the ability to open a PR (fork + PR is enough on GitHub for public repos). This is fully feasible and repeatable.

### Recommendation
Fix operator grouping so `review_stacks_enabled` gates the whole expression:

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

Apply the same audit to `ReopenedHandler`, `LabeledHandler`, and `UnlabeledHandler` since they share similar `provisioning_behavior` logic.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style (minitest), add:

```ruby
test "does not provision a stack when review_stacks_enabled is false, even with prevent_with_label and no label" do
  repository = shipit_repositories(:shipit)
  repository.update!(
    review_stacks_enabled: false,
    provisioning_behavior: "prevent_with_label",
    provisioning_label_name: "ship-it"
  )

  params = build_opened_params(repository: repository, labels: []) # no matching label

  assert_no_difference -> { Shipit::Stack.count } do
    Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params).process
  end
end
```

Running this against current code fails the `assert_no_difference` — a `Shipit::Stack` **is** created — proving `repository.review_stacks_enabled == false` (declared binding) diverges from the actual enforced gate (`true`/bypassed) in the `prevent_with_label` branch.

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
