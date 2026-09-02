### Title
`review_stacks_enabled` toggle bypassed by operator precedence in `provision?`, allowing unauthorized ReviewStack creation - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` intends `review_stacks_enabled` to gate all review-stack provisioning, but due to Ruby's `&&`/`||` precedence, `review_stacks_enabled` only scopes the `allow_all` branch. When `provisioning_behavior` is `allow_with_label` (or `prevent_with_label`), a `ReviewStack` is created regardless of `review_stacks_enabled`, letting any GitHub user who can open a PR with the configured label on a tracked repo create a Shipit stack the operator never opted into.

### Finding Description
The broken binding: `repository.review_stacks_enabled` (operator-set gate, `false`) is claimed to equal "the value gating stack creation for all provisioning behaviors," but it only gates the `allow_all?` disjunct.

`provision?` is:
```ruby
repository.review_stacks_enabled &&
  repository.provisioning_behavior_allow_all? ||
  (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
  (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
``` [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`.

So `review_stacks_enabled` never participates in the second or third clauses. With `review_stacks_enabled = false` and `provisioning_behavior = :allow_with_label`, an attacker who opens a PR labeled `deploy-me` (the configured `provisioning_label_name`) makes `provision?` return `true`.

The call chain confirms nothing else blocks this: `process` only checks `respond_to_pull_request_opened?` (action == "opened" && `provision?`) before invoking `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [2](#0-1) . `ReviewStackAdapter#create!` unconditionally builds a `ReviewStack` from `stack_attributes` (branch from `params.pull_request.head.ref`, environment `pr#{number}`) with no re-check of `review_stacks_enabled` [3](#0-2) . The `scope: repository.review_stacks` is just the `has_many :review_stacks` association [4](#0-3)  — it does not filter by the enabled flag. `review_stacks_enabled` and `provisioning_behavior` are operator-controlled settings exposed via `RepositoriesController#update_params`, meant to be an authorization boundary set by the repo owner in Shipit [5](#0-4) .

Standard guards (webhook signature verification, `ExplicitParameters` schema, `drop_unhandled_event`) validate the payload's structure and authenticity but do not evaluate this logic gap — they don't know that `review_stacks_enabled` is supposed to independently gate every provisioning behavior.

Exploit flow: attacker opens a pull request on a tracked repository (or any repo whose owner enabled `allow_with_label` but left `review_stacks_enabled` off, expecting no provisioning at all) with a label matching `provisioning_label_name`, and the webhook fires `pull_request`/`opened`. `provision?` returns true, and a new `Shipit::Stack`/`ReviewStack` row is created and queued for provisioning, despite the operator's explicit `review_stacks_enabled = false` setting.

### Impact Explanation
This is an unauthorized record write: a `ReviewStack` (with associated `PullRequest`) is created for a repository whose operator never enabled review stacks. `ReviewStackProvisioningQueue.add(stack)` is also invoked, kicking off deployment/provisioning workflows the operator did not opt into [6](#0-5) . The effect is scoped to repositories that already have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` — it does not cross tenant/repository boundaries beyond that repo, and it does not directly leak secrets or achieve RCE by itself, but it does trigger an unauthorized provisioning action (stack creation and queuing) that the "Critical" bucket describes as "an unauthorized deploy... or a record written for a repository that did not authenticate it."

### Likelihood Explanation
Preconditions: the target repository must already be tracked in Shipit with `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) and `provisioning_label_name` configured — this requires the operator to have partially opted in to provisioning but explicitly left `review_stacks_enabled` off, presumably believing that flag is a master switch. The attacker only needs the ability to open a PR and apply the matching label (or, for `prevent_with_label`, simply not apply an excluded label) — no Shipit credentials required. This is fully repeatable per matching repository/PR.

### Recommendation
Add parentheses so `review_stacks_enabled` gates the entire expression:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to the equivalent logic in `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler` if they share this pattern.

### Proof of Concept
Minitest plan (e.g. `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create a `Shipit::Repository` fixture/record with `review_stacks_enabled: false`, `provisioning_behavior: :allow_with_label`, `provisioning_label_name: 'deploy-me'`.
2. Build a valid `pull_request` `opened` payload for that repo's `full_name`, with `pull_request.labels` containing `{ "name" => "deploy-me" }`.
3. Assert both sides of the binding before invoking: `repository.review_stacks_enabled` is `false`, so no stack should be created.
4. Call `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(payload).process`.
5. Assert `Shipit::Stack.count` (or `repository.review_stacks.count`) increased by 1 — demonstrating that despite `review_stacks_enabled == false`, a `ReviewStack` was created, proving the binding is broken.

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

**File:** app/models/shipit/repository.rb (L47-48)
```ruby
    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy
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
