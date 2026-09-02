### Title
`OpenedHandler#provision?`/`ReopenedHandler#unarchive?` fail to AND-gate all provisioning branches with `review_stacks_enabled`, letting `review_stacks_enabled=false` repositories still provision/unarchive review stacks via open/reopen events - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb, app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`LabeledHandler#respond_to_label_change?` correctly requires `repository.review_stacks_enabled && (archive? || unarchive?)`, gating every provisioning branch. `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` instead write `repository.review_stacks_enabled && allow_all? || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`, and due to Ruby's `&&`/`||` precedence, `review_stacks_enabled` only gates the `allow_all?` disjunct — the `allow_with_label?` and `prevent_with_label?` disjuncts are evaluated independently of `review_stacks_enabled`.

### Finding Description
Binding claimed: `review_stacks_enabled` gate strength must be identical between `OpenedHandler`/`ReopenedHandler` and `LabeledHandler`/`UnlabeledHandler`. Tracing the code shows this is false.

`LabeledHandler#respond_to_label_change?` (app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb:78-83) and `UnlabeledHandler#respond_to_label_change?` (app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb:79-84) both write: [1](#0-0) 
`review_stacks_enabled && (archive? || unarchive?)` — the flag is the outer conjunct over the whole disjunction, so if `review_stacks_enabled` is `false`, no label-driven mutation can occur regardless of `provisioning_behavior` or label state.

`OpenedHandler#provision?` (app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70) and `ReopenedHandler#unarchive?` (app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:70-75) instead write: [2](#0-1) 
Because `&&` binds tighter than `||` in Ruby, this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. `review_stacks_enabled` only participates in the first term; the second and third terms — which govern the `allow_with_label` and `prevent_with_label` provisioning behaviors that repository owners actually use — are entirely independent of `review_stacks_enabled`.

Exploit path: a repository is configured with `review_stacks_enabled=false` and `provisioning_behavior=allow_with_label` with `provisioning_label_name="preview"` (a plausible admin state: review stacks disabled while a legacy/label config remains, or an operator toggles the flag off expecting it to fully disable review-stack automation as it does for `LabeledHandler`). An attacker who can open/label/reopen a PR on that repository:
- Sends a `labeled` webhook with the `preview` label → `LabeledHandler` correctly no-ops because `review_stacks_enabled` is `false`.
- Instead opens a new PR that already carries the `preview` label, or closes+reopens an existing PR carrying the label → `OpenedHandler#provision?` / `ReopenedHandler#unarchive?` evaluate `(allow_with_label? && has_label?)` = `true`, ignoring `review_stacks_enabled`, and `ReviewStackAdapter#find_or_create!`/`#unarchive!` create/enqueue the stack (app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:19-21,37-50), calling `Shipit::ReviewStackProvisioningQueue.add(stack)` which drives real provisioning automation.

No existing guard intercepts this: `respond_to_pull_request_opened?`/`respond_to_pull_request_reopened?` only check `params.action`, and the flawed `provision?`/`unarchive?` are the sole authorization checks for stack creation/unarchival on these two paths.

### Impact Explanation
An attacker who controls only their own PR's labels (in scope per the attacker capability list) can cause `Shipit::Stack`/`Shipit::ReviewStack` records to be created and enqueued for provisioning on a repository whose administrator explicitly disabled review stacks (`review_stacks_enabled=false`), purely by routing through `opened`/`reopened` webhook events instead of `labeled`. This is a handler-selection bypass of a control that is provably correct on the sibling `LabeledHandler`/`UnlabeledHandler` paths, causing unintended provisioning-queue work and stack lifecycle mutation for a repository that opted out of the feature.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled=false` combined with `provisioning_behavior_allow_with_label` (or `prevent_with_label`) and a known `provisioning_label_name` — a configuration state that is plausible (e.g., an operator toggling `review_stacks_enabled` off later without resetting `provisioning_behavior`). Given that, the attacker cost is trivial: open a PR with the matching label, or close/reopen a PR — both are ordinary, unprivileged PR actions available to anyone able to open a PR against the tracked repository, no secrets or elevated GitHub roles required. It is repeatable per PR/webhook delivery.

### Recommendation
Add explicit parentheses in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` so `review_stacks_enabled` gates the entire disjunction, matching `LabeledHandler`/`UnlabeledHandler`:
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
minitest plan (both files under `test/models/shipit/webhooks/handlers/pull_request/`):
1. Configure `shipit_repositories(:shipit)` with `review_stacks_enabled: false`, `provisioning_behavior: :allow_with_label`, `provisioning_label_name: "pull-requests-label"`.
2. `payload = payload_parsed(:pull_request_opened)`; append `{"name" => "pull-requests-label"}` to `payload["pull_request"]["labels"]`.
3. Assert `LabeledHandler.new(payload.merge(action: "labeled")).process` produces `assert_no_difference -> { Shipit::Stack.count }`.
4. Assert `OpenedHandler.new(payload).process` (action `"opened"`) produces `assert_difference -> { Shipit::Stack.count }` — demonstrating `review_stacks_enabled=false` is honored by `LabeledHandler` but bypassed by `OpenedHandler` for the identical `provisioning_behavior`/label state.
5. Repeat with an archived stack + `ReopenedHandler` (action `"reopened"`) to show `unarchive?` re-provisions despite `review_stacks_enabled=false`.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
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
