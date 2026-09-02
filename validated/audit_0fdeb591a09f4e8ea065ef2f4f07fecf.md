### Title
`provision?` operator-precedence bug lets `allow_with_label`/`prevent_with_label` provisioning behaviors bypass `review_stacks_enabled=false` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
The binding the codebase intends is `review_stacks_enabled == true` for *any* review stack ever to be created for a repository, regardless of `provisioning_behavior`. Due to missing parentheses in `OpenedHandler#provision?`, `&&` binds tighter than `||`, so `review_stacks_enabled` only gates the `provisioning_behavior_allow_all?` branch; the `allow_with_label` and `prevent_with_label` branches are evaluated independently of `review_stacks_enabled` and can return `true` even when it is `false`.

### Finding Description
Intended binding: `review_stacks_enabled == false` ⇒ `provision?` is `false` for all `provisioning_behavior` values and all label states.

Actual code:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Ruby operator precedence makes this equivalent to:
```
(review_stacks_enabled && allow_all?) ||
(allow_with_label? && has_label?) ||
(prevent_with_label? && !has_label?)
```
`review_stacks_enabled` is only ANDed into the first disjunct. If a repository is configured with `provisioning_behavior = allow_with_label` (or `prevent_with_label`) and `review_stacks_enabled = false`, the second (or third) disjunct still evaluates purely on label presence/absence, with no reference to `review_stacks_enabled` at all, so `provision?` returns `true`.

Path: an attacker who owns/controls a PR against the repository (they can add/remove a label on their own PR, or simply open a PR when `prevent_with_label` is configured and no label is required) triggers a genuine, correctly-signed `pull_request` "opened" GitHub webhook. This reaches `OpenedHandler#process`, which calls `respond_to_pull_request_opened?` → `provision?`, and if true calls:
```ruby
Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
  .new(params, scope: repository.review_stacks).find_or_create!
``` [2](#0-1) 
which creates a `ReviewStack` record and enqueues it for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)` [3](#0-2) , using the attacker-controlled `branch` (`params.pull_request.head.ref`) as the stack's deploy branch [4](#0-3) . Downstream provisioning/deploy of a `Stack` eventually shells out via `Command`/`PTY.spawn` using that branch's checked-out code — i.e., unauthorized RCE on the deploy host for a repository whose operator explicitly disabled review stacks.

This is not blocked by webhook signature verification (a real webhook for a real PR event on a repository the attacker controls is legitimately signed by GitHub), nor by `ExplicitParameters` schema validation (only checks payload shape), nor by any model validation on `Stack`/`ReviewStack` (branch/environment format checks do not re-check `review_stacks_enabled`). The only place `review_stacks_enabled` is supposed to act as a kill switch is this single boolean expression, and it fails to do so for two of the three `provisioning_behavior` enum values.

### Impact Explanation
For any repository whose operator has set `review_stacks_enabled = false` but left/set `provisioning_behavior` to `allow_with_label` or `prevent_with_label` (a supported, non-default but valid combination — nothing in the model or UI enforces that these fields are mutually consistent), an unprivileged PR author can force creation and provisioning of a `ReviewStack`, leading to execution of deploy/provisioning commands on the deploy host using attacker-controlled branch content. This is repeatable per PR/per repository matching that misconfiguration and matches the Critical impact category (RCE on the deploy host via the provisioning/deploy pipeline; an unauthorized deploy of a stack that should never have been created). Blast radius is scoped to repositories with this specific configuration combination, not all repositories.

### Likelihood Explanation
Preconditions: the target repository must have `review_stacks_enabled = false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` (operator/maintainer-controlled config, not attacker-controlled). Given that combination exists, attacker cost is trivial: open a PR (and add/remove a label, depending on behavior) on a repo they control. No secrets, tokens, or privileged roles are needed since it relies on a genuine GitHub-signed webhook for a real PR event. Likelihood is contingent on real-world use of this specific config combination, which is plausible since these are independent settings with no validation tying them together.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to the analogous `provision?`/`respond_to_*` logic in `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler`, since grep confirms the same pattern/matches exist in those files.

### Proof of Concept
Minitest table test in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` (extending existing file):
```ruby
test "provision? is false whenever review_stacks_enabled is false, regardless of provisioning_behavior/label" do
  [true, false].each do |enabled|
    %w[allow_all allow_with_label prevent_with_label].each do |behavior|
      [true, false].each do |has_label|
        repository = shipit_repositories(:shipit).tap do |r|
          r.update!(review_stacks_enabled: enabled, provisioning_behavior: behavior)
        end
        params = build_opened_params(labels: has_label ? [{ name: repository.provisioning_label_name }] : [])
        handler = Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(params)
        handler.instance_variable_set(:@repository, repository)

        result = handler.send(:provision?)
        if !enabled
          assert_equal false, result,
            "review_stacks_enabled=false must yield provision?=false (behavior=#{behavior}, label=#{has_label})"
        end
      end
    end
  end
end
```
This assertion currently fails for `behavior = "allow_with_label"` with `has_label = true`, and for `behavior = "prevent_with_label"` with `has_label = false`, both while `review_stacks_enabled = false`, proving `provision?` returns `true` and `find_or_create!` would be invoked despite the kill switch being off.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L87-94)
```ruby
          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```
