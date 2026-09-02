### Title
`OpenedHandler#provision?` operator-precedence bug lets attacker-controlled fork branches provision a `Shipit::ReviewStack` even when `review_stacks_enabled == false` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`PullRequest::OpenedHandler#provision?` combines `repository.review_stacks_enabled` with the three provisioning-behavior branches using `&&`/`||` in a way that only gates the `allow_all` branch; the `allow_with_label` and `prevent_with_label` branches are evaluated independently of `review_stacks_enabled`. As a result, a repository with review stacks explicitly disabled but `provisioning_behavior == 'allow_with_label'` will still create a `Shipit::ReviewStack` whose `branch` is the attacker's fork `head.ref` whenever the attacker adds the matching label to their own PR.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` must be a precondition for `provision? == true` in every branch. Tracing `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb#65-70`:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||` in Ruby, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So `review_stacks_enabled` is only ANDed into the first disjunct. If `review_stacks_enabled == false` and `provisioning_behavior == 'allow_with_label'`, the first disjunct is `false`, but the second disjunct `(allow_with_label? && has_label?)` can still be `true` independent of `review_stacks_enabled`, making the whole expression `true`.

`respond_to_pull_request_opened?` calls `provision?` and, if true, `process` unconditionally calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [2](#0-1) , which creates the stack via `create!` using `stack_attributes` where `branch: params.pull_request.head.ref` is taken directly from the webhook payload the attacker's fork controls [3](#0-2) .

Attack request: attacker opens a PR from their own fork against the target repository (which has `review_stacks_enabled = false`, `provisioning_behavior = 'allow_with_label'`), and applies the repository's configured `provisioning_label_name` to their own PR (an action any PR author with write access to labels on their own PR, or in many GitHub setups even non-collaborators via certain integrations, can trigger, at minimum this is testable with a forged `opened` webhook payload). GitHub (or a forged webhook, subject to signature verification) sends the `pull_request` `opened` event with that label attached. `OpenedHandler#process` runs, `provision?` returns `true` despite `review_stacks_enabled == false`, and a `Shipit::ReviewStack` is created bound to `branch = <attacker fork ref>`.

Existing guards that would normally prevent this (webhook signature verification, `ExplicitParameters` schema) only validate payload shape and webhook authenticity — they do not touch the `provision?` boolean logic, so they don't prevent this divergence. The webhook signature check gates *whether the handler runs at all*, not the internal decision correctness once it runs.

Once the `ReviewStack` exists with that branch, a maintainer later calling `DeploysController#create` on that stack (`app/controllers/shipit/deploys_controller.rb#25-35`) invokes `@stack.trigger_deploy`, which schedules a `Task` that eventually runs `TaskCommands`/`Command#start` against the checked-out `branch` — i.e., the attacker's fork content — reaching `PTY.spawn` with commands/deploy scripts sourced from that unreviewed branch.

### Impact Explanation
An attacker who can only open a PR and apply a label on their own PR (or forge a webhook `pull_request.opened` event with the right shape/signature) can force creation of a `Shipit::ReviewStack` for a repository whose administrator explicitly disabled review-stack provisioning (`review_stacks_enabled = false`). That stack's `branch` is fully attacker-controlled. Any maintainer who later deploys that stack from the UI executes deploy/build commands sourced from the attacker's fork on the Shipit host via `Command#start`/`PTY.spawn`, which is unauthorized code execution reachable indirectly through a record ("stack") the attacker was never authorized to create. This matches the Critical category ("RCE on the deploy host via `Command`/`PTY.spawn`" and "a payload for one repository mutating another's... stack... an unauthorized deploy"). The blast radius is scoped to any repository configured with `review_stacks_enabled = false` + `provisioning_behavior = allow_with_label` (or `prevent_with_label`, where the check is entirely absent regardless of label), which combined with a subsequent human "Deploy" click gives execution.

### Likelihood Explanation
Preconditions: the target repository must have `provisioning_behavior` set to `allow_with_label` (or `prevent_with_label`) — this is a plausible configuration for teams that want to restrict but not fully disable review stacks, and the bug also applies to `prevent_with_label` unconditionally since that branch never checks `review_stacks_enabled` at all. The attacker only needs to open a PR and add/omit a label matching `provisioning_label_name`, which is public knowledge or guessable/discoverable. No secrets are required to create the stack; a legitimate GitHub webhook from the attacker's own PR suffices, or the payload must pass normal webhook signature verification (not defeated here — the attacker uses a genuine GitHub event from their own repo/PR). The final "Deploy" step still requires a maintainer to click deploy, so exploitation isn't fully automatic but the malicious stack creation itself is fully automatic and repeatable per PR/label toggle.

### Recommendation
Fix the operator precedence/logic in `provision?` so `review_stacks_enabled` gates all three behavior branches, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Add regression tests asserting no stack is created for `allow_with_label`/`prevent_with_label` behaviors when `review_stacks_enabled == false`.

### Proof of Concept
```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Given current code, this assertion fails: `provision?` evaluates to `true` (because `(allow_with_label? && has_label?)` short-circuits `review_stacks_enabled`), and `Shipit::ReviewStack.count` increases by 1 with `branch == payload["pull_request"]["head"]["ref"]`, confirming the binding `repository.review_stacks_enabled == true` is not enforced for the `allow_with_label`/`prevent_with_label` branches.

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
