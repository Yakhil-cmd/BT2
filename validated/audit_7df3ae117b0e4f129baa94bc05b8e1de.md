### Title
`review_stacks_enabled` is not enforced for `allow_with_label`/`prevent_with_label` provisioning due to `&&`/`||` operator precedence in `provision?` - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#provision?` combines `repository.review_stacks_enabled` with the provisioning-behavior checks using `&&`/`||` without parentheses grouping the gate across all three disjuncts. As written, `review_stacks_enabled` only gates the `allow_all?` branch; the `allow_with_label?` and `prevent_with_label?` branches are unconditionally reachable, so a repository with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (or `prevent_with_label`) will still provision a `ReviewStack` from an attacker-controlled pull request.

### Finding Description
The claimed broken binding is: `repository.review_stacks_enabled == false` should imply no `ReviewStack` is ever created for that repository (`provision? == false` for all provisioning behaviors), but the code makes `provision?` independent of `review_stacks_enabled` whenever `provisioning_behavior_allow_with_label?` or `provisioning_behavior_prevent_with_label?` is true.

The actual code is: [1](#0-0) 

Due to Ruby operator precedence, this parses as:
```
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) ||
(repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```
`review_stacks_enabled` is only ANDed with `allow_all?`; it is not ANDed with the other two disjuncts. This exact same pattern (and thus the same bug) is duplicated in `ReopenedHandler#unarchive?`: [2](#0-1) 

By contrast, `LabeledHandler#respond_to_label_change?` correctly ANDs `review_stacks_enabled` across the *entire* condition before evaluating `archive?`/`unarchive?`: [3](#0-2) 
confirming the intended semantics are "no provisioning action of any kind unless `review_stacks_enabled`" — which `OpenedHandler` and `ReopenedHandler` fail to implement.

Attack flow: attacker opens a PR (or pushes a branch and lets GitHub emit the `pull_request` `opened` webhook) on a repository configured with `provisioning_behavior: allow_with_label` and `review_stacks_enabled: false`, applying the repository's exact `provisioning_label_name` to the PR. `respond_to_pull_request_opened?` calls `provision?`, which evaluates true via the `allow_with_label?` disjunct regardless of `review_stacks_enabled`. `process` then calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` unconditionally: [4](#0-3) 
`create!` builds the stack with `branch: params.pull_request.head.ref` (attacker-controlled) and enqueues it into `ReviewStackProvisioningQueue`: [5](#0-4) 
No other guard in `Repository`, `ReviewStackAdapter`, or webhook signature verification checks `review_stacks_enabled` before this point — `review_stacks_enabled` is a plain boolean column with no other enforcement.

### Impact Explanation
A `ReviewStack` is created and queued for provisioning for a repository that has explicitly opted out of review stacks (`review_stacks_enabled: false`), sourced from an attacker-controlled branch/PR. Provisioning eventually runs the repository's `shipit.yml`-defined steps via `Command`/`PTY.spawn` on the deploy host, giving the attacker code execution on infrastructure the operator believed was protected by the `review_stacks_enabled` toggle. This is repeatable against any repository configured with `allow_with_label` or `prevent_with_label` and `review_stacks_enabled: false`, and the blast radius covers every such repository/tenant on the Shipit instance. This matches the Critical category (RCE on deploy host via `Command`/`PTY.spawn`, and an unauthorized write/provisioning action for a repository that did not enable it).

### Likelihood Explanation
Preconditions are operator-configured but plausible: `provisioning_behavior: allow_with_label` (or `prevent_with_label`) with `review_stacks_enabled: false` — an operator may set the label-based behavior in advance of/independent from actually flipping the master `review_stacks_enabled` switch, believing the toggle is authoritative. The attacker only needs to open a PR carrying the exact label name (public information visible in repo settings/UI) — no credentials, no privileged role, and it is trivially repeatable per-request against any repository in this state.

### Recommendation
Fix the precedence bug by explicitly grouping `review_stacks_enabled` across the whole condition in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?`, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to `unarchive?` in `reopened_handler.rb`.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
1. Create `repository = shipit_repositories(:shipit).dup` (or a fixture) with `review_stacks_enabled: false`, `provisioning_behavior: :allow_with_label`, `provisioning_label_name: 'ship-it'`.
2. Build `payload_parsed(:pull_request_opened)` with `pull_request.labels = [{ name: 'ship-it' }]` and a `head.ref` set to an attacker-chosen branch.
3. Assert the binding before: `repository.review_stacks_enabled == false`.
4. POST to `/webhooks` with `action: 'opened'` and the payload.
5. `assert_difference('Shipit::ReviewStack.count', 1)` — proving a stack was created despite `review_stacks_enabled == false`.
6. `assert_equal payload.pull_request.head.ref, Shipit::ReviewStack.last.branch` — proving attacker-controlled branch reached the stack, violating the claimed binding that `review_stacks_enabled == false` must imply no stack creation.

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
