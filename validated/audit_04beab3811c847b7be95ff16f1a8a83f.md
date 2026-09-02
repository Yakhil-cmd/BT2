### Title
`PullRequest::OpenedHandler#provision?` ignores `review_stacks_enabled` for the `prevent_with_label` behavior due to Ruby operator precedence - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`provision?` is written as `A && B || C || D`, and since `&&` binds tighter than `||` in Ruby, `repository.review_stacks_enabled` only gates the first disjunct (`provisioning_behavior_allow_all?`). The third disjunct, `(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`, is evaluated independently of `review_stacks_enabled`, so an unlabeled PR against a repo with `provisioning_behavior: prevent_with_label` triggers stack creation even when `review_stacks_enabled` is `false`.

### Finding Description
Intended binding: `repository.review_stacks_enabled == true` must hold for `provision?` to be `true` under any behavior. Actual code: [1](#0-0) 
parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. When `review_stacks_enabled` is `false` and `provisioning_behavior_prevent_with_label?` is `true` and the PR carries no label, the third clause alone evaluates to `true`, making `provision?` (and thus `respond_to_pull_request_opened?`) `true` regardless of the disabled flag.

`process` then unconditionally calls `ReviewStackAdapter#find_or_create!`, which creates a `Shipit::ReviewStack` row scoped to `repository.review_stacks` and enqueues it via `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) [3](#0-2) 
`ReviewStackProvisioningQueue.add` merely sets `awaiting_provision = true`: [4](#0-3) 
The scheduled queue worker's `queued_stacks` scope does not filter on `repository.review_stacks_enabled` at all — it only checks `provision_status` and `awaiting_provision`: [5](#0-4) 
so a queued stack will eventually be provisioned by the cron worker regardless of the disabled flag, subject only to the (often no-op) `provisioner.provision?` guard.

By contrast, the sibling `LabeledHandler` correctly gates all behaviors behind the enabled flag by placing it as a top-level, un-ambiguous AND term before any behavior-specific branch: [6](#0-5) 
This asymmetry confirms `OpenedHandler#provision?` is the outlier and the precedence issue is the root cause, not intentional design.

No other guard intervenes: `params` schema validation only checks payload shape, not `review_stacks_enabled`; `Repository#from_github_repo_name` just looks up the same targeted repo; there is no additional check of `review_stacks_enabled` anywhere else in `process` or `ReviewStackAdapter`.

### Impact Explanation
An operator who disables review stacks (`review_stacks_enabled: false`) on a repository configured with `provisioning_behavior: prevent_with_label` reasonably expects no `ReviewStack` to ever be created. Due to this bug, any unlabeled pull request opened against that repository still creates a persisted `Shipit::ReviewStack` and enqueues it for provisioning (`awaiting_provision: true`), bypassing the operator's explicit toggle. Downstream, the cron-driven `ReviewStackProvisioningQueue#work` will pick up the queued stack and, absent a custom `provision?` guard on the configured provisioner (`ProvisioningHandler::Base#provision?` defaults to `true`), transition it into `provisioning`, invoking `stack.provisioner.up`. Whether this reaches actual command execution (`TaskCommands#perform` / `PTY.spawn`) depends on the host's custom `ProvisioningHandler` implementation, which is outside this engine's code; the engine itself cannot be shown here to directly invoke `Command`/`PTY.spawn` for a bare `ReviewStack` provisioning transition. The concretely demonstrable, in-engine impact is: unauthorized creation and enqueuing of a `ReviewStack` for a repository that disabled the feature — this is repeatable by any user who can open PRs against the affected repo, once per PR/environment slot.

### Likelihood Explanation
Requires only: (1) a repository configured with `provisioning_behavior: prevent_with_label` and `review_stacks_enabled: false`, and (2) an attacker capable of opening a pull request without the exclusion label against that repository — a routine, unprivileged action for anyone permitted to open PRs on the repo. No secrets, tokens, or elevated roles are needed; the webhook is a legitimate `pull_request.opened` event from GitHub. This is trivially repeatable for every new PR/branch.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every disjunct, matching the pattern already used in `LabeledHandler#respond_to_label_change?`:
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
Apply the equivalent fix to `ReopenedHandler` if it shares the same expression.

### Proof of Concept
minitest in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style (proof plan, per repo's existing `configure_provisioning_behavior` helper):
```ruby
test "does not create stacks when review_stacks_enabled is false, even for prevent_with_label without a label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # binding under test: review_stacks_enabled == false
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []  # no provisioning label

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails: `provision?` returns `true` and a `Shipit::ReviewStack` row is created and enqueued (`awaiting_provision: true`) despite `repository.review_stacks_enabled == false`, demonstrating the equality `review_stacks_enabled == true` (required) vs. actual `false` (observed) divergence. After applying the recommended parenthesization, the test passes (`assert_no_difference`).

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end
```

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L21-37)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```
