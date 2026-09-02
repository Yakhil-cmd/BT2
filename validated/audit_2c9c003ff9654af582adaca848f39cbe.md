### Title
`OpenedHandler#provision?` operator-precedence bug lets `review_stacks_enabled: false` repositories still auto-create and queue Review Stacks for provisioning, and `ReviewStackProvisioningQueue` never re-validates the flag before provisioning - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`, `app/models/shipit/review_stack_provisioning_queue.rb`)

### Summary
`OpenedHandler#provision?` combines `review_stacks_enabled` with the three provisioning-behavior branches using `&&`/`||` without parentheses, so `review_stacks_enabled` only gates the `allow_all` branch and is silently ignored for `allow_with_label`/`prevent_with_label`. Once a `ReviewStack` is created this way it is queued via `ReviewStackProvisioningQueue.add`, and `ReviewStackProvisioningQueue#work`/`#provision` never re-checks `repository.review_stacks_enabled` before calling `stack.provisioner.up` through the state machine.

### Finding Description
The broken binding is: intended invariant `repository.review_stacks_enabled == true` must hold whenever a stack is created **and** whenever it is provisioned; actual code only enforces it (partially, at creation time) for one of three configured behaviors, and never re-checks it at provisioning time.

Root cause, in `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`: [1](#0-0) 
Ruby's precedence makes this `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`. If a repository has `review_stacks_enabled = false` but `provisioning_behavior` left as `allow_with_label` or `prevent_with_label` (e.g., an operator previously configured behavior, then unchecked the master "Dynamically provision stacks" toggle without resetting behavior back to `allow_all`), `provision?` still returns `true` for matching PRs, and `ReviewStackAdapter#create!` creates the stack and calls `Shipit::ReviewStackProvisioningQueue.add(stack)`: [2](#0-1) 

Then, independent of how the stack got queued, `ReviewStackProvisioningQueue#queued_stacks` selects purely on `provision_status`/`awaiting_provision`, with no join or check against `repository.review_stacks_enabled`: [3](#0-2) 
and `#provision` only consults `stack.provisioner.provision?`, which for the default handler `ProvisioningHandler::Base` always returns `true`: [4](#0-3) 
so `stack.provision` proceeds to invoke `provisioner.up` unconditionally: [5](#0-4) 

No `Repository` validation ties `provisioning_behavior` to `review_stacks_enabled`: [6](#0-5) 
so nothing prevents this divergent configuration state, and the queue's asynchronous, scheduled `work` provides no second gate.

Attacker's action: open a pull request against a repository whose `provisioning_behavior` is `allow_with_label`/`prevent_with_label` while `review_stacks_enabled` is `false`, adding/omitting the configured label as needed. This is only reachable through the `opened` webhook path already covered by signature verification and `ExplicitParameters`, none of which validate the `review_stacks_enabled`/`provisioning_behavior` combination — those guards check payload shape and authenticity, not this business-logic invariant.

### Impact Explanation
When triggered, a `ReviewStack` is created and later provisioned (its `provisioner.up` invoked) for a repository whose owner has explicitly disabled review-stack provisioning. The concrete side effect is host-application-defined (`ProvisioningHandler::Base#up`/`#down` are no-ops by default, per `app/models/shipit/provisioning_handler/base.rb`), so real infrastructure impact only manifests when the host app registers a custom `ProvisioningHandler` (e.g., allocating Kubernetes namespaces or cloud resources) as documented in `docs/review_stacks.md`. Within this engine alone, the demonstrable impact is limited to unauthorized creation of a `ReviewStack`/`PullRequest` record and an unauthorized provisioning-state-machine transition for a repository that opted out — it does not by itself grant cross-repository writes, secret exfiltration, RCE, or authentication bypass, so it does not clearly map to the Critical/High categories defined in the rules.

### Likelihood Explanation
Exploitation requires the repository already be misconfigured: `review_stacks_enabled = false` combined with `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` — a state an operator can reach only by disabling the master toggle without also resetting the behavior selector, not something the unprivileged attacker can set themselves. Given that precondition, any GitHub user able to open a PR (and add/omit a label) against the repository can trigger it repeatedly for that repository once the misconfiguration exists. It is not exploitable against arbitrary repositories at will; it depends on this specific, non-default operator configuration.

### Recommendation
Fix operator precedence in `OpenedHandler#provision?` (and any sibling handlers with the same pattern, e.g. `LabeledHandler`/`UnlabeledHandler`/`ReopenedHandler`) so `review_stacks_enabled` gates all three behavior branches, e.g.:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Additionally, have `ReviewStackProvisioningQueue#queued_stacks`/`#provision` re-check `stack.repository.review_stacks_enabled` before provisioning, as defense in depth against any future creation-time bypass.

### Proof of Concept
minitest plan under `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not create/provision stacks when review_stacks_enabled is false, even with allow_with_label behavior" do
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
Assert both sides of the binding: before the fix, `repository.review_stacks_enabled` is `false` yet `Shipit::Stack.count` still increases and `stack.awaiting_provision?` becomes `true`; after the fix, no stack is created. A second test on `ReviewStackProvisioningQueue` can directly stub `stack.repository.review_stacks_enabled` to `false` on an already-queued stack and assert `provisioner.up`/`Command` is never invoked by `queue.work`, mirroring the existing `setup_provisioning_handler` mocking pattern in `test/models/shipit/review_stack_provisioning_queue_test.rb`.

### Citations

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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L21-25)
```ruby
    def queued_stacks
      @queued_stacks ||= Shipit::ReviewStack
                         .with_provision_status(:deprovisioned)
                         .where(awaiting_provision: true)
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

**File:** app/models/shipit/provisioning_handler/base.rb (L18-23)
```ruby
      # An (optional) guard to prevent provisioning. Intended to be
      # use to set logic to determine if enough actual resources exist
      # to complete the provisioning request.
      def provision?
        true
      end
```

**File:** app/models/shipit/repository.rb (L41-51)
```ruby
    validates :name, uniqueness: { scope: %i[owner], case_sensitive: false,
                                   message: 'cannot be used more than once' }
    validates :owner, :name, presence: true, ascii_only: true
    validates :owner, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: OWNER_MAX_SIZE }
    validates :name, format: { with: /\A[a-z0-9_\-.]+\z/ }, length: { maximum: NAME_MAX_SIZE }

    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy

    PROVISIONING_BEHAVIORS = %w[allow_all allow_with_label prevent_with_label].freeze
    enum :provisioning_behavior, PROVISIONING_BEHAVIORS.zip(PROVISIONING_BEHAVIORS).to_h, prefix: :provisioning_behavior
```
