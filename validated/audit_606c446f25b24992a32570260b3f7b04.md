## Finding Confirmed: Operator-precedence bug bypasses `review_stacks_enabled` in `OpenedHandler#provision?`

I verified the specific bug the question describes. It is real, but the full "RCE with GITHUB_TOKEN exfiltration in one webhook" chain the question describes overstates what is *automatically* proven — the confirmed, code-level bug is an authorization-bypass that causes an unauthorized `ReviewStack`/`PullRequest` record to be created and queued for provisioning, not an automatic execution of attacker steps (that still requires a separate authenticated deploy/task trigger, and provisioning behavior itself depends on the host app's `ProvisioningHandler`, which is out of this engine's scope).

### Title
Operator-precedence bug in `OpenedHandler#provision?` bypasses `repository.review_stacks_enabled` for label-based provisioning behaviors - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`OpenedHandler#provision?` intends `review_stacks_enabled` to be a master switch gating all three provisioning behaviors, but Ruby's `&&`/`||` precedence only applies it to the `allow_all` branch. When `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, a Review Stack (and its `PullRequest`) will be created and enqueued for provisioning even when `review_stacks_enabled` is `false`.

### Finding Description
Intended binding: `provision? == repository.review_stacks_enabled && (allow_all_cond || allow_with_label_cond || prevent_with_label_cond)`.

Actual code: [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all_cond) || allow_with_label_cond || prevent_with_label_cond`

So when `review_stacks_enabled = false` and `provisioning_behavior = :allow_with_label`, adding the configured label to the attacker's own PR makes `pull_request_has_provisioning_label?` true, and `provision?` returns `true` regardless of `review_stacks_enabled`. The same holds for `:prevent_with_label` when the label is absent. `process` then calls `ReviewStackAdapter#find_or_create!`, which persists a new stack and enqueues it: [2](#0-1) [3](#0-2) 

When the queue worker later runs, it calls `stack.provisioner.provision?` and, if true, `stack.provision`, which fires the `after_transition` callback invoking the host application's `ProvisioningHandler#up`: [4](#0-3) 

Existing guards do not stop this: `verify_signature`/`verify_webhook_signature` only authenticate that the webhook came from GitHub for that repository/org — they say nothing about `review_stacks_enabled`: [5](#0-4) 
The `params` schema (`ExplicitParameters`) validates payload shape only, not authorization policy. `respond_to_pull_request_opened?` simply delegates to the broken `provision?`: [6](#0-5) 

The identical precedence bug is present in `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler`, all of which reuse the same expression shape.

Important correction to the question's chain: `stack.provisioner.up` is a host-application-defined `ProvisioningHandler` (default is a documented no-op, `ProvisioningHandler::Base`), not `TaskCommands#perform`. Task/Deploy execution (which is what ultimately reaches `Command#start`/`PTY.spawn` with `Shipit.github(...).token`-derived `GITHUB_TOKEN` in the environment) requires a separate, explicit deploy/task trigger by an authenticated Shipit user — `ReviewStackAdapter#stack_attributes` sets `continuous_deployment: false`, so no deploy auto-fires from stack creation alone: [7](#0-6) 

So the bug's *proven, engine-internal* impact is: unauthorized creation of a `Shipit::ReviewStack` + `Shipit::PullRequest` and invocation of the repository's registered `ProvisioningHandler#up`/`#provision?` for a repository explicitly configured with `review_stacks_enabled = false`. Whether that further leads to command execution depends on (a) the host app's `ProvisioningHandler` implementation, and (b) a legitimate, authenticated user subsequently triggering a deploy/task against the illegitimately-created stack — both outside this engine's own code and outside the unprivileged attacker's control.

### Impact Explanation
An attacker who can open/label a pull request against a repository configured with `review_stacks_enabled: false` and `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` can force creation of a `ReviewStack` record, a `PullRequest` record, and trigger the repository's `ProvisioningHandler#up` — none of which should be possible while review stacks are disabled for that repo. This is a genuine authorization-bypass ("a record written for a repository that did not authenticate it") repeatable against any repository sharing this specific, non-default configuration. It does not, by itself, achieve RCE or `GITHUB_TOKEN` exfiltration without an additional authenticated deploy/task trigger or a host-specific `ProvisioningHandler` that executes shell commands — so it is best classified as a High-severity authorization-bypass rather than the Critical/RCE chain literally claimed in the question.

### Likelihood Explanation
Requires: `review_stacks_enabled=false` AND `provisioning_behavior` in `{allow_with_label, prevent_with_label}` (a non-default, specific combination an operator would have to configure, likely unintentionally believing the master toggle overrides behavior). Attacker cost is trivial: open a PR from a fork and add/remove a label they control on their own PR. No secrets or elevated privileges needed. Repeatable per qualifying repository each time a new PR/label event occurs.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates every branch:
```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```
Apply the same fix to `LabeledHandler#archive?`/`#unarchive?`, `UnlabeledHandler`, and `ReopenedHandler#unarchive?`, all of which share the same broken expression shape.

### Proof of Concept
minitest plan (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`):
```ruby
test "does not create stacks when review_stacks_enabled is false, even for allow_with_label repos with the label present" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,      # master switch OFF
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
Before the fix, `Shipit::Stack.count` increases by 1 despite `review_stacks_enabled: false`, proving `provision?` returns `true` and `ReviewStackAdapter#create!`/`ReviewStackProvisioningQueue.add` run — demonstrating the equality `provision? == review_stacks_enabled && (...)` is violated.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L60-63)
```ruby
          def respond_to_pull_request_opened?
            params.action == "opened" &&
              provision?
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-11)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end
```

**File:** app/models/shipit/review_stack.rb (L75-77)
```ruby
      after_transition deprovisioned: :provisioning do |stack, _|
        stack.provisioner.up
      end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```
