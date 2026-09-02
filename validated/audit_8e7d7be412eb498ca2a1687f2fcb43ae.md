### Title
Operator precedence bug in `PullRequest::OpenedHandler#provision?` allows stack provisioning when `review_stacks_enabled` is `false` - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`provision?` is written as `A && B || C || D` where Ruby's `&&`/`||` precedence groups it as `(A && B) || C || D`. Only the `allow_all` disjunct is gated by `repository.review_stacks_enabled`; the `allow_with_label` and `prevent_with_label` disjuncts are evaluated independently of that flag, so a repository with review stacks explicitly disabled can still auto-provision a stack from an attacker-controlled PR.

### Finding Description
The claimed binding is: `review_stacks_enabled_at_stack_creation == true` for every stack created by `OpenedHandler`. The code is: [1](#0-0) 

Ruby operator precedence makes this `(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) || (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) || (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)`. `review_stacks_enabled` is only ANDed into the first clause, so if an operator sets `provisioning_behavior = :allow_with_label` (or `:prevent_with_label`) while leaving `review_stacks_enabled = false`, the second (or third) clause can still evaluate `true`, making `provision?` return `true` even though review stacks are disabled for that repository.

When `provision?` is true, `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` [2](#0-1) , which creates a `ReviewStack` using `branch: params.pull_request.head.ref` — an attacker-controlled fork branch — and queues it for provisioning. Provisioning subsequently reads `shipit.yml` from that branch and executes its steps via `Command#start`/`PTY.spawn`.

Contrast this with `LabeledHandler#respond_to_label_change?`, which correctly ANDs `repository.review_stacks_enabled` across the *entire* expression using top-level `&&` with no unparenthesized `||` at that level [3](#0-2) , showing the intended behavior that `OpenedHandler#provision?` fails to replicate.

No other guard intercepts this: `respond_to_pull_request_opened?` only checks `params.action == "opened" && provision?` [4](#0-3) , and the `params` schema (`ExplicitParameters`) only validates payload shape, not authorization [5](#0-4) . `NullRepository` (used for untracked repos) returns `false` for all provisioning predicates, so this only affects repositories that are already tracked in Shipit and misconfigured this way [6](#0-5) .

Exploit request: an attacker opens a pull request against a tracked repository configured with `review_stacks_enabled = false`, `provisioning_behavior = :allow_with_label`, `provisioning_label_name = "some-label"`, adding that label to their own PR (labels are attacker-settable on their own fork/PR in the payload construction sense — though note: applying a label on GitHub typically requires write access to the upstream repo; this needs verification against GitHub's actual label permissions, which is outside this engine's code). Assuming the label condition can be satisfied, `pull_request_opened` webhook payload with `labels: [{name: "some-label"}]` causes `provision?` to return `true`, `ReviewStackAdapter#find_or_create!` builds a `ReviewStack` with the attacker's branch, and the provisioning queue eventually executes the attacker's `shipit.yml`.

### Impact Explanation
If reached, this results in unauthorized stack creation and eventual execution of attacker-supplied `shipit.yml` steps via `Command`/`PTY.spawn` on the deploy host, for a repository where the operator explicitly disabled review stacks — matching the Critical RCE-on-deploy-host category. The blast radius is scoped to repositories that are tracked in Shipit and specifically configured with `provisioning_behavior: allow_with_label` or `prevent_with_label`, not the whole install.

### Likelihood Explanation
Exploitation requires the repository to already have `provisioning_behavior` set to `allow_with_label` or `prevent_with_label`, which is an operator/maintainer-controlled setting permitted via `update_params` in `RepositoriesController` [7](#0-6) , combined with `review_stacks_enabled = false` — a configuration state that is plausible (operator turns off review stacks for a repo but leaves stale `provisioning_behavior` config) but not the default (`review_stacks_enabled` gates everything by design intent). The critical open question — whether an "unprivileged" GitHub user (per the attacker model, someone with no repo write access) can actually cause the `labeled`/label-bearing webhook payload to be emitted with a label attached to their own PR — is a GitHub-permissions question outside this engine's code and I could not verify it from the repo alone; ordinarily, adding labels to a PR requires triage/write access on the target repository, which would put this outside the "unprivileged" threat model unless the attacker already has that access (in which case provisioning is arguably expected). This significantly limits real-world exploitability by a truly unprivileged actor, though the underlying logic bug (`review_stacks_enabled` not gating all disjuncts) is real and independently verifiable in code.

### Recommendation
Parenthesize the entire condition so `review_stacks_enabled` gates every disjunct:
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
```ruby
test "does not create stacks when review_stacks_enabled is false, even with allow_with_label and matching label" do
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
Both sides of the binding (`repository.review_stacks_enabled == false` vs. a `ReviewStack` actually being queued for provisioning) must be asserted: before the fix, `Shipit::Stack.count` changes despite `review_stacks_enabled == false`, violating the binding; after applying the recommended fix, `Shipit::Stack.count` does not change, restoring it.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L8-39)
```ruby
          params do
            requires :action, String
            requires :number, Integer
            requires :pull_request do
              requires :id, Integer
              requires :number, Integer
              requires :url, String
              requires :title, String
              requires :state, String
              requires :additions, Integer
              requires :deletions, Integer
              requires :head do
                requires :sha, String
                requires :ref, String
              end
              requires :user do
                requires :login, String
              end
              requires :assignees, Array do
                requires :login, String
              end
              requires :labels, Array do
                requires :name, String
              end
            end
            requires :repository do
              requires :full_name, String
            end
            requires :sender do
              requires :login, String
            end
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L78-83)
```ruby
          def respond_to_label_change?
            params.action == "labeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end
```

**File:** app/models/shipit/repository.rb (L4-32)
```ruby
  class NullRepository
    def id
      nil
    end

    def stacks
      Shipit::Stack.none
    end

    def review_stacks
      Shipit::ReviewStack.none
    end

    def review_stacks_enabled
      false
    end

    def provisioning_behavior_allow_all?
      false
    end

    def provisioning_behavior_allow_with_label?
      false
    end

    def provisioning_behavior_prevent_with_label?
      false
    end
  end
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
