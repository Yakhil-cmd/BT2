### Title
`OpenedHandler#provision?` ignores `review_stacks_enabled` for `allow_with_label`/`prevent_with_label` behaviors, provisioning review stacks for repos with review stacks disabled - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`provision?` is written as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`. Because `&&` binds tighter than `||`, `review_stacks_enabled` only gates the `allow_all` branch; it is never consulted for `allow_with_label`/`prevent_with_label`. An attacker who labels their own PR on a repository configured with `provisioning_behavior: allow_with_label` (or leaves the label off under `prevent_with_label`) can force stack creation even when the operator has `review_stacks_enabled = false`.

### Finding Description
The broken binding: `repository.review_stacks_enabled == false` should imply "no review stack is ever created for this repository," but the code allows `Stack.count` to increase for that same repository when `provisioning_behavior_allow_with_label?` and the label are present.

Code path: `OpenedHandler#process` ( [1](#0-0) ) calls `respond_to_pull_request_opened?`, which calls `provision?`: [2](#0-1) 

Ruby operator precedence makes this `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)` — the master toggle `review_stacks_enabled` is scoped only to the first disjunct. If `provision?` returns true, `ReviewStackAdapter#find_or_create!` → `create!` builds a `ReviewStack` using `branch: params.pull_request.head.ref` supplied entirely by the attacker's PR payload ( [3](#0-2) ).

Exploit request: attacker opens a PR against a repository with `review_stacks_enabled: false`, `provisioning_behavior: allow_with_label`, `provisioning_label_name: 'deploy-me'`, and applies the `deploy-me` label to their own PR (label management on one's own PR requires no special GitHub permission on a repo where the attacker can open PRs, e.g. their own fork PR against the tracked repo, or any collaborator-level label capability). The webhook payload `{action: 'opened', pull_request: {head: {ref: 'attacker-branch'}, labels: [{name: 'deploy-me'}]}, number: N}` reaches `OpenedHandler`, `provision?` evaluates true via the `allow_with_label?` branch regardless of `review_stacks_enabled`, and a `ReviewStack` is created with `branch: 'attacker-branch'`.

Existing guards do not prevent this: signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only authenticates that the request came from GitHub for that repo/event — it does not enforce the `review_stacks_enabled` policy. `ExplicitParameters` only validates the payload shape ( [4](#0-3) ). No model validation on `Repository` or `ReviewStack` cross-checks `review_stacks_enabled` against `provisioning_behavior`. The test suite (`test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`) only exercises `review_stacks_enabled: false` combined with `allow_all` (line 96-107) and `allow_with_label`/`prevent_with_label` combined with the *default* `review_stacks_enabled: true` (lines 129-187) — the disabled + allow_with_label/prevent_with_label combination is never tested, consistent with this being an unnoticed logic gap.

### Impact Explanation
Any unprivileged GitHub user who can open a PR and apply a label to it (their own PR/fork) can force provisioning of a review stack on a repository whose operator explicitly disabled review stacks (`review_stacks_enabled = false`). This causes: a `ReviewStack`/`Stack` record and `ReviewStackProvisioningQueue` entry to be created for an unauthorized branch, invoking whatever provisioning pipeline is wired to it. This is a policy/authorization bypass — a repository owner's explicit "review stacks disabled" toggle is silently overridden by a secondary, unrelated setting (`provisioning_behavior`). It is repeatable against any repository configured this way (one webhook per PR/label event), and the label the attacker needs is one they can set themselves on their own PR. This matches "an unauthorized deploy/provisioning for a repository that did not authenticate it" — Critical, per the impact taxonomy.

### Likelihood Explanation
Requires the specific but plausible operator misconfiguration: `review_stacks_enabled: false` alongside `provisioning_behavior: allow_with_label` (or `prevent_with_label`) with a configured `provisioning_label_name`. This is a normal, reachable configuration state via the repository settings UI (`update_params` permits `review_stacks_enabled`, `provisioning_behavior`, `provisioning_label_name` independently — [5](#0-4) ); nothing in the UI or model prevents this combination. Attacker cost is trivial: open a PR and add/remove a label on their own PR. Fully repeatable.

### Recommendation
Fix operator precedence/logic in `provision?` so `review_stacks_enabled` gates all branches, e.g.:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not create stacks for allow_with_label repos when review_stacks_enabled is false" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :allow_with_label,
    label: "deploy-me"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "deploy-me" }

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Assert both sides of the binding: `repository.review_stacks_enabled == false` (set explicitly) vs. `Shipit::Stack.count` unchanged (expected) — this test currently fails against the shown code because `provision?` returns `true` via the `allow_with_label?` branch, causing `Stack.count` to increase despite `review_stacks_enabled == false`.

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
