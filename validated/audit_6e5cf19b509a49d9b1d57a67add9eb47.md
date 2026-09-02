### Title
`review_stacks_enabled` is not enforced for `prevent_with_label`/`allow_with_label` behaviors due to operator precedence in `provision?` - (File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`OpenedHandler#provision?` intends to gate all review-stack provisioning on `repository.review_stacks_enabled`, but Ruby operator precedence (`&&` binds tighter than `||`) makes `review_stacks_enabled` apply only to the `allow_all` branch. For repositories configured with `provisioning_behavior: prevent_with_label` (or `allow_with_label`), an unlabeled (or labeled) pull request opened by any outside contributor will provision a `Shipit::ReviewStack` row even when the operator has explicitly set `review_stacks_enabled = false`.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled (false)` should equal the effective gate applied before any `ReviewStack` row is written for that repository. The code in [1](#0-0)  is:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` has higher precedence than `||`, this parses as:

```ruby
(repository.review_stacks_enabled && repository.provisioning_behavior_allow_all?) ||
(repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
(repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
```

`review_stacks_enabled` is only ANDed into the first disjunct (`allow_all`). The second and third disjuncts (`allow_with_label`, `prevent_with_label`) are evaluated independently of `review_stacks_enabled`.

Attacker flow:
1. Victim repository row has `review_stacks_enabled = false`, `provisioning_behavior = 'prevent_with_label'` — a real, documented-as-common misconfiguration since `prevent_with_label` semantically means "provision unless labeled otherwise."
2. Any outside contributor (unprivileged, no org membership, no Shipit session) opens a pull request against that repository without the provisioning-opt-out label.
3. GitHub sends a legitimate, signature-valid `pull_request`/`opened` webhook (signature verification is not being bypassed here — the webhook is genuinely from GitHub for a genuine PR event, so `verify_signature`/`GitHubApp#verify_webhook_signature` do not block it, and they are irrelevant to this bug).
4. `OpenedHandler#repository` resolves the row via `Shipit::Repository.from_github_repo_name(params.repository.full_name)` at [2](#0-1) .
5. `respond_to_pull_request_opened?` calls `provision?`, which evaluates true via the third disjunct: `provisioning_behavior_prevent_with_label?` is true and `!pull_request_has_provisioning_label?` is true (no label present) — independent of `review_stacks_enabled == false`.
6. `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` runs `create!`, and because `scope` is the `has_many :review_stacks` association on the resolved `repository` [3](#0-2) , Rails automatically sets `repository_id` to that repository's id when calling `scope.create!(stack_attributes)` [4](#0-3) .

No existing guard intercepts this: `respond_to_pull_request_opened?` only checks `params.action == "opened"` and `provision?` [5](#0-4) ; there is no separate/explicit `review_stacks_enabled` check anywhere else in the handler or adapter.

### Impact Explanation
A `Shipit::ReviewStack` (and its associated `PullRequest`) row is written for a repository whose operator explicitly disabled review-stack provisioning (`review_stacks_enabled = false`), and the stack is queued for provisioning via `Shipit::ReviewStackProvisioningQueue.add(stack)`. This is a write triggered by an unauthenticated (from Shipit's perspective) outside contributor's PR action that the repository owner explicitly opted out of — matching "a payload for one repository mutating another's stack" in spirit (state divergently mutated against explicit configuration), and is repeatable for every PR opened by any contributor against any repository sharing this misconfiguration (`review_stacks_enabled: false` + `provisioning_behavior: prevent_with_label`, or `allow_with_label`). Blast radius spans every tenant repository with this configuration combination.

### Likelihood Explanation
Requires the specific repository configuration `review_stacks_enabled: false` combined with `provisioning_behavior: prevent_with_label` (or `allow_with_label`), which the question notes is a plausible/common misconfiguration given `prevent_with_label`'s "provision by default unless labeled" semantics. No attacker secrets, sessions, or team membership are needed — only the ability to open a PR against the repository (any outside contributor can do this on a public repo, or any collaborator on a private one). Cost is a single PR open action; fully repeatable.

### Recommendation
Fix operator precedence in `provision?` so `review_stacks_enabled` gates all branches, e.g.:

```ruby
def provision?
  return false unless repository.review_stacks_enabled

  repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

### Proof of Concept
minitest plan (in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, out of scope to edit per rules but described for verification):
1. Fixture repository with `review_stacks_enabled: false`, `provisioning_behavior: :prevent_with_label`.
2. Build `pull_request opened` webhook params for that repository's `full_name`, `pull_request.labels = []` (empty).
3. Instantiate `OpenedHandler.new(params: params).process`.
4. Assert: `repository.review_stacks_enabled == false` (left side of binding) yet `Shipit::ReviewStack.exists?(repository_id: repository.id)` is `true` (right side / actual effect) — demonstrating the two sides that should be equal (opt-out should mean no stack) diverge.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
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

**File:** app/models/shipit/repository.rb (L47-48)
```ruby
    has_many :stacks, dependent: :destroy
    has_many :review_stacks, dependent: :destroy
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
