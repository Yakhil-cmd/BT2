### Title
`review_stacks_enabled` is bypassed for `allow_with_label`/`prevent_with_label` repos due to `&&`/`||` operator precedence - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
The binding "review stacks are disabled at the repo level" ⇒ "no review stack is provisioned" is broken by an operator-precedence bug in `provision?`. Because Ruby's `&&` binds tighter than `||`, `review_stacks_enabled` only gates the `allow_all` branch of the expression, not the `allow_with_label` or `prevent_with_label` branches, so a repo with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` will still provision a `ReviewStack` if the PR carries the configured label.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == false` ⇒ `provision? == false` for all `provisioning_behavior` values.

The actual code is:
```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Due to Ruby operator precedence (`&&` binds tighter than `||`), this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
`review_stacks_enabled` is only ANDed with the first disjunct (`allow_all?`). It has no effect on the second (`allow_with_label?`) or third (`prevent_with_label?`) disjuncts. So when `review_stacks_enabled == false` and `provisioning_behavior == 'allow_with_label'`, the first disjunct is `false`, but the second disjunct evaluates purely on `provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?`, both of which are still satisfiable regardless of `review_stacks_enabled`.

`pull_request_has_provisioning_label?` only checks the PR's own `labels` array against `repository.provisioning_label_name` [2](#0-1) , and PR labels are attacker-controlled on a PR the attacker opens against their own repository. `respond_to_pull_request_opened?` gates only on `params.action == "opened"` and `provision?` [3](#0-2) , then `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!` unconditionally once `respond_to_pull_request_opened?` is true [4](#0-3) .

Standard webhook authenticity checks (GitHub signature verification in `Shipit::WebhooksController`) do not block this, because this is not a forged webhook — it is a legitimately signed `pull_request.opened` event from GitHub, since the attacker is the owner/maintainer of their own repository and can open PRs and add labels on it, causing GitHub to emit a correctly-signed webhook. The vulnerability is purely a logic bug inside the engine's own gating condition, not a signature-verification bypass.

### Impact Explanation
Any repository owner who has explicitly disabled review stacks (`review_stacks_enabled: false`) but has `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` will still have `Shipit::ReviewStack` records created/provisioned when a PR is opened with (or without) the configured label, contrary to the maintainer's opt-out. This is a same-tenant policy-bypass (an unprivileged PR author on their own repo triggers provisioning against the maintainer's explicit "review stacks disabled" setting) rather than cross-tenant record mutation, since `repository` is resolved strictly from `params.repository.full_name` [5](#0-4)  and the created `ReviewStack` is scoped to that same repository's `review_stacks` association [6](#0-5) . This matches the "unauthorized... provisioning" style of the question but the blast radius is confined to the repository whose config is misapplied — it does not let attacker A affect repository B. This is repeatable on every PR open for any repo configured this way.

### Likelihood Explanation
Preconditions: a repository must be configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label` (or `prevent_with_label`) with a `provisioning_label_name` set — a real, supported, non-default configuration exposed in the repository settings UI [7](#0-6) . Any GitHub user who can open a PR against such a repo and add the configured label (or omit it, for `prevent_with_label`) triggers the bug with a single, ordinary, correctly-signed GitHub webhook — no secrets, tokens, or elevated privileges are required. This is highly feasible and fully repeatable.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates the entire disjunction, matching the evident intent:
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
The same pattern should be checked/fixed in `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler`, which greps show contains the identical `provisioning_behavior`/`review_stacks_enabled` logic.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`, add:
```ruby
test "does not create stacks when review_stacks_enabled is false even with allow_with_label + matching label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # review_stacks_enabled == false
    behavior: :allow_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  assert_no_difference -> { Shipit::ReviewStack.count } do
    OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails: `Shipit::ReviewStack.count` (and `Shipit::Stack.count`) increases despite `review_stacks_enabled == false`, demonstrating the bypass; after applying the parenthesization fix, the count stays unchanged, restoring the `review_stacks_enabled == false ⇒ provision? == false` binding.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-46)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end
```

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L72-78)
```ruby
          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end

          def pull_request_label_names
            Array.new(pull_request["labels"]).map { |label| label["name"] }
          end
```

**File:** app/views/shipit/repositories/settings.html.erb (L1-1)
```erb
<%= render partial: 'shipit/repositories/header', locals: { repository: @repository } %>
```
