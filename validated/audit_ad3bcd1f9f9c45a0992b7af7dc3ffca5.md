### Title
`OpenedHandler#provision?` missing `review_stacks_enabled` gate for `allow_with_label`/`prevent_with_label` behaviors due to operator precedence - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` is written without explicit parentheses around the `&&`/`||` chain, so Ruby's operator precedence causes `repository.review_stacks_enabled` to only gate the `allow_all?` branch, not the `allow_with_label?` or `prevent_with_label?` branches. This means a repository with `review_stacks_enabled: false` can still have review stacks auto-provisioned from an attacker-controlled pull request if the (unrelated, orthogonal) `provisioning_behavior` happens to be `allow_with_label` or `prevent_with_label`.

### Finding Description
The binding under test is: `provision?` == `(review_stacks_enabled && allow_all?) || (review_stacks_enabled && allow_with_label? && label) || (review_stacks_enabled && prevent_with_label? && !label)`. The actual code at [1](#0-0)  is:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby precedence (`&&` binds tighter than `||`), this parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && label) || (prevent_with_label? && !label)`. The `review_stacks_enabled` flag is *not* applied to the second and third disjuncts. So if `review_stacks_enabled` is `false` but `provisioning_behavior` is `allow_with_label` (with a label present) or `prevent_with_label` (with label absent), `provision?` still returns `true` and `ReviewStackAdapter#find_or_create!` runs, creating/mutating a `Shipit::Stack` for that repository — entirely attacker-triggered via a crafted `opened` pull-request webhook payload (label name and PR head ref are both attacker-controlled from a forked PR).

Existing guards do not prevent this: signature verification (`verify_signature`/webhook secret checks) only authenticates that the payload came from GitHub for *that* repository — it says nothing about whether review-stack provisioning should be *enabled* for it, which is exactly the flag this bug bypasses. `respond_to_pull_request_opened?` at [2](#0-1)  just delegates straight to the broken `provision?`.

The test suite in `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` confirms the gap: the only test combining `provisioning_enabled: false` is `"only provision stacks for repos with auto-provisioning enabled"` at lines 96-107, which pairs it exclusively with `behavior: :allow_all`. There is no test pairing `provisioning_enabled: false` with `behavior: :allow_with_label` or `behavior: :prevent_with_label` (with label present/absent), so the cross-product of `(provisioning_enabled, behavior)` tuples needed to prove `review_stacks_enabled` is enforced for every behavior is **not** covered — confirming the binding in the question is broken both in code and in test coverage. [3](#0-2) 

### Impact Explanation
An unprivileged attacker who owns a repository connected to Shipit (or forks/PRs against one) with `review_stacks_enabled: false` but `provisioning_behavior` set to `allow_with_label` or `prevent_with_label` can still cause Shipit to auto-provision a review stack (a real deploy environment) by opening a PR with (or without) a specific label. This is a record being written/provisioned for a repository whose owner explicitly disabled review-stack auto-provisioning — an authorization-bypass-style logic flaw, matching "unauthorized deploy/provisioning" impact. It's repeatable against any repository configured this way and does not require any secret.

### Likelihood Explanation
Requires the specific repository configuration `review_stacks_enabled: false` combined with `provisioning_behavior` of `allow_with_label` or `prevent_with_label` (a non-default, but plausible, admin setting intended to *restrict* provisioning while still allowing label-gated stacks elsewhere). Given that combination, any GitHub user able to open a PR against the repo (or push a labeled/unlabeled PR to their own fork if PRs from forks are accepted) can trigger it with zero additional cost — no secrets, no privileged role.

### Recommendation
Add explicit parentheses so `review_stacks_enabled` gates all three disjuncts, matching the question's rewritten form:
```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
      (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
      (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
Add to `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb`:
```ruby
test "does not provision when review_stacks disabled even with allow_with_label + label present" do
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

test "does not provision when review_stacks disabled even with prevent_with_label + label absent" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] = []

  assert_no_difference -> { Shipit::Stack.count } do
    OpenedHandler.new(payload).process
  end
end
```
With the current unparenthesized code, both assertions fail (`Shipit::Stack.count` changes by 1), proving `review_stacks_enabled` is not enforced for these two behaviors. After applying the recommended parenthesization fix, both pass.

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

**File:** test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb (L96-107)
```ruby
          test "only provision stacks for repos with auto-provisioning enabled" do
            repository = shipit_repositories(:shipit)
            configure_provisioning_behavior(
              repository:,
              provisioning_enabled: false,
              behavior: :allow_all
            )

            assert_no_difference -> { Shipit::Stack.count } do
              OpenedHandler.new(payload_parsed(:provision_disabled_pull_request)).process
            end
          end
```
