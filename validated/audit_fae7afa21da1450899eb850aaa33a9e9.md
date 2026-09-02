### Title
`provision?` operator-precedence bug bypasses `review_stacks_enabled` for label-driven provisioning behaviors - ([File: app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb])

### Summary
`provision?` in `OpenedHandler` uses `&&`/`||` without parentheses grouping `review_stacks_enabled` across all three provisioning behaviors. Because `&&` binds tighter than `||` in Ruby, `review_stacks_enabled` is only ANDed with `provisioning_behavior_allow_all?`, and is NOT applied to the `allow_with_label?` or `prevent_with_label?` branches, so a repository configured with `provisioning_behavior: allow_with_label` (or `prevent_with_label`) will auto-provision review stacks purely from the PR's own labels even when `review_stacks_enabled == false`.

### Finding Description
The claimed binding is: `provision? == true` should require `repository.review_stacks_enabled == true` in all cases. The actual code is: [1](#0-0) 

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Due to Ruby's operator precedence (`&&` > `||`), this parses as:

`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

The `review_stacks_enabled` guard is scoped only to the first disjunct. The second and third disjuncts (`allow_with_label?`/`prevent_with_label?`) evaluate independently of `review_stacks_enabled`, contradicting the intended binding that label-driven provisioning is gated by the review-stacks feature flag.

Attacker path: an attacker who can open a PR on their own fork against a repository that is already tracked in Shipit (i.e., `Shipit::Repository.from_github_repo_name` resolves, per `repository` method at line 50-54) and where that repository's owner has configured `provisioning_behavior: allow_with_label` with a known/discoverable `provisioning_label_name` can label their own PR with that name via the GitHub API (label creation/application on one's own PR requires no maintainer privilege). GitHub then delivers a legitimately-signed `pull_request.opened` webhook (signed with the real webhook secret configured by the repo owner, so `verify_signature`/`GitHubApp#verify_webhook_signature` passes normally — no signature forgery needed since this is a real GitHub-originated webhook), and `OpenedHandler#process` calls `ReviewStackAdapter#find_or_create!`, creating a `Shipit::ReviewStack` regardless of `review_stacks_enabled`.

Existing guards (`verify_signature`, `ExplicitParameters` schema, `NullRepository` fallback for untracked repos) do not prevent this because they don't touch the `provision?` boolean-logic bug itself; they only stop unrelated attack surfaces (unsigned webhooks, malformed payloads, untracked repos).

### Impact Explanation
This causes an unauthorized `Shipit::ReviewStack` record to be created/provisioned for a repository whose operator explicitly disabled `review_stacks_enabled`, from an unprivileged actor's own PR labels. Once provisioned, review stacks run deploy-spec-driven provisioning/deployment commands for that branch (via `Shipit::Commands`/task execution), so this is not merely a benign DB row — it can trigger execution of the repository's CI/CD pipeline (build/provision/deploy commands) against attacker-controlled branch content, for a feature the repo owner had turned off. This matches the "unauthorized deploy" / authorization-bypass category (label-driven authorization intended to be gated by `review_stacks_enabled` is bypassed). It is repeatable against any repository configured with `provisioning_behavior: allow_with_label` or `prevent_with_label` regardless of `review_stacks_enabled`, since the flaw is a static logic error in `provision?`, not per-request state.

### Likelihood Explanation
Preconditions: the target repository must already be tracked by Shipit, and its `provisioning_behavior` must be `allow_with_label` or `prevent_with_label` (the default enum has no explicit default set in `app/models/shipit/repository.rb`, but `allow_with_label`/`prevent_with_label` are documented, supported configurations independent of `review_stacks_enabled`). The attacker needs only to know/guess `provisioning_label_name` (often a conventional name like "deploy" or similar, potentially discoverable via the repo's public label list) and open a PR with that label on their own fork — both are unprivileged, low-cost actions. This does not require bypassing webhook signature verification since GitHub delivers the webhook normally with the real secret. Feasibility is high for any repo using label-driven provisioning behaviors while `review_stacks_enabled` is false.

### Recommendation
Fix operator grouping in `provision?` so `review_stacks_enabled` gates all three branches, e.g.:

```ruby
def provision?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb
test "does not create stacks when review_stacks_enabled is false even if allow_with_label matches" do
  repository = shipit_repositories(:shipit)
  repository.review_stacks_enabled = false
  repository.provisioning_behavior = :allow_with_label
  repository.provisioning_label_name = "pull-requests-label"
  repository.save!

  payload = payload_parsed(:pull_request_opened)
  payload["pull_request"]["labels"] << { "name" => "pull-requests-label" }

  # BINDING: provision? should be false because review_stacks_enabled == false
  assert_no_difference -> { Shipit::Stack.count } do
    Shipit::Webhooks::Handlers::PullRequest::OpenedHandler.new(payload).process
  end
end
```
Before the fix, this assertion fails: a `Shipit::Stack` (review stack) is created even though `review_stacks_enabled == false`, demonstrating the broken binding.

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
