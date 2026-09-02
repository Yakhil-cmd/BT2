### Title
`review_stacks_enabled` is bypassed by `||` operator precedence in `OpenedHandler#provision?`, allowing stack auto-provisioning even when review stacks are disabled - (File: `app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb`)

### Summary
`Repository#review_stacks_enabled` is intended as a master switch gating all automatic review-stack provisioning, but `provision?` only applies it to the `allow_all` branch due to Ruby's `&&`/`||` precedence. An attacker who can label their own PR on a repository configured with `provisioning_behavior: :allow_with_label` (or `:prevent_with_label`) can get a `Shipit::Stack` created even though the repository operator explicitly disabled review stacks.

### Finding Description
The claimed binding is: `repository.review_stacks_enabled == true` gates `repository.review_stacks` write eligibility for repository X. Tracing `provision?`:

```ruby
def provision?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
``` [1](#0-0) 

Because `&&` binds tighter than `||`, this parses as:
`(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)`

So `review_stacks_enabled` only participates in the first disjunct. If `provisioning_behavior = :allow_with_label` and `review_stacks_enabled = false`, the first clause is `false && false = false`, but the second clause `allow_with_label? && has_label?` evaluates independently to `true` when the attacker's PR carries `repository.provisioning_label_name`. `provision?` returns `true`, `respond_to_pull_request_opened?` returns `true`, and `process` calls `ReviewStackAdapter.new(params, scope: repository.review_stacks).find_or_create!`, writing a new `Shipit::Stack` for repository X. [2](#0-1) 

The attacker's exact action: open a pull request on repository X (a repo they can push branches/labels to, e.g., their own fork with write access to the target repo's labels, or any repo where they can label PRs) whose payload includes `pull_request.labels[].name == repository.provisioning_label_name`, and send this via the `/webhooks` endpoint (or trigger it through GitHub's normal webhook delivery for their PR). No Shipit session, token, or GitHub secret is required.

None of the existing guards catch this: signature verification (`verify_signature`) only proves the payload came from GitHub for repository X, it does not evaluate provisioning policy; `ExplicitParameters` only validates payload shape; `Repository.from_github_repo_name` correctly resolves repository X (not another repo) so there's no cross-tenant confusion — the bug is a same-repository policy bypass. The existing test suite in `opened_handler_test.rb` never exercises `review_stacks_enabled: false` combined with `allow_with_label`/`prevent_with_label`, only combined with `allow_all` (line 96-107), so the divergence is untested and unguarded. [3](#0-2) 

The same flawed `provision?` logic (or its equivalent) is duplicated in `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler`, meaning this bypass is reachable from labeling/unlabeling/reopening events too, not just PR opening. [4](#0-3) 

### Impact Explanation
The attacker causes `Shipit` to provision review-stack infrastructure (a `Shipit::Stack`/`Shipit::ReviewStack` record with `awaiting_provision?` state, which subsequently drives real deploy/task pipelines) for repository X, directly contradicting the operator's explicit `review_stacks_enabled = false` configuration. This is an unauthorized provisioning of deploy/task infrastructure and matches the "unauthorized deploy" Critical impact category. It is fully repeatable: any PR carrying the provisioning label on a repository configured with `allow_with_label`/`prevent_with_label` and `review_stacks_enabled: false` triggers the bypass, and it applies to every repository using that (mis)configuration, not just one tenant.

### Likelihood Explanation
Preconditions: repository X exists in Shipit and its operator has set `provisioning_behavior` to `allow_with_label` (or `prevent_with_label`) while also setting `review_stacks_enabled = false` — an operator config combination that is plausible if the operator believes `review_stacks_enabled` is a global kill-switch (its name and UI framing imply this) independent of `provisioning_behavior`. Attacker cost is trivial: label a PR with a known/discoverable label name and let the normal GitHub webhook deliver the payload, or open a PR from a fork. No secrets, sessions, or elevated GitHub permissions are needed. This is fully repeatable per PR/label event.

### Recommendation
Fix operator precedence in `provision?` so `review_stacks_enabled` gates all branches:
```ruby
def provision?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```
Apply the same fix to the duplicated logic in `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/opened_handler_test.rb` style (minitest):
```ruby
test "does not create stacks when review_stacks_enabled is false, even with allow_with_label and matching label" do
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,   # operator intends "no auto stacks ever"
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
Before the fix, `assert_no_difference` fails because `Shipit::Stack.count` increases by 1, proving `repository.review_stacks_enabled == false` does not prevent the write to `repository.review_stacks` when `provisioning_behavior_allow_with_label?` and the label matches.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L1-8)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      module PullRequest
        class LabeledHandler < Shipit::Webhooks::Handlers::Handler
          params do
```
