### Title
Operator precedence bug bypasses `review_stacks_enabled` in `ReopenedHandler#unarchive?` and `OpenedHandler#provision?` - ([File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb])

### Summary
`ReopenedHandler#unarchive?` and `OpenedHandler#provision?` intend to gate all provisioning/unarchival on `repository.review_stacks_enabled`, but due to Ruby `&&`/`||` precedence, the enabled-check is only applied to the `allow_all` branch. When `provisioning_behavior` is `allow_with_label` or `prevent_with_label`, unarchival/creation proceeds regardless of `review_stacks_enabled`.

### Finding Description
The broken binding: the code requires `repository.review_stacks_enabled == true` to gate any (un)archival, but for two of the three `provisioning_behavior` branches, the actual evaluated condition is independent of `review_stacks_enabled`.

In `app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb:70-75`: [1](#0-0) 

```ruby
def unarchive?
  repository.review_stacks_enabled &&
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
end
```

Because `&&` binds tighter than `||`, this parses as:
```
(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label?) || (prevent_with_label? && !has_label?)
```
The `review_stacks_enabled` check only participates in the first disjunct. If a repository has `review_stacks_enabled: false` and `provisioning_behavior: prevent_with_label` with no provisioning label configured/attached, the third disjunct (`prevent_with_label? && !has_label?`) evaluates `true` independent of the disabled flag, so `unarchive?` returns `true`.

`respond_to_pull_request_reopened?` (line 65-68) only checks `params.action == "reopened" && unarchive?` — it does not separately verify `review_stacks_enabled`. `process` (line 41-45) then unconditionally calls `stack.unarchive!`, which either re-provisions an archived `ReviewStack` (`ReviewStackAdapter#unarchive!`, `app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb:37-50`) or creates a brand-new one via `create!` (`review_stack_adapter.rb:72-85`) when none exists, enqueuing it to `Shipit::ReviewStackProvisioningQueue`.

The identical pattern exists in `OpenedHandler#provision?` (`app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb:65-70`), meaning newly opened PRs on a "disabled" repo under `prevent_with_label` (no label) or `allow_with_label` (with label) also provision review stacks.

Note that `LabeledHandler`/`UnlabeledHandler` do not have this flaw because they gate `archive?`/`unarchive?` behind an independent `repository.review_stacks_enabled &&` check in `respond_to_label_change?` (`labeled_handler.rb:78-83`, `unlabeled_handler.rb:79-84`), confirming the intended invariant that these two handlers correctly enforce but `ReopenedHandler`/`OpenedHandler` do not.

Exploit flow: repo owner configures `provisioning_behavior: prevent_with_label` while `review_stacks_enabled` is `false` (e.g., temporarily disabling review stacks without changing the behavior setting, or leaving stale config). An attacker who is the PR author (unprivileged, no Shipit session/token needed) opens or reopens their own PR without attaching any label. GitHub emits a legitimate `pull_request` webhook (`opened`/`reopened`) which is verified by signature but the handler's authorization logic (this flag check) is bypassed by the bug, not the signature check. This causes `ReviewStack` creation/unarchival and enqueues it for provisioning — writing/mutating state for a repository that explicitly disabled review stacks.

### Impact Explanation
The impact is unauthorized re-provisioning of a `ReviewStack` (creation of a `Stack` record and enqueue for provisioning) for a repository that has explicitly disabled review stacks (`review_stacks_enabled: false`). This is a record being written/provisioned that should not occur under the operator's configuration, matching "a record written for a repository that did not authenticate it / unauthorized provisioning" impact category. It is repeatable by any PR author against any repository configured with `provisioning_behavior: prevent_with_label` (no label) or `allow_with_label` (with label) while `review_stacks_enabled` is `false`, for every PR they open/reopen.

### Likelihood Explanation
Requires a specific repository misconfiguration: `review_stacks_enabled: false` combined with a non-`allow_all` `provisioning_behavior` setting still configured. This is plausible if an operator disables review stacks (e.g., via `review_stacks_enabled = false`) without resetting `provisioning_behavior`, since these are independent columns on `Shipit::Repository`. Attacker cost is minimal: open/reopen a PR (with or without a label depending on the configured behavior) from a repo they control. No secrets or elevated privileges are required beyond normal GitHub PR authorship.

### Recommendation
Fix operator precedence by parenthesizing the `review_stacks_enabled` check across all branches, e.g.:
```ruby
def unarchive?
  repository.review_stacks_enabled &&
    (repository.provisioning_behavior_allow_all? ||
     (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
     (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?))
end
```
Apply the same fix to `OpenedHandler#provision?`.

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb`, add:
```ruby
test "does not unarchive stacks when review_stacks_enabled is false and prevent_with_label has no label" do
  stack = create_archived_stack
  repository = shipit_repositories(:shipit)
  configure_provisioning_behavior(
    repository:,
    provisioning_enabled: false,
    behavior: :prevent_with_label,
    label: "pull-requests-label"
  )
  payload = payload_parsed(:pull_request_reopened)
  payload["pull_request"]["labels"] = []

  assert_no_changes -> { stack.reload.archived? } do
    Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(payload).process
  end
end
```
Before the fix: `stack.reload.archived?` transitions from `true` to `false` and the stack is enqueued for provisioning even though `review_stacks_enabled` is `false`. After applying the recommended fix, the assertion passes (no change), confirming the binding `repository.review_stacks_enabled == true` is properly enforced.

### Citations

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```
