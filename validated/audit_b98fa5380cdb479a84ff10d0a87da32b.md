### Title
`unarchive?` operator-precedence bug bypasses `review_stacks_enabled` gate - (File: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb)

### Summary
`ReopenedHandler#unarchive?` uses `&&`/`||` with unintended precedence so that `repository.review_stacks_enabled` only gates the `allow_all?` disjunct, not the `allow_with_label?` or `prevent_with_label?` disjuncts. As a result, a PR author can reopen a previously archived PR on a repository with `review_stacks_enabled == false` and still trigger re-provisioning via `ReviewStackAdapter#unarchive!`.

### Finding Description
The intended binding is: `unarchive? == (review_stacks_enabled == true) && (allow_all? || (allow_with_label? && has_label) || (prevent_with_label? && !has_label))`. The actual code is: [1](#0-0) 

which Ruby parses as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`, because `&&` binds tighter than `||`. So the last two disjuncts are entirely independent of `review_stacks_enabled`.

Path: an attacker who owns a PR against a target repo opens a PR, gets it closed/archived (creating an archived `ReviewStack`), attaches (or already had) the provisioning label, and reopens the PR. GitHub emits `pull_request` `reopened` webhook. `ReopenedHandler#process` calls `respond_to_pull_request_reopened?` → `unarchive?`; with `review_stacks_enabled == false`, `provisioning_behavior == 'allow_with_label'`, and the label present, the second disjunct evaluates true, so `unarchive?` returns `true` despite review stacks being disabled for that repo. `process` then calls `stack.unarchive!`, which delegates to [2](#0-1)  — this re-adds the stack to `ReviewStackProvisioningQueue` and calls `stack.unarchive!`, re-enabling provisioning of attacker-controlled branch content (the PR's own head ref/commits) even though the repo has explicitly disabled review stacks.

No other guard intervenes: `respond_to_pull_request_reopened?` only checks `params.action == "reopened"` and `unarchive?`; the webhook signature verification (`verify_signature`/`GitHubApp#verify_webhook_signature`) only authenticates that the payload came from GitHub for the named repository, it does not enforce the `review_stacks_enabled` business rule; `ReviewStack`/`Stack` model validations do not check `review_stacks_enabled` at write time; the `ReviewStackAdapter` does not re-check repository settings, it simply trusts the handler's `unarchive?` decision.

### Impact Explanation
On any repository configured with `review_stacks_enabled: false` and `provisioning_behavior: allow_with_label`, an unprivileged PR author can re-trigger provisioning of a review stack that the operator believed was disabled, causing execution of the provisioning pipeline (`ReviewStackProvisioningQueue` → `provision` state machine → `stack.provisioner.up`) against attacker-supplied branch content. This is a write/action taken for a repository whose maintainer explicitly opted out of review stacks, matching "an unauthorized deploy... for a repository" style impact — Critical, since it results in re-provisioning (deploy-like action) of attacker-controlled code on infrastructure the repo owner intended to keep disabled. The blast radius is scoped to repositories that both disabled review stacks and use `allow_with_label`/`prevent_with_label` behaviors with a pre-existing archived `ReviewStack`; it does not cross repository/tenant boundaries beyond the affected repo itself.

### Likelihood Explanation
Preconditions are config-dependent but plausible: `review_stacks_enabled == false` combined with a non-default `provisioning_behavior` (`allow_with_label` or `prevent_with_label`) left set, plus a pre-existing archived `ReviewStack` (created before stacks were disabled, or from before the flag flip). Attacker cost is minimal — open a PR, add a label they control (if `allow_with_label`), get it closed/archived, then reopen it — all standard, self-service GitHub PR actions requiring no Shipit credentials. This is deterministic and repeatable against any repo matching the configuration.

### Recommendation
Fix operator precedence to actually gate all disjuncts on `review_stacks_enabled`, mirroring the same fix needed in `LabeledHandler`, `UnlabeledHandler`, and `OpenedHandler`'s equivalent methods:

```ruby
def unarchive?
  repository.review_stacks_enabled && (
    repository.provisioning_behavior_allow_all? ||
    (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
    (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
  )
end
```

### Proof of Concept
In `test/models/shipit/webhooks/handlers/pull_request/reopened_handler_test.rb` (existing file, extend with):
1. Create a `Repository` fixture with `review_stacks_enabled: false`, `provisioning_behavior: 'allow_with_label'`.
2. Create an archived `Shipit::ReviewStack` for that repository with `environment: "pr<number>"` and `provision_status: 'deprovisioned'`/archived state.
3. Build a `reopened` webhook payload for that PR number with a label matching `repository.provisioning_label_name`.
4. Call `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler.new(...).process` (or dispatch via the webhook handler entrypoint).
5. Assert `stack.reload.provision_status == "provisioning"` (or that `ReviewStackProvisioningQueue` contains the stack) — demonstrating that despite `repository.review_stacks_enabled == false`, unarchival/provisioning was triggered, i.e. the equality `review_stacks_enabled == true` required for provisioning does **not** hold, yet provisioning occurred.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L37-50)
```ruby
          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```
