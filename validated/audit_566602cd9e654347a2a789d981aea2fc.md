### Title
Organization-fallback selects a different, weaker webhook verifier than the repository the handler actually mutates - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#repository_owner` picks the HMAC verification key from `params.dig('organization','login')` whenever `repository.owner.login` is absent, while every `pull_request` handler (including `LabelCapturingHandler`, `OpenedHandler`, `ReopenedHandler`) resolves the actual `Repository`/`Stack` to mutate from the independent `params.repository.full_name` field. An attacker can therefore authenticate a forged webhook with any organization's (or an unconfigured organization's) secret while the payload body still targets a victim repository. This is compounded by an operator-precedence bug in `provision?`/`unarchive?` that lets `provisioning_behavior` override `review_stacks_enabled: false`.

### Finding Description
The broken binding, stated as an equality that should hold but does not:

`repository_owner` (used to pick the `GitHubApp`/secret for `verify_webhook_signature`) **should equal** `params.repository.full_name`'s owner (used by every handler to look up the `Repository`/`Stack` that gets mutated). Instead: [1](#0-0) 

selects the verifier from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `LabelCapturingHandler#repository` resolves the mutated object from a completely different, independently attacker-controlled field: [2](#0-1) 

By omitting `repository.owner.login` and instead supplying an `organization.login` for an org that is either (a) configured in Shipit with a webhook secret the attacker knows (e.g., their own onboarded org/repo), or (b) configured with no `webhook_secret` at all, `verify_webhook_signature` returns `true` unconditionally: [3](#0-2) 

The signature check therefore validates against the wrong tenant's secret (or no secret), yet `repository.full_name` in the same JSON body is set by the attacker to the victim repository, so `LabelCapturingHandler`, `OpenedHandler`, and `ReopenedHandler` all operate on the victim's `Repository`/`ReviewStack`: [4](#0-3) [5](#0-4) 

`LabelCapturingHandler#capture_labels?` never checks `review_stacks_enabled` at all — it only checks `stack.present? && !stack.archived?` — so if a `ReviewStack` already exists for the victim's PR (created before the flag was disabled, or reactivated as below), a forged `reopened` event lets the attacker overwrite `pull_request.labels` with arbitrary values that later become uppercased environment-variable keys via `ReviewStack#env` (per the described model behavior — this file was not directly re-verified in this session due to iteration limits, this remains an assumption inherited from the target description).

Separately, the "review stacks disabled" invariant is independently broken by an operator-precedence bug in both `OpenedHandler#provision?` and `ReopenedHandler#unarchive?`: [6](#0-5) [7](#0-6) 

Ruby's `&&`/`||` precedence parses this as `(review_stacks_enabled && allow_all?) || (allow_with_label? && has_label) || (prevent_with_label? && !has_label)`, not `review_stacks_enabled && (allow_all? || (allow_with_label? && has_label) || ...)`. So a repository with `review_stacks_enabled: false` but `provisioning_behavior: allow_with_label` (or `prevent_with_label`) will still unarchive/create the review stack on a forged `reopened`/`opened` event, directly contradicting the "review stacks disabled" configuration.

None of the existing guards stop this: `drop_unhandled_event` only checks the event type exists a handler; `verify_signature` validates against the wrong org's secret by design of the fallback; the `ExplicitParameters` schema only validates JSON shape, not that `repository.owner.login == organization.login`; and `capture_labels?`/`provision?`/`unarchive?` do not re-validate which repository authenticated the request.

### Impact Explanation
An unprivileged attacker (owning any GitHub org/repo integrated with Shipit, or targeting any org configured without a `webhook_secret`) can forge `pull_request` webhooks that write to a **victim** repository's `ReviewStack`/`PullRequest` records — a payload for one repository mutating another's stack, matching the Critical impact class. Because attacker-supplied label names become uppercased environment variables consumed later by provisioning/deploy `Command`/`PTY.spawn` execution on the deploy host, this is a path toward environment-variable injection into the deploy process, and combined with the `provision?`/`unarchive?` precedence bug, it can force provisioning to occur even when the victim explicitly disabled `review_stacks_enabled`. This is repeatable against any repository whose `full_name` the attacker knows, from a single forged HTTP request per repository/PR-number combination.

### Likelihood Explanation
Preconditions: the attacker needs the Shipit instance to have at least one organization configured either without a `webhook_secret` or with a secret the attacker can obtain (e.g., their own onboarded GitHub org). They need to know the victim repository's `full_name` and PR number, and the victim repository needs an existing (or precedence-bug-reactivatable) `ReviewStack`. No Shipit credentials, session, or GitHub App keys are required — only the ability to send a raw HTTP POST to `/webhooks`. This is a low-cost, fully repeatable attack once a lenient/misconfigured organization exists.

### Recommendation
1. In `Shipit::WebhooksController#repository_owner`, never allow the verifier selector to diverge from the repository the handlers act on — require `repository.owner.login` to be present and match `repository.full_name`'s owner segment, and reject (422) any payload lacking `repository` entirely for `pull_request` events, rather than silently falling back to `organization.login`.
2. Fix the operator precedence in `OpenedHandler#provision?` and `ReopenedHandler#unarchive?` by wrapping with explicit parentheses: `repository.review_stacks_enabled && (allow_all? || (allow_with_label? && has_label) || (prevent_with_label? && !has_label))`.
3. Have `LabelCapturingHandler#capture_labels?` also gate on `repository.review_stacks_enabled` before mutating `PullRequest#labels`.

### Proof of Concept
Minitest plan (no live GitHub, under `test/controllers/webhooks_controller_test.rb` and `test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb`):
1. Create `repository_a` (attacker-owned or secret-less org) and `repository_victim` (`review_stacks_enabled: false`, `provisioning_behavior: allow_with_label`) with an existing archived-false `ReviewStack` and associated `PullRequest`.
2. Assert the binding under test: `repository_owner_from_payload = organization.login` (set to `repository_a`'s owner) **should equal but does not equal** `params.repository.full_name`'s owner (`repository_victim`'s owner).
3. POST to `/webhooks` with `X-Github-Event: pull_request`, body `{"action":"reopened","repository":{"full_name":"victim-org/victim-repo"},"organization":{"login":"attacker-org"}, "pull_request": {..., "labels":[{"name":"INJECTED_ENV=malicious"}]}, ...}`, signed (or unsigned if `attacker-org` has no `webhook_secret`) with `attacker-org`'s secret.
4. Assert response is `200 OK` (not `422`).
5. Reload `repository_victim`'s `ReviewStack#pull_request` and assert `labels` now contains the attacker-supplied label, and/or assert the stack was unarchived/provisioned despite `review_stacks_enabled == false`, proving cross-tenant mutation and the precedence-bug bypass.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L41-47)
```ruby
          def process
            return unless capture_labels?

            capture_labels

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb (L70-75)
```ruby
          def unarchive?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
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
