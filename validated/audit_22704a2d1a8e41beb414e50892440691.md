### Title
Webhook signature verified against attacker-chosen organization while handler mutates a different, unrelated repository's ReviewStack - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` derives the organization used to check the HMAC signature from `params.dig('repository','owner','login') || params.dig('organization','login')`, while `UnlabeledHandler` (and the shared `ReviewStackAdapter`) act on whatever `repository.full_name` appears in the payload, looked up directly via `Shipit::Repository.from_github_repo_name`. Because these two values are never required to be the same, and because `GitHubApp#verify_webhook_signature` returns `true` unconditionally when the resolved organization has no `webhook_secret` configured, an attacker can pick an unrelated, secret-less Shipit org for verification while targeting an arbitrary victim repository for the actual write.

### Finding Description
The broken binding: `organization_that_verified_signature == organization_owning_repository.full_name_used_by_handler`. Trace:

1. `WebhooksController#verify_signature` computes `repository_owner` via `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and looks up `Shipit.github(organization: repository_owner)` [2](#0-1) .
2. If the attacker omits `repository.owner.login` from the JSON payload (the `UnlabeledHandler` params schema only `requires :full_name`, not `:owner` [3](#0-2) ), `repository_owner` falls back to `params.dig('organization','login')`, which the attacker fully controls and can set to any org configured in Shipit that lacks a `webhook_secret`.
3. `GitHubApp#verify_webhook_signature` returns `true` unconditionally when `webhook_secret` is blank: `return true unless webhook_secret` [4](#0-3) . No `X-Hub-Signature` value is even required to be well-formed for this branch since it's checked before the signature is examined.
4. `create` then dispatches to `Shipit::Webhooks.for_event(event)` and calls `UnlabeledHandler#process` with the raw parsed JSON [5](#0-4) .
5. `UnlabeledHandler#repository` resolves the **victim** repository purely from `params.repository.full_name`, independent of whatever organization satisfied step 1-3: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [6](#0-5) .
6. `handle` then calls `stack.archive!` / `stack.unarchive!` on the `ReviewStackAdapter` built from that victim repository's `review_stacks` scope [7](#0-6) , guarded only by `respond_to_label_change?` (action, PR state, `review_stacks_enabled`, label logic) - none of which re-checks the organization that verified the signature [8](#0-7) .

Attacker request: `POST /webhooks` with header `X-Github-Event: pull_request`, arbitrary/garbage `X-Hub-Signature`, and JSON body containing `action: "unlabeled"`, `pull_request.state: "open"`, forged `labels`, `organization: { "login": "attacker-controlled-secretless-org" }`, and `repository: { "full_name": "victim-owner/victim-repo" }` (no `repository.owner.login`). No session, API token, or valid `webhook_secret` is presented at any point.

Existing guards do not prevent this: `drop_unhandled_event` only checks the event is registered [9](#0-8) ; the `ExplicitParameters` schema for `UnlabeledHandler` never requires or cross-checks `repository.owner.login` against the verifying organization; and `verify_signature`'s only failure mode is an *unknown* organization (`GithubOrganizationUnknown` -> 422), not a *mismatched* one - a known org with no secret sails through with `verified = true`.

### Impact Explanation
A single unauthenticated HTTP request causes Shipit to mutate (archive/unarchive) a ReviewStack belonging to a repository the attacker never proved control over and that has no relationship to the organization whose (non-existent) secret "verified" the request. This is a cross-tenant authorization bypass: any Shipit deployment that hosts multiple GitHub organizations, where at least one configured org has no `webhook_secret` set (a documented/legitimate configuration state, e.g. during onboarding or for internal/dev orgs), exposes every other org's repositories' ReviewStacks to unauthorized state changes. The attack is fully repeatable against arbitrary victim `owner/repo` values, each request independently controlling archive vs. unarchive. This matches the Critical category: "a payload for one repository mutating another's stack" and "authentication bypass (forged webhook ... accepted)".

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one organization configured under `Shipit.github` without a `webhook_secret`, and the target victim repository must exist as a `Shipit::Repository` with `review_stacks_enabled`. Both are realistic operational configurations for multi-org Shipit deployments (documented as supported by `github_app_config`/`TOP_LEVEL_GH_KEYS`). Attacker cost is a single crafted HTTP POST with no credentials, no prior interaction with the victim, and no GitHub-side action required at all (the "PR"/labels are entirely fabricated JSON, never validated against GitHub's API). This is trivially automatable and repeatable.

### Recommendation
Bind signature verification to the actual acted-upon repository, not an attacker-suppliable fallback: derive `repository_owner` solely from `params.dig('repository','owner','login')` (require it, do not fall back to `organization.login`), and additionally validate post-verification that the org resolved for signature verification matches the owner segment of `repository.full_name` used by every handler. Also treat a missing/blank `webhook_secret` for a configured organization as a hard verification failure (or require explicit opt-in) rather than short-circuiting to `verified = true` in `GitHubApp#verify_webhook_signature`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb`-style, no live GitHub):
1. Configure two orgs in test secrets: `victim-owner` (with a `webhook_secret`) and `attacker-org` (no `webhook_secret`).
2. Create `Shipit::Repository` `victim-owner/victim-repo` with `review_stacks_enabled: true` and provisioning-behavior label config, plus an existing `ReviewStack` for a PR branch, initially not archived.
3. POST to `/webhooks` with headers `X-Github-Event: pull_request`, arbitrary `X-Hub-Signature`, and body:
```json
{
  "action": "unlabeled",
  "number": 1,
  "pull_request": { "id":1, "number":1, "url":"...", "title":"x", "state":"open",
    "additions":1, "deletions":1, "head": {"sha":"abc","ref":"victim-branch"},
    "user": {"login":"attacker"}, "assignees": [], "labels": [] },
  "repository": { "full_name": "victim-owner/victim-repo" },
  "organization": { "login": "attacker-org" },
  "sender": { "login": "attacker" }
}
```
4. Assert `response.status == 200`.
5. Assert before/after: `victim_stack.reload.archived?` (or `branch`) changed exactly as the label logic dictates - i.e., `organization_that_verified_signature ("attacker-org") != repository_owner_of_mutated_stack ("victim-owner")`, yet the mutation occurred, proving the binding claimed by the question is false.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L19-22)
```ruby
    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-26)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L49-69)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb (L79-94)
```ruby
          def respond_to_label_change?
            params.action == "unlabeled" &&
              pull_request_state == "open" &&
              repository.review_stacks_enabled &&
              (archive? || unarchive?)
          end

          def archive?
            (repository.provisioning_behavior_allow_with_label? && !pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && pull_request_has_provisioning_label?)
          end

          def unarchive?
            (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end
```

**File:** lib/shipit/github_app.rb (L76-77)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret
```
