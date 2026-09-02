### Title
Webhook signature verified against the payload's `repository.owner.login`, but event handlers (e.g. `StatusHandler`) act on repositories/commits by unrelated fields never covered by that check - allowing cross-organization CI status forgery ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the `GitHubApp` (and thus which `webhook_secret` to verify the HMAC signature against) using `repository_owner`, derived from `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`). [1](#0-0) [2](#0-1) 

However, once the signature passes, the actual event handlers do not re-derive or cross-check that same `repository.owner.login`. `Handler#stacks`/`repository_name` reads `payload.dig('repository', 'full_name')` independently, and `StatusHandler#process` doesn't even scope by repository at all — it looks up commits globally by SHA: [3](#0-2) [4](#0-3) 

### Finding Description
This engine supports hosting multiple GitHub organizations with independent `webhook_secret`s (`config/secrets.development.example.yml`, `docs/setup.md`), each keyed by organization name via `Shipit.github_app_config`. [5](#0-4) 

The equality that should hold is: **organization whose secret authenticated the request == organization/repository the event is applied to**. In reality:

- Authentication binds only to `repository.owner.login` (or `organization.login`) — a field the attacker fully controls in the raw JSON body, and which is only used to pick which secret to HMAC-verify against.
- The business logic binds to a *different* field — `repository.full_name` for most handlers (`Handler#repository_name`), or, for `status` events, to no repository field at all (`Commit.where(sha: params.sha)`), since `Commit` records span every tracked stack/repository in the whole Shipit instance.

Consequently, an attacker who legitimately knows (or controls) the `webhook_secret` for **one** organization configured in this Shipit instance can produce a validly-signed `status` webhook whose `repository.owner.login` matches their own org (so `verify_signature` succeeds), while the payload's `sha`/`state`/`context` target a commit that actually belongs to a **completely different, unrelated repository/stack**. Because `StatusHandler` never checks which repository the commit belongs to, the forged status is applied to that commit regardless of tenant boundary. `push`/`pull_request`/`check_suite` handlers are scoped by `repository.full_name` instead of `repository.owner.login`, so they are similarly exploitable by mismatching those two fields (owner used only for signature key selection, full_name used for the actual repository lookup).

### Impact Explanation
`Commit#create_status_from_github!` persists these forged statuses, which feed directly into deploy-gating logic (`ci.require`/`ci.allow_failures` from `shipit.yml`) that determines whether a commit is eligible to deploy. An attacker able to forge a "success" status for an arbitrary commit SHA in a stack they do not own can make an unreviewed/malicious commit appear CI-green and eligible for deployment — an unauthorized-deploy-class impact, matching the report's underlying theme where a state transition intended to be scoped to a specific, verified actor/context is instead applied more broadly than the check that gated it.

### Likelihood Explanation
Requires the attacker to control (or know) at least one organization's `webhook_secret` configured in this Shipit deployment — plausible in any multi-tenant/multi-org Shipit setup where different organizations' admins each configure their own GitHub App/webhook secret independently but share the same Shipit instance and `Commit`/`Stack` table space. No GitHub repository write access, `ApiClient` token, or Shipit session is required — only the ability to send an HTTP POST with a correctly-signed body for the org the attacker does control.

### Recommendation
`verify_signature` should require that the same repository/organization identity used to select the signing key is the one the handler actually acts on: validate `repository.full_name`'s owner against the resolved `repository_owner`/`Shipit.github(organization:)` before dispatching to handlers, and scope `StatusHandler#process` (and any other handler) lookups by `Repository`/`Stack`, not merely by`sha`, so cross-tenant/cross-repository writes are structurally impossible.

### Proof of Concept
1. Attacker is (or compromises) an admin for `org-attacker`, one of several GitHub organizations configured in a shared Shipit instance, and knows `org-attacker`'s `webhook_secret`.
2. Attacker crafts a `status` event JSON body:
   ```json
   {
     "sha": "<sha-of-a-commit-belonging-to-org-victim/some-repo>",
     "state": "success",
     "context": "ci/required-check",
     "repository": {"owner": {"login": "org-attacker"}}
   }
   ```
3. Attacker computes `X-Hub-Signature` using `org-attacker`'s known `webhook_secret` and POSTs to `/webhooks`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "org-attacker")` and verifies successfully since the attacker used the correct secret. [1](#0-0) 
5. `StatusHandler#process` runs `Commit.where(sha: params.sha)` with no repository scoping and marks the victim organization's commit as `success`, regardless of it belonging to a different, unrelated tenant/stack. [4](#0-3)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```
