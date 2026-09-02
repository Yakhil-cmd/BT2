### Title
Cross-organization commit-status forgery breaks signature-org / affected-repository binding, enabling CI-gate bypass for merge/deploy - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/status_handler.rb)

### Summary
The webhook signature check authenticates the *organization* implied by `params.dig('repository','owner','login')` (or `organization.login`), but the `status` webhook handler acts on commits selected purely by SHA, with no verification that the SHA actually belongs to a commit/stack owned by that authenticated organization. An attacker who administers any GitHub organization/repo already configured in this Shipit instance (and therefore knows/controls that org's webhook secret) can self-sign an arbitrary `status` event payload and set the commit `sha` to a commit belonging to a completely different, victim stack, forging a passing CI status for it.

### Finding Description
`WebhooksController#verify_signature` derives the authenticating identity solely from attacker-suppliable payload fields: [1](#0-0) [2](#0-1) 

`github_app = Shipit.github(organization: repository_owner)` selects the `webhook_secret` used for HMAC verification based on `repository.owner.login` in the JSON body — a value fully controlled by whoever POSTs the request, not by GitHub-side binding. This is fine for genuine GitHub-originated events (GitHub always fills in the correct owner and signs with the matching secret), but it means the *only* thing the signature actually proves is "the sender knows the webhook secret configured for organization X" — it says nothing about which repository/commit the rest of the payload refers to.

`Shipit::Webhooks::Handlers::StatusHandler#process` then acts on the payload with no organization/repository scoping at all: [3](#0-2) 

`Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }` looks up commits **globally by SHA across the entire Shipit instance**, independent of which organization's secret validated the request. There is no check that the commit's stack/repository belongs to the same organization used in `verify_signature`.

This breaks the intended binding: **organization that authenticated == repository/commit actually written**. Concretely:
- Left side (authenticated identity): the org whose `webhook_secret` produced a valid HMAC, derived from `params['repository']['owner']['login']`.
- Right side (entity mutated): `Commit` rows matched by `params['sha']`, which is unconstrained by repository/org and can reference any commit in the whole Shipit database, including commits belonging to other organizations' stacks.

An attacker who is a normal (non-privileged w.r.t. the victim) admin of *their own* org/repo that is also configured on this Shipit instance can:
1. Have GitHub send (or directly POST, since they know their own webhook secret) a `status` webhook where `repository.owner.login` = "attacker-org" (so `verify_webhook_signature` succeeds using the attacker's own secret) but `sha` = the SHA of a commit belonging to a victim stack in a different organization, and `state` = `success`, `context` = one of the victim's `ci.require` contexts.
2. `StatusHandler` finds the victim's `Commit` row purely by SHA and calls `create_status_from_github!`, writing a fabricated "success" status onto it.
3. If the victim stack requires that CI context for merging/deploying (`ci.require` in `shipit.yml`), the forged status can satisfy that requirement and enable an unauthorized merge/deploy of a commit that never actually passed the victim's real CI.

`PushHandler` and `CheckSuiteHandler` do scope lookups through `Handler#stacks`, which uses `payload.dig('repository','full_name')` via `Repository.from_github_repo_name`: [4](#0-3) 
but this is likewise never cross-checked against the organization used for signature verification (`repository.owner.login`) — nothing stops `repository.full_name`'s owner segment from differing from `repository.owner.login`. `StatusHandler` is the most severe instance because it doesn't even use `repository_name`/`stacks` scoping — it is entirely global by SHA.

### Impact Explanation
This allows an attacker who only controls a webhook secret for their own onboarded organization (not privileged with respect to the victim stack, no GitHub write access to the victim repo, no Shipit session/API token) to forge CI status data for arbitrary commits belonging to any other stack managed by the same Shipit instance. Where `ci.require` gates merges or deploys on that status context, this is a path to an **unauthorized merge/deploy**, matching the Critical impact category for this engine.

### Likelihood Explanation
Requires only that: (a) the Shipit instance hosts multiple organizations (a normal multi-tenant Shipit deployment), (b) the attacker administers a repo/org that is itself onboarded to that Shipit instance (so they legitimately know their own org's `webhook_secret`), and (c) they can determine or guess the target commit SHA and `ci.require` context name of a victim stack (often discoverable via the public GitHub commit history/checks of the victim repo). No credential belonging to the victim is required.

### Recommendation
- In `StatusHandler` (and other handlers), scope the lookup to commits/stacks belonging to the repository named in the payload, and — critically — verify that the repository named in the payload (`repository.full_name`) belongs to the same organization that was used to select the webhook secret in `verify_signature` (`repository.owner.login` == `full_name`'s owner segment, and that repository is actually registered under that organization).
- Do not trust `repository.owner.login` alone to select the verification secret while allowing a different, unchecked `full_name`/`sha` to determine what gets mutated; bind the verified identity to the acted-upon resource in one place (e.g., verify the signature, then look up the `Repository`/`Stack` from the same organization scope, and reject if inconsistent).
- Scope `StatusHandler#process`'s `Commit` lookup to `stacks` (as `PushHandler`/`CheckSuiteHandler` already partially do) rather than a bare global `Commit.where(sha: ...)`.

### Proof of Concept
1. Attacker is admin of `attacker-org/attacker-repo`, onboarded to the shared Shipit instance, and knows its configured `webhook_secret`.
2. Attacker crafts a JSON body:
```json
{
  "sha": "<victim-commit-sha>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "attacker-org/attacker-repo" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=HMAC_SHA1(attacker-org's webhook_secret, body)` and POSTs it to `/webhooks` with `X-Github-Event: status`.
4. `WebhooksController#verify_signature` succeeds because it only checks the signature against `attacker-org`'s secret, derived from the attacker-controlled `repository.owner.login` field: [1](#0-0) 
5. `StatusHandler#process` matches `Commit.where(sha: "<victim-commit-sha>")` — belonging to a victim stack in an entirely different organization — and creates a forged success status on it: [5](#0-4) 
6. If the victim stack's `ci.require` includes `ci/required-check`, the victim commit now appears to satisfy CI requirements, potentially enabling merge/deploy without having passed real CI.

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-38)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```
