## Title
Webhook signature is verified against `repository.owner.login`, but the target repository/stack that is mutated is resolved from the independently attacker-supplied `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

## Summary
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to verify the HMAC signature against based on `repository_owner`, derived from the payload's `repository.owner.login` (or `organization.login`) field. Every webhook handler, however, resolves the actual `Stack`/`Repository` to mutate using a *different* field of the very same payload: `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name`. The HMAC only proves "this raw body was produced by whoever holds the secret associated with `repository.owner.login`" - it says nothing about whether `repository.full_name` inside that same body actually belongs to that owner. In a single-organization deployment this is harmless because GitHub always emits self-consistent payloads. In the documented and supported multi-organization configuration (`docs/setup.md`, "Using Multiple Github Applications"), where several independent organizations each have their own `webhook_secret` but all deliver to the same shared `/webhooks` endpoint, this binding no longer holds for anyone able to compute a valid signature with *any one* of the configured secrets.

## Finding Description
The verification path is: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` is used purely to pick which app/secret's HMAC to check via `verify_webhook_signature`: [3](#0-2) 

Once the signature check passes, the raw JSON body is handed unmodified to every registered handler for the event: [4](#0-3) 

But the base `Handler` class - used by `PushHandler`, `StatusHandler`, `CheckSuiteHandler`, and all `PullRequest::*Handler`s - resolves the affected repository/stacks from a *different* key in the same payload, `repository.full_name`, not `repository.owner.login`: [5](#0-4) 

The same divergent-field pattern repeats in the pull-request handlers, which independently call `Shipit::Repository.from_github_repo_name(params.repository.full_name)`: [6](#0-5) 

Because the HMAC is computed over the entire raw request body, it cryptographically proves only "the sender knows secret S", where S is chosen using `repository.owner.login`. It does not prove any relationship between `repository.owner.login` and `repository.full_name` - both are just JSON fields inside the signed blob, and the signer (who legitimately knows their own org's secret because they administer that GitHub App/organization) can set them independently before signing.

**Binding that should hold, but doesn't:**
`organization authenticated via webhook secret (repository.owner.login)` == `organization of the repository actually written to (repository.full_name)`

**Before the equality is checked:** signature verification only confirms knowledge of secret `S_orgB` (attacker's own, legitimately configured organization).
**After:** the handler trusts `repository.full_name = "orgA/target-repo"` taken from the same signed-but-uncorrelated payload, and looks up/mutates `orgA`'s `Stack` (e.g. `PushHandler#process` calls `stack.sync_github`, `StatusHandler` creates a `Status` on a specific commit of that stack, `PullRequest::OpenedHandler` provisions a review stack under it).

This matches the report's bug class exactly: a value relied on by the trust/verification layer (`repository.owner.login`, analogous to the oracle chosen by E-mode) diverges from the value the business logic actually acts on (`repository.full_name`, analogous to the price actually used for LTV/liquidation math) - both are nominally "the same asset/repository" but are independently controllable.

## Impact Explanation
An attacker who legitimately administers **any one** organization/app connected to this shared Shipit instance (as is explicitly supported and documented for multi-tenant setups) can forge a webhook whose `repository.owner.login` matches their own org (so it passes signature verification with their own known secret) while `repository.full_name` names an arbitrary repository belonging to a *different* organization also connected to the instance. This yields cross-repository writes into another organization's `Stack`:
- `push` events can force `stack.sync_github(expected_head_sha: ...)` on another org's stack, injecting an attacker-chosen `after` SHA to be treated as the new head.
- `status` events can inject fabricated CI statuses on arbitrary commits of another org's stack, which can unblock deploy/merge-queue eligibility (`ci.require` checks) — a documented "unauthorized deploy" surface.
- `pull_request` events can provision/archive/label review stacks belonging to another org's repository.

This falls under the "cross-repository writes" / "unauthorized deploy" impact classes.

## Likelihood Explanation
This requires the operator to run Shipit in the documented multi-organization mode (multiple `github` app configs behind one shared `/webhooks` endpoint) and requires the attacker to control (or have visibility into) the webhook secret of at least one of the connected organizations/apps - a materially lower bar than compromising the target organization itself, and one entirely internal to this engine's design rather than a third-party admin action. Like the referenced Aave report, this is a "configuration/feature interaction" bug: the vulnerable condition (multi-org config) is a supported, documented feature that can be enabled at any time, not a rare edge case.

## Recommendation
After signature verification selects an organization, re-validate that every organization-identifying field consumed by handlers (`repository.owner.login`, `repository.full_name`'s owner segment, `organization.login`) is consistent with the organization whose secret verified the request. Concretely: derive `repository_owner` and `repository_name`/`full_name`'s owner from the same field, and/or have `Handler#stacks` reject/ignore payloads whose `repository.full_name` owner does not match the organization determined during signature verification (which could be threaded through, e.g. via a request-scoped value set in `verify_signature`).

## Proof of Concept
1. Deploy Shipit with multi-org config: `config/secrets.yml` has `github.orgB.webhook_secret = S_B` and `github.orgA.webhook_secret = S_A`, both delivering to the same `/webhooks` endpoint (per `docs/setup.md`, "Using Multiple Github Applications").
2. Attacker administers `orgB`'s GitHub App and therefore knows `S_B`.
3. Attacker crafts a raw JSON body for a `push` event:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "orgB" },
    "full_name": "orgA/target-repo"
  }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(S_B, body)` and POSTs to `/webhooks` with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` computes `repository_owner = "orgB"`, calls `Shipit.github(organization: "orgB").verify_webhook_signature(sig, body)`, which succeeds since the attacker used `S_B` correctly.
6. `PushHandler#process` is invoked; `Handler#stacks` resolves `Repository.from_github_repo_name("orgA/target-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on `orgA`'s stack, even though the request was authenticated solely against `orgB`'s secret. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-27)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
    end
  end
end
```
