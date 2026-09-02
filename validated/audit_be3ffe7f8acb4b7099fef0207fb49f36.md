### Title
Webhook signature is verified against `repository.owner.login`/`organization.login` while every event handler routes and writes against the unauthenticated `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
This is the same bug class as the reported `request_profit_withdraw_from_vault` flaw: a security-critical check is computed from one value, while the state-mutating action is actually keyed off a *different, unchecked* value that the attacker controls. In Bluefin, the assertion validated against a stale/incomplete balance while the payout was driven by an inflated `pending_profit_amount`. In Shipit, `WebhooksController#verify_signature` validates the HMAC signature using a GitHub *organization* derived from `repository.owner.login` (or `organization.login`), but the actual write path — resolving which `Stack`/`Repository` a payload applies to — uses `repository.full_name`, a completely separate JSON field that is never covered by, or cross-checked against, the signature-selected organization.

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/organization whose `webhook_secret` will validate the signature using: [1](#0-0) 

```ruby
def repository_owner
  # Fallback to the organization sub-object if repository isn't included in the payload
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

This binds the request's authenticity only to whichever organization's secret can validate `X-Hub-Signature` against `repository.owner.login`.

However, every dispatched handler determines *which repository/stack the payload actually operates on* using a different key, `repository.full_name`: [3](#0-2) 

```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
```

and `PushHandler` (and other handlers such as the pull-request handlers) resolve the target stacks/repository purely from this `full_name`, e.g.: [4](#0-3) 

Nothing in the request pipeline asserts that `repository.full_name`'s owner segment equals `repository.owner.login`/`organization.login` used to select the webhook secret. In a Shipit deployment configured to host stacks for multiple GitHub organizations (each org supplies its own `webhook_secret` for its own GitHub App/webhook, as documented in the engine's multi-org configuration), a payload author who legitimately controls one org's webhook secret can:

1. Set `repository.owner.login` (or `organization.login`) to their own organization "A", so `verify_signature` succeeds using A's `webhook_secret`.
2. Set `repository.full_name` to `victim-org/victim-repo`, a repository belonging to an entirely different, unrelated organization "B" tracked on the same Shipit instance.

The signature check passes (it never inspects `full_name`), and the handler then acts on organization B's stack because it only reads `full_name`. This breaks exactly the binding called out for this bug class: *the organization that authenticated the payload* vs. *the repository whose state is written*.

### Impact Explanation
Depending on the event type, this cross-organization forgery reaches Critical/High impact:
- `push` events: `PushHandler` calls `stack.sync_github(expected_head_sha:)` on the victim's stack for the forged branch/sha, which can desynchronize commit tracking or, combined with continuous deployment, contribute to triggering an unauthorized deploy pipeline evaluation for a repository the attacker does not own — a cross-organization/cross-repository interaction the attacker should never be able to trigger.
- `pull_request` events: handlers such as `OpenedHandler`, `ClosedHandler`, `LabeledHandler` create/archive/unarchive review stacks (`Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter`) for the victim's repository based purely on the forged `full_name`, allowing an attacker with no relationship to the victim's org to manipulate victim review-stack lifecycle state.
- Because `Repository.from_github_repo_name` is a simple owner/name lookup with no tie back to which organization's credentials/secret validated the request, this constitutes an authentication-binding bypass across repository/organization boundaries — matching the "cross-repository writes" / "unauthorized deploy" criteria for a Critical/High finding.

### Likelihood Explanation
Exploitability requires only that the attacker control (or know) the `webhook_secret` for *any one* organization configured on the shared Shipit instance — which is, by design, distributed to that organization's own administrators so they can configure their GitHub App/webhook delivery. No access to the victim organization, no `ApiClient` token, no Shipit user session, and no GitHub App private key for the victim org is required. The attacker only needs to send a raw HTTP POST to the shared `/webhooks` (or engine-mounted) endpoint with a crafted JSON body and a valid `X-Hub-Signature` computed with their own org's secret — something entirely within their control since they own that secret. This is realistic in any Shipit deployment that serves more than one GitHub organization, which is an explicitly supported and documented configuration.

### Recommendation
Bind the entire payload's trust to a single, consistent identity. Concretely:
- Compute `repository_owner` (or the equivalent trust anchor) from the *same* field the handlers use to resolve the target repository (`repository.full_name`'s owner segment), not from a separate/independent field.
- After signature verification succeeds for organization X, assert that `repository.full_name`'s owner segment (and, where applicable, `organization.login`) also equals X before dispatching to any handler; reject the webhook otherwise.
- Alternatively, resolve the target `Repository`/`Stack` first from `repository.full_name`, look up that repository's *actual* configured organization, and use that (not attacker-suppliable fields elsewhere in the payload) to select the `webhook_secret` for verification.

### Proof of Concept
1. Shipit hosts stacks for org `victim-org/victim-repo` and separately has an onboarded org `attacker-org` (attacker legitimately owns this org's GitHub App/webhook and thus knows its `webhook_secret`).
2. Attacker builds a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac using attacker-org's webhook_secret over the raw body>`.
4. Attacker POSTs this to the Shipit webhooks endpoint with `X-Github-Event: push`.
5. `WebhooksController#verify_signature` calls `repository_owner` → `"attacker-org"`, loads `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature using the attacker's own secret.
6. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")`, matching the victim's stack, and invokes `stack.sync_github(expected_head_sha: params.after)` on it — despite the request never being authenticated by, or associated with, `victim-org`'s own credentials. [5](#0-4) [3](#0-2) [6](#0-5)

### Citations

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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
