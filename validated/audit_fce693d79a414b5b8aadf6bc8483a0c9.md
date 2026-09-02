### Title
Webhook organization used to select the signing secret is never bound to the repository the payload actually targets, enabling cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary

### Finding Description
`WebhooksController#verify_signature` determines which GitHub App/organization secret to use for HMAC verification purely from `repository.owner.login` (or the fallback `organization.login`) inside the JSON body: [1](#0-0) [2](#0-1) 

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` hands the *entire, attacker-controlled* JSON body to the handler. Every handler resolves the target repository/stack from a completely different field, `repository.full_name`, with no cross-check that this repository belongs to the organization that produced the valid signature: [3](#0-2) [4](#0-3) [5](#0-4) 

Because `repository.owner.login` (used only to pick the secret) and `repository.full_name` (used only to pick the target) are two independent fields inside the same HMAC-signed JSON blob, a party that legitimately possesses the webhook secret for *one* organization/GitHub App tenant of a multi-tenant Shipit deployment (e.g. `somegithuborg` in `config/secrets.development.shopify.yml`) can construct a payload where `repository.owner.login`/`organization.login` names their own org (so `verify_signature` succeeds against their own secret) while `repository.full_name` names a repository belonging to a completely different, victim organization also tracked by the same Shipit instance. Every handler — `PushHandler`, `StatusHandler`, the `PullRequest::*` handlers, `CheckSuiteHandler` — will happily act on the stack/repository resolved from the forged `full_name`.

This is the same trust-binding failure as the reported DSToken bug: an operation is gated on one identity/value ("country before change" / here, "the organization whose secret validated the signature") while the actual state mutation is keyed on a different, unguarded value ("country after change" / here, "the repository named in the body"). The equality that must hold and does not is:

`organization that signed the webhook == organization owning the repository the handler mutates`

### Impact Explanation
An attacker who administers (or controls the GitHub App/webhook secret of) any one organization tracked by a shared/multi-tenant Shipit instance can forge `push`, `status`, `check_suite`, or `pull_request` webhooks that are routed, via `repository.full_name`, to stacks belonging to a different organization they have no access to. Depending on the handler this can:
- Trigger `GithubSyncJob`/`stack.sync_github` on a victim's stack via the forged `push` event [6](#0-5) , causing an unauthorized deploy/merge-queue advance on infra they don't own.
- Manipulate commit statuses (`StatusHandler`) or archive/unarchive review stacks and provisioning state (`PullRequest::LabeledHandler`, `ClosedHandler`, etc.), all resolved solely from the forged `full_name` [7](#0-6) .

This satisfies the Critical/High bar: unauthorized deploy/merge on a repository the attacker does not control, i.e. a cross-repository write achieved without possessing that repository's credentials.

### Likelihood Explanation
Requires the attacker to hold a valid webhook secret for *some* organization/tenant configured in the running Shipit instance (a normal, unprivileged capability for any tenant admin in a multi-org deployment as illustrated by the multi-entry `github:` config) — no Shipit session, `ApiClient` token, or the victim organization's own webhook secret is needed. Because the two fields (`repository.owner.login` and `repository.full_name`) are never cross-validated anywhere in the request pipeline, exploitation is a straightforward payload construction problem, not a cryptographic one.

### Recommendation
In `Handler#stacks`/`repository_name`, and in every handler that resolves a target repository/stack from `repository.full_name`, verify that the resolved `Repository#organization` (or its stored GitHub owner) matches the organization that was used to validate the webhook signature in `WebhooksController#verify_signature`, and reject (422) the payload if they differ. Equivalently, pass the verified `repository_owner` down into `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` and have `Handler#repository_name`/`stacks` enforce equality with `payload.dig('repository', 'owner', 'login')` before resolving/mutating anything.

### Proof of Concept
1. Deploy Shipit tracking two orgs, `attacker-org` and `victim-org`, each with its own GitHub App/webhook secret (as in `config/secrets.development.shopify.yml`) — `attacker-org`'s secret is known to the attacker as its legitimate admin.
2. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "attacker-org" },
    "full_name": "victim-org/victim-repo"
  }
}
```
3. Attacker signs this exact body with `attacker-org`'s webhook secret and POSTs it to `/github/webhooks` with `X-Github-Event: push` and `X-Hub-Signature`.
4. `WebhooksController#verify_signature` resolves `repository_owner` = `"attacker-org"` [2](#0-1) , fetches `Shipit.github(organization: "attacker-org")`, and successfully verifies the signature against the attacker's own secret [1](#0-0) .
5. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"victim-org/victim-repo"` [4](#0-3)  and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack [6](#0-5)  — an unauthorized action on a repository the attacker never controls.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-17)
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
```

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
