### Title
Cross-tenant webhook forgery via organization/repository binding mismatch in signature verification - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App (and therefore which `webhook_secret`) to validate an inbound webhook against using the payload's `repository.owner.login` field, while every event handler resolves the target `Stack`/`Repository` to write to using the completely independent `repository.full_name` field. On a Shipit instance configured with more than one GitHub App (a documented, supported configuration — see `test/dummy/config/secrets_double_github_app.yml`), a party who controls one onboarded organization's legitimate webhook credentials can forge a payload whose `repository.owner.login` matches their own org (so it passes signature verification) but whose `repository.full_name` names a different, victim organization's repository. Handlers act on `repository.full_name` without ever checking that it is consistent with the organization that authenticated the request.

### Finding Description
`app/controllers/shipit/webhooks_controller.rb` computes the authorizing organization from the payload itself: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')` and is used to pick `Shipit.github(organization: repository_owner)`, whose `webhook_secret` is then used to HMAC-verify `X-Hub-Signature` over the raw body: [3](#0-2) 

Once the signature check passes, `params = JSON.parse(request.raw_post)` is dispatched unmodified to every registered handler for the event: [4](#0-3) 

All handlers, however, resolve the `Stack`/`Repository` they operate on from a *different* JSON field — `repository.full_name`: [5](#0-4) 

For example `PushHandler` looks up stacks solely from `repository_name` (i.e. `full_name`) and branch, then triggers a GitHub sync for whatever stack matches: [6](#0-5) 

Pull-request handlers (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `ReopenedHandler`, `LabelCapturingHandler`) likewise resolve `repository` from `params.repository.full_name` to find or create/archive review stacks: [7](#0-6) 

**The binding that should hold:** `organization that authenticated the webhook (repository.owner.login)` == `organization that owns the repository being written to (repository.full_name)`.

**What actually happens:** these are two unrelated strings inside the same JSON body. Nothing enforces that `full_name` starts with `owner.login`. `verify_signature` only confirms the body was HMAC-signed by *some* configured organization's secret — not that the target of the write belongs to that organization.

### Impact Explanation
On any Shipit deployment hosting more than one GitHub organization behind distinct GitHub App configurations (an explicitly supported setup, evidenced by `secrets_double_github_app.yml` and the `Shipit::GithubOrganizationUnknown` per-organization lookup logic), a party who legitimately controls webhook delivery for Organization A (their own onboarded org) can forge a webhook whose `repository.owner.login` = `"org-a"` (so `verify_signature` selects and successfully validates against org A's real secret) but whose `repository.full_name` = `"org-b/victim-repo"`. This is accepted as an authentic event for `org-b`'s stacks:
- `push` events can invoke `stack.sync_github(expected_head_sha:)` on a victim stack belonging to another tenant, feeding attacker-chosen commit data into that stack's tracked history.
- `status`/commit-status style events (dispatched the same way, keyed off `repository.full_name`) can write `Status` records used to satisfy `required_statuses` — this directly gates whether Shipit will allow a deploy, so a forged "success" status can enable an operator to trigger a deploy of a commit that never actually passed CI.
- `pull_request` events can create/archive review stacks (provisioning/deprovisioning infrastructure) for a repository the forging party does not control.

This is a cross-tenant write (writes to `org-b`'s Stack/Commit/Status/ReviewStack records driven only by credentials scoped to `org-a`), and forging deploy-gating `Status` records is a path to an unauthorized deploy — both are in the Critical impact bucket defined for this scan (cross-repository writes / unauthorized deploy).

### Likelihood Explanation
Requires: (1) the target Shipit instance to be configured with more than one GitHub App/organization (a supported, real-world multi-tenant configuration), and (2) the attacker to legitimately possess (or have compromised) the webhook secret/App credentials for at least one onboarded organization — which is a much lower bar than compromising the victim organization itself, and is exactly the kind of unprivileged-relative-to-the-victim-tenant scenario the binding is supposed to prevent. No GitHub App private key, `api_clients_secret`, or Shipit session is required; only the ability to deliver a signed webhook for one's own, already-onboarded organization.

### Recommendation
When resolving the target repository/stack in `Shipit::Webhooks::Handlers::Handler#repository_name` (and equivalent handler code paths), verify that the resolved `Repository#owner` matches the `repository_owner` (or `organization.login`) value that was actually used to select the verifying GitHub App/secret in `WebhooksController#verify_signature`. Reject (422) any event where `full_name`'s owner segment does not match the authenticating organization.

### Proof of Concept
Given a Shipit instance configured with two GitHub Apps, one for `org-a` (attacker-controlled, real webhook secret known) and one for `org-b` (victim, unrelated secret):

1. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen-or-known-sha>",
  "repository": {
    "owner": { "login": "org-a" },
    "full_name": "org-b/victim-repo"
  }
}
```
2. Attacker computes `X-Hub-Signature` using `org-a`'s real webhook secret over the raw JSON body and POSTs it to `/webhooks`.
3. `WebhooksController#repository_owner` returns `"org-a"`; `Shipit.github(organization: "org-a").verify_webhook_signature` succeeds because the signature was legitimately computed with `org-a`'s secret. [8](#0-7) 
4. `PushHandler#process` (dispatched with the same raw JSON `params`) resolves `stacks` via `Repository.from_github_repo_name("org-b/victim-repo")`, matching `org-b`'s tracked stack, and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-or-known-sha>")` on it — a write to a stack the attacker's authenticated identity (`org-a`) does not own. [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-38)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
