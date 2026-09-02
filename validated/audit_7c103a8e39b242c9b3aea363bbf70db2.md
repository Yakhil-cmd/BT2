### Title
Webhook secret selection is based on an unverified payload field, letting one configured GitHub organization forge signed events for another organization's repository - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController` uses a single shared endpoint for all GitHub organizations configured on the instance (multi-org setups are explicitly documented in `docs/setup.md`). Before verifying the HMAC signature, it picks *which* org's `webhook_secret` to verify against by reading a field straight out of the untrusted, not-yet-verified JSON body. The event handlers that actually mutate data then key off a *different* field of that same untrusted body to decide which repository/stack to act on. Because these two fields are never cross-checked against each other, the org whose secret validated the signature can differ from the repository that gets written.

### Finding Description
`WebhooksController#verify_signature` resolves the GitHub App/secret to check with: [1](#0-0) 

and `repository_owner` is computed purely from request body content, before any signature has been checked: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up the per-org config block (`app_id`, `installation_id`, `webhook_secret`) documented for multi-org deployments: [3](#0-2) 

Each org's `GithubApp#verify_webhook_signature` only checks the HMAC against that org's own `webhook_secret`: [4](#0-3) 

Once the (correctly-signed-for-its-own-org) request passes, `WebhooksController#create` dispatches the same raw, attacker-supplied payload to every registered handler for the event type: [5](#0-4) 

All handlers (`PushHandler`, `PullRequest::*Handler`, `StatusHandler`, etc.) resolve the target repository/stack from `payload.dig('repository', 'full_name')` — a field that is completely independent of `repository_owner`/`organization.login` used for signature routing: [6](#0-5) [7](#0-6) [8](#0-7) 

The equality that should be enforced — "the GitHub organization whose secret validated the signature" == "the repository/stack that the handler writes to" — is never checked. An attacker who legitimately administers **one** GitHub organization configured on this Shipit instance (and therefore knows that org's `webhook_secret`, since they installed the App and can see/reset it in their own org's GitHub App settings) can send a webhook where:
- `repository.owner.login` (or `organization.login`) = their own org → signature verification succeeds using their known secret.
- `repository.full_name` = `victim-org/victim-repo` → the handler acts on a stack belonging to a completely different, unrelated organization also hosted on the same Shipit instance.

This is analogous to the reported `deleteToken`/`saveToken` inconsistency: one code path (signature verification) is gated on a value, while the state-changing action (handler dispatch) is keyed on a *different, uncontrolled* value from the same untrusted input, breaking the intended one-to-one binding between "authenticated organization" and "repository written."

### Impact Explanation
Handlers reachable this way include:
- `StatusHandler`, which records commit CI status directly from the payload — a forged "success" status on a victim stack's commit can make that commit appear `deployable?`/pass CI checks required for merge queue or continuous deployment, resulting in an **unauthorized deploy** of attacker-chosen state on a stack the attacker does not control.
- `PullRequest::*Handler`s, which can archive/unarchive review stacks, or edit/label/close pull requests belonging to the victim repository.
- `PushHandler`, which can force a sync (`sync_github`) against a victim stack.

Cross-organization write access to stack/commit/PR state without holding a Shipit session, `ApiClient` token, or the victim org's own webhook secret meets the "cross-repository writes / unauthorized deploy" Critical bar in this engine.

### Likelihood Explanation
Requires the attacker to control (own/administer) at least one GitHub organization that the operator has configured as a *second tenant* on the same shared Shipit instance (i.e., multi-org deployments, which the project explicitly documents and supports). No compromise of the victim org's credentials, GitHub App, or Shipit account is needed — only knowledge of the attacker's own org's `webhook_secret`, which they legitimately possess. This is realistic wherever an operator hosts multiple independent orgs/customers behind one Shipit instance.

### Recommendation
After signature verification succeeds for `repository_owner`, validate that every payload's `repository.full_name`/`organization.login` actually belongs to the same GitHub organization whose secret validated the signature (e.g., compare the resolved `Repository`'s owner against `repository_owner`) before dispatching to handlers, and reject the event otherwise.

### Proof of Concept
1. Operator configures two GitHub orgs in `config/secrets.yml`: `victim-org` and `attacker-org` (per the documented multi-org setup).
2. Attacker (owner of `attacker-org`, thus knowing its `webhook_secret`) crafts a `status` (or `push`) webhook JSON body with:
   - `organization.login` / `repository.owner.login` = `attacker-org`
   - `repository.full_name` = `victim-org/victim-repo`
   - `sha`, `state: "success"`, `context` matching the victim stack's required status context.
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` and POSTs to the shared `/github/webhooks` endpoint.
4. `verify_signature` looks up `Shipit.github(organization: 'attacker-org')`, verifies successfully with the attacker's own secret.
5. `StatusHandler` (or `PushHandler`) resolves the target stack via `Repository.from_github_repo_name('victim-org/victim-repo')` and records the forged status/sync against the victim's commit — with no relationship between `attacker-org` and `victim-org` ever checked.

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

**File:** docs/setup.md (L184-209)
```markdown
A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
