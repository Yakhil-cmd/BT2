### Title
Webhook signature verification selects the GitHub App/secret by `repository.owner.login`, but write handlers key off the unrelated `repository.full_name`, allowing cross-organization forged webhook events - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
Shipit supports multi-org GitHub App configuration where each organization has its own `webhook_secret` (`docs/setup.md`). `WebhooksController#verify_signature` picks which app/secret to validate the incoming payload's signature against using a field read straight out of the untrusted JSON body — `repository.owner.login` (or `organization.login` as fallback) — instead of any value bound to the actual resource the event will act on.

### Finding Description
`verify_signature` resolves the signing secret exclusively from attacker-controlled payload data: [1](#0-0) [2](#0-1) 

The HMAC signature is checked against `github_app.verify_webhook_signature(...)` where `github_app = Shipit.github(organization: repository_owner)`, and `repository_owner` is simply `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. Nothing else in the payload is cross-checked against this value.

Once the signature passes, `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` dispatches the full raw payload to handlers. Every handler resolves the target repository/stack from a *different* field, `repository.full_name`: [3](#0-2) 

This is the root cause: the binding `organization authenticated == organization/repository written` is never enforced. `repository.owner.login` (used to pick the secret) and `repository.full_name` (used to pick the Stack/Repository/Team/Membership to mutate) are independent fields inside the same untrusted JSON body and can be set inconsistently by anyone who can produce a validly-signed payload for *any* one organization configured in the multi-org `github:` section.

In a multi-org Shipit deployment, an attacker who administers (or is invited to/installs) their own GitHub App/organization tracked by this Shipit instance knows their own organization's `webhook_secret` used to sign real webhooks. They can craft an arbitrary raw POST body with `repository.owner.login` (or `organization.login`) set to their own org, but `repository.full_name` (and all other fields) pointing at a victim repository/stack tracked under a different organization on the same Shipit instance, sign it with their own secret, and send it to the shared `/github/webhooks` endpoint. `verify_signature` will select their org's `GitHubApp`, verify the signature successfully (since they control that secret), and the request proceeds to handlers that operate on the victim repository's Stack, Team, or Membership records.

### Impact Explanation
Depending on event type this reaches:
- `push` → `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)` on victim stacks not owned by the attacker's organization, an attacker-controlled resync of an unrelated repository.
- `membership` → `MembershipHandler` creates/deletes `Team`/`Membership`/`User` records globally (not repo-scoped), which can influence `Shipit.github_teams` authorization used across the whole Shipit instance.
- `pull_request` events → can create/archive Review Stacks (`ReviewStackAdapter`) for a victim repository.

This is a cross-repository/cross-organization write achieved purely by exploiting a validly-issued (but wrongly-scoped) HMAC secret, matching the "cross-repository writes" / "escalation into `Shipit.github_teams` authorization" impact classes, without requiring any Shipit session, API token, or repository write access on GitHub.

### Likelihood Explanation
Requires: (a) the Shipit instance to be configured for multiple GitHub organizations (a documented, supported configuration — `docs/setup.md`), and (b) the attacker to control/administer at least one of those onboarded organizations (i.e., know that org's `webhook_secret`, which they naturally do as the app installer for their own org). No compromise of the victim organization, its secret, or a Shipit account is needed. This is realistic for any Shipit instance shared across independent teams/organizations, which is exactly the use case the multi-app config exists for.

### Recommendation
Bind the signature-selection field to the field actually used by the handlers: after signature verification, re-derive the app for the concrete `repository.full_name`'s owner and require it to match the app whose secret validated the signature (or, more robustly, derive `repository_owner` from `repository.full_name`'s owner segment rather than trusting `repository.owner.login`/`organization.login` independently, and reject payloads where these are inconsistent). Alternatively, verify the payload against all configured `webhook_secret`s only when the resolved app's organization matches the repository actually referenced by `repository.full_name`.

### Proof of Concept
1. Configure Shipit with two organizations in `config/secrets.yml`'s `github:` map: `attacker-org` (secret known to the attacker, who installed/administers the GitHub App there) and `victim-org` (tracked stack `victim-org/victim-repo`).
2. Attacker crafts a `push` (or `membership`/`pull_request`) JSON payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker chosen sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(webhook_secret_of_attacker_org, raw_body)`.
4. POST to `/github/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"attacker-org"`, fetches `Shipit.github(organization: "attacker-org")`, and the signature checks out (attacker used the correct secret for that org).
6. `PushHandler` (via `Handler#repository_name` → `payload.dig('repository', 'full_name')` = `"victim-org/victim-repo"`) resolves and mutates the victim's `Stack`, e.g. triggering `sync_github(expected_head_sha: <attacker chosen sha>)` for a repository the attacker does not own or control on GitHub. [4](#0-3)

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
