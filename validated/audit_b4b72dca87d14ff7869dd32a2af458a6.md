## Analysis

This maps to the same root-cause pattern as ASA-2024-003: **a value used to establish trust (the organization whose secret validated the request) is never bound to the value the code actually acts on (the repository / commit that gets written).**

### Binding broken

`organization that authenticated the webhook request` ≠ `repository/commit that the webhook handler writes to`

### Root cause chain

1. `WebhooksController#verify_signature` picks which GitHub App/secret to use for HMAC verification purely from the payload itself, before the payload is trusted: [1](#0-0) [2](#0-1) 

2. `GitHubApp#verify_webhook_signature` explicitly returns `true` (i.e., accepts the payload unverified) whenever that organization has no `webhook_secret` configured: [3](#0-2) 

3. This "no secret" state is a documented, supported configuration, not a misconfiguration — every example secrets file ships `webhook_secret: # nil` and `docs/setup.md` calls it "optional": [4](#0-3) [5](#0-4) 
Multi-organization hosting of several independent GitHub orgs behind one Shipit instance is also a first-class, documented feature: [6](#0-5) 

4. Crucially, `StatusHandler` — reached once the (possibly-unverified) payload clears `verify_signature` — never checks `repository.full_name`/`repository.owner` at all. It looks up commits **globally across the entire database** by SHA alone: [7](#0-6) 

Compare this with the base `Handler` class, which *does* have a `repository_name`/`stacks` scoping mechanism used by other handlers (e.g. `PushHandler`), but `StatusHandler` doesn't use it: [8](#0-7) [9](#0-8) 

### Concrete attack

If any single organization configured on a shared Shipit instance has `webhook_secret` unset (a supported config), an unprivileged attacker who merely knows that org's name (public) can POST a forged `status` event to `/webhooks`:

```json
{
  "sha": "<victim-org/victim-repo commit sha, public on GitHub>",
  "state": "success",
  "repository": { "owner": { "login": "org-with-no-webhook-secret" } }
}
```

`verify_signature` resolves `Shipit.github(organization: 'org-with-no-webhook-secret')`, whose `verify_webhook_signature` short-circuits to `true` because no secret is configured — no HMAC is checked at all. `StatusHandler#process` then writes a forged `success` status onto the **victim's** commit, in a completely different organization/repository than the one that "authenticated" the request, since the handler never cross-checks `repository.owner`/`full_name` against the org used for verification.

This status is exactly the mechanism `ci.require` gates deploys on (per README's CI section), so a forged `success` status can make an otherwise CI-blocked commit appear deployable — an unauthorized-deploy-enabling forgery achieved with zero credentials, tokens, or secrets, purely by exploiting the documented "no webhook secret" + multi-org configuration and the missing repository binding in `StatusHandler`.

### Title
Unscoped `StatusHandler` Commit Lookup Allows Cross-Organization Status Forgery When Any Configured Org Has No Webhook Secret - (File: `app/models/shipit/webhooks/handlers/status_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects the HMAC-verifying organization from unauthenticated payload fields (`repository.owner.login`/`organization.login`), and `GitHubApp#verify_webhook_signature` accepts the request unconditionally when that organization has no `webhook_secret` configured — a supported, documented state. `StatusHandler` then updates commit statuses by SHA alone, with no check that the commit's repository belongs to the organization that was used to authenticate the request.

### Finding Description
The verification-organization binding (`repository.owner.login` → which secret validates the raw body) is never re-checked against the data the handler actually mutates. `StatusHandler.process` (`app/models/shipit/webhooks/handlers/status_handler.rb:20-24`) performs `Commit.where(sha: params.sha)` with no `stacks`/`repository_name` scoping, unlike sibling handlers such as `PushHandler`. Combined with `verify_webhook_signature`'s `return true unless webhook_secret` (`lib/shipit/github_app.rb:76-83`), any organization configured without a webhook secret becomes an unauthenticated ingress point for status events that can target commits belonging to any other organization hosted on the same Shipit instance.

### Impact Explanation
Forged `success`/`failure` statuses can manipulate `ci.require`-gated deployability of arbitrary commits/stacks not owned by the attacker, enabling an unauthorized deploy path — matching the Critical impact bar ("an unauthorized deploy").

### Likelihood Explanation
Requires the host to have at least one organization configured with no `webhook_secret`, which is the shipped example default and explicitly documented as optional; requires no session, token, or secret from the attacker — only knowledge of a public commit SHA and an org name.

### Recommendation
Have `StatusHandler` (and any other handler lacking it) scope commit lookups through `stacks`/`Repository.from_github_repo_name(repository_name)` like `PushHandler`, and/or require `verify_webhook_signature` to fail closed (reject) when no secret is configured instead of returning `true`.

### Proof of Concept
1. Identify a Shipit-hosted org `OrgA` with `webhook_secret` unset in `secrets.yml` (default/example config).
2. Obtain a public commit SHA from a stack under an unrelated org `OrgB` also hosted on the same instance.
3. `POST /webhooks` with header `X-Github-Event: status` and body `{"sha": "<OrgB commit sha>", "state": "success", "repository": {"owner": {"login": "OrgA"}}}` — no valid `X-Hub-Signature` needed since `OrgA` has no secret.
4. `verify_signature` passes; `StatusHandler` writes a forged `success` status onto the `OrgB` commit, satisfying its `ci.require` checks.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.example.yml (L8-16)
```yaml
github:
  app_id:
  installation_id:
  webhook_secret: # nil
  private_key:
  oauth:
    id:
    secret:
    teams: # Optional
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

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
