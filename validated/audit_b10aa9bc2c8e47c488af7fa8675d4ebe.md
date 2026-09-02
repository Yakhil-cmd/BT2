### Title
Webhook signature check authenticates `repository.owner.login`/`organization.login` while all event handlers act on the independent `repository.full_name` field, allowing cross-organization payload spoofing when any configured GitHub org lacks a `webhook_secret` - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and thus which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (or `organization.login`), but every event handler (`Handler#repository_name`, `PushHandler`, `StatusHandler`, etc.) resolves the actual target `Stack`/`Repository` from the independent `repository.full_name` field. Because these two payload fields are never cross-validated for consistency, and because `GitHubApp#verify_webhook_signature` trivially returns `true` whenever an organization's `webhook_secret` is unset (a documented, supported configuration for multi-org setups), an attacker can craft a payload whose `repository.owner.login` names an org with no configured secret while `repository.full_name` names a completely different, secured org's repository, causing the request to be accepted and dispatched against that other org's stack.

### Finding Description
- `WebhooksController#verify_signature` picks the signing organization from the payload itself: [1](#0-0) [2](#0-1) 

- `GitHubApp#verify_webhook_signature` unconditionally passes if no `webhook_secret` is configured for that organization: [3](#0-2) 

- This "no secret" configuration is explicitly documented as a normal setup for multi-org deployments (webhook_secret left blank per org): [4](#0-3) [5](#0-4) 

- Meanwhile, every webhook handler resolves the *actual* repository/stack acted upon from a **different** field, `repository.full_name`, not `repository.owner.login`: [6](#0-5) [7](#0-6) 

- `PushHandler` uses this `stacks` helper (backed by `repository_name` = `repository.full_name`) to sync commits for any matching stack: [8](#0-7) 

This mirrors the C4 report's bug class exactly: a payload field that is *used* by downstream logic (`repository.full_name`, driving the actual write/action) is never covered by the binding that determined trust (`repository.owner.login`, driving signature selection). The report frames this as "a field acted on but never covered by the verified signature/binding" — here the binding broken is "organization that authenticated" (`repository.owner.login`) vs. "repository that is written" (`repository.full_name`), which is explicitly listed as an in-scope analog class in the rules.

### Impact Explanation
If a Shipit deployment is configured with multiple GitHub organizations (a documented supported feature) and at least one of them has no `webhook_secret` set (also documented as a valid default), an unprivileged external attacker who merely knows that org's *name* (not secret) can forge a `push`/`status`/`check_suite`/`pull_request` payload with:
- `repository.owner.login` = the org lacking a secret (verification auto-passes, no HMAC needed)
- `repository.full_name` = `victim-org/victim-repo` (a different, secured org's stack)

The request passes `verify_signature` and is dispatched to `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }`, which resolves the target strictly via `repository.full_name`. This lets the attacker trigger unauthorized `GithubSyncJob` runs, fabricate commit statuses, or otherwise manipulate the state of a stack belonging to an organization they have no legitimate access to — an unauthorized write against a repository the attacker does not control, achieved purely by exploiting the mismatch between the field used for authentication and the field used for the write target.

### Likelihood Explanation
Requires the Shipit instance to run with more than one GitHub App/org configured, and at least one of those orgs to have no `webhook_secret`. This is a supported and documented configuration shape (shown in the shipped example secrets file and setup docs), meaning it is plausible in real deployments rather than purely theoretical. No credentials, tokens, or webhook secrets are needed by the attacker for the org they impersonate as signer; they only need to know that org's login name, and craft an inconsistent `repository.owner.login` vs `repository.full_name` payload — something GitHub itself would never produce, but which this endpoint does not reject.

### Recommendation
In `WebhooksController#verify_signature`, verify the webhook against the organization actually referenced by the field the handlers use to locate the target (`repository.full_name`'s owner segment), and reject requests where `repository.owner.login`/`organization.login` does not match the owner parsed from `repository.full_name`. Additionally, consider requiring `webhook_secret` to be present for every configured organization in production, or fail closed (reject) rather than pass-through when a secret is not configured, so that a single unsecured org config cannot be leveraged to bypass verification for other orgs' repositories.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `OrgA` (no `webhook_secret` set) and `OrgB` (properly configured, with a real Stack for `OrgB/victim-repo`) — mirroring the shipped example in `config/secrets.development.shopify.yml`.
2. As an external, unauthenticated attacker, POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgA" },
    "full_name": "OrgB/victim-repo"
  }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required, since `Shipit.github(organization: "OrgA").verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`, because `OrgA` has no `webhook_secret`).
3. `verify_signature` passes; `WebhooksController#create` runs `Shipit::Webhooks.for_event("push")`, and `PushHandler#process` resolves stacks via `repository.full_name` = `"OrgB/victim-repo"` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, `app/models/shipit/repository.rb:53-56`), triggering a `GithubSyncJob` against `OrgB`'s real stack — despite the attacker never possessing `OrgB`'s webhook secret.

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

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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
