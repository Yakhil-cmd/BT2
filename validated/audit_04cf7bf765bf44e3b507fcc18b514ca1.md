### Title
Cross-Organization Webhook Signature Bypass via `repository.owner.login`/`repository.full_name` Mismatch - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
In multi-GitHub-App deployments, `WebhooksController#verify_signature` selects which organization's webhook secret to verify against using `repository.owner.login` (or `organization.login`), while the actual event handlers act on `repository.full_name` from the same unsigned JSON body. Because `GitHubApp#verify_webhook_signature` treats a blank/unconfigured `webhook_secret` as automatically verified, an unauthenticated caller can pick an organization slot that has no `webhook_secret` configured to sail through verification, then point `repository.full_name` at a victim repository/stack tracked under a *different*, properly-configured organization, causing Shipit to act on that victim stack without ever presenting a valid signature for it.

### Finding Description
`verify_signature` computes the organization used to select the `GitHubApp` (and thus the secret used for HMAC verification) purely from attacker-controlled JSON fields: [1](#0-0) [2](#0-1) 

```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end
...
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
```

`GitHubApp#verify_webhook_signature` returns `true` unconditionally when no secret is configured for that organization: [3](#0-2) 

The `create` action then dispatches the *entire, unmodified raw payload* to the event handlers: [4](#0-3) 

Handlers, however, resolve the target `Repository`/`Stack` from a *different* field — `repository.full_name` — not `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

The engine explicitly supports multiple GitHub App configs keyed by organization, each with its own optional `webhook_secret` (docs confirm `webhook_secret` is optional per-org): [8](#0-7) [9](#0-8) 

This is the exact bug class from the report: a field (`repository.owner.login`, used to pick the trust/verification "reference") is decoupled from the field that actually drives the state-changing action (`repository.full_name`), even though both are attacker-supplied in the same unsigned/weakly-verified body. The binding that should hold — "organization whose secret authenticated the request" == "repository that gets written to" — is broken.

Equality that should hold but doesn't: `org(repository.owner.login used for signature check) == org(repository.full_name used for handler dispatch)`.

### Impact Explanation
If any organization configured in `Shipit.secrets.github` has a blank `webhook_secret` (explicitly supported/optional per docs, and shown as a normal configuration in `test/dummy/config/secrets_double_github_app.yml` and `test/dummy/config/secrets.yml`), an unauthenticated attacker can:
1. Set `X-Github-Event: push` (or another handled event) with no valid `X-Hub-Signature`.
2. Set `repository.owner.login` = the org with no secret configured, causing `verify_webhook_signature` to short-circuit to `true`.
3. Set `repository.full_name` = `victim-org/victim-repo`, a real, properly-secured stack tracked by Shipit.

The `PushHandler` will resolve `stacks` via `Repository.from_github_repo_name("victim-org/victim-repo")` and invoke `stack.sync_github(expected_head_sha: params.after)` — forcing Shipit to sync/ingest attacker-chosen commit SHAs into the victim stack's pipeline, entirely bypassing the intended signature check for that victim organization. Depending on downstream trust in synced commits/branches (deploy specs, CI-gated auto-deploys), this can escalate to an unauthorized deploy trigger — matching the "unauthorized deploy" High-impact category, achieved purely as an unprivileged network attacker with no session, API token, or webhook secret.

### Likelihood Explanation
Requires a specific but not-unusual precondition: at least one organization slot in a multi-org (or single legacy) configuration with a blank/unset `webhook_secret`, which the docs and shipped fixture files treat as a normal, supported configuration state, not a hardening requirement. Given that precondition, exploitation needs no credentials, no session, and no rate-limited resource — a single unauthenticated POST to `/webhooks`.

### Recommendation
Do not let attacker-controlled JSON fields decide both (a) which secret validates the request and (b) which repository the request acts upon. Concretely:
- Derive the organization used for signature verification from the same value ultimately used for handler dispatch (`repository.full_name`'s owner segment), and reject payloads where `repository.owner.login` doesn't match the owner encoded in `repository.full_name`.
- Stop treating a blank `webhook_secret` as automatic verification success; require an explicit, opt-in "unsigned webhooks allowed" flag per organization rather than defaulting to `true`.

### Proof of Concept
Given Shipit configured with two orgs, `OrgOne` (no `webhook_secret`) and `victim-org` (configured with a real `webhook_secret`), and a tracked `Stack` for `victim-org/victim-repo`:

```
POST /webhooks HTTP/1.1
X-Github-Event: push
Content-Type: application/json
(no valid X-Hub-Signature required)

{
  "ref": "refs/heads/master",
  "after": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
  "repository": {
    "owner": { "login": "OrgOne" },
    "full_name": "victim-org/victim-repo"
  }
}
```

`repository_owner` resolves to `OrgOne`; `Shipit.github(organization: "OrgOne")` has `webhook_secret` blank, so `verify_webhook_signature` returns `true` without checking `X-Hub-Signature`. `PushHandler` then resolves the target via `repository.full_name` = `victim-org/victim-repo`, calling `stack.sync_github(expected_head_sha: "deadbeef...")` on the victim's stack — a state-changing action taken without ever validating a signature scoped to `victim-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** test/dummy/config/secrets_double_github_app.yml (L1-7)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
```
