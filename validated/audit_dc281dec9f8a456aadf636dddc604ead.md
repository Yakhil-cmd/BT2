### Title
Webhook signature verification is keyed by `repository.owner.login`, but the acted-upon repository comes from the unverified `repository.full_name` field, allowing cross-organization webhook forgery - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/`webhook_secret` to validate the `X-Hub-Signature` against based on `repository.owner.login` (or `organization.login`) taken directly from the untrusted request body. Once "verified," the entire raw payload is dispatched to handlers, which instead resolve the target `Repository`/`Stack` using `repository.full_name` — a completely different field of the same untrusted JSON that is never covered by the signature check that was actually performed.

### Finding Description
`verify_signature` picks the app config to verify against like this: [1](#0-0) [2](#0-1) 

`GitHubApp#verify_webhook_signature` short-circuits to `true` whenever the selected organization has no `webhook_secret` configured: [3](#0-2) 

Shipit explicitly supports hosting multiple GitHub organizations behind one instance, each with its own (optionally absent) `webhook_secret`, as documented and exercised in the test fixtures (`OrgTwo`'s `webhook_secret` is `nil`): [4](#0-3) [5](#0-4) 

Once `verify_signature` passes, the raw, unmodified payload is handed to every registered handler: [6](#0-5) 

But `Handler#stacks`/`repository_name` — used by every handler (`PushHandler`, `StatusHandler`, `pull_request/*`, `check_suite_handler`) to pick which `Repository`/`Stack` to mutate — reads a different field, `repository.full_name`, not the `repository.owner.login`/`organization.login` field that gated the signature check: [7](#0-6) 

The broken binding is: **organization authenticated (`repository.owner.login` / `organization.login`, checked against that org's `webhook_secret`) ≠ repository written (`repository.full_name`, used to resolve the target `Stack`)**. Nothing ties these two fields together, and they are independently attacker-controlled in the same unsigned JSON body.

### Impact Explanation
If a Shipit instance is configured for multiple GitHub organizations (a documented, supported configuration) and at least one of them has no `webhook_secret` set (also documented as valid — `webhook_secret: # nil`), an unauthenticated attacker can:
1. Set `repository.owner.login` (or `organization.login`) to the org with no secret, so `verify_signature` passes unconditionally.
2. Set `repository.full_name` to any repository/stack tracked by the *other*, properly-secured organization.

This lets the attacker drive handlers against a stack they have no credentials for:
- `PushHandler#process` calls `stack.sync_github(expected_head_sha: params.after)` for an attacker-chosen SHA on the target stack's branch, forging sync state: [8](#0-7) 
- `StatusHandler#process` creates a `CommitStatus` directly from attacker-supplied `state`/`context`/`sha` on any existing commit, which can be used to forge a passing CI status (`ci.require` context) on a target repo's commit, unblocking continuous deployment / merge-queue gating that assumes only GitHub-originated, signature-verified statuses reach this code path: [9](#0-8) 

Forging a passing status to unlock deploy/merge gating on a repository the attacker does not control satisfies the "unauthorized deploy" impact bar, since Shipit's continuous-deployment and merge-queue logic trusts these `CommitStatus` rows as coming from GitHub.

### Likelihood Explanation
Requires: (a) a Shipit instance configured for ≥2 GitHub organizations (explicitly documented/supported multi-org feature), and (b) at least one configured organization without a `webhook_secret`. Both conditions are operator configuration choices rather than code defects introduced by the attacker, but neither is flagged as insecure or disallowed anywhere in the code or docs — `secrets.development.example.yml` and `secrets.development.shopify.yml` both ship with `webhook_secret: # nil` as the default/example value, so an operator following the documented setup for a second org without also setting a webhook secret is a realistic outcome. No attacker credentials, tokens, or GitHub access are required — only knowledge that the instance hosts multiple orgs and that one lacks a secret (observable, e.g., by simply trying it).

### Recommendation
Bind the signature-verification identity to the same repository identity used by handlers: verify the webhook signature using the `webhook_secret` belonging to the organization/owner of `repository.full_name` (or, better, verify against every configured org's secret list and require at least one exact match tied to the exact repository acted upon), and reject payloads where `repository.owner.login`/`organization.login` does not match the owner segment of `repository.full_name`. Additionally, consider treating a missing `webhook_secret` as "reject all events for repositories under other organizations" rather than "accept unconditionally," or require `webhook_secret` to be mandatory when more than one GitHub organization is configured.

### Proof of Concept
Assume `config/secrets.yml`:
```yaml
production:
  github:
    OrgSecure:
      webhook_secret: "s3cret"
      ...
    OrgOpen:
      webhook_secret: # nil
      ...
```
`OrgSecure/target-repo` is a tracked Shipit stack with CI requirement `ci/required`.

Attacker sends, without any valid signature:
```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything

{
  "repository": { "owner": { "login": "OrgOpen" }, "full_name": "OrgSecure/target-repo" },
  "organization": { "login": "OrgOpen" },
  "sha": "<real pending commit sha on target-repo>",
  "state": "success",
  "context": "ci/required",
  "description": "forged",
  "target_url": "http://attacker"
}
```
- `repository_owner` resolves to `"OrgOpen"` → `Shipit.github(organization: "OrgOpen")` has no `webhook_secret` → `verify_webhook_signature` returns `true` unconditionally.
- `StatusHandler` resolves the affected commit via `params.sha` (global `Commit.where(sha:)`, not scoped by owner) and creates a forged successful `ci/required` status on `OrgSecure/target-repo`'s commit, satisfying CI requirements for continuous deployment or merge queue on a repository the attacker never authenticated for.

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

**File:** test/dummy/config/secrets_double_github_app.yml (L41-46)
```yaml
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
