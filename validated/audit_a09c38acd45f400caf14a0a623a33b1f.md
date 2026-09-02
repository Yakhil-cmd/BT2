### Title
Webhook signature verification keyed on `repository.owner.login` while target repository/stack is resolved from `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App configuration (and thus which `webhook_secret`) to use for HMAC verification based on `repository.owner.login` (with a fallback to `organization.login`), while every webhook handler resolves the actual `Stack`/`Repository` to act on from a *different* field of the same attacker-controlled JSON body: `repository.full_name`. Because these two fields are never cross-checked, and because `webhook_secret` is optional per-organization, an attacker can bind a forged/unsigned payload to one organization for authentication purposes while it actually mutates state belonging to a different, real (secret-protected) organization/repository.

### Finding Description
`verify_signature` picks the GitHub App used to verify the request: [1](#0-0) [2](#0-1) 

The signature check itself is a no-op when the selected organization has no `webhook_secret` configured: [3](#0-2) 

`docs/setup.md` documents `webhook_secret` as optional and shows the multi-org config shape (`github: {org_a: {...}, org_b: {...}}`), so it is a supported, in-scope deployment configuration for this engine to have multiple organizations, some without a secret set.

Meanwhile, every `Shipit::Webhooks::Handlers::Handler` subclass (push, status, check_suite, pull_request, etc.) resolves the target repository purely from `repository.full_name`, independent of `repository.owner.login`: [4](#0-3) [5](#0-4) 

Since the whole JSON body is attacker-supplied on an unauthenticated `POST /webhooks` endpoint, `repository.owner.login` and `repository.full_name` need not agree. The equality the code implicitly (and incorrectly) assumes is:

`organization used to verify signature (repository.owner.login) == organization that owns the repository actually written to (repository.full_name.split('/').first)`

This equality is never enforced. An attacker who knows (or engineers) that some organization `X` configured in this Shipit instance has no `webhook_secret` set can send:
```json
{
  "repository": { "owner": { "login": "X" }, "full_name": "Y/real-repo" },
  ...
}
```
`verify_signature` calls `Shipit.github(organization: "X")`, whose `verify_webhook_signature` returns `true` unconditionally (no secret configured), so the request passes verification with no valid HMAC at all — yet the handler dispatched in `create` acts on `Y/real-repo`, a completely different, secret-protected organization's repository/stack. [6](#0-5) 

### Impact Explanation
This lets an unprivileged, unauthenticated attacker forge arbitrary GitHub webhook events (push, status, check_suite, check_run, pull_request, membership, etc.) against a fully-secured repository/stack that never had its signing secret compromised, as long as any other organization on the same Shipit instance has no `webhook_secret` configured. Concretely this allows forging commit `Status` records (used to gate deployability) or check-run/check-suite results for a target stack's commits, and forging push events that trigger `GithubSyncJob`/`sync_github` — undermining the CI-status-gated deploy trust model and enabling an unauthorized deploy path once combined with the normal deploy flow (an operator or auto-deploy relying on the forged green status). This matches the "unauthorized deploy" / authentication-bypass class of impact for this engine.

### Likelihood Explanation
Likelihood depends on the deployment having at least one configured organization with `webhook_secret` unset (explicitly documented as optional, and the multi-org config format is officially supported), plus knowledge of that organization's login. No credentials, GitHub App keys, `ApiClient` tokens, or repository write access are required — only an HTTP POST to the public `/webhooks` endpoint.

### Recommendation
In `WebhooksController#verify_signature`, cross-validate that the organization used to select the webhook secret matches the owner of `repository.full_name` (and `organization.login` if present) before dispatching to handlers, and/or make `verify_webhook_signature` fail closed (reject, not silently pass) whenever the organization resolved from the payload does not match the repository actually referenced by the event body.

### Proof of Concept
1. Configure Shipit with two organizations: `secure-org` (has `webhook_secret` set, owns a real stack) and `open-org` (no `webhook_secret` configured — allowed by docs).
2. As an unauthenticated attacker, `POST /webhooks` with header `X-Github-Event: status` and body:
```json
{
  "sha": "<commit sha of secure-org/real-repo>",
  "state": "success",
  "context": "ci/build",
  "repository": {
    "full_name": "secure-org/real-repo",
    "owner": { "login": "open-org" }
  }
}
```
No `X-Hub-Signature` header (or any bogus value) is required.
3. `verify_signature` calls `Shipit.github(organization: "open-org")`; since `open-org` has no `webhook_secret`, `verify_webhook_signature` returns `true` regardless of the header/body.
4. `Shipit::Webhooks.for_event('status')` handler resolves the repository via `payload.dig('repository', 'full_name')` = `secure-org/real-repo`, and records a forged `success` status for that commit — with no valid signature ever presented for `secure-org`.

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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
