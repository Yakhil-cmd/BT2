### Title
Webhook signature verification authenticates the payload's `repository.owner.login` but handlers act on the unverified `repository.full_name` — organization-authenticated ≠ repository-written - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization secret to use for HMAC verification based on a field read directly out of the *unverified* JSON body (`repository.owner.login`, falling back to `organization.login`), then verifies the raw body against that org's `webhook_secret`. Once the signature check passes, every event handler (`Shipit::Webhooks::Handlers::Handler#repository_name`, and each concrete handler such as `OpenedHandler`, `ClosedHandler`, `LabeledHandler`, etc.) independently re-reads a *different* field from the same unverified body — `repository.full_name` — to resolve the `Repository`/`Stack` that will actually be mutated (labels applied, review stacks archived/unarchived/created, commits synced). Nothing ties the value used to pick the verifying secret to the value used to pick the acted-upon repository.

### Finding Description [1](#0-0) 
`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` — both taken from the raw JSON body before any authenticity check — and uses it to look up `Shipit.github(organization: repository_owner)`, whose `webhook_secret` is used to verify `X-Hub-Signature` against the raw POST body. [2](#0-1) 

`GitHubApp#verify_webhook_signature` explicitly treats an organization with no configured `webhook_secret` as always-valid: [3](#0-2) 
`return true unless webhook_secret`

Separately, every webhook handler resolves the target repository from a *different* JSON field, `repository.full_name`, via `Shipit::Webhooks::Handlers::Handler#repository_name`: [4](#0-3) 
and concrete handlers such as `OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`, `EditedHandler` all call `Repository.from_github_repo_name(params.repository.full_name)` to find the `Stack`/`Repository` to act on: [5](#0-4) 

Because `repository.owner.login` (used to pick the verifying secret) and `repository.full_name` (used to pick the affected repository) are two independent, attacker-controlled fields in the same unsigned-until-verified JSON body, an attacker can craft a payload where these two fields disagree: they set `repository.owner.login`/`organization.login` to any GitHub organization that is configured in Shipit's `secrets.github` map **without** a `webhook_secret` set (or otherwise not enforcing signatures), causing `verify_webhook_signature` to short-circuit to `true` for zero cost, while setting `repository.full_name` to `"<protected-org>/<protected-repo>"`, a completely different, secret-protected organization's repository that is tracked as a Shipit stack.

The equality that should hold but doesn't:
`organization whose secret authenticated the request == organization that owns the repository the handler mutates`

Before the attacker's request: only genuine GitHub-signed webhooks for org A can affect stacks under org A, and only genuine webhooks for org B can affect stacks under org B.
After the attacker's request: a request that "authenticates" as unsigned-org A (because A has no secret, or the check is bypassed) is free to drive handler logic (`archive!`, `unarchive!`, label capture, `find_or_create!` of review stacks, `GithubSyncJob` scheduling) against stacks that belong to org B, whose secret was never checked.

### Impact Explanation
This lets an unauthenticated network attacker perform unauthorized actions against stacks/review-stacks of a *different, secret-protected* GitHub organization than the one whose (absent or attacker-known) secret satisfied the check — e.g. archiving/unarchiving review-stacks, forcing provisioning of review stacks, or capturing/altering pull-request label state for a target repository, and triggering `GithubSyncJob` for the push handler with attacker-chosen commit data. This is a cross-repository/cross-organization state-write outside the trust boundary that the per-organization webhook secret is meant to enforce, matching the "cross-repository writes" high/critical impact bucket in scope.

### Likelihood Explanation
Exploitability depends entirely on a specific, non-default deployment configuration: Shipit must be configured with **multiple** GitHub organizations (`secrets.github` keyed by org) where at least one configured organization has no `webhook_secret` set (or is otherwise unauthenticated), while other organizations are properly secured. In that specific multi-tenant configuration the attack requires no secret knowledge at all — only that Shipit's webhook endpoint is reachable, which it is for any deployment (webhook route is unauthenticated by design). In a typical single-organization Shipit installation with a `webhook_secret` configured, `repository_owner` and `repository.full_name`'s owner will normally coincide and there is only one secret to check, making the discrepancy unreachable. This narrows the likelihood to specific multi-org configurations, but the vulnerable code path (verifying against one field, acting on another, with no cross-check) exists unconditionally in the engine regardless of configuration.

### Recommendation
Verify the webhook signature using the same organization/repository identity that the event handlers will subsequently use to resolve the target `Repository`/`Stack` (i.e., derive `repository_owner` from `repository.full_name`'s prefix, and require that this exact string is what handlers use), and reject payloads where `repository.owner.login`/`organization.login` disagree with the owner segment of `repository.full_name`. Additionally, consider making `webhook_secret` mandatory for every configured GitHub organization so `verify_webhook_signature` never silently returns `true`.

### Proof of Concept
Preconditions: Shipit configured with two GitHub orgs in `secrets.github`: `orgA` (no `webhook_secret` configured) and `orgB` (has `webhook_secret`, and owns a tracked repository `orgB/service`).

1. Attacker sends `POST /github/webhooks` with header `X-Github-Event: pull_request` and body:
```json
{
  "action": "labeled",
  "number": 1,
  "pull_request": { "...": "attacker-controlled" },
  "repository": { "owner": { "login": "orgA" }, "full_name": "orgB/service" },
  "organization": { "login": "orgA" },
  "sender": { "login": "attacker" }
}
```
No `X-Hub-Signature` value needs to correctly HMAC the body, because `verify_signature` looks up `Shipit.github(organization: "orgA")`, whose `verify_webhook_signature` returns `true` unconditionally per [6](#0-5) .
2. `WebhooksController#create` dispatches to `Shipit::Webhooks::Handlers::PullRequest::LabeledHandler`, which resolves `repository = Shipit::Repository.from_github_repo_name(params.repository.full_name)` → `orgB/service`, and executes `stack.archive!` / `stack.unarchive!` on `orgB`'s protected stack, per [7](#0-6) , despite the request never being validated against `orgB`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
