### Title
Multi-org webhook signature verification is keyed on `repository.owner.login`, but write-side handlers are keyed on `repository.full_name`, letting an attacker use an unconfigured org's "always verified" secret to forge webhooks for a different, victim organization's stacks - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` (and thus which `webhook_secret`) to verify a webhook payload against using `repository_owner`, a value read from the same untrusted JSON body (`repository.owner.login`, falling back to `organization.login`). Every event handler, however, independently determines which `Stack`/`Repository` to mutate using a different field from the same body: `repository.full_name` (`app/models/shipit/webhooks/handlers/handler.rb:36-38`, and every `PullRequest::*Handler#repository`). In a multi-organization Shipit deployment (`Shipit.github_organizations`/`github_app_config`, as exercised by `test/dummy/config/secrets_double_github_app.yml`), `GitHubApp#verify_webhook_signature` unconditionally returns `true` when `webhook_secret` is blank (`lib/shipit/github_app.rb:76-77`). This decouples "the organization whose secret was used to authenticate this request" from "the repository the request is allowed to mutate," breaking the equality: `organization authenticated (repository.owner.login → org config) == repository written (repository.full_name)`.

### Finding Description
In `app/controllers/shipit/webhooks_controller.rb`:
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

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a per-organization `GitHubApp` from `secrets.github[organization]` (`lib/shipit/github_app.rb`), and:
```ruby
def verify_webhook_signature(signature, message)
  return true unless webhook_secret
  ...
end
``` [3](#0-2) 

If any configured organization has no `webhook_secret` (a valid, engine-supported configuration - see `test/dummy/config/secrets_double_github_app.yml:6-7,46` where both `OrgOne` and `OrgTwo` explicitly set `webhook_secret:` to nil), then any payload whose `repository.owner.login` (or `organization.login`) names that org is treated as fully verified with **no signature check whatsoever**.

Once past `verify_signature`, the request body is dispatched to handlers via `Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }` (`app/controllers/shipit/webhooks_controller.rb:12`). Every handler determines the target repository independently from `repository.full_name`:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [4](#0-3) 

`repository.owner.login` and `repository.full_name` are two independent, attacker-controlled JSON fields in the same unsigned/trivially-signed payload - nothing ties them together. An attacker can therefore set `repository.owner.login` (or `organization.login`) to a Shipit-configured org that has no `webhook_secret` (bypassing verification entirely) while setting `repository.full_name` to `victim-org/victim-repo`, a completely unrelated, properly-secured organization's tracked stack. Handlers such as `PushHandler` (`app/models/shipit/webhooks/handlers/push_handler.rb:12-17`) will then act on that victim stack: `stacks.not_archived.where(branch:).find_each { |stack| stack.sync_github(expected_head_sha: params.after) }`. [5](#0-4) 

This is the direct analog of the reported bug class: just as ZRX delegated-stake weighting could be routed around a smart contract wrapper that never enforces the intended binding between "who actually owns the stake" and "who is credited with the weight," Shipit's webhook trust binding between "which org's secret authenticated this request" and "which repository's data gets written" is enforced only by two independently-controlled fields in the same payload rather than a single, structurally-tied value.

### Impact Explanation
An unauthenticated attacker (no Shipit session, no `ApiClient` token, no repository access) can forge GitHub webhook events (`push`, `pull_request`, `status`, `check_suite`, `membership`) for any repository Shipit tracks, as long as the deployment configures more than one GitHub organization and at least one of them omits `webhook_secret`. This can:
- Trigger `stack.sync_github` for arbitrary target repositories/branches, forcing Shipit to fetch and act on attacker-influenced state (`push` events).
- Manipulate `PullRequest` records, review-stack provisioning/archival, and labels for a victim stack via the pull-request handlers, since they too resolve their target purely from `params.repository.full_name`.
- Trigger `membership`-driven team/user creation tied to an arbitrary `organization.login`.

This crosses a trust boundary the engine is designed to enforce (webhook authenticity per organization) and results in unauthorized manipulation of another organization's Stack/PullRequest state - qualifying as a High-severity issue (escalation of trust across repository/organization boundaries via a webhook the app believed was authenticated).

### Likelihood Explanation
Exploitability depends entirely on deployment configuration: multiple `Shipit.github_organizations` entries must be configured, and at least one entry must have a blank/absent `webhook_secret`. The engine's own test fixtures (`secrets_double_github_app.yml`) demonstrate this exact configuration is a supported, documented setup, and nothing in `WebhooksController` or the `Handler` base class prevents or even warns about this cross-field mismatch. No credentials, sessions, or repository access are required - only network access to the public `/webhooks` endpoint (mounted outside `Shipit::Authentication`, with `verify_authenticity_token` skipped).

### Recommendation
Bind signature verification to the same field used for write-side repository resolution. Concretely:
- Derive the verifying organization from `repository.full_name`'s owner segment (or from the same `Repository` record subsequently looked up), not from a separately-controlled `repository.owner.login`/`organization.login` field.
- Alternatively, after signature verification, re-derive and assert that `repository_owner` matches the owner segment of `repository.full_name` before dispatching to handlers, rejecting mismatches.
- Do not allow `verify_webhook_signature` to silently return `true` for organizations with no configured `webhook_secret`; require a secret for any organization capable of authenticating writes to other repositories, or fail closed.

### Proof of Concept
1. Deploy Shipit with two configured GitHub orgs, e.g. mirroring `test/dummy/config/secrets_double_github_app.yml`: `OrgOne` (attacker-known, no `webhook_secret`) and `victim-org` (properly secured, tracking a real stack `victim-org/victim-repo`).
2. POST to `/webhooks` with header `X-Github-Event: push` and body:
```json
{
  "ref": "refs/heads/main",
  "after": "deadbeef",
  "repository": { "owner": { "login": "OrgOne" }, "full_name": "victim-org/victim-repo" }
}
```
No `X-Hub-Signature` header is required (or any arbitrary value works).
3. `WebhooksController#verify_signature` computes `repository_owner == "OrgOne"`, loads `Shipit.github(organization: "OrgOne")`, whose `webhook_secret` is nil, so `verify_webhook_signature` returns `true` unconditionally - the request passes verification. [6](#0-5) 
4. `Shipit::Webhooks.for_event("push")` dispatches to `PushHandler`, which resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: "deadbeef")` on the victim's stack. [5](#0-4) 

The attacker never possessed `victim-org`'s webhook secret, session, or repository access, yet forced Shipit to act on `victim-org`'s tracked stack.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```
