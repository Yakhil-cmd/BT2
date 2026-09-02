### Title
Webhook signature bypass via blank `webhook_secret` decouples the organization used for authentication from the repository whose state is written - ([File: lib/shipit/github_app.rb])

### Summary
`GitHubApp#verify_webhook_signature` unconditionally returns `true` when no `webhook_secret` is configured for the organization resolved from the payload. Because the organization used to select which secret governs authentication (`repository.owner.login` / `organization.login`) is a different field from the one used by webhook handlers to locate which `Stack`/`Repository` to mutate (`repository.full_name`), a deployment with any organization configured without a `webhook_secret` allows a fully unauthenticated attacker to submit arbitrary, unsigned webhook bodies that act on the state of *any* repository/stack tracked by the instance, not just the unsecured organization's own repository.

### Finding Description
`WebhooksController#verify_signature` resolves the organization to check against from attacker-suppliable JSON fields: [1](#0-0) [2](#0-1) 

It then verifies the raw body against that organization's secret via `GitHubApp#verify_webhook_signature`: [3](#0-2) 

The critical flaw is line 77: `return true unless webhook_secret`. If the organization resolved from `repository_owner`/`organization.login` has no `webhook_secret` configured — a state the engine's own sample configuration explicitly shows as a valid value (`webhook_secret: # nil`) — the signature check is skipped entirely and the request is treated as authentic.

Once past `verify_signature`, `WebhooksController#create` re-parses the raw body and dispatches it to registered handlers: [4](#0-3) 

Every handler locates the `Repository`/`Stack` to act on using a *separate* field from the same JSON body — `repository.full_name` — completely independent of the `repository.owner.login` value that was used (or bypassed) for authentication: [5](#0-4) [6](#0-5) 

Nothing enforces that `repository.full_name`'s owner segment matches `repository.owner.login`/`organization.login`. So the "organization that authenticated" and "the repository that is written" are never checked for equality:

`repository_owner (used to select/skip secret) == owner(repository.full_name) (used to select the Stack that gets mutated)`

is never asserted. In a multi-organization deployment (a documented, supported configuration — see `config/secrets.development.shopify.yml`), if even one configured organization has a blank `webhook_secret`, an attacker can:
1. Send a POST to `/webhooks` with `X-Github-Event: push` (or `status`, `membership`, `pull_request`, etc.).
2. Set `repository.owner.login` (or `organization.login`) to the unsecured organization's name, so `verify_signature` takes the `return true unless webhook_secret` shortcut and skips HMAC verification entirely.
3. Set `repository.full_name` to `"other-org/other-repo"` — any repository/stack tracked by the instance, regardless of organization.

Because handlers act on `repository.full_name` alone, the forged event is applied to the targeted stack: `PushHandler` triggers `stack.sync_github(expected_head_sha: ...)`, `status`/`check_suite` handlers write commit statuses that gate `MergeRequest#reject_unless_mergeable!` and deploy readiness, `membership` handlers create/delete `Team`/`Membership` records, and PR handlers can create/archive Review Stacks.

### Impact Explanation
This is a genuine authentication-bypass and cross-repository-write vulnerability: it allows an unauthenticated, credential-less attacker to inject unsigned events that mutate the internal state (commit statuses, merge-gating signals, team/user membership, review-stack provisioning) of stacks belonging to organizations other than the misconfigured one. Because commit status is used by `MergeRequest#reject_unless_mergeable!` / `StatusChecker` to gate merges, and push events drive `sync_github`, this can influence which commits are considered deployable/mergeable — matching the "unauthorized deploy/merge" and "cross-repository writes" impact tiers.

### Likelihood Explanation
Exploitability is gated entirely on operator configuration: it requires at least one organization entry in `Shipit.secrets.github` to have `webhook_secret` unset/blank while other organizations' stacks exist in the same instance. This is a state the codebase's own example secrets files present as valid (`webhook_secret: # nil` in `config/secrets.development.shopify.yml` and `test/dummy/config/secrets.yml`), and is a realistic transient state during onboarding of a new GitHub App before its secret is filled in. No attacker credentials, tokens, or session are needed — only knowledge that the organization exists (discoverable from the target's public GitHub org name).

### Recommendation
- Remove the `return true unless webhook_secret` short-circuit in `GitHubApp#verify_webhook_signature`; treat a missing `webhook_secret` as a hard misconfiguration (raise/reject) rather than an implicit bypass.
- Bind authentication and mutation to the same identity: after verifying the signature for the organization derived from the payload, assert that `repository.full_name`'s owner segment equals the authenticated `repository_owner`/`organization.login` before dispatching to handlers, rejecting mismatches with `422`.

### Proof of Concept
1. Configure two orgs in `Shipit.secrets.github`: `org-a` (no `webhook_secret`) and `org-b` (has a tracked `Stack` for `org-b/service`).
2. POST to `/webhooks` with header `X-Github-Event: push` and no/garbage `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker chosen sha>",
  "repository": { "full_name": "org-b/service", "owner": { "login": "org-a" } }
}
```
3. `verify_signature` resolves `repository_owner` = `"org-a"`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` unconditionally regardless of the (invalid) `X-Hub-Signature`.
4. `PushHandler` runs and executes `stack.sync_github(expected_head_sha: "<attacker chosen sha>")` against `org-b/service`, a repository the attacker never authenticated for.

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
