### Title
Webhook signature verification keys off `repository.owner.login`, but event handlers act on `repository.full_name` — an attacker who controls a low/no-secret organization can forge events attributed to any other configured repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App configuration (and therefore which HMAC secret) to use for signature verification based on a field taken directly from the still-unverified JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is `params.dig('repository', 'owner', 'login')` (or `organization.login`). This value is passed to `Shipit.github(organization: repository_owner)` to look up the corresponding `GithubApp`/`GithubHook` config and its `webhook_secret`, and `verify_webhook_signature` is then called: [3](#0-2) 

Critically, `verify_webhook_signature` returns `true` unconditionally if that organization's config has no `webhook_secret` set (`return true unless webhook_secret`). Shipit explicitly supports multiple GitHub organizations configured simultaneously (see the multi-org fixture `test/dummy/config/secrets_double_github_app.yml`, where both `OrgOne` and `OrgTwo` have `webhook_secret: # nil`), and the setup docs describe `webhook_secret` as **optional**.

Once `verify_signature` passes (either because the org that "authenticated" the request has no secret at all, or the org was resolved from attacker-controlled JSON), the actual body is parsed again and handed to event handlers, all of which resolve the target `Repository`/`Stack` from a *different* JSON field — `repository.full_name` — via `Repository.from_github_repo_name`: [4](#0-3) [5](#0-4) [6](#0-5) 

Nothing in the controller or in `Handler` cross-checks that `repository.owner.login` (the field the signature check trusts) matches the owner segment of `repository.full_name` (the field the handlers act on). The two are read independently from the same untrusted JSON body, and are never bound together by any verification step.

This is structurally identical to the ENS `NameWrapper` bug class described in the report: a security-relevant assertion (`PARENT_CANNOT_CONTROL` fuse / "this event is authenticated for organization X") is decoupled from the actual protected state (domain expiry & fuses / "the repository record that gets mutated"), letting an attacker satisfy the check on one binding while acting on another.

### Impact Explanation
An attacker who can trigger a webhook delivery accepted for an organization with no `webhook_secret` configured (a documented, optional configuration state, not a secret compromise) can set `repository.full_name` to point at *any* repository/stack tracked by this Shipit instance while setting `repository.owner.login`/`organization.login` to the unsecured org. This allows unauthorized cross-repository state changes without possessing any GitHub App private key, webhook secret, or Shipit session:
- `PushHandler` can trigger `stack.sync_github(expected_head_sha: ...)` against an arbitrary stack.
- `StatusHandler`/`CheckSuiteHandler`-style handlers can inject fabricated commit statuses/check results that influence the merge queue and deploy safety checks, potentially causing an unauthorized deploy or merge.
- `PullRequest` handlers can archive/unarchive review stacks or capture forged labels for repositories outside the attacker's control.

This matches the report's Impact bucket of "unauthorized deploy, rollback, or merge" / "cross-repository writes" reachable by an unprivileged external actor who only needs the ability to have any webhook accepted for an org lacking a secret — no privileged credential is required for that org specifically.

### Likelihood Explanation
Requires the Shipit deployment to have at least one configured GitHub organization/app without a `webhook_secret` (explicitly supported/optional per `docs/setup.md`) while other organizations manage sensitive repositories. Multi-org configurations with mixed secret presence are exercised in the codebase's own test fixtures (`test/dummy/config/secrets_double_github_app.yml`), indicating this is a realistic, intended deployment shape rather than a purely theoretical edge case. The attacker only needs to get GitHub (or a controlled endpoint mimicking it) to deliver one crafted POST to `/webhooks` — no signature is even necessary for the unsecured org.

### Recommendation
- Bind the field used for signature verification to the field used for state mutation: verify that `repository.owner.login` matches the owner segment parsed out of `repository.full_name` (and reject if they diverge) before dispatching to handlers.
- Do not silently treat "no `webhook_secret` configured" as "signature always valid" for that org when a payload references resources belonging to a different, secret-protected organization; consider requiring `webhook_secret` for any organization once more than one organization is configured, or scoping `Repository.from_github_repo_name` lookups to repositories owned by `repository_owner`.
- Reject webhook events where `full_name`'s owner segment doesn't match the resolved `repository_owner`/`organization.login` used to select the verifying secret.

### Proof of Concept
1. Configure Shipit with two organizations, e.g. `SecureOrg` (has `webhook_secret` set) owning tracked repository `SecureOrg/critical-app`, and `OpenOrg` (no `webhook_secret`, per the supported optional configuration shown in `test/dummy/config/secrets_double_github_app.yml`).
2. POST to `/webhooks` with header `X-Github-Event: push` and a body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "full_name": "SecureOrg/critical-app",
    "owner": { "login": "OpenOrg" }
  }
}
```
No `X-Hub-Signature` header (or any arbitrary value) is required.
3. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OpenOrg")`, finds `webhook_secret` blank, and `verify_webhook_signature` returns `true` unconditionally (`lib/shipit/github_app.rb:76-83`).
4. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("SecureOrg/critical-app")` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and calls `stack.sync_github(expected_head_sha: params.after)` on the `SecureOrg` stack — an action the attacker was never authenticated to perform for that organization.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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
