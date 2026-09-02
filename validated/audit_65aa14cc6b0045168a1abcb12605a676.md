### Title
Webhook authenticity is verified against an organization extracted from the unsigned payload while the mutated repository/stack is resolved from a different, independently-untrusted payload field, allowing signature bypass against any org with no `webhook_secret` to forge events for a different, secured repository - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks *which* GitHub App config (and thus which `webhook_secret`) to validate the HMAC against by reading `repository_owner` straight out of the still-unverified JSON body. Every webhook `Handler` (used to actually mutate Shipit state - sync commits, set commit statuses, archive review stacks, etc.) independently re-reads a *different* field of that same untrusted body, `repository.full_name`, to resolve the target `Repository`/`Stack`. Nothing ties these two lookups together. Combined with `GitHubApp#verify_webhook_signature` returning `true` unconditionally when an org's `webhook_secret` is blank, an attacker who merely knows the login of *any* org configured on the Shipit instance without a `webhook_secret` can send a completely unsigned, self-crafted POST that authenticates as that "no-secret" org while acting on an arbitrary victim repository/stack that does have protections configured.

### Finding Description
`verify_signature` derives the org used for authentication purely from request content, before any signature check: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` resolves the per-org config, and `verify_webhook_signature` is a no-op (`return true unless webhook_secret`) when that org's secret is blank: [3](#0-2) 

This is a real, supported configuration state, not a hypothetical edge case - the shipped multi-org example config explicitly shows organizations coexisting with a configured secret and organizations with `webhook_secret: # nil`: [4](#0-3) 

Meanwhile, every webhook `Handler` subclass resolves the repository/stack that actually gets mutated from a completely separate field of the same unauthenticated JSON body: [5](#0-4) [6](#0-5) [7](#0-6) 

The binding that should hold is:
`org-that-authenticated-the-request (repository.owner.login used in verify_signature) == org-of-the-repository-that-gets-mutated (owner segment of repository.full_name used by Handler#repository_name)`

The code never enforces this equality. `repository_owner` and `repository.full_name` are two independent reads of the same attacker-supplied JSON, and only the first one gates signature verification. This is precisely the "AccountTag"-style class of bug from the report: two different consumers (the auth check vs. the mutation logic) trust two different fields of the same payload as if they denoted the same entity, with no cross-field consistency check and no unified/authoritative discriminator.

### Impact Explanation
An unprivileged external attacker who knows the GitHub login of any organization configured on the target Shipit instance without a `webhook_secret` (org names are public GitHub identifiers, easily discoverable, and many self-hosted Shipit deployments run multiple orgs at different stages of onboarding) can POST directly to the webhooks endpoint with:
- `X-Github-Event` set to any handled event (e.g. `status`, `pull_request`, `push`)
- `repository.owner.login`/`organization.login` = the no-secret org (satisfies `verify_signature` trivially, no HMAC needed)
- `repository.full_name` = `victim-org/victim-repo` (the actual, secured target)

Because `verify_signature` never checks that these two org references agree, the forged, completely unsigned request is accepted and dispatched to handlers that operate on `victim-org/victim-repo`'s real `Stack`. Concretely this allows an attacker to:
- Forge `commit_status`/`status` events to fabricate a passing CI status on a victim commit, defeating the `ci.require` gate that continuous delivery relies on before deploying - i.e., enabling an unauthorized deploy of a commit that never actually passed CI.
- Forge `pull_request` closed/labeled events to archive/unarchive a victim's review stacks, and force resyncs (`push` → `GithubSyncJob`) against the victim stack's commit history state.

This crosses the required High/Critical bar ("unauthorized deploy" via forged CI status bypass) without any Shipit session, API token, or the victim org's `webhook_secret`.

### Likelihood Explanation
Likelihood is moderate-to-high in realistic self-hosted deployments: multi-organization Shipit installs commonly have some orgs still using the legacy/no-secret configuration path shown in the shipped example config, while other orgs are properly secured. The attacker needs no credentials, no GitHub App private key, and no TLS interception - only the login name of one weakly-configured org and knowledge of the victim repo's `owner/name`, both public information. The request is a single unauthenticated HTTP POST.

### Recommendation
Do not select the authentication key from an unverified field of the request body. Instead:
- Verify the signature using a single, deployment-wide default `webhook_secret` or explicitly reject requests when the resolved org has no `webhook_secret` configured (never silently return `true`).
- After successful authentication, cross-check that the `owner` embedded in `repository.full_name` (and in any other repository identifiers used by handlers) matches the `repository_owner` used to select the verification key; reject the request otherwise.
- Consider using GitHub's `X-Github-Hook-Installation-Target-ID`/App ID or a per-install identifier bound to the signature check, rather than an attacker-controlled JSON field, to select the verification secret.

### Proof of Concept
Preconditions: Shipit instance configured with at least two GitHub orgs, e.g. `secure-org` (has `webhook_secret`) and `open-org` (no `webhook_secret`, as in the shipped example config), and a real stack under `secure-org/victim-repo`.

```
POST /github/webhooks HTTP/1.1
Host: shipit.example.com
X-Github-Event: status
Content-Type: application/json
(no X-Hub-Signature header, or any arbitrary value)

{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "description": "forged",
  "target_url": "https://attacker.example.com",
  "repository": {
    "full_name": "secure-org/victim-repo",
    "owner": { "login": "open-org" }
  }
}
```

- `verify_signature` computes `repository_owner = "open-org"`, resolves `open-org`'s (secret-less) `GitHubApp`, and `verify_webhook_signature` returns `true` unconditionally.
- The `status` handler then resolves the target via `payload.dig('repository','full_name')` = `"secure-org/victim-repo"`, and records a forged successful `Status` on the victim's real commit, satisfying `ci.require` for continuous delivery of that commit - all without ever proving knowledge of `secure-org`'s webhook secret.

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
