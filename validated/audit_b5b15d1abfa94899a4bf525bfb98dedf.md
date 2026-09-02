### Title
Webhook authentication is bound to `repository.owner.login`, not to the `repository.full_name` the handlers actually act on, allowing cross-repository webhook forgery when any configured GitHub org has no webhook secret - (File: app/controllers/shipit/webhooks_controller.rb, lib/shipit/github_app.rb, app/models/shipit/webhooks/handlers/handler.rb)

### Summary
This mirrors the OlympusGovernance bug class: an action is authorized based on one piece of state (`userVotesForProposal`, checked at `vote`/`reclaimVotes` time) while a different, unguarded piece of state (the live token balance) is what a privileged actor actually needed to control. Here, Shipit's webhook trust decision is bound to `repository.owner.login` (used to pick which GitHub App/secret verifies the signature), while the handlers that mutate state key off a different field of the same attacker-supplied payload, `repository.full_name`. When an organization has no `webhook_secret` configured — an explicitly supported, documented state — the signature check is skipped entirely, letting the attacker point `full_name` at any other repository.

### Finding Description
`WebhooksController#verify_signature` selects which `GitHubApp`/secret to verify against using a field taken straight from the unauthenticated JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config, and `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization has no `webhook_secret` set: [3](#0-2) [4](#0-3) 

`webhook_secret` is explicitly documented as optional per organization: [5](#0-4) 

Multi-organization configuration (multiple GitHub Apps, each potentially with its own secret) is a first-class, documented and tested feature: [6](#0-5) 

Meanwhile, every webhook handler resolves the target `Stack`/`Repository` using a *different* field of the payload, `repository.full_name`, entirely decoupled from `repository.owner.login`: [7](#0-6) [8](#0-7) [9](#0-8) 

The binding that breaks: **the organization that authenticated the request (`repository.owner.login` used for secret lookup) ≠ the repository the handler actually writes to (`repository.full_name`)**. Both fields are read from the same untrusted attacker body and there is no cross-check that they refer to the same repository/org.

### Impact Explanation
If a Shipit deployment configures multiple GitHub organizations and at least one of them has no `webhook_secret` set (a supported, documented, and tested configuration), an unauthenticated attacker can:
1. Set `repository.owner.login` (or `organization.login`) to the name of the org with no secret, so `verify_signature` passes unconditionally regardless of the `X-Hub-Signature` header sent.
2. Set `repository.full_name` to `victim-org/victim-repo`, a completely different, properly-secured organization's repository.
3. Send a forged `status` event to fake a green CI check for an arbitrary commit SHA on the victim repository, undermining `ci.require` deploy safety gates, or a forged `push` event to trigger `GithubSyncJob` with an attacker-chosen `expected_head_sha`, or forged `pull_request` events to archive/unarchive review stacks belonging to the victim repository.

This is an authentication-bypass on the webhook trust boundary that lets an unprivileged, unauthenticated external attacker inject GitHub state (commit statuses, sync signals, review-stack lifecycle events) for repositories they do not control, which can facilitate an unauthorized deploy by defeating status-based deploy safety checks.

### Likelihood Explanation
Requires the operator to run Shipit in the documented multi-org mode with at least one organization intentionally left without a `webhook_secret` (explicitly presented as an acceptable/optional setting in `docs/setup.md`). Given the docs treat the secret as optional per-org and multi-org setups exist specifically to onboard many teams/orgs with varying security postures, this is a realistic, not purely theoretical, deployment shape. I was not able to fully verify from the index whether any additional server-side check (outside `app/**`/`lib/shipit/**`) cross-validates `owner.login` against `full_name` before dispatch; based on the code paths found, no such check exists in-scope.

### Recommendation
Bind the authentication decision to the same field the handlers act on: derive `repository_owner` for secret selection from the same value used by `Repository.from_github_repo_name` (i.e., parse the owner out of `repository.full_name` itself, not a separate `repository.owner.login`/`organization.login` field), and reject the webhook if the two disagree. Additionally, do not allow `verify_webhook_signature` to silently return `true` when `webhook_secret` is blank for a specific organization in multi-org mode — require a secret per configured organization, or fail closed instead of open when a secret is missing.

### Proof of Concept
Given a multi-org config where `OrgWithoutSecret` has no `webhook_secret` and `VictimOrg/critical-repo` has `continuous_deployment` enabled with `ci.require` status checks:

```
POST /webhooks
X-Github-Event: status
X-Hub-Signature: sha1=anything-invalid

{
  "repository": {
    "owner": { "login": "OrgWithoutSecret" },
    "full_name": "VictimOrg/critical-repo"
  },
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "ci/required-check",
  "branches": [{ "name": "master" }]
}
```

`verify_signature` calls `Shipit.github(organization: "OrgWithoutSecret")`, whose `verify_webhook_signature` returns `true` unconditionally (`app/controllers/shipit/webhooks_controller.rb:24-30`, `lib/shipit/github_app.rb:76-83`). The `status` handler then records a passing status for `VictimOrg/critical-repo` looked up via `full_name` (`app/models/shipit/webhooks/handlers/handler.rb:33-38`), satisfying `ci.require` and clearing the way for a deploy that should have required a real, verified passing status from GitHub.

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

**File:** lib/shipit.rb (L170-181)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end
```

**File:** docs/setup.md (L29-30)
```markdown
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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
