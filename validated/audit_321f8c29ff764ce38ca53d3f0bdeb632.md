### Title
Webhook signature verification is bound to `repository.owner.login` while the state-mutating handlers act on the independent `repository.full_name` field, allowing cross-organization webhook spoofing when any configured GitHub org has no `webhook_secret` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's secret to validate the HMAC against using `repository_owner`, which is parsed from `params.dig('repository', 'owner', 'login')` (or `organization.login`) in the untrusted JSON body itself. [1](#0-0) [2](#0-1) 

But the actual event handlers (`PushHandler`, `StatusHandler`, `PullRequest::*Handler`, etc.) resolve the target `Repository`/`Stack` using a *different* field of the same payload: `repository.full_name`. [3](#0-2) [4](#0-3) 

Nothing enforces that `repository.owner.login` (the field used to select the signing org) matches the owner encoded in `repository.full_name` (the field used to select the write target). This is the same class of bug as the UniswapV3 report: the code operates on two different representations of "the same" piece of data (there, path bytes reversed as a whole instead of per-element; here, "owner" used for authentication vs. "full_name" used for the actual write) and assumes they stay in lock-step, when they are actually independent, attacker-controlled fields.

### Finding Description
`GitHubApp#verify_webhook_signature` explicitly bypasses HMAC verification entirely when no `webhook_secret` is configured for an organization: `return true unless webhook_secret`. [5](#0-4) 

This is a documented, supported deployment mode — the setup docs describe the webhook secret as optional (`Webhook secret (optional): Fill it with some randomly generated string`). [6](#0-5) 

Shipit also supports multi-organization configurations, each with an independent `webhook_secret` (`Shipit.github_app_config(organization)` looks up per-org config by the organization key). [7](#0-6) 

Given this, if *any* one configured organization has no `webhook_secret` (a state the engine's own docs recommend as acceptable and which `verify_webhook_signature` explicitly special-cases), an attacker can:
1. Craft a JSON webhook body with `repository.owner.login` set to that unsecured organization's name (so `verify_signature` looks up that org's `GitHubApp` and the signature check trivially passes via the `return true unless webhook_secret` bypass), and
2. Set `repository.full_name` in the very same payload to `victim-org/victim-repo` — an entirely different, secured organization's repository.

Because `WebhooksController#verify_signature` and `Webhooks::Handlers::Handler#repository_name` read two different keys from the same untrusted JSON (`repository.owner.login` vs. `repository.full_name`), and the engine never cross-checks that these are consistent, the forged event is dispatched to handlers (e.g. `PushHandler`) that resolve the stack via `Repository.from_github_repo_name(repository.full_name)` and perform state-mutating actions (queuing `GithubSyncJob`, creating commit statuses, etc.) against the victim's stack — despite the "signature" only ever having been checked (trivially, due to the bypass) against the unrelated, unsecured organization. [8](#0-7) [9](#0-8) 

The binding that is broken (equality that should hold but doesn't):
`repository_owner` used by `verify_signature` (authenticates the org) ≠ owner encoded in `repository.full_name` used by `Handler#repository_name` (identifies the repo actually written to).

### Impact Explanation
An unauthenticated, unprivileged attacker who merely knows (a) that some organization on the Shipit instance has no webhook secret configured (discoverable, e.g., via the `422`/error behavior differences, or simply because it's their own organization which they legitimately administer and intentionally left unsecured) and (b) the `owner/name` of a victim stack's repository (public information, visible via Shipit's own UI/API) can forge `push`, `status`, `check_suite`, `pull_request`, or `membership` events targeting the victim stack. This can trigger unauthorized `GithubSyncJob`s (syncing arbitrary/forced commits into a stack's known-commit list), forge commit statuses, or manipulate merge/PR state for a repository the attacker does not control — an unauthorized state change on a stack belonging to a different, unrelated GitHub organization. This matches the "unauthorized deploy/rollback/merge" / cross-repository writes class of impact.

### Likelihood Explanation
Requires: (1) a multi-org (or even single-org) Shipit deployment where at least one configured GitHub org/app has no `webhook_secret` — an explicitly documented, supported and "optional" configuration choice, not a misconfiguration outside the engine's control; (2) knowledge of the target stack's `owner/name`, which is normal public/discoverable data. No GitHub credentials, session, API token, or repository write access is required — only the ability to POST to the public `/webhooks` endpoint. This is a real deployment-trust boundary crossing reachable by an unprivileged network attacker, contingent on a documented-as-acceptable configuration state.

### Recommendation
- Do not select the verification key using an attacker-controlled field of the same payload whose authenticity is being checked. Instead, always verify the raw payload signature against every configured organization's secret (or against a repository-specific hook secret, as already modeled by `GithubHook`/`Hook::DeliverySigner`) rather than trusting `repository.owner.login` to pick the verification key.
- After (or instead of) selecting the signing key, cross-validate that `repository.owner.login` (or `organization.login`) matches the owner portion of `repository.full_name` before dispatching to handlers, rejecting mismatches.
- Reconsider allowing `webhook_secret` to be fully optional (`return true unless webhook_secret`) in multi-org configurations, since one unsecured org can be leveraged as a signature bypass affecting other orgs' repositories through this field confusion. At minimum, warn/fail loudly when a heterogeneous mix of secured/unsecured orgs is detected.

### Proof of Concept
Given a Shipit instance configured with two orgs, e.g. mirroring `test/dummy/config/secrets_double_github_app.yml` structure, where `OrgAttacker` has `webhook_secret: nil` and `OrgVictim` has a real secret and owns stack `OrgVictim/app`:

```
POST /webhooks
X-Github-Event: push
X-Hub-Signature: sha1=anything   # irrelevant, bypassed

{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "OrgAttacker" },
    "full_name": "OrgVictim/app"
  }
}
```

- `verify_signature` computes `repository_owner` → `"OrgAttacker"`, looks up `Shipit.github(organization: "OrgAttacker")`, whose `webhook_secret` is `nil`, so `verify_webhook_signature` returns `true` unconditionally. [1](#0-0) [5](#0-4) 
- `PushHandler#process` then resolves `stacks` via `Repository.from_github_repo_name("OrgVictim/app")`, and queues a `GithubSyncJob`/updates state for that stack, even though the "signature" was verified only against `OrgAttacker`'s (nonexistent) secret. [8](#0-7) [3](#0-2)

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** docs/setup.md (L26-30)
```markdown
  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
```

**File:** lib/shipit.rb (L170-200)
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

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
