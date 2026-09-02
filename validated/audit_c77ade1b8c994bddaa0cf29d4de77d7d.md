### Title
Cross-organization webhook forgery via `repository.owner.login` / `repository.full_name` mismatch — organization authenticated ≠ repository written - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a webhook against using `repository.owner.login` (or `organization.login`) from the **unverified** JSON body, while the handlers that actually act on the payload (e.g. `PushHandler`, `StatusHandler`) resolve the target `Stack`/`Repository`/`Commit` using `repository.full_name` from the **same** unverified body. Nothing binds these two fields together, so on a multi-tenant Shipit install (multiple GitHub orgs configured under `secrets.github`), a party who controls (or is simply onboarded to) one configured organization can forge a webhook whose signature is validated against *their own* org's secret while the payload's `repository.full_name` points at a stack belonging to a *different* configured organization.

### Finding Description
`verify_signature` picks the app/secret purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-org config (secret, app_id, etc.) keyed by that same attacker-supplied string: [3](#0-2) 

Critically, if an organization's config has no `webhook_secret` set (a supported, documented configuration — see `test/dummy/config/secrets_double_github_app.yml`'s `OrgTwo: webhook_secret: # nil`), signature verification is a no-op: [4](#0-3) 

Meanwhile, the code path that decides *which repository/stack is mutated* uses an entirely different field from the same untrusted body, `repository.full_name`, with no cross-check against `repository.owner.login`: [5](#0-4) [6](#0-5) 

`PushHandler` uses this repository resolution to trigger a GitHub sync for any stack under the resolved owner/name and target branch: [7](#0-6) 

`StatusHandler` writes a `Status` directly from attacker-supplied fields (`state`, `description`, `target_url`, `context`, `created_at`) onto any `Commit` matching the attacker-chosen `sha`, again with no relation to `repository.owner.login`: [8](#0-7) 

Binding that should hold but doesn't:
`repository_owner` (the org whose secret validated `X-Hub-Signature`) `==` `owner segment of repository.full_name` (the org whose `Stack`/`Commit` data is mutated).

Before the attack: for a legitimate webhook, GitHub always sets both fields consistently for the org actually emitting the event, so the two values are always equal.
After the attack: an attacker who administers (or is simply given access to) any one org configured in this shared Shipit instance's `secrets.github` map can send `POST /webhooks` with `repository.owner.login = "attacker-org"` (whose secret they know, or which may be unset) while setting `repository.full_name = "victim-org/victim-repo"` and a valid HMAC signature computed with `attacker-org`'s own secret over the full raw body. `verify_signature` succeeds (it only checks the signature is valid for `attacker-org`), yet the handler dispatch (`Repository.from_github_repo_name`) operates on `victim-org/victim-repo`.

### Impact Explanation
This breaks the trust boundary between distinct GitHub organizations that are onboarded to the same Shipit deployment (a configuration explicitly supported per `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`). Concretely reachable, unauthenticated-relative-to-victim-org impacts:
- Forged CI `status` events (`StatusHandler`) writing attacker-chosen `state`/`context`/`description` for commits in a victim org's stacks — this can satisfy `ci.require` gating used by Shipit's deploy/merge-queue logic, enabling an unauthorized deploy or merge of a commit that never actually passed CI in the victim's real CI system.
- Forged `push` events (`PushHandler`) causing `stack.sync_github` on a victim's stack, an unsolicited, attacker-triggered write/refresh against a repository outside the attacker's own organization/webhook trust domain.

This satisfies the High-severity criterion "cross-repository writes" / "an unauthorized deploy, rollback or merge," since it crosses the organizational credential boundary the multi-tenant webhook design is meant to enforce, using only knowledge of (or unauthenticated access to) one tenant's own webhook configuration.

### Likelihood Explanation
Requires Shipit to be configured with more than one GitHub organization (a documented, supported feature) and requires the attacker to be an administrator of at least one of those organizations' GitHub App installations (i.e., they can set/know that org's webhook secret, or that org's secret is left blank as shown in the shipped example config). No access to the victim org, no `ApiClient` token, and no Shipit session is needed — only the ability to send an HTTP POST to the shared, public `/webhooks` endpoint. This is a realistic scenario for shared/managed Shipit deployments serving multiple teams/orgs.

### Recommendation
Bind the field used for secret selection to the field used for repository/stack resolution: derive both from the same trusted value, or require that `repository.owner.login`/`organization.login` (used to pick the verifying secret) equal the owner segment of `repository.full_name` (used by every handler) before processing, rejecting the request otherwise. Additionally, never treat "no webhook_secret configured" as an implicit "always verified" for orgs that share an installation with other tenants.

### Proof of Concept
1. Configure Shipit with two orgs, e.g. `secrets.github["attacker-org"]` (secret known/blank) and `secrets.github["victim-org"]` (hosts `Stack` for `victim-org/victim-repo`) — a supported topology per `test/dummy/config/secrets_double_github_app.yml`.
2. Attacker crafts a `status` webhook payload:
```json
{
  "sha": "<victim commit sha>",
  "state": "success",
  "context": "required-ci-check",
  "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s webhook secret (known to them) or sends unsigned if `attacker-org`'s secret is blank, per `GitHubApp#verify_webhook_signature` returning `true` when `webhook_secret` is nil: [4](#0-3)  and `WebhooksController#repository_owner` resolving to `attacker-org`: [2](#0-1) .
4. `verify_signature` passes because it only validates against `attacker-org`.
5. `StatusHandler#process` ( [9](#0-8) ) creates a forged success status on the victim's commit (looked up globally by `sha`, unscoped to owner), potentially unblocking a gated deploy/merge in `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class StatusHandler < Handler
        params do
          requires :sha, String
          requires :state, String
          accepts :description, String
          accepts :target_url, String
          accepts :context, String
          accepts :created_at, String

          accepts :branches, Array do
            requires :name, String
          end
        end

        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
        end
```
