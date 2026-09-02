### Title
Webhook signature verification is scoped to `repository.owner.login`, but stack/repository resolution is scoped to `repository.full_name` — allowing cross-organization webhook forgery when any configured organization has no `webhook_secret` set (`File: app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and thus which `webhook_secret`) to validate the HMAC signature against using `repository.owner.login` (with fallback to `organization.login`) taken directly from the unverified request body. `GitHubApp#verify_webhook_signature` unconditionally returns `true` when that organization's `webhook_secret` is blank. All downstream event handlers (e.g. `PushHandler`, pull-request handlers) then resolve the actual `Repository`/`Stack` to act on using a *different* field of the same payload, `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name`. Nothing binds the "organization that authenticated" to the "repository that is written to."

### Finding Description
The verification and the authorization-scoping decisions are decoupled and keyed off two independent, attacker-supplied fields of the same unsigned-at-parse-time JSON body:

- Signature/organization selection: [1](#0-0) [2](#0-1) 

- Signature check that trivially passes when the selected organization's app config has no `webhook_secret`: [3](#0-2) 

- Repository/Stack resolution used by every handler, based on `repository.full_name`, not on the organization used for signature verification: [4](#0-3) [5](#0-4) [6](#0-5) 

Multi-organization deployments configure per-org GitHub App settings (`app_id`, `installation_id`, `webhook_secret`, ...) and `Shipit.github(organization:)` looks them up by the org name: [7](#0-6) 

Because `verify_signature` derives the organization purely from `repository.owner.login`/`organization.login` in the body, and `verify_webhook_signature` treats a blank `webhook_secret` as "always verified," any organization entry lacking a configured `webhook_secret` becomes an unauthenticated bypass gate: an attacker can submit a `push` (or other) webhook with `repository.owner.login` set to that unsecured organization while setting `repository.full_name` to `<protected-org>/<protected-repo>`. Signature verification passes (no secret to check against), but `PushHandler` resolves the target `Stack` purely from `repository.full_name`, triggering `stack.sync_github(expected_head_sha:)` against a repository that belongs to an entirely different, secured organization.

This is the same class of bug as the report's core issue: a field that is authorized/verified (here, the organization tied to the signature) does not match the field that is actually acted upon (here, the repository resolved from a sibling, unverified field of the same payload) — i.e., "organization authenticated" != "repository written."

### Impact Explanation
An attacker who can identify (a) that a Shipit instance uses the multi-organization config schema, and (b) that at least one configured organization lacks a `webhook_secret`, can forge unsigned `push` webhooks that are accepted as authentic for a completely different, secured organization's repository. This can enqueue `GithubSyncJob`/trigger `stack.sync_github` for stacks the attacker has no legitimate write access to, effectively an unauthorized sync/trigger of downstream deploy pipelines tied to arbitrary branches/SHAs the attacker chooses in the forged payload, without ever needing the target organization's actual `webhook_secret`.

### Likelihood Explanation
Exploitability is conditioned on the specific multi-org configuration state (one org present with a blank `webhook_secret`) rather than a universal default, so it is not guaranteed in every deployment. However, `webhook_secret` is explicitly optional in the code (`return true unless webhook_secret`), so this is a realistic and easily-triggered misconfiguration in any installation onboarding multiple GitHub organizations incrementally (e.g., adding a new org before wiring up its webhook secret). Likelihood is Medium: no privileged credential is required, only knowledge of one unsecured org's name, which may be discoverable from `Repository` records or public GitHub org listings.

### Recommendation
Bind repository/stack resolution to the same organization identity used for signature verification, not to a separate unverified field:
- Reject or scope handler processing when `repository.full_name`'s owner segment does not case-insensitively match the `repository_owner`/`organization` value used in `verify_signature`.
- Do not treat a blank `webhook_secret` as an implicit "always verified" pass in multi-organization mode; require every configured organization to have a non-blank `webhook_secret`, or explicitly opt an organization into "no verification" with a distinct, audited flag rather than silent fallback.
- Consider deriving the effective organization strictly from the resolved `Repository` record (post-lookup) and re-validating that it matches the organization whose secret verified the signature, before invoking any handler side effects.

### Proof of Concept
1. Configure Shipit with `secrets.github` containing two organizations: `secured-org` (with `webhook_secret` set) and `unsecured-org` (no `webhook_secret`).
2. `secured-org/target-repo` exists as a tracked `Repository`/`Stack` in Shipit.
3. Send `POST /webhooks` with header `X-Github-Event: push` and no valid `X-Hub-Signature`, body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-sha>",
  "repository": {
    "owner": { "login": "unsecured-org" },
    "full_name": "secured-org/target-repo"
  }
}
```
4. `verify_signature` calls `Shipit.github(organization: "unsecured-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` regardless of the (missing/invalid) `X-Hub-Signature` header — request passes verification.
5. `PushHandler#process` resolves `stacks` via `Repository.from_github_repo_name("secured-org/target-repo")` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen-sha>")` on the secured org's stack, entirely unauthenticated with respect to `secured-org`.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
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
