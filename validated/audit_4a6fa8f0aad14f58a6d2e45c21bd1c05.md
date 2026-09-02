### Title
Cross-organization webhook forgery via organization/repository binding mismatch in multi-tenant GitHub App configuration - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-organization Shipit deployment (multiple GitHub Apps configured under `secrets.github`, keyed by organization), the webhook signature is verified using a secret selected from `repository.owner.login` (or `organization.login`) in the JSON payload, but the code that actually acts on the payload (looking up the target `Repository`/`Stack`, applying commit statuses, syncing pushes, etc.) uses `repository.full_name`, which is never checked against the organization that was used to select and validate the HMAC. This breaks the binding "organization whose secret authenticated the request == repository being written to."

### Finding Description
`WebhooksController#verify_signature` selects the `GitHubApp`/webhook secret to validate the request against based on a value pulled straight out of the (as-yet-unverified) JSON body: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up per-organization config via `github_app_config`, which is only exercised when Shipit is running in multi-tenant mode (multiple orgs configured under `secrets.github`): [3](#0-2) 

Once `verify_webhook_signature` succeeds (using the *claimed* organization's own secret), the full raw JSON body is dispatched unchanged to every registered handler: [4](#0-3) 

Handlers, however, determine *which* `Repository`/`Stack` to mutate using a completely different field of the same payload — `repository.full_name` — with no cross-check against the organization whose secret validated the signature: [5](#0-4) [6](#0-5) 

Concretely, `PushHandler` (queues `sync_github`/deploys) and `StatusHandler` (writes CI/commit statuses that gate deploys) both resolve their target purely from `repository.full_name` in the same trusted-because-signed payload, independent of `repository.owner.login`: [7](#0-6) [8](#0-7) 

**Broken binding (equality that should hold but doesn't):**
`organization_that_signed_the_request (repository.owner.login used to pick the HMAC secret) == organization_owning_the_repository_being_mutated (owner segment of repository.full_name used by Repository.from_github_repo_name)`

**Before the attack:** Tenant A (`OrgA`) has its own GitHub App/webhook secret configured on the shared Shipit instance; Tenant B (`OrgB`) has a separate repository/stack on the same instance. Nothing in `OrgA`'s config or webhook grants it any authority over `OrgB`'s repositories.

**After the attack:** Anyone who can produce a validly-signed webhook body for `OrgA` (i.e., anyone with OrgA's webhook secret — the legitimate operator of OrgA's own GitHub App, who needs no privileges whatsoever on Shipit or on `OrgB`) can set `repository.owner.login` (or `organization.login`) to `"OrgA"` so the signature check passes with OrgA's secret, while setting `repository.full_name` to `"OrgB/victim-repo"`. `WebhooksController` never re-derives or checks that `full_name`'s owner matches the signing organization, so the forged event is processed as an authentic event for OrgB's repository.

### Impact Explanation
This crosses a repository/tenant trust boundary that the multi-organization webhook-secret feature is explicitly designed to enforce (separate secrets per organization exist specifically so one tenant cannot act as another). By exploiting the mismatch:
- `push` events can be forged for `OrgB`'s stacks, triggering `stack.sync_github(expected_head_sha:)` (queues `GithubSyncJob`) for a repository the attacker does not own — effectively an unauthorized write into another tenant's deploy pipeline state.
- `status` events can be forged to write arbitrary CI/commit statuses (`Commit#create_status_from_github!`) on `OrgB`'s commits, which is exactly the signal Shipit's deploy-safety checks (CI gating before deploy/merge) rely on — allowing an attacker to make a bad commit appear "green" and eligible for deploy/merge in a repository/organization they have no access to.
- `check_suite`/`pull_request` events can similarly be forged against other tenants' repositories.

This matches the "cross-repository writes" / unauthorized-deploy category: an entity authenticated only for its own organization is able to write state (sync, CI status, PR/label state) belonging to a different organization's repository on the same Shipit instance.

### Likelihood Explanation
Exploitability requires only that Shipit be deployed in the (supported, documented, tested) multi-organization mode, i.e. `secrets.github` keyed by multiple organizations, each with its own webhook secret (`test/dummy/config/secrets_double_github_app.yml`, `Shipit.github(organization:)` / `github_app_config` are directly built for this). No access to the target tenant, no Shipit account, and no GitHub repository permissions on the victim org are required — only knowledge of one's *own* legitimately-provisioned webhook secret, which by design is not restricted to only emitting events for that org's own repositories inside this controller. This is a straightforward, low-effort forgery once multi-tenant mode is in use.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), after resolving both the signing organization and the target repository from the payload, enforce that they match, e.g.:
```ruby
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def repository_full_name_owner
  params.dig('repository', 'full_name')&.split('/')&.first
end
```
and reject (`head 422`) if `repository_full_name_owner` is present and does not case-insensitively match `repository_owner`, before dispatching to handlers. Alternatively, resolve the target `Repository` strictly by the same organization value that was used to select the verifying webhook secret, rather than trusting `repository.full_name` independently.

### Proof of Concept
Preconditions: Shipit instance configured in multi-org mode with (at least) `OrgA` (attacker-controlled GitHub App/webhook secret) and `OrgB` (victim, has a stack/repository configured on the same Shipit instance).

1. Attacker crafts a `push` webhook JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen-existing-sha-in-OrgB-repo>",
  "repository": {
    "full_name": "OrgB/victim-repo",
    "owner": { "login": "OrgA" }
  }
}
```
2. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(OrgA_webhook_secret, raw_body)` using OrgA's own legitimately-known webhook secret.
3. POST to `/webhooks` with header `X-Github-Event: push`.
4. `WebhooksController#repository_owner` returns `"OrgA"` → `Shipit.github(organization: "OrgA")` → `verify_webhook_signature` succeeds (correct secret for OrgA).
5. `Shipit::Webhooks.for_event("push")` dispatches the full payload to `PushHandler`, which computes `repository_name` from `payload.dig('repository','full_name')` = `"OrgB/victim-repo"`, resolves `OrgB`'s stacks via `Repository.from_github_repo_name`, and enqueues `stack.sync_github(expected_head_sha: ...)` for OrgB's repository — despite the request only being authenticated for OrgA. [9](#0-8) [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-30)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end

    private

    def drop_unhandled_event
      # Acknowledge, but do nothing
      head(204) unless Shipit::Webhooks.for_event(event).present?
    end

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

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L1-25)
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
      end
```
