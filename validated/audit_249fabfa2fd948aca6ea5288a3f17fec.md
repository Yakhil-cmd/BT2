This confirms the multi-org config: `Shipit.github(organization:)` selects a distinct `GitHubApp` (and thus distinct `webhook_secret`) per organization key, e.g. `OrgOne`/`OrgTwo` as shown in `test/dummy/config/secrets_double_github_app.yml`, and this is a documented, supported deployment mode (`docs/setup.md` "Using Multiple Github Applications").### Title
Cross-organization webhook forgery: signature verification key is chosen by `repository.owner.login`, but the repository acted upon is chosen by `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate the HMAC signature against based on `params.dig('repository', 'owner', 'login')` (falling back to `params.dig('organization', 'login')`), while every webhook `Handler` (`PushHandler`, `CheckSuiteHandler`, and the `pull_request` handlers) resolves the target `Repository`/`Stack` using a *different* payload field, `params.dig('repository', 'full_name')`. In a multi-org Shipit deployment (`docs/setup.md`'s "Using Multiple Github Applications" mode, exercised by `test/dummy/config/secrets_double_github_app.yml`), these two fields are never checked for consistency, so a request that is legitimately signed with one organization's secret can act on a stack belonging to an entirely different organization's repository.

### Finding Description
`verify_signature` computes `repository_owner` and uses it only to pick which `GitHub::App`/secret to validate the HMAC against: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` returns a distinct `GitHubApp` instance (and thus a distinct `webhook_secret`) keyed strictly by this organization name in multi-app configurations: [3](#0-2) 

Once the signature passes, `WebhooksController#create` dispatches the entire raw payload to the registered `Handler`s for the event, with no re-check that the field used for authentication (`repository.owner.login`) matches the field the handler actually uses to select which `Stack`/`Repository` to modify: [4](#0-3) 

The base `Handler` class (and every concrete handler that inherits `stacks`, e.g. `PushHandler`, `CheckSuiteHandler`, and the `pull_request/*` handlers) resolves the acted-upon repository from `payload.dig('repository', 'full_name')`, a field that is completely independent of `repository.owner.login`: [5](#0-4) [6](#0-5) [7](#0-6) 

This is the same bug class as the Pico `read_ghost_addr` finding: the code that performs the "verification"-adjacent operation (choosing/consuming the secret keyed on `repository.owner.login`) is inconsistent with the code that performs the actual state-changing action (looking up the target by `repository.full_name`), because two logically-related fields that should be checked together are instead independently trusted. The equality that should hold and is not enforced is:

`organization used to select/validate webhook_secret (repository.owner.login / organization.login) == owner segment of repository.full_name that the handler writes to`

Before the (hypothetical) fix, an attacker who controls or knows the `webhook_secret` for any one organization configured in Shipit's multi-org `github:` section can build an arbitrary payload where `repository.owner.login` (or `organization.login`) is set to their own org (so `Shipit.github(organization: "their-org")` picks their own secret, and they can compute a valid HMAC over the full raw body with that secret) while `repository.full_name` is set to `"victim-org/victim-repo"`. The HMAC covers the whole body, but it authenticates only "this request was signed with their-org's secret" — it does not authenticate "this request concerns their-org's repository." The handler then acts on `victim-org/victim-repo`'s real `Stack`s using the attacker-supplied event data.

### Impact Explanation
Concretely reachable unauthorized actions on an unrelated repository's `Stack`, without requiring any Shipit login, `ApiClient` token, or the victim org's webhook secret:
- `PushHandler` triggers `stack.sync_github(expected_head_sha:)` (a `GithubSyncJob`) for the victim's stacks, forcing Shipit to re-sync/append commits and re-cache the deploy spec for a `sha` chosen by the attacker.
- `CheckSuiteHandler` schedules check-run refreshes (`schedule_refresh_check_runs!`) on victim commits based on attacker-supplied `head_sha`/`head_branch`.
- `pull_request` handlers (`OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, `LabeledHandler`, `UnlabeledHandler`, `LabelCapturingHandler`) create/archive/unarchive `ReviewStack`s and mutate PR-derived labels for the victim repository, effectively provisioning or tearing down review stacks the attacker does not own.

This crosses a repository/organization trust boundary the engine is supposed to enforce — the multi-org config exists precisely to give each organization its own trusted webhook channel — and satisfies the "cross-repository writes" / "unauthorized deploy" high-severity impact category, since `sync_github` can drive automatic (`continuous_deployment`) deploys on a repository the attacker's credentials were never meant to reach.

### Likelihood Explanation
Requires a Shipit instance configured with the documented multi-organization GitHub App setup (`docs/setup.md`, `test/dummy/config/secrets_double_github_app.yml`), and requires the attacker to know/control the `webhook_secret` for at least one of the configured organizations (e.g., they administer that org's own GitHub App, which is the normal case for a self-service multi-tenant Shipit deployment). No other credential (no `ApiClient` token, no session, no GitHub write access to the victim repo) is needed. This is a moderate-likelihood scenario specific to multi-org deployments; single-org deployments are not exposed because there is only one secret to choose from.

### Recommendation
In `WebhooksController#create`/`verify_signature`, and in `Shipit::Webhooks::Handlers::Handler`, enforce that the organization used to select/verify the webhook secret matches the owner of the repository the handler is about to act on — e.g., compare `repository_owner` (used for signature verification) against `payload.dig('repository', 'full_name')`'s owner segment (and `organization.login` for org-scoped events like `membership`) and reject the request (422) on mismatch before dispatching to handlers.

### Proof of Concept
1. Configure Shipit with two organizations, each with a distinct `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`): `OrgAttacker` (secret known to the attacker) and `OrgVictim` (secret unknown to the attacker, hosting a real Shipit `Stack` for `OrgVictim/app`).
2. Craft a `push` event JSON body: `{"ref": "refs/heads/main", "after": "<attacker-chosen sha>", "repository": {"owner": {"login": "OrgAttacker"}, "full_name": "OrgVictim/app"}}`.
3. Compute `X-Hub-Signature: sha1=HMAC(OrgAttacker_webhook_secret, raw_body)`.
4. POST to `/webhooks` with header `X-Github-Event: push`.
5. `verify_signature` resolves `repository_owner` = `"OrgAttacker"`, calls `Shipit.github(organization: "OrgAttacker")`, and the signature validates successfully against the attacker's own secret.
6. `Shipit::Webhooks::Handlers::PushHandler` then resolves `stacks` via `Repository.from_github_repo_name("OrgVictim/app")` and enqueues `GithubSyncJob` for the victim's real stack with the attacker-supplied `expected_head_sha`, despite the attacker never possessing `OrgVictim`'s webhook secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L49-54)
```ruby

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
