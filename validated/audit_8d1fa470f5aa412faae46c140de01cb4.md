### Title
Cross-organization webhook forgery via mismatched authentication/authorization scope in multi-org GitHub App installs - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
In a multi-tenant Shipit deployment (multiple GitHub organizations configured under `secrets.github`), the webhook signature is verified using the GitHub App secret selected by the top-level `repository.owner.login` field of the incoming payload, but the handlers that mutate application state select the `Repository`/`Stack` to act on using the `repository.full_name` field of the *same* payload. Because these two fields are never cross-checked against each other, an org that legitimately controls its own GitHub App webhook secret can forge a payload that authenticates as its own organization while causing writes against a completely different organization's repository.

### Finding Description
`WebhooksController#verify_signature` picks the app/secret to validate the signature with, based on the attacker-controlled JSON body: [1](#0-0) [2](#0-1) 

`repository_owner` is read from `params.dig('repository', 'owner', 'login')`. `Shipit.github(organization: repository_owner)` then looks up the corresponding `GitHubApp` and its `webhook_secret` from the multi-org config schema documented in `docs/setup.md` and exercised in `lib/shipit.rb`: [3](#0-2) 

Once the HMAC signature validates against *that org's* secret, `WebhooksController#create` dispatches the entire raw payload to the relevant `Shipit::Webhooks::Handlers` handler: [4](#0-3) 

Handlers, however, resolve the target `Repository`/`Stack` using an entirely different field of the same payload — `repository.full_name` — with no re-validation that it belongs to the organization whose secret authenticated the request: [5](#0-4) [6](#0-5) [7](#0-6) 

This breaks the trust equality that should hold: `organization_that_authenticated_the_request == organization_owning_the_repository_that_gets_written`. Any org (`OrgB`) that is a legitimate tenant of the shared Shipit instance and therefore knows its own `webhook_secret` can:
1. Sign an arbitrary JSON body with its own secret.
2. Set `repository.owner.login = "OrgB"` (so `verify_signature` selects and validates against `OrgB`'s known secret).
3. Set `repository.full_name = "OrgA/some-repo"` (a different tenant's repository configured in the same Shipit instance).
4. POST to the public `/webhooks` endpoint (`resources :webhooks, only: :create` in `config/routes.rb`, line 14), which requires no session/API token — the whole point of the endpoint is to accept unauthenticated GitHub-signed traffic.

Shipit will then execute the handler logic against `OrgA`'s `Stack`/`Repository`/`PullRequest` records, believing the event genuinely originated from GitHub for `OrgA`.

### Impact Explanation
Depending on the forged event type, this allows an org that only controls its own tenant to reach into another tenant's data and trigger state-changing actions it has no authorization over, e.g.:
- `push` events can invoke `stack.sync_github(expected_head_sha:)` on an unrelated org's stack (`PushHandler#process`), forcing Shipit to treat an attacker-chosen (but real, public) commit as the expected head for `OrgA`'s branch, which can influence deploy/merge decision-making for that stack.
- `pull_request` `closed`/`reopened`/`labeled` events can archive/unarchive review stacks belonging to `OrgA` (`ClosedHandler#process`, `ReopenedHandler#process`, `LabeledHandler#process`), causing unauthorized provisioning/deprovisioning of infrastructure for a repository the attacker does not own.
- `status`/`check_suite`-style events feed into commit status bookkeeping that Shipit's continuous delivery / merge queue logic consults before it performs *real* GitHub actions (merges, deploys) using `OrgA`'s actual GitHub App credentials — this is precisely the "unauthorized deploy, rollback or merge" and "cross-repository writes" impact class called out as Critical.

This is a genuine cross-tenant boundary break with no requirement to compromise `OrgA`'s secret, GitHub App, or Shipit session — only possession of `OrgB`'s own, intentionally-scoped webhook secret.

### Likelihood Explanation
This is only reachable on Shipit installations that use the documented multi-organization GitHub App configuration (`secrets.github.<org>.webhook_secret`, see `docs/setup.md` "Using Multiple Github Applications" and `test/dummy/config/secrets_double_github_app.yml`). On single-org installs there is only one secret/org, so the mismatch is not exploitable. Where multi-org is used, any tenant org onboarded onto the shared instance can carry out the attack against any other tenant with zero additional privileges — likelihood is high in that deployment configuration.

### Recommendation
After signature verification, re-derive the repository/organization strictly from the same trusted field used to select the signing key (or vice-versa), and reject the webhook if `repository.full_name`'s owner does not match `repository_owner` used for `Shipit.github(organization:)`. Concretely, in `WebhooksController#verify_signature`/`#create`, assert that `params.dig('repository','full_name')&.split('/')&.first&.casecmp?(repository_owner)` before dispatching to handlers, and have handlers reject payloads whose repository owner doesn't match the authenticated organization.

### Proof of Concept
1. Configure Shipit with two tenants, `OrgA` and `OrgB`, each with a distinct `webhook_secret` (per `docs/setup.md`), and stacks for both `OrgA/target-repo` and `OrgB/attacker-repo`.
2. As an operator of `OrgB` (who legitimately knows `OrgB`'s `webhook_secret`), craft a `pull_request` `closed` event JSON body with:
   - `repository.owner.login = "OrgB"`
   - `repository.full_name = "OrgA/target-repo"`
   - a valid `pull_request` object matching an existing open review stack under `OrgA/target-repo`.
3. Compute `X-Hub-Signature` using `OrgB`'s `webhook_secret` over the raw JSON body (mirrors `Hook::DeliverySigner`/`GitHubApp#verify_webhook_signature` logic).
4. `POST /webhooks` with header `X-Github-Event: pull_request` and the computed signature.
5. `WebhooksController#verify_signature` resolves `Shipit.github(organization: "OrgB")` and validates successfully against `OrgB`'s secret.
6. `PullRequest::ClosedHandler#process` resolves `Shipit::Repository.from_github_repo_name("OrgA/target-repo")` and calls `review_stack.archive!`, archiving `OrgA`'s review stack — an action the `OrgB` operator has no authorization to perform.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
