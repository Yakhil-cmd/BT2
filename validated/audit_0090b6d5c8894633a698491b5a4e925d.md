This confirms the multi-tenant GitHub App configuration design: `Shipit.github(organization:)` maintains a separate `GitHubApp` instance (and separate `webhook_secret`) per organization, keyed by `github_app_config(organization)` [1](#0-0) . `Repository#github_app` likewise resolves its GitHub App/secret purely from `owner` [2](#0-1) . This confirms the binding-mismatch analog is real and reachable in this engine's supported multi-org deployment mode.

### Title
Webhook signature is verified against the secret of the payload's `repository.owner.login`, while all events act on the independently-declared `repository.full_name` - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a delivery using `repository.owner.login` (or `organization.login`) pulled from the request body, then hands the *entire* parsed body to event handlers, which independently resolve the target `Repository`/`Stack` from `repository.full_name` [3](#0-2) . In a multi-tenant Shipit instance (explicitly supported via per-organization GitHub Apps, see `Shipit.github_app_config` and `test/dummy/config/secrets_double_github_app.yml`), these two fields are never cross-checked, so a webhook correctly signed with organization A's secret can declare `repository.full_name` = `"B/some-repo"` and Shipit will act on organization B's stack.

### Finding Description
`verify_signature` computes:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [4](#0-3) . `Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization via `github_app_config(organization)` [1](#0-0) , a scheme the docs and test fixtures (`test/dummy/config/secrets_double_github_app.yml`) confirm is a first-class, supported multi-org configuration.

Once the signature is accepted, `create` passes the raw JSON body unchanged to `Shipit::Webhooks.for_event(event)` handlers [5](#0-4) . Handlers never re-check `repository.owner.login`; instead they resolve the acted-upon repository/stack purely from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [6](#0-5)  and `Repository.from_github_repo_name` simply splits that string on `/` and looks up any matching record regardless of which org's secret authenticated the request [7](#0-6) . `PushHandler`, and all the `PullRequest::*Handler`s (`OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, `ReopenedHandler`) resolve their target `Repository`/`Stack` the same way, via `params.repository.full_name` [8](#0-7) [9](#0-8) .

This is exactly the DCA bug class: the field that is actually acted upon (`repository.full_name`, which determines the stack that gets a `sync_github`, an archive/unarchive, or a `ReviewStack` provisioning) is decoupled from the field the signature-selection logic actually trusts (`repository.owner.login`). The binding `verified_organization == acted_upon_repository_owner` is never enforced.

### Impact Explanation
An attacker who legitimately administers a GitHub organization A that has its own GitHub App/webhook installed against a shared Shipit instance (and therefore knows/controls A's `webhook_secret`) can forge an arbitrary webhook body, sign it with A's secret, but set `repository.owner.login` = A (to pick A's secret) and `repository.full_name` = `"B/other-repo"` (any other tenant's repository tracked by the same Shipit instance). Shipit will process the event as authentic and act on organization B's stack — triggering unauthorized `sync_github` (spoofing what commit is considered pushed and eligible for continuous deployment/merge), or unauthorized archive/unarchive/provisioning of B's `ReviewStack`. This is a cross-repository/cross-tenant write performed without any credential belonging to organization B, satisfying the "cross-repository writes" / "unauthorized deploy" Critical impact bar.

### Likelihood Explanation
This requires the Shipit deployment to run in the explicitly-supported multi-organization mode (`Shipit.github_app_config`, demonstrated by `test/dummy/config/secrets_double_github_app.yml`), and requires the attacker to be a legitimate but low-trust tenant (an org admin who owns a real webhook secret for their own organization on that shared instance). No repository write access, Shipit session, or `ApiClient` token is needed — only a raw HTTP POST to `/webhooks` with a hand-crafted body signed by a secret the attacker legitimately possesses for their own tenant.

### Recommendation
In `WebhooksController#verify_signature` (or in `Shipit::Webhooks::Handlers::Handler`), after signature verification, assert that the resolved `Repository.from_github_repo_name(repository.full_name)`'s `owner` equals the `repository_owner` used to select the verifying secret, and reject (422) the delivery if they diverge.

### Proof of Concept
1. Deploy Shipit in multi-org mode with two configured GitHub Apps, `OrgA` (attacker-administered, webhook secret known to attacker) and `OrgB` (victim tenant, tracked stack `OrgB/app`).
2. Attacker crafts a `push` payload:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/app" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with header `X-Github-Event: push`.
4. `verify_signature` selects `Shipit.github(organization: "OrgA")`, verifies successfully since the attacker used OrgA's own secret.
5. `PushHandler#process` resolves `stacks` from `repository.full_name` = `"OrgB/app"`, and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stack — an action wholly unauthorized by OrgB.

### Citations

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

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L36-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```
