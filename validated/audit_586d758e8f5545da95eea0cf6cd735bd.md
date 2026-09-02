This confirms the multi-organization GitHub App configuration model, where each organization gets its own webhook secret in `Shipit.github(organization:)`, and `WebhooksController#verify_signature` selects that secret using only `params.dig('repository', 'owner', 'login')` or `params.dig('organization', 'login')`, while `Handlers::Handler#repository_name`/`#stacks` act on `payload.dig('repository', 'full_name')` — a distinct, unvalidated field. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Title
Webhook organization authenticated via `repository.owner.login` is never bound to the `repository.full_name` the handlers act on - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the `X-Hub-Signature` against using `repository_owner`, computed only from `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')`). Once the signature validates against that organization's secret, `create` dispatches the entire, attacker-controlled JSON body to `Shipit::Webhooks.for_event(event)` handlers, which resolve the target `Repository`/`Stack` from a completely different field: `payload.dig('repository', 'full_name')`. Nothing ties these two fields together, so a caller who legitimately holds one organization's webhook secret can forge an event whose `full_name` names a stack belonging to an entirely different, unrelated organization configured in the same Shipit instance.

### Finding Description
Shipit supports hosting multiple GitHub organizations from a single instance, each with its own `webhook_secret` under `Shipit.github(organization:)`. [1](#0-0) 

The signature check in `verify_signature` picks the app/secret using `repository_owner`:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [2](#0-1) 

Once `verified` is true (i.e., the HMAC matches organization X's secret), `create` hands the *entire raw JSON body* to every registered handler for the event, unmodified:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [5](#0-4) 

Handlers never re-check `repository.owner.login`; they resolve the acted-upon repository purely from `repository.full_name`:
```ruby
def repository_name
  payload.dig('repository', 'full_name')
end
``` [3](#0-2) 

`PushHandler`, for instance, uses that `full_name`-derived `stacks` scope to trigger `sync_github` (which schedules `GithubSyncJob` and can lead to deploy pipelines picking up new commits) for whatever stack matches: [4](#0-3) 

Because the HMAC signature only proves the payload came from someone possessing organization X's `webhook_secret` — it says nothing about which repository the payload's `full_name` field claims to represent — an attacker who has, or can obtain, one organization's `webhook_secret` (e.g., because they administer that org's GitHub App/webhook settings, a plausible "unprivileged" actor relative to organizations they don't own) can construct a payload with `repository.owner.login` set to their own org (to pick the matching secret) but `repository.full_name` set to `"other-org/other-repo"`. This breaks the equality that should hold: `organization authenticated == organization of repository written`.

### Impact Explanation
A forged, signature-valid webhook naming an arbitrary `full_name` lets the attacker drive `Shipit::Webhooks` handlers for stacks/repositories under organizations they do not control: triggering `GithubSyncJob` via `PushHandler`, manipulating `PullRequest`/review-stack archive/unarchive/labels state via the `PullRequest` handlers, or updating commit statuses — all scoped to repositories outside the authenticating organization. This is a cross-organization/cross-repository write achieved purely by holding a webhook secret for an unrelated org hosted on the same Shipit instance, matching the "organization that authenticated versus the repository that is written" binding break called out in scope.

### Likelihood Explanation
Exploitability requires the deployment to actually use the documented multi-organization `github:` configuration (explicitly documented in `docs/setup.md` and `test/dummy/config/secrets_double_github_app.yml`) and for the attacker to control/know a `webhook_secret` for at least one hosted organization — a realistic scenario for a self-service Shipit instance shared across several GitHub orgs, since each org's own administrators/webhook configuration determine that secret. No `ApiClient` token, GitHub App private key, or Shipit session is required.

### Recommendation
After parsing the payload, verify that `repository.owner.login` (the value used to select the signing organization) matches the organization portion of `repository.full_name` before dispatching to handlers, or better, use the same authenticated `repository_owner` value as the sole trust anchor for resolving `Repository`/`Stack` records in `Shipit::Webhooks::Handlers::Handler`, rejecting any event whose `full_name` organization prefix disagrees with the verified `repository_owner`.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` and `OrgB`, each with its own GitHub App and `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`).
2. As an attacker who administers `OrgA`'s GitHub App/webhook, craft a `push` event JSON body:
   ```json
   { "ref": "refs/heads/master", "after": "<attacker-chosen sha>",
     "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/some-stack" } }
   ```
3. Sign the raw body with `OrgA`'s `webhook_secret` (`sha1=` HMAC) and POST it to `/webhooks` with `X-Github-Event: push` and the computed `X-Hub-Signature`.
4. `verify_signature` calls `Shipit.github(organization: 'OrgA')` and validates successfully. `PushHandler#stacks` resolves `Repository.from_github_repo_name('OrgB/some-stack')`, and `sync_github` is invoked for `OrgB`'s stack even though the request was never authenticated by `OrgB`'s secret.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
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
