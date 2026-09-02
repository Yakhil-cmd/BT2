### Title
Webhook signature is verified against the organization named in `repository.owner.login`, but event handlers act on the repository named in the unrelated `repository.full_name` field, letting one onboarded organization forge state for another organization's repository - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
Shipit supports multi-organization GitHub App configuration, where each organization can have its own independent `webhook_secret` in `secrets.github`. `WebhooksController#verify_signature` selects which organization's secret to verify the HMAC signature against using one payload field (`repository.owner.login`), while the actual event handlers resolve the target `Repository`/`Stack` to mutate using a different, independently attacker-controlled field in the same JSON body (`repository.full_name`). Nothing ties these two fields together, so a forged payload can pass signature verification "as organization A" while writing state into organization B's repository.

### Finding Description
`verify_signature` computes the verifying organization strictly from the payload itself: [1](#0-0) [2](#0-1) 

`Shipit.github(organization:)` looks up a distinct `webhook_secret` per organization when Shipit is configured for multiple tenants (`github_app_config`/`github_default_organization`), each organization's secret being known only to that organization's own GitHub App owner: [3](#0-2) 

After signature verification succeeds, `create` blindly hands the *entire* parsed payload to the registered handlers: [4](#0-3) 

Every handler resolves the target repository from a **different** field of the same payload — `repository.full_name` — with no check that it belongs to the organization that was used to validate the signature: [5](#0-4) 

For example, `StatusHandler` uses this to attach a forged commit status directly to any `Commit` row matching an attacker-chosen `sha`: [6](#0-5) 

and `PushHandler` triggers a sync for any stack belonging to the resolved repository: [7](#0-6) 

**Binding broken:** *organization authenticated by the HMAC signature* (`repository.owner.login` / `organization.login`, used to pick the secret) **≠** *repository whose state handlers write* (`repository.full_name`, used by `Handler#stacks`/`#repository_name`). A legitimate GitHub-originated webhook always keeps these two fields consistent, but nothing in `WebhooksController` or `Handler` enforces that invariant on a directly-POSTed, attacker-crafted body. An administrator of any organization onboarded as its own tenant (i.e., someone who legitimately created their own org's GitHub App and therefore knows their own org's `webhook_secret`) can:
1. Build a JSON payload with `repository.owner.login` = their own organization (so `verify_signature` picks their own known secret) and `organization.login` likewise.
2. Set `repository.full_name` = `victim-org/victim-repo`.
3. Sign the raw body with their own known `webhook_secret` and POST it to `/github/webhooks`.
4. `verify_webhook_signature` succeeds (their org's secret matches their own signature), yet the handler dispatch operates on `victim-org/victim-repo`'s `Stack`/`Commit` records.

### Impact Explanation
This is a cross-repository/cross-tenant write achieved without any Shipit session, `ApiClient` token, or repository access to the victim: an org that was authenticated is not the org whose repository state is mutated. Via `StatusHandler`, the attacker can inject fabricated commit-status records (`Commit#create_status_from_github!`) for arbitrary commit SHAs in a repository they do not control, corrupting deployability/CI signal data other Shipit users rely on when deciding to deploy. Via `PushHandler`/`CheckSuiteHandler`, forged events can trigger sync/refresh actions against a victim stack. This satisfies the "cross-repository writes" high/critical impact category, since it lets one onboarded tenant write into another tenant's repository data purely by crafting a webhook body.

### Likelihood Explanation
The vulnerability requires:
- Shipit deployed with multi-organization GitHub App configuration (multiple orgs in `secrets.github`).
- At least two organizations onboarded as separate tenants (each with their own `webhook_secret`).
- An attacker who is an administrator of one of those organizations (so they can create a GitHub App and learn their own `webhook_secret`).

This is a realistic multi-tenant SaaS scenario. The attacker does not need to compromise GitHub, intercept TLS, or social-engineer anyone; they only need legitimate admin access to their own organization's GitHub App settings.

### Recommendation
Enforce that the organization used to verify the signature matches the organization that owns the repository being acted upon. After `verify_signature` succeeds and before dispatching to handlers, validate that `params.dig('repository', 'owner', 'login')` (or `params.dig('organization', 'login')` as a fallback) equals the `repository_owner` that was used to select the verifying secret. Reject the webhook with a 422 if they do not match.

### Proof of Concept
1. Set up Shipit with two organizations: `org-a` and `org-b`, each with their own GitHub App and `webhook_secret`.
2. As an admin of `org-a`, obtain `org-a`'s `webhook_secret` from the GitHub App settings.
3. Craft a JSON payload:
   ```json
   {
     "action": "created",
     "commit_status": {
       "sha": "abc123...",
       "state": "failure",
       "description": "Forged CI failure"
     },
     "repository": {
       "owner": { "login": "org-a" },
       "full_name": "org-b/victim-repo"
     },
     "organization": { "login": "org-a" }
   }
   ```
4. Sign the raw JSON body with `org-a`'s `webhook_secret` using HMAC-SHA1, producing a signature like `sha1=...`.
5. POST the body to `https://shipit.example.com/github/webhooks` with header `X-Hub-Signature: sha1=...` and `X-Github-Event: status`.
6. `verify_signature` succeeds (the signature is valid for `org-a`'s secret).
7. `StatusHandler` processes the payload and calls `Commit.where(sha: 'abc123...').each { |commit| commit.create_status_from_github!(...) }`, creating a forged status on any commit in `org-b/victim-repo` that matches the attacker's chosen SHA. [8](#0-7)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-64)
```ruby
# frozen_string_literal: true

module Shipit
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature

    respond_to :json

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
  end
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/webhooks/handlers/status_handler.rb (L20-24)
```ruby
        def process
          Commit.where(sha: params.sha).each do |commit|
            commit.create_status_from_github!(params)
          end
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
