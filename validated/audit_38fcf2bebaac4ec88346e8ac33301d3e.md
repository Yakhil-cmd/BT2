## Title
Webhook signature verified against `repository.owner.login`'s GitHub App while the acted-upon repository is taken from the unbound `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

## Summary
When Shipit is configured with multiple GitHub Apps (the documented multi-organization `secrets.yml` schema), `WebhooksController#verify_signature` selects which org's `webhook_secret` to validate the HMAC signature against using `repository.owner.login` (or `organization.login`) from the *unauthenticated* JSON body, then hands the very same raw body to event handlers which independently resolve the target repository/stack from `repository.full_name`. Nothing cross-validates that `repository.owner.login` and the owner segment of `repository.full_name` refer to the same organization. An attacker who legitimately possesses (or can compute) the webhook secret for *any one* organization configured in Shipit can therefore forge a validly-signed payload whose `repository.full_name` points at a completely different organization's repository, and have Shipit act on that other org's stacks.

## Finding Description
`WebhooksController#verify_signature` does: [1](#0-0) 

`repository_owner` is read straight from the untrusted JSON body: [2](#0-1) 

`Shipit.github(organization: repository_owner)` looks up a *per-organization* app config/`webhook_secret` when the multi-app schema is used: [3](#0-2) 

This is the documented deployment model — each org gets its own `app_id`/`webhook_secret`: [4](#0-3) 

Once the signature check passes (using whichever org's secret matches `repository.owner.login`), the *same raw body* is dispatched to handlers, none of which re-derive the repository from `repository.owner.login`. Instead they all key off `repository.full_name`: [5](#0-4) [6](#0-5) 

`Repository.from_github_repo_name` simply splits `full_name` on `/` and looks the record up — it never checks it against the value that was used to select the signing org: [7](#0-6) 

The binding that should hold is:
`organization whose webhook_secret validated the signature == organization that owns the repository the handlers write to`

Because `repository.owner.login` (used for signature-org selection) and `repository.full_name`'s owner segment (used for write-target selection) are two independently attacker-controlled fields inside the *same unauthenticated payload*, this equality is never enforced. Before the attack, both fields naturally match for real GitHub-originated webhooks. After the attacker's forged request, they can be set to different organizations while the signature still validates (computed with OrgA's known secret), and the handler still executes against OrgB's stack.

## Impact Explanation
An attacker who has push/webhook access to one repository/org that Shipit manages (and therefore knows or can obtain that org's `webhook_secret`, which is explicitly meant to be shared with GitHub App owners of that org, not other orgs) can forge a validly-signed webhook whose `repository.full_name` names a repository belonging to a different organization/tenant also hosted by the same Shipit instance. Depending on event type this reaches:
- `PullRequest::ClosedHandler` → `ReviewStackAdapter#archive!`, which calls `stack.deprovision` and `stack.archive!` on a review stack belonging to the victim org — an unauthorized deprovision/rollback-class action on cross-tenant infrastructure.
- `PushHandler` → `stack.sync_github`, which can drive automatic deploy pipelines for the victim org's stack.
- `PullRequest` opened/reopened handlers → creation of new `ReviewStack` records (and associated provisioning) under the victim org's `Repository`.

This is a cross-repository/cross-organization write triggered without the correct organization's authorization credential, matching the "cross-repository writes" / "unauthorized deploy, rollback" Critical-impact criteria for this engine.

## Likelihood Explanation
Requires the attacker to already control (or have legitimate access to configure webhooks for) one organization onboarded to a multi-tenant Shipit deployment — this is the documented "Using Multiple GitHub Applications" configuration. This is a plausible real deployment shape for shared Shipit instances serving multiple GitHub orgs, and the attack requires only crafting an HTTP POST with a computed HMAC and no other credential (no `ApiClient` token, no GitHub App private key of the victim org, no session). Likelihood is therefore moderate — contingent on multi-org configuration being used, which the engine explicitly supports and documents.

## Recommendation
In `WebhooksController`, after selecting the app/secret via `repository_owner` and verifying the signature, re-derive and enforce that the owner segment of `repository.full_name` (or `organization.login`) used by handlers matches the same `repository_owner` value used for signature verification, rejecting (422) the request if they diverge. Alternatively, pass the verified `repository_owner` into `Shipit::Webhooks.for_event` handlers and have `Handler#stacks`/`Repository.from_github_repo_name` scope lookups to that verified owner instead of trusting `full_name` independently.

## Proof of Concept
1. Shipit is configured with the multi-org schema for `OrgA` (attacker-controlled, webhook secret `secretA`) and `OrgB` (victim, unrelated), both with stacks/review stacks configured.
2. Attacker crafts a `pull_request` "closed" webhook JSON body:
   ```json
   {
     "action": "closed",
     "number": 42,
     "pull_request": { "...": "..." },
     "repository": {
       "owner": { "login": "OrgA" },
       "full_name": "OrgB/victim-repo"
     },
     "sender": { "login": "attacker" }
   }
   ```
3. Attacker computes `X-Hub-Signature: sha1=HMAC(secretA, raw_body)` using the known `secretA`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")`, which validates the signature successfully against `secretA`.
5. `Shipit::Webhooks.for_event('pull_request')` dispatches to `PullRequest::ClosedHandler`, which resolves `repository` via `Shipit::Repository.from_github_repo_name("OrgB/victim-repo")` and, if the PR/stack exists, calls `review_stack.archive!`, deprovisioning and archiving `OrgB`'s review stack — all without ever presenting a credential belonging to `OrgB`. [8](#0-7) [9](#0-8)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L1-63)
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

**File:** docs/setup.md (L181-209)
```markdown

### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L49-53)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end
```
