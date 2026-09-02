### Title
Cross-organization webhook forgery: authenticated webhook organization not bound to repository acted upon - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` resolves *which* GitHub App/organization's `webhook_secret` to validate a signature against using `repository_owner` (`repository.owner.login` or `organization.login` from the payload), but the handlers that subsequently act on the payload (`Handler#repository_name`, used to load the `Repository`/`Stack` and mutate them) key off `repository.full_name` instead. [1](#0-0) [2](#0-1)  Nothing ties `repository.owner.login` (the field the HMAC signature check is scoped to) to the organization prefix of `repository.full_name` (the field that determines the repository actually mutated).

### Finding Description
Shipit supports a multi-tenant configuration where each GitHub organization has its own App config, including its own `webhook_secret`, keyed under `secrets.github`. [3](#0-2)  The example config confirms this per-organization secret model. [4](#0-3) 

In `WebhooksController`, the signature is verified against the secret of the organization named in the payload's `repository.owner.login` (falling back to `organization.login`):
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(
    request.headers['X-Hub-Signature'],
    request.raw_post
  )
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [5](#0-4) 

However, `create` hands the *entire raw JSON payload* to the event handlers unchanged:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [6](#0-5) 

Every handler resolves the repository/stacks to act on using `repository.full_name`, a completely separate JSON field from the one used to select the signing secret:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 
Handlers such as `PushHandler` and the `PullRequest::LabeledHandler` follow the same pattern, resolving state purely off `repository.full_name`/`repository.owner.login` inside the payload with no cross-check against the organization whose secret authenticated the request. [7](#0-6) [8](#0-7) 

This is the same class of bug as the reported DeBridge issue: a field that is verified/authenticated (`repository.owner.login`, bound to the signing secret) is not equal to the field that is actually acted upon (`repository.full_name`, bound to the mutated `Repository`/`Stack`). In a multi-organization Shipit deployment, an actor who legitimately possesses the `webhook_secret` for *their own* configured organization can craft a signed payload where `repository.owner.login`/`organization.login` names their own org (so `Shipit.github(organization: repository_owner)` resolves to their own app config and the HMAC check passes with their own secret) while `repository.full_name` names a stack belonging to a **different** organization/repository configured in the same Shipit instance. Because handlers never verify that `repository.full_name`'s owner matches `repository_owner`, the forged payload is processed as if genuinely delivered by GitHub for the victim repository.

### Impact Explanation
This breaks the binding "organization that authenticated == repository that is written," directly analogous to the reported bug class. Depending on the handler triggered, an attacker holding only their own tenant's webhook secret can force actions against a victim stack in another tenant's namespace within the same Shipit install — e.g. triggering `stack.sync_github` via `PushHandler`, or archiving/unarchiving review stacks via `PullRequest::LabeledHandler` — none of which validate that the acted-upon repository belongs to the organization that produced a valid signature. This is a cross-repository/cross-tenant write achieved without possessing the victim's own `webhook_secret`, which the scan rules explicitly call out as an accepted analog ("an organization that authenticated versus the repository that is written").

### Likelihood Explanation
Requires: (1) a Shipit deployment configured with multiple GitHub organizations (each with distinct `webhook_secret`s) sharing one Shipit instance, and (2) the attacker possessing a legitimately-obtained `webhook_secret` for their own onboarded organization (not the victim's). Given that, forging the payload is trivial — no other authentication or session is required, since `WebhooksController` has no CSRF or session gating. [9](#0-8)  The main mitigating factor is that this only matters in multi-org deployments, and the practical blast radius is limited to what webhook handlers can do (sync/archive operations), not raw merges or deploys, based on the handlers reviewed.

### Recommendation
In `WebhooksController#verify_signature` (or in the shared `Handler` base class), assert that the organization used to select/verify the signing secret is equal to the organization prefix parsed out of `repository.full_name` (and/or `organization.login`) before dispatching to handlers — i.e., enforce `repository_owner == repository.full_name.split('/').first` (case-insensitively) and reject with `422`/`INVALID_ACTION` otherwise, mirroring the recommended `args_.dstChainId == args_.liqDstChainId` check from the source report.

### Proof of Concept
1. Deploy Shipit with two organizations configured, e.g. `github: { attacker-org: { webhook_secret: "s1", ... }, victim-org: { webhook_secret: "s2", ... } }`. [4](#0-3) 
2. As the legitimate admin of `attacker-org` (who possesses `s1`), craft a `push` payload:
   ```json
   {
     "ref": "refs/heads/main",
     "after": "<attacker-controlled sha>",
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" }
   }
   ```
3. Sign the raw body with `s1` and set `X-Hub-Signature`, `X-Github-Event: push`.
4. POST to `/webhooks`. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully against `s1`. [10](#0-9) 
5. `PushHandler` then resolves `Repository.from_github_repo_name("victim-org/victim-repo")` and calls `stack.sync_github(expected_head_sha: params.after)` on the victim's stacks — an action the attacker was never authorized to trigger via their own secret. [7](#0-6)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L4-6)
```ruby
  class WebhooksController < ActionController::Base
    skip_before_action :verify_authenticity_token, raise: false
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
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

**File:** config/secrets.development.example.yml (L18-38)
```yaml
# Use this configuration schema if you are configuring multiple Github applications for different Github organizations

# github:
#   somegithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
#   someothergithuborg:
#     app_id:
#     installation_id:
#     webhook_secret: # nil
#     private_key:
#     oauth:
#       id:
#       secret:
#       teams: # Optional
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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```
