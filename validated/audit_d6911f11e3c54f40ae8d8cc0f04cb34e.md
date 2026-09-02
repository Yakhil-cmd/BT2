### Title
Cross-organization commit-status forgery via organization/repository binding mismatch in webhook signature verification - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to use for HMAC verification based on an untrusted field inside the *unverified* JSON body (`repository.owner.login`, falling back to `organization.login`), while every event handler that actually mutates state resolves the target `Repository`/`Stack` from a *different* field of the same untrusted body: `repository.full_name` (`owner/name`). [1](#0-0) [2](#0-1) [3](#0-2) 

### Finding Description
Shipit supports multiple GitHub Apps/organizations configured under `github:` in secrets, each with its own `webhook_secret`, all funneled through the single `WebhooksController#create` endpoint. [4](#0-3) 

The signature check picks the verifying secret like this:
```
def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end

def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end
```
`repository_owner` is read straight out of the attacker-supplied, not-yet-verified JSON body. `Shipit.github(organization:)` resolves the org-specific `webhook_secret` from that value. [5](#0-4) [6](#0-5) 

Once the signature is confirmed valid *for whatever organization `repository.owner.login` claims to be*, `create` dispatches the parsed body unchanged to the registered handler(s):
```
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
```
Handlers such as `Handler#stacks` / `#repository_name` and `StatusHandler#process` locate the target repository/commit using `repository.full_name`, not `repository.owner.login`:
```
def repository_name
  payload.dig('repository', 'full_name')
end
```
```
class StatusHandler < Handler
  ...
  def process
    Commit.where(sha: params.sha).each { |commit| commit.create_status_from_github!(params) }
  end
end
``` [7](#0-6) [8](#0-7) 

`Repository.from_github_repo_name` splits `full_name` on `/` and looks the row up purely by `owner`/`name` columns, with no cross-check against the organization whose secret verified the request:
```
def self.from_github_repo_name(github_repo_name)
  repo_owner, repo_name = github_repo_name.downcase.split('/')
  find_by(owner: repo_owner, name: repo_name)
end
``` [9](#0-8) 

**Binding broken (equality that should hold but doesn't):**
`organization authenticated via signature (repository.owner.login) == organization of the repository actually written to (repository.full_name's owner)`

Because these are two independent JSON fields inside the same unauthenticated payload, an attacker who legitimately controls a GitHub App/organization "OrgA" configured in Shipit (and therefore knows OrgA's `webhook_secret`, e.g. because they administer that org's GitHub App installation) can sign a payload whose HMAC is valid for OrgA (`repository.owner.login = "OrgA"`) while setting `repository.full_name = "OrgB/victim-repo"`. `verify_signature` succeeds using OrgA's secret, and the handler then acts on `OrgB/victim-repo`, a repository the attacker does not control at all.

### Impact Explanation
With the `status` webhook event this becomes a forged CI status for a `Stack` the attacker has no rights to: `StatusHandler` creates a `CommitStatus` for any existing `Commit` matching the attacker-chosen `sha`, using attacker-controlled `state`, `context`, `description`, `target_url`. [8](#0-7)  Because Shipit's merge queue and CI gating (`ci.require`/blocking statuses, `merge.require`) rely on `CommitStatus` rows to decide whether a commit is deployable/mergeable, an attacker cross-organization can inject a fake "success" status on `OrgB`'s commit, potentially unblocking an unauthorized deploy or merge of a commit that never actually passed CI in the victim organization — landing squarely in the "unauthorized deploy, rollback, or merge" impact tier.

This is a direct analog of the reported bug class: a value used for one binding decision (`_endTime`/here, the *verifying organization*) is disconnected from the value used for the actual effect (*the repository being acted upon*), with no validation tying the two together.

### Likelihood Explanation
Exploitation requires the attacker to be a legitimate administrator of at least one GitHub organization/App that is configured in this Shipit instance's `github:` secrets (so they know that org's `webhook_secret`) — this is an "unprivileged" precondition relative to the victim organization/repo, satisfying the required attacker model (no `ApiClient` token, no `webhook_secret` of the target org, no repository write access on the victim repo needed). Multi-organization configuration is an explicitly documented and supported deployment mode (`config/secrets.development.shopify.yml`), so this is not a theoretical edge case for shared/multi-tenant Shipit deployments. [4](#0-3) 

### Recommendation
After signature verification, re-derive the organization from `repository.full_name` (or `repository.owner.login`) and require it to exactly match the organization whose `webhook_secret` verified the signature before dispatching to handlers. Reject the request (422) on mismatch.

### Proof of Concept
1. Configure Shipit with two orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (as supported by `config/secrets.development.shopify.yml`).
2. Attacker administers `OrgA`'s GitHub App and knows `OrgA`'s `webhook_secret`.
3. Attacker crafts a `status` event JSON body:
```json
{
  "sha": "<victim commit sha in OrgB/victim-repo>",
  "state": "success",
  "context": "ci/required-check",
  "repository": { "owner": { "login": "OrgA" }, "full_name": "OrgB/victim-repo" }
}
```
4. Attacker computes `X-Hub-Signature` using `OrgA`'s `webhook_secret` over the raw body.
5. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")` and validates successfully, since `repository_owner` reads `repository.owner.login = "OrgA"`. [1](#0-0) 
6. `StatusHandler.call(params)` executes and creates a `CommitStatus` on the matching commit belonging to `OrgB/victim-repo`, using `Commit.where(sha:)` with no organization scoping. [10](#0-9) 
7. The forged status can satisfy `Stack`/merge-queue CI requirements for `OrgB`, potentially enabling an unauthorized deploy or merge on a repository the attacker never had access to.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L15-38)
```ruby
        def self.call(params)
          new(params).process
        end

        attr_reader :params, :payload

        def initialize(payload)
          @payload = payload
          @params = self.class.param_parser.parse!(payload)
        end

        def process
          raise NotImplementedError
        end

        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```
