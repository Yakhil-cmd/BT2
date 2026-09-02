### Title
Webhook signature verification selects the signing organization from an unverified payload field, letting a webhook_secret holder for one org write cross-org repository/team state - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` chooses which GitHub App/`webhook_secret` to validate an inbound webhook against using a field taken from the still-unverified JSON body, while the handlers that act on that same body pick the *target* repository/team from a different, unrelated field of the body. Nothing binds "the org whose secret verified this payload" to "the org/repo the payload claims to mutate," so a party who only holds the `webhook_secret` for one configured org can forge a fully self-signed payload that is verified as legitimate for that org but whose effects land on another org's stack, commit statuses, or team membership.

### Finding Description
`verify_signature` computes the org used for verification from the raw, unauthenticated request body: [1](#0-0) [2](#0-1) 

`repository_owner` (`params.dig('repository','owner','login') || params.dig('organization','login')`) is read from `request.raw_post` before any signature check occurs, and is used only to select which `GitHubApp` (and thus which `webhook_secret`) validates `X-Hub-Signature` via `verify_webhook_signature`: [3](#0-2) 

Shipit explicitly supports multiple GitHub orgs each with an independent `webhook_secret`, resolved by `Shipit.github(organization:)`: [4](#0-3) [5](#0-4) 

However, all the event handlers determine what to *act on* using an entirely different field, `repository.full_name` (not `repository.owner.login`), with no cross-check that it belongs to the org that was used to verify the signature: [6](#0-5) [7](#0-6) 

For example `PushHandler` triggers a sync/deploy pipeline for whatever stack matches `repository.full_name`: [8](#0-7) 

And `MembershipHandler` creates/updates `Team`/`Membership` records using `organization.login` and `member.login` taken directly from the same forgeable body, ungated by which org's secret validated the request: [9](#0-8) 

Because HMAC verification covers the entire raw body (`request.raw_post`), an attacker cannot tamper with a real GitHub-issued webhook without invalidating the signature. But an attacker who legitimately possesses (or can obtain, e.g. as an org owner configuring their own GitHub App/webhook) the `webhook_secret` for **any one** configured org can construct an **entirely new** payload from scratch, self-sign it with that org's secret, and freely set every other field — including `repository.full_name` pointing at a stack that actually belongs to a *different*, unrelated org configured in the same Shipit instance, or `organization.login`/`team.id`/`member.login` for `MembershipHandler`. The engine binds "verified organization" (`repository_owner` -> selected `webhook_secret`) to nothing; it never checks that binding equals "organization of the repository/team actually written" (`repository.full_name` owner / `team.organization`).

Binding broken as an equality: `verified_org(repository_owner used to pick webhook_secret) == written_org(owner of repository.full_name / team.organization)` is assumed but never enforced.

### Impact Explanation
This crosses a credential/authorization boundary the rules call out explicitly ("an organization that authenticated versus the repository that is written"). With only one org's `webhook_secret` (not a Shipit session, `ApiClient` token, or GitHub App private key for the *target* org), an attacker in a multi-org Shipit deployment can:
- Force cross-repository writes: trigger `PushHandler`/`stack.sync_github` and `StatusHandler#create_status_from_github!` against another org's stacks/commits, injecting fabricated commit statuses that can influence CI-gated deploy/merge decisions (`ci.require`/`ci.blocking` checks driven by `Status` records).
- Manipulate `Team`/`Membership` records for teams tied to *another* org, which feed directly into `User#authorized?`, the gate used for `Shipit.github_teams` authorization: [10](#0-9) 

This matches the High-severity bucket in scope ("escalation into `Shipit.github_teams` authorization") and, depending on which handlers are reachable, can enable unauthorized deploy-adjacent actions (cross-repository status/state writes) without ever holding credentials for the targeted organization.

### Likelihood Explanation
Requires the instance to be configured with multiple GitHub orgs (a documented, supported configuration — see `config/secrets.development.shopify.yml`), and requires the attacker to hold the `webhook_secret` for at least one of those orgs (e.g., as an admin of that org's GitHub App) but not the target org's secret. This is a realistic scenario for shared Shipit deployments serving multiple orgs/teams with different trust levels, since nothing in the code prevents it — the vulnerability is a straightforward missing binding check rather than a timing/race condition.

### Recommendation
After signature verification succeeds, enforce that the org used to select the `webhook_secret` (`repository_owner`) matches the owner embedded in every field the handlers subsequently trust to select a mutation target (`repository.full_name`'s owner segment, `organization.login` for membership events, etc.). Reject the webhook (422) if these disagree, rather than trusting `repository.full_name`/`organization.login` independently of which secret validated the payload.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with its own `webhook_secret` (per `config/secrets.development.shopify.yml` schema).
2. As an attacker who administers a GitHub App/webhook for `orgB` (and thus knows `orgB`'s `webhook_secret`) but has no access to `orgA`, craft a `push` event JSON body:
```json
{
  "ref": "refs/heads/main",
  "after": "<attacker-chosen sha>",
  "repository": { "full_name": "orgA/private-repo", "owner": { "login": "orgB" } }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgB_webhook_secret, raw_body)>` and POST it to `/webhooks` with `X-Github-Event: push`.
4. `verify_signature` reads `repository_owner` as `"orgB"` (from `repository.owner.login`), selects `orgB`'s `GitHubApp`, and the HMAC checks out — `verified` is `true`.
5. `Shipit::Webhooks::Handlers::PushHandler` then resolves the target via `repository.full_name = "orgA/private-repo"` and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on a stack that belongs to `orgA`, even though the attacker never held `orgA`'s webhook secret.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L1-24)
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

        private

        def branch
          params.ref.gsub('refs/heads/', '')
        end
      end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-47)
```ruby
# frozen_string_literal: true

module Shipit
  module Webhooks
    module Handlers
      class MembershipHandler < Handler
        params do
          requires :action, String
          requires :team do
            requires :id, Integer
            requires :name, String
            requires :slug, String
            requires :url, String
          end
          requires :organization do
            requires :login, String
          end
          requires :member do
            requires :login, String
          end
        end
        def process
          team = find_or_create_team!
          member = User.find_or_create_by_login!(params.member.login)

          case params.action
          when 'added'
            team.add_member(member)
          when 'removed'
            team.members.delete(member)
          else
            raise ArgumentError, "Don't know how to perform action: `#{action.inspect}`"
          end
        end

        private

        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
      end
    end
  end
end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
