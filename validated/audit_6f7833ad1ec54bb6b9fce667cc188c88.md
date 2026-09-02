### Title
Webhook signing-organization is not bound to the organization/team the payload mutates, allowing cross-organization team-membership forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook against by reading an **unauthenticated** field out of the payload itself (`repository.owner.login`, falling back to `organization.login`), then verifies the raw body against that org's `webhook_secret`. Nothing ties the *organization whose secret validated the signature* to the *GitHub object (team, repository) the corresponding handler actually mutates*. In a multi-tenant Shipit install (the shipped example `config/secrets.development.shopify.yml` explicitly supports several orgs each with its own `webhook_secret`), an attacker who legitimately controls the GitHub App/webhook secret of **any one** configured organization can forge a `membership` event that authenticates with their own org's secret while acting on a `Team` record belonging to a **different** configured organization.

### Finding Description
`verify_signature` in `app/controllers/shipit/webhooks_controller.rb:24-30` does:
```ruby
github_app = Shipit.github(organization: repository_owner)
verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
```
where `repository_owner` (`app/controllers/shipit/webhooks_controller.rb:59-62`) is:
```ruby
params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
``` [1](#0-0) 

This value comes straight from the JSON body the attacker controls. Since the entire raw body is signed, an attacker who knows the `webhook_secret` for organization "A" can freely construct any payload and correctly sign it with A's secret — the check only proves "this body was signed by A's key," never that the content of the body actually pertains to A.

`MembershipHandler` then trusts the `team.id`/`organization.login` fields in that same attacker-authored payload to find or create a `Team` and mutate its membership, independent of which organization's secret validated the request:
```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
...
team.add_member(member)  # or team.members.delete(member)
``` [2](#0-1) 

`Team.find_or_create_by!(github_id: ...)` looks the team up **only by GitHub's numeric team id**, which is globally unique but is not scoped to (and not cross-checked against) the organization that just authenticated the request via `verify_signature`. If a `Team` record already exists in Shipit's database for org "B" (created earlier by a legitimate `membership` webhook from B, or by `Team.find_or_create_by_handle`/`teams:fetch`), an attacker who only controls org A's webhook secret can send:
```json
{"action":"added","organization":{"login":"A"},"team":{"id":<B's team github_id>, ...},"member":{"login":"attacker-account"}}
```
signed with **A's** `webhook_secret`. `verify_signature` picks org A's key (because `repository_owner`/`organization.login` in the payload says "A") and the signature checks out — but `find_or_create_team!` resolves and mutates B's actual `Team` object by id, adding the attacker's GitHub login as a member.

This is exactly the deployment-trust binding the report's staleness-check analog generalizes to: the field the code trusts to select/validate a credential (`repository.owner.login`/`organization.login` → which org's secret authorizes the request) is not the same field, nor cryptographically bound, to the object the handler actually writes (`team.id` → an arbitrary pre-existing `Team` belonging to any configured org).

### Impact Explanation
If the target `Team` (`id = B`) is one of the teams configured in `Shipit.github_teams` (`lib/shipit.rb:256-258`), adding the attacker's user to it flips `User#authorized?` (`app/models/shipit/user.rb:80-82`) to true for that account, granting them full authenticated access to the Shipit UI/API for stacks that trust team B — i.e., escalation into `Shipit.github_teams` authorization from an identity that was never a member of the trusted GitHub organization. This satisfies the High-severity bucket ("escalation into `Shipit.github_teams` authorization") without requiring a Shipit session, an `ApiClient` token, or B's own `webhook_secret`/GitHub App key — only administrative control of any other org that happens to be configured in the same multi-tenant Shipit instance.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment configuring more than one GitHub organization (explicitly supported and documented — see `config/secrets.development.shopify.yml` and `lib/shipit.rb:170-200` `github_app_config`/`github_organizations`), (2) the attacker administers the GitHub App/webhook for at least one of those configured orgs (so they know that org's `webhook_secret`), and (3) the target `Team`'s numeric GitHub `id` is known or guessable/discoverable (team ids are visible via various GitHub API/UI surfaces to non-members in many configurations). This is a plausible but non-trivial precondition; likelihood is moderate rather than certain, and is highest for shared/managed Shipit instances serving many customer orgs.

### Recommendation
Do not let attacker-controlled payload fields select which secret validates the request when that same field also is trusted to drive privileged mutations. Concretely:
- After signature verification, cross-check that `params.dig('organization','login')` (or `repository.owner.login`) used to select the webhook secret matches the organization actually recorded/expected for the `Team`/`Repository` being mutated (e.g., reject if an existing `Team.organization` differs from the authenticating org's login).
- Scope `Team.find_or_create_by!` lookups by `(github_id, organization)` rather than `github_id` alone, and refuse to mutate a team whose stored `organization` doesn't match the authenticating organization.
- More generally, treat `repository_owner`/`organization.login` used for key-selection as merely a hint for *routing*, not as proof of authorization for the object being modified — always re-validate object ownership against the verified org after signature checks pass.

### Proof of Concept
1. Configure Shipit with two orgs, `orgA` and `orgB`, each with its own `webhook_secret` (per `docs/setup.md` multi-org support).
2. Legitimately install/administer a GitHub App for `orgA` (attacker knows `orgA`'s `webhook_secret`).
3. Determine the numeric GitHub `team.id` of an `orgB` team that is already present in Shipit's DB and listed in `Shipit.github_teams`.
4. Craft a `membership` webhook body:
```json
{"action":"added","organization":{"login":"orgA"},"team":{"id":<orgB_team_github_id>,"name":"x","slug":"x","url":"https://x"},"member":{"login":"attacker"}}
```
5. Sign it with `orgA`'s `webhook_secret` using HMAC-SHA1 and send it to `/webhooks` with header `X-Github-Event: membership` and the resulting `X-Hub-Signature`.
6. `verify_signature` resolves `repository_owner` to `"orgA"`, validates successfully against `orgA`'s secret (`app/controllers/shipit/webhooks_controller.rb:24-30`); `MembershipHandler#find_or_create_team!` looks up the existing `orgB` team purely by `github_id` and calls `team.add_member(attacker_user)` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-43`), granting the attacker's GitHub identity membership in an `orgB`-trusted Shipit `Team`. [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
