### Title
Signature verification keys off `repository.owner.login`/`organization.login`, but handlers act on the untied `repository.full_name`/`organization.login` value from the same unverified payload, letting a webhook signed for one configured GitHub org forge events for another org's stack — ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and thus which `webhook_secret`) to validate the HMAC against using `repository_owner`, a value read straight out of the *same unverified* JSON payload it is about to validate. [1](#0-0) [2](#0-1) 

The rest of the request — the fields the handlers actually act on (`repository.full_name` for push/pull_request/status handlers, `organization.login`/`team`/`member` for the membership handler) — is not required to be consistent with `repository_owner`. [3](#0-2) [4](#0-3) [5](#0-4) 

Shipit explicitly supports multi-organization configuration, each org with its own independent `webhook_secret`, looked up via `Shipit.github_app_config(organization)`. [6](#0-5) 
Critically, when an org's `webhook_secret` is unset (documented as *optional*), `verify_webhook_signature` returns `true` unconditionally regardless of the payload content. [7](#0-6) 

### Finding Description
The engine binds "which secret authenticates this webhook" to `repository_owner` (derived from `params.dig('repository','owner','login')` or the `organization.login` fallback) at `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`. This value is attacker-controlled input inside the very payload whose signature is being checked — it has no independent verification.

Once `verify_webhook_signature` passes (either because the attacker correctly signed with org A's secret, or trivially because org A has no `webhook_secret` configured at all), the full raw payload — including fields the signature-selection step never inspected, such as `repository.full_name` — is handed unmodified to `Shipit::Webhooks.for_event(event)` handlers: [8](#0-7) 

Handlers resolve the actual `Stack`/`Repository`/`Team` to mutate purely from `repository.full_name` (push, pull_request, status, check_suite handlers) or from `organization.login` + `team` + `member` (membership handler) — none of which is required to equal `repository_owner`: [3](#0-2) [9](#0-8) 

This breaks the intended equality: `organization whose secret authenticated the request == repository/organization actually written by the handler`. An attacker who knows (or who exploits a blank/optional) `webhook_secret` for *any one* configured organization "A" can set `repository.owner.login` (or `organization.login`) to "A" to pass `verify_signature`, while setting `repository.full_name` to `"B/some-protected-repo"` (any other configured org's tracked repository) or `organization.login`+`team`/`member` fields to organization "B" for the membership event, so that the handler writes to org B's `Stack`/`Team` state as if GitHub itself had sent the event.

### Impact Explanation
- **Push events**: forging a `push` webhook for org B's stack triggers `GithubSyncJob` / `stack.sync_github(expected_head_sha: ...)`, causing Shipit to sync/act on a forged head SHA for a repository the attacker does not control — an unauthorized deploy-trigger path. [10](#0-9) 
- **Membership events**: forging a `membership` webhook lets the attacker call `team.add_member(member)` for any org's `Team`, escalating an arbitrary `User` (potentially themselves) into a `Shipit.github_teams`-authorized team, which is the exact authorization boundary the engine's `force_github_authentication` relies on. [11](#0-10) [12](#0-11) 
- **Status/check_suite events**: forging CI status for org B's commits can be used to bypass deploy safety checks that gate merges/deploys.

This satisfies the High-impact criteria in the rules: "escalation into `Shipit.github_teams` authorization" and contributes toward "an unauthorized deploy" via forged push/status events.

### Likelihood Explanation
Requires the operator to run Shipit with multiple GitHub organizations configured under `secrets.github` (a documented, supported configuration) and at least one of those organizations to have a guessable, leaked, or (per the docs, "optional") unset `webhook_secret`. Given webhook secret is explicitly documented as optional and multi-org setups are a first-class supported schema, this is a realistic operational configuration, not a purely theoretical one — but it does depend on that specific deployment choice, which the reviewer should weigh.

### Recommendation
Do not let signature-key selection and payload-processing operate on disjoint, independently-unverified fields of the same payload. Concretely:
1. In `WebhooksController#verify_signature`, after establishing which organization's secret validated the signature, re-check that every repository/organization referenced later in the payload (`repository.full_name`'s owner, `organization.login`, membership `team`/`organization`) belongs to that same verified organization before dispatching to handlers.
2. Require `webhook_secret` to be present for every configured organization (fail closed instead of `return true unless webhook_secret`) in `lib/shipit/github_app.rb#verify_webhook_signature`.
3. Alternatively, look up the organization from a value that cannot diverge from what handlers use (e.g., always derive the authenticating org from `repository.full_name`'s owner rather than `repository.owner.login`, so both fields are the same field).

### Proof of Concept
1. Deploy configuration with two organizations, `orgA` and `orgB`, each with distinct `webhook_secret`s in `secrets.github` (multi-org schema per `lib/shipit.rb#github_app_config`), or `orgA` configured with no `webhook_secret` at all.
2. Attacker crafts a `membership` webhook payload:
```json
{
  "action": "added",
  "team": { "id": 48, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://example.com" },
  "organization": { "login": "orgB" },
  "member": { "login": "attacker-controlled-user" },
  "repository": { "owner": { "login": "orgA" } }
}
```
3. `WebhooksController#repository_owner` resolves to `"orgA"` (from `repository.owner.login`), so `verify_signature` validates against `orgA`'s webhook config — trivially true if `orgA.webhook_secret` is blank, or computable if the attacker knows/leaked `orgA`'s secret.
4. `Shipit::Webhooks::Handlers::MembershipHandler` then processes `params.organization.login == "orgB"` and adds `attacker-controlled-user` to `orgB`'s team, per `find_or_create_team!` / `team.add_member(member)`. [13](#0-12) 
5. If `orgB`'s teams are part of `Shipit.github_teams`, the attacker's user now satisfies `current_user.authorized?` in `force_github_authentication`, granting them access to org B's stacks despite the webhook only ever having been authenticated for org A. [14](#0-13)

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L1-44)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```
