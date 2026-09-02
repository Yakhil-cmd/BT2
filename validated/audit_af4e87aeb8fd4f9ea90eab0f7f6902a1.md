Based on the webhook signature-verification flow, there is a genuine analog of the cross-chain-replay bug class: the field used to pick the *authenticating* secret and the field used to determine the *organization whose state gets written* are not the same binding, and an attacker can make them diverge in a single crafted payload.

### Title
Webhook signature verification selects the authenticating GitHub organization from a spoofable payload field that is decoupled from the organization the `membership` handler actually writes to - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` picks which `GitHubApp` (and therefore which `webhook_secret`) to use for HMAC verification based on `repository.owner.login`, falling back to `organization.login` only when no `repository` key is present. `MembershipHandler`, however, always trusts the separate `organization.login` field to decide which `Team` gets created/updated and which GitHub user gets added as a member — it never checks that this value matches the organization whose secret validated the request.

### Finding Description
`verify_signature` computes the "authenticating organization" like this: [1](#0-0) [2](#0-1) 

`repository_owner` prefers `repository.owner.login` and only falls back to `organization.login` when `repository` is absent. GitHub's real `membership` event has no `repository` field, so in a legitimate delivery `repository_owner` and `organization.login` are always identical.

`MembershipHandler`, though, only ever reads `params.organization.login`, completely independent of whatever field `verify_signature` used: [3](#0-2) 

In a multi-organization deployment (explicitly supported, see `docs/setup.md` "Using Multiple Github Applications"), `Shipit.github(organization:)` looks up a distinct `webhook_secret` per configured org: [4](#0-3) 

An attacker who controls (or is an admin of) any one of the multiple GitHub organizations onboarded into the same Shipit instance knows that organization's `webhook_secret`. By adding a spurious top-level `"repository": {"owner": {"login": "<attacker-org>"}}` object to an otherwise normal `membership` payload while keeping `"organization": {"login": "<victim-org>"}`, they force `verify_signature` to validate the signature against **their own** org's secret (which they legitimately hold), while `MembershipHandler#process` writes a `Team`/`Membership` under the **victim** organization.

Because `find_or_create_team!` keys purely on the attacker-supplied `params.team.id` and, on creation, stores `team.organization = params.organization.login` with no cross-check against the verified organization, the attacker can fabricate a `Team` record whose `organization`/`slug` match a required `Shipit.github_teams` handle (e.g. `victim-org/developers`) and add an arbitrary member login (their own GitHub login) to it: [5](#0-4) 

`Shipit.github_teams` resolves required teams by `organization`+`slug` lookup, so it will pick up this attacker-forged record instead of (or ahead of) the genuine team: [6](#0-5) 

Once that record exists with the attacker's login as a member, `User#authorized?` becomes true for the attacker's real GitHub identity after a normal OAuth login: [7](#0-6) [8](#0-7) 

### Impact Explanation
This is an escalation into `Shipit.github_teams` authorization: an unprivileged holder of a webhook secret for one onboarded organization can forge team membership for a different, privileged organization and grant themselves (or anyone) authenticated, authorized access to the whole Shipit instance — bypassing the team-membership gate that is meant to restrict access. This matches the explicitly in-scope High-impact category "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Requires a multi-organization Shipit deployment (a documented, supported configuration) and requires the attacker to know the `webhook_secret` of at least one configured organization — a realistic scenario for any Shipit instance shared across multiple tenants/orgs where each org's own admins are told/aware of "their" webhook secret, or where one org is lower-trust than others. No `ApiClient` token, session, or GitHub App private key is needed; the `/webhooks` endpoint is unauthenticated aside from the per-org HMAC.

### Recommendation
Bind the two organization references together: `MembershipHandler` (and any other handler that trusts an org/repo identifier from the payload) should verify that `params.organization.login` (or `params.repository.owner.login`) equals the `repository_owner`/organization value that `verify_signature` actually used to select the secret, and reject the event otherwise. More generally, pass the verified organization explicitly from the controller into the handler rather than letting handlers re-derive it from unauthenticated payload fields.

### Proof of Concept
1. Shipit is configured with two GitHub Apps: `victim-org` (target, whose `oauth.teams` includes `victim-org/developers`) and `attacker-org` (attacker is an admin, knows its `webhook_secret`).
2. Attacker crafts a JSON body:
```json
{
  "action": "added",
  "team": { "id": 999999, "name": "Developers", "slug": "developers", "url": "https://example.com" },
  "organization": { "login": "victim-org" },
  "member": { "login": "attacker-login" },
  "repository": { "owner": { "login": "attacker-org" } }
}
```
3. Attacker computes `X-Hub-Signature` using `attacker-org`'s known `webhook_secret` over this exact raw body, sets `X-Github-Event: membership`, and POSTs to `/webhooks`.
4. `verify_signature` resolves `repository_owner` to `attacker-org` (because `repository` is present) and successfully verifies using the attacker's own secret.
5. `MembershipHandler#process` creates a `Team` with `organization: "victim-org", slug: "developers"` and adds `attacker-login` as a member.
6. Attacker logs into Shipit via normal GitHub OAuth as `attacker-login`; `Shipit.github_teams` resolves `victim-org/developers` to the forged `Team`, and `current_user.authorized?` returns true, granting full access to `victim-org`'s stacks.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L15-43)
```ruby
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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```

**File:** app/models/shipit/team.rb (L17-21)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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
