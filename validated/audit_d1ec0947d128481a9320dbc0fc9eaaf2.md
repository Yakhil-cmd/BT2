### Title
`MembershipHandler#find_or_create_team!` looks up teams by `github_id` alone, letting a validly-signed webhook from Organization A inject `Membership` rows into a `Team` that belongs to Organization B - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#process` resolves the target `Team` solely via `Team.find_or_create_by!(github_id: params.team.id)`, with no check that the request's `organization.login` (already verified by `verify_signature`) actually owns that `Team`. Because `Shipit.github(organization:)` and `verify_webhook_signature` are keyed per-organization [1](#0-0) [2](#0-1) , a webhook that is cryptographically genuine for Organization A can still carry a `team.id` that collides with a `Team` record already owned by Organization B, and the handler will happily attach a new member to Organization B's team.

### Finding Description
**Broken binding:** `Membership.exists?(team_id: T, user_id: U)` is supposed to equal "GitHub organization `T.organization` actually reports user `U` as a member of team `T`". The code instead enforces only: `Team.find_by(github_id: params.team.id)` exists AND the webhook signature validated for `params.organization.login` (or `params.repository.owner.login`) — with **no equality check that `team.organization == params.organization.login`**.

Code path:
1. `WebhooksController#verify_signature` computes `repository_owner` from the payload's `organization.login` (membership events have no `repository` key) and verifies the HMAC using `Shipit.github(organization: repository_owner)`'s **own** `webhook_secret` [3](#0-2) [4](#0-3) . This only proves the request is a genuine GitHub webhook *for the attacker's own organization* — it says nothing about which team the payload references.
2. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id) { |team| team.organization = params.organization.login }` [5](#0-4) . The `organization` assignment only runs in the creation block — if a `Team` row with that `github_id` **already exists** (created earlier by a legitimate event from the real owning org), `find_or_create_by!` returns the existing record untouched, still bound to the real organization, but the caller has no way to know the current request wasn't actually for that org.
3. `User.find_or_create_by_login!(params.member.login)` creates/finds a `User` keyed purely on `login`, fetching real GitHub profile data for that login [6](#0-5) .
4. `team.add_member(member)` inserts a `Membership` row unconditionally on `action == 'added'` [7](#0-6) , [8](#0-7) .

Attacker request: attacker owns/administers GitHub organization `attacker-org`, which the Shipit operator has legitimately onboarded into the multi-tenant `secrets.github` config (so `Shipit.github(organization: 'attacker-org')` resolves and the attacker knows/controls that org's `webhook_secret`, since they configured GitHub's webhook delivery for their own org). The attacker sends (or triggers via a real GitHub membership event on their own org, editing the JSON is not even required if they can control team ids server-side, but at minimum they can craft the raw POST since they hold the correct secret for their own org) a `membership`/`added` event with `team.id` equal to the `github_id` of a `Team` already present in `Shipit.github_teams` (an authorization-gating team belonging to a *different*, legitimate organization) and `member.login = 'attacker_handle'`. `verify_signature` passes (it's a real, correctly-signed webhook for `attacker-org`). `find_or_create_team!` returns the existing target `Team` row (belonging to the other org) because lookup is by `github_id` only. A `Membership` is created linking `attacker_handle` to that team.

**Why existing guards don't catch this:** `verify_signature` only authenticates *which organization* sent the request, not *which team the payload claims to be about* [9](#0-8) ; `ExplicitParameters` schema on `MembershipHandler` only validates types/presence, not organization ownership [10](#0-9) ; `find_or_create_team!` has no `where(organization: params.organization.login)` clause [5](#0-4) .

Once the `Membership` exists, `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) returns `true` for `attacker_handle` [11](#0-10) , and `Authentication#force_github_authentication` grants full application access on OAuth login as that handle [12](#0-11) .

### Impact Explanation
This is an authentication/authorization-bypass escalation into `Shipit.github_teams`: an attacker who controls one legitimately onboarded organization can grant themselves (or anyone whose GitHub login they choose) membership in a *different* organization's access-controlling team, without that organization ever reporting the membership to GitHub. Once such membership exists and the attacker completes OAuth as that login, `User#authorized?` returns true, granting full access to the entire Shipit instance (stacks, deploys, rollbacks, API client creation) — Critical severity per the escalation criteria. It is repeatable for every `github_id` the attacker can enumerate/guess that maps to an existing `Team` row, and affects every tenant/organization sharing the Shipit deployment, not just the attacker's own.

### Likelihood Explanation
Requires: (1) the Shipit deployment to be multi-tenant, onboarding more than one GitHub organization in `secrets.github` (supported by `Shipit.github(organization:)` / `github_app_config` [13](#0-12) ); (2) attacker legitimately controls one onboarded org and can trigger/craft a signed `membership` webhook for it; (3) attacker knows or discovers the numeric `github_id` of a `Team` belonging to another onboarded org that appears in that org's `Shipit.github_teams`. No Shipit secrets, sessions, or privileged roles are needed beyond ownership of the attacker's own org — this matches the stated unprivileged-attacker model. Cost is low: send one webhook per attempt; team IDs are not secrets and are discoverable through GitHub's team APIs for teams the attacker can see, or brute-forceable given they are small sequential integers.

### Recommendation
Scope `find_or_create_team!` to the verified organization, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and reject/no-op (or log+422) when a `Team` with that `github_id` exists but its `organization` doesn't match `params.organization.login`, so a webhook can never mutate another organization's team membership.

### Proof of Concept
In `test/controllers/webhooks_controller_test.rb` style (minitest, no live GitHub):
```ruby
test "membership webhook from org A cannot add members to org B's team" do
  org_b_team = shipit_teams(:shopify_developers) # organization: 'shopify', github_id known
  Shipit.stubs(:github_teams).returns([org_b_team])

  # Attacker's own org "attacker-org" is a distinct, legitimately-verified tenant.
  GithubHook.any_instance.stubs(:verify_signature).returns(true) # simulates valid signature for attacker-org

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    team: { id: org_b_team.github_id, name: org_b_team.name, slug: org_b_team.slug, url: org_b_team.api_url },
    organization: { login: 'attacker-org' },
    member: { login: 'attacker_handle' }
  }.to_json

  assert_no_difference -> { Team.count } do
    post :create, body: payload, as: :json
  end

  attacker = Shipit::User.find_by(login: 'attacker_handle')
  # Binding check: membership must equal a real GitHub-reported membership for shopify/developers.
  assert_not org_b_team.reload.members.include?(attacker), "org A's webhook must not add a member to org B's team"
  assert_not attacker.authorized?, "attacker must not gain Shipit.github_teams authorization via a cross-org webhook"
end
```
Currently, `org_b_team.members.include?(attacker)` is `true` and `attacker.authorized?` is `true`, demonstrating the cross-tenant membership injection and the resulting authorization bypass.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L7-21)
```ruby
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
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L26-28)
```ruby
          case params.action
          when 'added'
            team.add_member(member)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L38-43)
```ruby
        def find_or_create_team!
          Team.find_or_create_by!(github_id: params.team.id) do |team|
            team.github_team = params.team
            team.organization = params.organization.login
          end
        end
```

**File:** app/models/shipit/user.rb (L22-28)
```ruby
    def self.find_or_create_by_login!(login)
      find_or_create_by!(login:) do |user|
        # Users are global, any app can be used
        # This will not work for users that only exist in an Enterprise install
        user.github_user = Shipit.github.api.user(login)
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
