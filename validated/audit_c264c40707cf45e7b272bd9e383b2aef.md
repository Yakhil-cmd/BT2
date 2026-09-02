### Title
Cross-organization webhook signature scoping allows forging `membership` events that grant authorization-team access - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which GitHub App's `webhook_secret` to validate a request against using a value taken from the very payload it is about to trust, and that value is never re-checked against the organization actually referenced by the event being processed. For `membership` events this lets anyone who legitimately knows the `webhook_secret` of *any* one organization configured in a multi-tenant Shipit instance forge a signed payload that manipulates a `Team` record belonging to a completely different, more privileged organization — including the team(s) that gate application-wide authorization via `Shipit.github_teams`.

### Finding Description
`verify_signature` computes the signing organization purely from attacker-controlled JSON: [1](#0-0) [2](#0-1) 

`repository_owner` falls back to `params.dig('organization', 'login')` when no `repository` key exists — which is exactly the case for `membership` events. The HMAC is then verified against `Shipit.github(organization: repository_owner).webhook_secret`, i.e. whichever organization's secret the *attacker names in the payload*: [3](#0-2) [4](#0-3) 

Because the attacker both writes the raw body and picks which org's secret is used to verify it, anyone who legitimately possesses the `webhook_secret` for *one* onboarded, low-privilege organization (normal for whoever configured that org's GitHub webhook) can produce a request that passes `verify_signature`, regardless of which team/organization the event content actually targets.

That forged event is then handed to `MembershipHandler`, which trusts the payload's `team.id` alone to locate or create the `Team` row and blindly grants membership: [5](#0-4) 

`find_or_create_team!` keys strictly on `github_id`; it does not verify that `params.organization.login` matches the organization that was used to authenticate the request, nor the `Team#organization` already stored for that `github_id`. If a `Team` row already exists (as it would for any team previously synced from real GitHub `membership` events, e.g. the authorization-gating teams), the forged event reuses that exact row and calls `team.add_member(member)` with an attacker-supplied `User`.

Authorization is later granted based purely on membership in that same `Team` row: [6](#0-5) [7](#0-6) 

This breaks the trust binding: *the organization whose secret authenticated the webhook* ≠ *the team/organization the event content actually mutates*. Before the attacker's forged request: `repository_owner (signing org) == team.organization (target org)` is assumed by the code but never enforced. After: an attacker names their own org for `organization.login` (to pass signature verification with a secret they know) while setting `team.id` to the `github_id` of an unrelated, privileged team — the equality silently fails and the mutation proceeds anyway.

### Impact Explanation
Successful exploitation lets an attacker who only controls one low-privilege organization's webhook secret add an arbitrary GitHub login (their own) as a member of any `Team` record already known to Shipit — including whichever team(s) are configured in `Shipit.github_teams` to gate `current_user.authorized?`. Once that membership exists, the attacker's account passes `force_github_authentication` on next login and gains full authenticated access to the Shipit application (deploys, rollbacks, API client management, etc.). This is an authorization/authentication bypass, escalating into `Shipit.github_teams` authorization as explicitly listed as an in-scope High/Critical impact.

### Likelihood Explanation
Requires a multi-organization Shipit deployment (`secrets.github` keyed by multiple orgs, each with its own `webhook_secret`) where at least one lower-trust organization is onboarded alongside a higher-trust one whose team gates authorization. The attacker needs only the `webhook_secret` of the low-trust org — knowledge normal for anyone who configured that org's GitHub webhook — and the numeric `github_id` of the target team (learnable via GitHub's team API or from prior legitimate `membership` payloads/logs, which are not secret). No repository write access, `ApiClient` token, or privileged Shipit account is needed, satisfying the "unprivileged attacker" requirement.

### Recommendation
When verifying webhook signatures, the organization used to select the `webhook_secret` must be the same trust anchor used to authorize the mutation the event performs. Concretely: (1) do not derive `repository_owner`/verification organization solely from attacker-supplied JSON fields without pinning it to a known, pre-registered organization for the target resource; (2) in `MembershipHandler#find_or_create_team!`, verify that `params.organization.login` matches the organization used to authenticate the current request (and matches the stored `Team#organization` for pre-existing `github_id` rows) before mutating membership, rejecting the event otherwise.

### Proof of Concept
1. Shipit is configured with two organizations in `secrets.github`: `acme` (attacker is `acme`'s webhook admin, knows `secrets.github[:acme][:webhook_secret]`) and `shopify` (whose team `shopify/developers`, `github_id = 4242`, is listed in `Shipit.github_teams` and already exists as a `Team` row from prior real events).
2. Attacker builds a `membership` payload:
```json
{
  "action": "added",
  "team": {"id": 4242, "name": "Developers", "slug": "developers", "url": "https://api.github.com/teams/4242"},
  "organization": {"login": "acme"},
  "member": {"login": "attacker"}
}
```
3. Attacker computes `X-Hub-Signature: sha1=<hmac_sha1(secrets.github[:acme][:webhook_secret], body)>`.
4. POST to the Shipit webhooks endpoint with `X-Github-Event: membership`.
5. `verify_signature` resolves `repository_owner == "acme"`, verifies against `acme`'s secret, and passes.
6. `MembershipHandler` finds the existing `Team` with `github_id: 4242` (the real `shopify/developers` team) and adds user `attacker` as a member.
7. Attacker logs in via GitHub OAuth; `User#authorized?` now returns `true` because the attacker's `User` belongs to a `Team` whose `id` is in `Shipit.github_teams.map(&:id)`, granting full authenticated access to the Shipit instance.

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

**File:** lib/shipit.rb (L170-180)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-44)
```ruby
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
