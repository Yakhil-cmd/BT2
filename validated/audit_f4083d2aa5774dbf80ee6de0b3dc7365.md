### Title
Cross-organization webhook forges GitHub team membership, bypassing `Shipit.github_teams` authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
In a multi-organization Shipit configuration, the `membership` webhook handler trusts the `team.id` and `member.login` fields from the JSON body to grant Shipit team membership, without verifying that the *organization whose webhook secret authenticated the request* is the same organization that owns the target team. Because `Shipit.github_teams` (the source of truth for instance-wide authorization) is derived from only a single, arbitrarily-chosen "default" organization's OAuth team config, an operator/attacker who controls the webhook secret of any configured low-trust organization can forge a `membership` event that adds an arbitrary GitHub login to a `Team` record tied to a different, higher-trust organization — escalating that account into `Shipit.github_teams` authorization.

### Finding Description
`WebhooksController#verify_signature` selects which GitHub App/webhook secret to validate a signature against based on data taken directly from the untrusted request body: [1](#0-0) [2](#0-1) 

For a `membership` event, GitHub's real payload has no `repository` key, so `repository_owner` resolves to `params.dig('organization', 'login')` — a value fully controlled by whoever is crafting the payload. This means the signature is checked against the webhook secret belonging to *whatever organization the attacker names in the payload*, not necessarily the organization that is actually being mutated.

`Shipit.github` supports exactly this multi-organization scheme, keeping a separate `GitHubApp` (and separate `webhook_secret`) per configured organization key: [3](#0-2) 

The `MembershipHandler` then processes the event by looking up (or creating) a `Team` **only by its GitHub-global `github_id`**, and never re-validates that the payload's `organization.login` matches the `organization` already recorded on that `Team`: [4](#0-3) 

It then adds or removes an arbitrary GitHub login (`params.member.login`, also attacker-supplied) as a member of that team: [5](#0-4) [6](#0-5) 

Crucially, instance-wide authorization is computed from a *single* organization's OAuth team list, regardless of how many organizations are configured: [7](#0-6) [8](#0-7) 

And a user is treated as authorized to use the whole Shipit instance if they belong to any team in that list: [9](#0-8) [10](#0-9) 

**Binding that should hold but doesn't:** `organization that authenticated the webhook (secret used in verify_signature)` == `organization that owns the Team object being mutated by MembershipHandler`. The handler enforces neither (a) that the authenticating organization matches `team.organization`, nor (b) that the numeric `team.id` actually belongs to that organization on GitHub (no API call is made to confirm team ownership — only the *user's* existence is checked via `Shipit.github.api.user(login)` in `User.find_or_create_by_login!`, and that call itself uses the *default* org's API client, not the authenticating org's).

### Impact Explanation
This breaks the deployment-trust binding between the GitHub organization that cryptographically authenticated a webhook and the GitHub team/organization that Shipit's authorization model (`Shipit.github_teams`) actually protects. In any multi-org Shipit deployment (a documented, supported configuration — see `config/secrets.development.example.yml` and `docs/setup.md`), an attacker who is able to obtain/administer the webhook secret for *any* one configured organization (e.g. a low-trust org onboarded to the same Shipit instance) can forge a `membership` "added" event that inserts their own GitHub login into a `Team` record belonging to the high-trust organization whose team IDs feed `Shipit.github_teams`. This satisfies `User#authorized?` and grants that GitHub identity full access to the Shipit instance — i.e., escalation into `Shipit.github_teams` authorization, which per the scan rules is a High-impact finding, and in practice enables an unauthorized deploy/rollback once authenticated via OmniAuth as that GitHub login.

### Likelihood Explanation
Requires: (1) a multi-organization Shipit configuration (explicitly documented/supported), (2) knowledge of the webhook secret for at least one configured organization other than the one enforcing `Shipit.github_teams`, and (3) knowledge/guessability of the numeric GitHub `team.id` of the target authorization team (team IDs are visible to GitHub org members/admins and are not treated as secret by GitHub). No Shipit session, API token, or GitHub App private key is needed — only a webhook secret for a lesser-trusted configured org, which is plausible in a "federated" Shipit setup where multiple business units/orgs each manage their own GitHub App entry in `secrets.yml`.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (`params.organization.login`), and reject/ignore the event if an existing `Team` with that `github_id` has a different `organization`. Additionally, verify (via the GitHub API using the organization's own authenticated client) that the reported `team.id` actually belongs to `params.organization.login`, and ensure `Shipit.github_teams` cannot be satisfied by team objects whose `organization` doesn't match the organization that is expected to gate authorization. Consider also making `WebhooksController#repository_owner`/`verify_signature` explicitly reject events whose declared organization doesn't correspond to the entity being written to, rather than only performing organization-based secret selection.

### Proof of Concept
1. Deploy Shipit with a multi-org config, e.g. `secrets.yml`:
```yaml
github:
  high-trust-org:
    webhook_secret: SECRET_HIGH
    oauth: { teams: ["high-trust-org/admins"] }
  low-trust-org:
    webhook_secret: SECRET_LOW   # known/administered by attacker
```
2. `Shipit.github_teams` resolves from whichever org key is first in the hash (`github_default_organization`), e.g. `high-trust-org/admins`, with a known/guessable GitHub `team.id` (e.g. `999`).
3. Attacker, knowing `SECRET_LOW`, crafts a `membership` webhook body:
```json
{
  "action": "added",
  "organization": { "login": "low-trust-org" },
  "team": { "id": 999, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/999" },
  "member": { "login": "attacker-github-login" }
}
```
4. Attacker computes `X-Hub-Signature: sha1=HMAC-SHA1(SECRET_LOW, body)` and POSTs to the webhooks endpoint with `X-Github-Event: membership`.
5. `verify_signature` resolves `repository_owner` = `"low-trust-org"`, fetches `Shipit.github(organization: "low-trust-org")`, and successfully verifies the signature using `SECRET_LOW`.
6. `MembershipHandler#process` finds the existing `Team` with `github_id: 999` (which is `high-trust-org/admins`, feeding `Shipit.github_teams`) and adds `attacker-github-login` as a member — with no check that `"low-trust-org" == team.organization`.
7. Attacker logs into Shipit via GitHub OAuth as `attacker-github-login`; `User#authorized?` now returns true because they belong to a team in `Shipit.github_teams`, granting full access to deploy/rollback stacks across the instance.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-43)
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
```

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
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
