### Title
Membership webhook trusts attacker-controlled `team.id` to bind users into any existing `Team`, allowing cross-organization escalation into `Shipit.github_teams` authorization - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization config (and therefore which `webhook_secret`) to verify a webhook against using `repository.owner.login` (or `organization.login`) taken from the attacker-controlled JSON body. `MembershipHandler`, however, resolves the `Team` record to mutate using only the numeric `team.id` field from that same body, and never re-validates it against the organization that was actually authenticated. In a multi-organization Shipit deployment, an org that is legitimately onboarded (and therefore able to produce a validly-signed webhook using its own registered secret) can spoof a `membership` event whose `team.id` points at a **different, more privileged** organization's already-existing `Team` row, and add an arbitrary GitHub login as a member of that team - escalating into `Shipit.github_teams` authorization.

### Finding Description
`WebhooksController#verify_signature` picks a `GitHubApp` config using the org derived purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github` looks the config up by that organization name in the multi-app schema documented for supporting several GitHub organizations on one Shipit instance: [3](#0-2) [4](#0-3) 

Each organization in that schema has its **own independently-configured** `webhook_secret`, and signature verification is scoped to that org's secret only: [5](#0-4) 

So in a multi-org Shipit deployment, org "B" (a legitimately onboarded, lower-privileged tenant) knows and controls its own `webhook_secret`/GitHub App, and can therefore produce a correctly-signed webhook body containing *arbitrary* JSON content it chooses (not necessarily content GitHub itself generated), as long as `repository.owner.login`/`organization.login` in that body is "orgB".

`MembershipHandler`, however, resolves which `Team` row to mutate using only the numeric GitHub `team.id`, and the organization field is set **only when the record is first created** - once a `Team` exists it is never re-validated against the organization that authenticated the request: [6](#0-5) 

This breaks the binding: `organization that authenticated the webhook (repository.owner.login / organization.login used to pick the GitHubApp/secret) == organization that owns the Team acted upon (team.id)`. An attacker who controls org B's signing key can submit `team.id` equal to a pre-existing, privileged org A `Team`'s GitHub id (team ids are not treated as secrets by GitHub) together with `member.login` set to any GitHub login (including their own), and `action: "added"`. `Team.find_or_create_by!(github_id: ...)` matches the existing org A team by id alone and `team.add_member(member)` adds the attacker-chosen user to it.

### Impact Explanation
`Shipit.github_teams` (the set of teams whose membership grants access to the whole Shipit application via `force_github_authentication`/`current_user.authorized?`) is derived from `Team` records populated by this same webhook path: [7](#0-6) 

If any of the configured `Shipit.github_teams` correspond to a `Team` row reachable via a colliding/spoofed `team.id`, an attacker who only controls a lesser-privileged onboarded organization can grant an arbitrary GitHub login membership in that authorization-relevant team, bypassing the intended team/organization boundary and gaining full Shipit access (view stacks, task streams, and trigger deploys) - matching the "High: escalation into `Shipit.github_teams` authorization" impact category.

### Likelihood Explanation
Exploitation requires: (1) a multi-organization Shipit deployment (explicitly documented and supported), (2) the attacker being a legitimate but low-privileged tenant able to sign webhooks for their own org, and (3) knowledge of the target `Team`'s GitHub numeric id (not treated as a secret by GitHub and typically discoverable). No `ApiClient` token, GitHub App private key, or Shipit session is required, satisfying the unprivileged-attacker constraint. This is realistic for shared/multi-tenant Shipit installs but does not apply to single-organization deployments, so likelihood is moderate.

### Recommendation
In `MembershipHandler#find_or_create_team!`, always validate (and if mismatched, reject or re-key) the `organization` value against the org that authenticated the webhook (the value used in `WebhooksController#repository_owner`) rather than trusting `team.id` alone; consider scoping the `Team` lookup to `(github_id, organization)` and rejecting the event when the organizations disagree.

### Proof of Concept
1. Deploy Shipit with the multi-org schema (`docs/setup.md`, "Using Multiple Github Applications") including org `orgA` (privileged, member of `Shipit.github_teams`) and org `orgB` (attacker-controlled tenant with its own registered `webhook_secret`).
2. As the attacker (admin of `orgB`'s own registered GitHub App), compute a valid `X-Hub-Signature` over a JSON body using `orgB`'s `webhook_secret`:
```json
{
  "action": "added",
  "team": { "id": <orgA_team_github_id>, "name": "x", "slug": "x", "url": "https://example.com" },
  "organization": { "login": "orgB" },
  "member": { "login": "attacker" },
  "repository": { "owner": { "login": "orgB" } }
}
```
3. POST to `/webhooks` with `X-Github-Event: membership` and the computed signature.
4. `verify_signature` validates successfully against `orgB`'s secret; `MembershipHandler` finds the existing `orgA` team by `github_id` (ignoring the `orgB` mismatch) and adds `attacker` as a member of it.
5. If that team's handle is listed in `Shipit.github_teams`, log in as `attacker` via OAuth - `current_user.authorized?` now returns true, granting full application access.

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

**File:** docs/setup.md (L182-209)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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
