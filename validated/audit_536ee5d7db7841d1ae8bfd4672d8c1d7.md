## Finding

### Title
Cross-organization `Team` hijack via forged `membership` webhook escalates into `Shipit.github_teams` authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
Shipit explicitly supports trusting **multiple independent GitHub organizations** in a single deployment (`docs/setup.md` "Using Multiple GitHub Applications", `Shipit.github_app_config`), each with its own webhook secret used to verify inbound webhooks. The `membership` webhook handler, however, resolves the target `Team` record purely by GitHub's numeric `team.id` and never re-validates that the authenticated organization (the one whose `webhook_secret` matched) actually owns that team. An attacker who controls just one of the trusted-but-lower-privilege organizations can forge a validly-signed `membership` webhook that references a `Team` belonging to a *different* organization — including a team listed in `Shipit.github_teams`, which gates login authorization for the entire Shipit instance — and add an arbitrary GitHub login as a member of it.

### Finding Description
Signature verification happens in `WebhooksController#verify_signature`, which picks the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) strictly from the organization named in the payload: [1](#0-0) [2](#0-1) 

This only proves "this request was signed with organization X's secret" — it says nothing about which *resource* (team, repository) the payload subsequently claims to act on. The `MembershipHandler` then trusts `params.team.id` (GitHub's numeric team ID) to find or create the target `Team`, and only sets `team.organization` when the record is newly created: [3](#0-2) 

Because `find_or_create_by!(github_id: params.team.id)` skips the setter block whenever a `Team` with that `github_id` already exists, the handler never checks that `params.organization.login` (the organization whose secret authenticated the request) matches the pre-existing `team.organization`. This is exactly the "organization that authenticated versus [the resource] that is written" binding break: the signature proves the sender controls Org B, but the code writes membership onto a `Team` that may belong to Org A.

Multi-org configurations are first-class and documented: `Shipit.github_app_config` looks up per-organization secrets from `secrets.github`, and `Shipit.github(organization:)` returns the matching `GitHubApp` instance: [4](#0-3) 

The impact of adding a member to an arbitrary `Team` is significant because `Shipit.github_teams` (built from admin-configured `oauth.teams`) is the sole authorization gate for the whole application: [5](#0-4) [6](#0-5) [7](#0-6) 

`Team#add_member` performs no additional ownership or provenance checks: [8](#0-7) 

### Impact Explanation
By forging a `membership` "added" webhook, correctly signed with the attacker's own (lower-trust) organization's `webhook_secret`, but specifying `team.id` equal to the GitHub team ID of a `Team` already tracked by Shipit for a *different*, privileged organization (e.g. one whose `organization/slug` appears in `Shipit.github_teams`), the attacker can add any GitHub login of their choosing (including their own) as a member of that privileged `Team` inside Shipit's database — without ever actually being a member of that team on GitHub. Once that user next authenticates via GitHub OAuth, `User#authorized?` returns true and `force_github_authentication` grants full access to the Shipit instance. This is an authentication/authorization bypass into `Shipit.github_teams`, matching the "High" (arguably higher, since it grants full instance access) impact category defined for this engine.

### Likelihood Explanation
The prerequisite — controlling any one organization that the Shipit instance trusts under the documented multi-organization configuration — is realistic in real deployments (e.g., a company operating Shipit for several orgs/business units with differing trust levels, or a partner/vendor org onboarded for a subset of stacks). No Shipit session, `ApiClient` token, `api_clients_secret`, or GitHub App private key is needed; the attacker only needs the webhook secret of the org they legitimately administer and the numeric GitHub team ID of the target team (discoverable via GitHub's team API for orgs/teams the attacker can query, or leaked via other means).

### Recommendation
In `MembershipHandler#find_or_create_team!`, validate that `params.organization.login` matches the resolved `team.organization` (case-insensitively) even when the `Team` record already exists, and reject/no-op the event otherwise. More generally, every webhook handler that resolves an existing record by a GitHub-provided numeric ID should re-assert that the record's owning organization/repository matches the organization that authenticated the request via `verify_webhook_signature`, rather than only enforcing that binding at creation time.

### Proof of Concept
1. Shipit is configured with two trusted organizations, `OrgA` (privileged: `oauth.teams: ["OrgA/admins"]`) and `OrgB` (attacker-controlled), each with its own `webhook_secret`.
2. Shipit has previously synced `Team` `OrgA/admins` (via `Team.find_or_create_by_handle`), storing its real GitHub `github_id` (e.g. `1001`) and `organization: "OrgA"`.
3. Attacker crafts a `membership` payload:
```json
{
  "action": "added",
  "team": { "id": 1001, "name": "Admins", "slug": "admins", "url": "https://github.com/..." },
  "organization": { "login": "OrgB" },
  "member": { "login": "attacker-controlled-login" }
}
```
4. Attacker computes `X-Hub-Signature` using `OrgB`'s `webhook_secret` (which they legitimately know) over the raw JSON body and POSTs it to `/webhooks` with `X-Github-Event: membership`.
5. `verify_signature` resolves `Shipit.github(organization: "OrgB")` and the signature verifies successfully.
6. `MembershipHandler#find_or_create_team!` finds the existing `Team` (`github_id: 1001`, i.e. `OrgA/admins`) without checking `organization.login == "OrgB"`, and `team.add_member(User.find_or_create_by_login!("attacker-controlled-login"))` executes, granting that user Shipit-side membership in `OrgA/admins`.
7. When `attacker-controlled-login` logs in via GitHub OAuth, `authorized?` returns `true`, bypassing the intended `Shipit.github_teams` restriction.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
