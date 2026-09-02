### Title
Membership webhook trusts the organization that signed the request, not the organization that owns the team being modified, allowing cross-tenant escalation into `Shipit.github_teams` authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` authenticates an incoming GitHub webhook using the GitHub App/`webhook_secret` associated with the organization named in the payload (`repository_owner`) [1](#0-0) . For `membership` events, that organization comes from `params.dig('organization', 'login')` [2](#0-1) . However, `MembershipHandler` looks up (or creates) the `Team` being mutated purely by the numeric `params.team.id` from the same payload, and only sets `team.organization` on first creation - it never verifies that the found team actually belongs to the organization whose secret validated the request [3](#0-2) . This breaks the binding: "organization whose webhook_secret authenticated the request" == "organization that owns the team being written to."

### Finding Description
In a multi-tenant Shipit deployment (the officially documented "Using Multiple GitHub Applications" configuration, where each customer organization has its own GitHub App and its own `webhook_secret` in `secrets.yml`) [4](#0-3) , an attacker who administers their own onboarded organization (Org A) knows Org A's `webhook_secret`, because they set it when they created their GitHub App for use with Shipit.

`WebhooksController#verify_signature` selects which `GitHubApp` (and therefore which `webhook_secret`) to verify the HMAC signature against, based solely on the attacker-controlled `organization.login` field of the payload: [1](#0-0) [2](#0-1) 

The attacker sets `organization.login = "org-a"` so the signature check passes using their own known secret. They then set `team.id` to the GitHub team ID of an existing `Team` record belonging to a different, victim organization (Org B) - team IDs are GitHub's own global numeric IDs, and Shipit already persists such `Team` rows once any genuine `membership` event from Org B has occurred (this is the normal steady state for any onboarded org).

`MembershipHandler#find_or_create_team!` looks the team up **only** by `github_id`: [5](#0-4) 

Since the team already exists, `find_or_create_by!`'s block (which sets `team.organization`) never runs, and the pre-existing Org-B team is returned untouched. The handler then does: [6](#0-5) 

`User.find_or_create_by_login!(params.member.login)` creates/looks up a `User` by an attacker-chosen GitHub login (e.g. the attacker's own account), and `team.add_member(member)` unconditionally appends that user to Org B's `Team`: [7](#0-6) 

`User#authorized?` grants access to the whole Shipit instance for a user belonging to any `Team` listed in `Shipit.github_teams`: [8](#0-7) 

and this is exactly the gate enforced on every request by `force_github_authentication`: [9](#0-8) 

So the value used to authenticate the request (`organization.login`, checked against Org A's secret) is never checked against the value that determines which privileged resource is mutated (`team.id`, resolved independent of organization). This is structurally identical to the reported bug class: a field that gates the outcome (`reward_score`/`slash_score` in the analog; `team.id`/`organization.login` here) is not bound to the value that was actually verified, letting the attacker supply a "cheap" value for the verified side while controlling the value that drives the privileged effect.

### Impact Explanation
This is a cross-tenant authorization escalation: an attacker who only controls their own onboarded organization's webhook secret can add an arbitrary GitHub login (typically their own account) as a member of a `Team` belonging to a different tenant. If that team is configured in the victim's `Shipit.github_teams`, the attacker's account becomes `authorized?` for the victim's Shipit instance, granting them full access to trigger deploys, rollbacks, and merges on the victim's stacks - matching the "escalation into `Shipit.github_teams` authorization" High-impact criterion, and potentially enabling unauthorized deploys/merges (Critical) once logged in.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment using the documented multi-org GitHub App configuration, (2) the attacker being a legitimate administrator of at least one onboarded organization (so they know that org's own `webhook_secret` - not the victim's), and (3) knowledge/guessability of a target team's numeric GitHub `github_id` (globally unique, and often discoverable via GitHub's own team APIs/URLs for teams the attacker can view, or via the victim team's public GitHub team page). No access to the victim's secrets, GitHub App, or Shipit session is needed. This is a realistic scenario for any Shipit-as-a-service style deployment matching the documented multi-org setup.

### Recommendation
When processing `membership` events (and other org-scoped events), `MembershipHandler` must verify that the `Team` record's `organization` matches the `organization.login` that was actually used to authenticate the webhook (i.e., scope the `find_or_create_by!` lookup by both `github_id` and `organization`, and reject/ignore the event if an existing team's organization doesn't match the authenticated organization). More generally, `WebhooksController#verify_signature` should ensure the organization it authenticates against is the same organization whose resources every downstream handler is permitted to mutate, rather than letting each handler independently trust unrelated identifiers from the same payload.

### Proof of Concept
1. Attacker administers Org A, onboarded to a multi-tenant Shipit instance, and knows Org A's `webhook_secret` (they configured it themselves in the GitHub App they registered).
2. Victim Org B is also onboarded; Shipit already has a `Team` row with `github_id = 555, organization: "org-b"` from a prior genuine `membership` webhook, and `Shipit.github_teams` includes that team's handle.
3. Attacker computes `sha1=HMAC(org_a_webhook_secret, payload)` for:
```json
{
  "action": "added",
  "team": {"id": 555, "name": "Org B Deployers", "slug": "deployers", "url": "https://api.github.com/teams/555"},
  "organization": {"login": "org-a"},
  "member": {"login": "attacker-github-login"}
}
```
4. POST to `/webhooks` with `X-Github-Event: membership` and the computed `X-Hub-Signature`.
5. `verify_signature` resolves `repository_owner` = `"org-a"`, fetches Org A's `GitHubApp`, and the signature validates against Org A's known secret [1](#0-0) .
6. `MembershipHandler#find_or_create_team!` finds the existing `github_id: 555` team (Org B's team) [5](#0-4) , and `team.add_member(User.find_or_create_by_login!("attacker-github-login"))` adds the attacker to Org B's authorized team [7](#0-6) .
7. Attacker logs into Shipit via GitHub OAuth as `attacker-github-login`; `User#authorized?` now returns true because they belong to the victim's team ID, bypassing `force_github_authentication` for Org B's stacks [8](#0-7) [9](#0-8) .

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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
