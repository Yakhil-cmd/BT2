### Title
Cross-tenant webhook signature scoping allows any configured org to write Memberships for any `Shipit.github_teams` team ID - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects the `GithubApp`/`webhook_secret` to verify against using `params.dig('organization','login')` (the payload's self-reported org), not any value tied to the actual `Team` being mutated. `MembershipHandler#find_or_create_team!` then looks up/creates the `Team` purely by the numeric `github_id` from the payload, so once the signature check passes with the attacker's own org secret, any pre-existing team row (e.g., one listed in `Shipit.github_teams`) can have members added, regardless of which org actually owns that GitHub team ID.

### Finding Description
The broken binding is: organization whose `webhook_secret` verified the request body (`repository_owner` = `params.dig('organization','login')`, used in `Shipit.github(organization: repository_owner)` at [1](#0-0)  and [2](#0-1) ) **should equal** the organization that actually owns the GitHub team with `github_id == params.team.id` on GitHub. Nothing in the code enforces this.

`Shipit.github(organization:)` is a multi-tenant lookup that resolves a distinct `GitHubApp` (and thus a distinct `webhook_secret`) per organization key configured in `secrets.github` [3](#0-2) ; any org present in that config has its own valid secret, and an attacker who administers that org's GitHub App/webhook can compute a valid `X-Hub-Signature` for a payload they craft themselves.

Once `verify_signature` passes, `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)`—keyed solely on the numeric id from the payload, with no comparison against `params.organization.login` or the app's actual organization [4](#0-3) . If a `Team` row with that `github_id` already exists (e.g., because it's one of the IDs referenced by `Shipit.github_teams`), the `find_or_create_by!` block (which sets `team.organization`) never executes—only the lookup matters. The handler then does `team.add_member(User.find_or_create_by_login!(params.member.login))` [5](#0-4) , creating a `Membership` for an attacker-controlled login on a team the attacker's org never actually controls on GitHub.

`User#authorized?` grants access whenever the user belongs to any team ID listed in `Shipit.github_teams` [6](#0-5) , so this Membership write directly translates into authorization bypass.

None of the existing guards catch this: `verify_signature` only checks that the signature matches *some* configured org's secret—it never checks that org against the team's real ownership; `drop_unhandled_event` only checks the event type is registered; the `ExplicitParameters` schema in `MembershipHandler.params` only validates types/presence, not cross-organization consistency.

### Impact Explanation
A successful request creates a real `Membership` row for an attacker-chosen `login` on a `Team` whose `github_id` is one of the IDs in `Shipit.github_teams`, without the victim organization that actually owns that team ever emitting the webhook. Since `User#authorized?` is gated on membership in `Shipit.github_teams`, this is a full authentication/authorization bypass for the entire Shipit instance—escalation into `Shipit.github_teams` authorization, matching the High/Critical impact categories in scope. The attack is repeatable for any team ID the attacker can guess or enumerate (numeric GitHub team IDs), and blast radius spans the whole multi-tenant Shipit deployment, not just the attacker's own org's repositories.

### Likelihood Explanation
Preconditions required: (1) Shipit must be configured in the multi-tenant `secrets.github` schema with more than one organization entry (each with its own `webhook_secret`), and (2) the attacker must control at least one of those configured orgs (own its GitHub App installation/webhook secret) — both of which are plausible in real multi-tenant Shipit deployments serving several orgs, and are exactly the scenario `Shipit.github(organization:)`/`github_app_config` exist to support [7](#0-6) . Attacker cost is low: sign an arbitrary JSON payload with their own valid webhook secret and guess/know a `Shipit.github_teams`-listed numeric team ID. No Shipit session, API token, or victim secret is needed.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and any other webhook handler that trusts payload-provided ids), verify that `params.organization.login` matches the organization associated with the verified `GithubApp`/webhook_secret (e.g., pass the verified organization down from `WebhooksController` into the handler dispatch and compare it against `params.organization.login` and/or the `Team#organization` already stored, rejecting the event on mismatch). Do not allow team membership mutation for an org different from the one whose secret verified the signature.

### Proof of Concept
Minitest plan (in `test/controllers/webhooks_controller_test.rb`, out of scope to write but described):
1. Configure two `GithubApp` orgs, `victim-org` and `attacker-org`, each with a distinct `webhook_secret`, via `secrets.github`.
2. Create a `Team` fixture with `github_id: 42, organization: 'victim-org'`, and set `Shipit.github_teams` to include that team.
3. Assert precondition: `Membership.where(team_id: team.id, user: attacker_user)` does not exist, and `attacker_user.authorized?` is `false`.
4. POST `/webhooks` with header `X-Github-Event: membership`, body `{"action":"added","team":{"id":42,"name":"n","slug":"s","url":"u"},"organization":{"login":"attacker-org"},"member":{"login":"attacker-login"}}`, signed with `attacker-org`'s `webhook_secret` in `X-Hub-Signature`.
5. Assert response is `200`/`204` (accepted), then assert a `Membership` row now exists linking `Team.find_by(github_id: 42)` to `User.find_by(login: 'attacker-login')`, and that `User.find_by(login: 'attacker-login').authorized?` is now `true`—demonstrating the equality "verifying org == team's real org" was violated.

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

**File:** lib/shipit.rb (L170-181)
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
```

**File:** lib/shipit.rb (L196-200)
```ruby
  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
  end
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L22-34)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
