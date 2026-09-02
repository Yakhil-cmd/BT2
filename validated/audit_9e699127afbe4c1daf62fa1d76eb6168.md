### Title
Cross-organization webhook `membership` event allows escalation into `Shipit.github_teams` authorization via `github_id`-only `Team` lookup - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a webhook **only against the organization named in the payload itself** (`repository.owner.login` or, for org-level events like `membership`, `organization.login`), selecting the corresponding GitHub App's `webhook_secret` for that org via `Shipit.github(organization: repository_owner)`. Once the signature matches *that* organization's secret, the entire payload is handed to `Shipit::Webhooks::Handlers::MembershipHandler`, which resolves the target `Team` **solely by the numeric `github_id` field taken from the payload** — with no check that the team actually belongs to the organization whose secret validated the request. This breaks the binding: `organization authenticated (secret used to verify signature) == team/organization actually written`.

### Finding Description
`verify_signature` in [1](#0-0)  picks the GitHub App/secret to verify against using `repository_owner`, which is derived directly from the untrusted payload: [2](#0-1) . For a `membership` event there is no `repository` key, so `organization.login` (also attacker-supplied but signed) is used to look up the org-specific secret.

In a multi-tenant deployment (explicitly supported and documented at [3](#0-2) ), a single Shipit instance can be configured with several independent GitHub App installations for different organizations. Any organization owner among these (an "unprivileged attacker" relative to the *other* tenants) can legitimately trigger a real, correctly-signed `membership` webhook from their **own** GitHub organization.

`MembershipHandler#process` then does: [4](#0-3) 

`find_or_create_team!` performs `Team.find_or_create_by!(github_id: params.team.id)` — matching is keyed **only** on the numeric `github_id`, which is attacker-controlled payload content. It is never checked against `params.organization.login`, i.e. against the organization whose secret actually authenticated the request.

The authorization-critical `Team` records are originally created by `Team.find_or_create_by_handle`, which resolves a `"org/slug"` handle configured in `Shipit.github_teams` to a real GitHub team and stores its real `github_id`: [5](#0-4) . These are exactly the teams used for access control: [6](#0-5)  and [7](#0-6) .

Because `find_or_create_team!` matches by `github_id` alone, an attacker who knows (or brute-forces/enumerates, since GitHub team IDs are small sequential integers and often discoverable via the public GitHub API) the `github_id` of a victim organization's authorization-gating team can send a `membership` webhook — signed with the attacker's own org's `webhook_secret` — containing that `github_id` and an arbitrary `member.login`. The handler will match the existing victim `Team` record and call `team.add_member(member)`, adding an attacker-chosen (or attacker-controlled) `User` to a team that `User#authorized?` treats as sufficient for access to the Shipit instance.

### Impact Explanation
This is an escalation into `Shipit.github_teams` authorization (High impact per the scan rules): an attacker with only their own (unprivileged, non-victim) organization's legitimate webhook credentials can add an arbitrary GitHub identity to a `Team` record that grants access to stacks/deploys belonging to a completely different, victim organization on the same shared Shipit instance. This effectively bypasses the team-membership authorization check without any actual GitHub team membership change on GitHub's side.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment with more than one configured GitHub App/organization (explicitly documented as supported), (2) attacker control of a legitimate GitHub App installation for their *own* org on that same instance (not privileged access to the victim), and (3) knowledge of the victim's authorization team's numeric `github_id` (typically discoverable, e.g. via GitHub's public teams API or prior interaction). No `ApiClient` token, session, or GitHub App private key of the victim is needed — only the attacker's own webhook secret, which they legitimately possess for their own org.

### Recommendation
Scope the `Team` lookup in `MembershipHandler#find_or_create_team!` to the organization that authenticated the webhook (i.e., require `organization: params.organization.login` as part of the match key, not just `github_id`), and reject/ignore membership events whose `organization.login` does not match the previously recorded `organization` for a `Team` with that `github_id`. More generally, bind the webhook's authenticated organization to every entity the handler is permitted to mutate, rather than trusting organization-scoped fields embedded in the same payload used to select the verification secret.

### Proof of Concept
1. Configure Shipit with two GitHub App orgs, `victim-org` (owns team `github_id: 555`, which is listed in `Shipit.github_teams`) and `attacker-org` (attacker's own legitimate installation).
2. As the owner of `attacker-org`, trigger (or directly deliver, since they hold `attacker-org`'s real `webhook_secret`) a `membership` webhook:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "x", "slug": "x", "url": "https://api.github.com/teams/555" },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-controlled-user" }
}
```
signed with `attacker-org`'s webhook secret via `X-Hub-Signature`.
3. `WebhooksController#verify_signature` resolves `repository_owner` → `"attacker-org"`, fetches `attacker-org`'s app, and the signature validates successfully (it's genuinely signed by that org).
4. `MembershipHandler#find_or_create_team!` looks up `Team.find_or_create_by!(github_id: 555)`, which matches the **victim's** existing authorization team, and adds `attacker-controlled-user` as a member.
5. `attacker-controlled-user` now passes `User#authorized?` and gains access to `victim-org`'s stacks/deploys in Shipit.

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

**File:** docs/setup.md (L181-209)
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

**File:** app/models/shipit/team.rb (L17-27)
```ruby
    class << self
      def find_or_create_by_handle(handle)
        organization, slug = handle.split('/').map(&:downcase)
        find_by(organization:, slug:) || fetch_and_create_from_github(organization, slug)
      end

      def fetch_and_create_from_github(organization, slug)
        return unless github_team = find_team_on_github(organization, slug)

        create!(github_team:, organization:)
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
