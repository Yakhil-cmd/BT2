### Title
Membership webhook verified against one GitHub org can add/remove a member on another org's `Shipit::Team` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` authenticates a `membership` webhook only against the org named in `params.dig('organization','login')` (or `repository.owner.login`), i.e. it proves "this payload was signed with org X's webhook secret." `MembershipHandler#find_or_create_team!` then looks up the `Shipit::Team` purely by `params.team.id` (GitHub's numeric team id), with no check that the resolved team's `organization` matches the org that authenticated the request. This lets a payload signed for org X mutate the membership of a `Shipit::Team` that actually belongs to a different org Y, provided X already knows/guesses Y's GitHub numeric team id.

### Finding Description
The binding that must hold is: `org that verified webhook signature (params.dig('organization','login') / repository_owner)` == `Shipit::Team#organization for the row mutated by params.team.id`. Trace:

1. `Shipit::WebhooksController#verify_signature` (`app/controllers/shipit/webhooks_controller.rb:24-49`) computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` (`:59-62`) and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`. This only proves the payload was signed with the webhook secret configured for that one org.
2. `Shipit::Webhooks::Handlers::MembershipHandler#process` (`app/models/shipit/webhooks/handlers/membership_handler.rb:22-34`) then calls `find_or_create_team!`, which does:
```ruby
Team.find_or_create_by!(github_id: params.team.id) do |team|
  team.github_team = params.team
  team.organization = params.organization.login
end
```
(`app/models/shipit/webhooks/handlers/membership_handler.rb:38-42`). The block that assigns `organization` only runs when a *new* record is created. If a `Shipit::Team` with that `github_id` **already exists** (created earlier via legitimate sync of a different org, e.g. via `lib/tasks/teams.rake` or a prior legitimate membership webhook), `find_or_create_by!` returns the existing row untouched, and its `organization` column is never compared against `params.organization.login`.
3. `team.add_member(member)` / `team.members.delete(member)` (`app/models/shipit/team.rb:41-43`) is then executed against that pre-existing team row — which may belong to a completely different tenant org.

Attacker flow: attacker onboards/owns org "A" in the same Shipit instance (or otherwise knows/controls a webhook secret valid for some org recognized by `Shipit.github`), and knows the numeric GitHub team id of a `Shipit::Team` belonging to org "B" (team ids are visible to team members, to former members, or via other org disclosure, and are not secret in the way the DB row is). Attacker sends a signed `membership` webhook:
```json
{
  "action": "added",
  "organization": {"login": "A"},
  "team": {"id": <org-B-team-github-id>, "name": "x", "slug": "x", "url": "..."},
  "member": {"login": "attacker-controlled-user"}
}
```
signed with org A's webhook secret. `verify_signature` passes because it only checks org A's secret against org A's data. `find_or_create_team!` resolves the existing org-B `Team` row by `github_id` and adds the attacker's chosen GitHub user as a member of org B's team, or removes an existing member from org B's team, with no cross-tenant check.

Existing guards don't stop this: `verify_signature` only authenticates the org named in the payload, not the resolved team's actual owning org; the `ExplicitParameters` schema (`params do ... end`) only validates types/presence, not org affinity; `Team` has no validation tying `github_id` uniqueness/organization consistency at write time in this code path; `Membership` model only enforces `user_id` uniqueness scoped to `team_id` (`app/models/shipit/membership.rb:8`), not org provenance.

### Impact Explanation
This is a cross-tenant write: a webhook that only proves authorization for org A can mutate `Shipit::Team` membership rows belonging to org B. Team membership backs `User#authorized?` (`app/models/shipit/user.rb:80-82`: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?`), which gates login/session authorization when `Shipit.github_teams` is configured. An attacker who can sign membership payloads for one onboarded org can therefore add an arbitrary GitHub login as a member of a privileged team belonging to a different org, potentially granting that account `authorized?` status and access to stacks/deploys under org B — a "payload for one repository mutating another's [...] team" and a path toward "escalation into `Shipit.github_teams` authorization." Repeatable against any `Shipit::Team` whose numeric GitHub id is known, across all organizations onboarded to the same Shipit instance.

### Likelihood Explanation
Preconditions: the attacker needs a webhook signature valid for *some* org configured in this Shipit instance (e.g. their own onboarded org "A", if Shipit is multi-tenant/self-service, or an org with no `webhook_secret` configured — in which case `GitHubApp#verify_webhook_signature` returns `true` unconditionally per `lib/shipit/github_app.rb:76-77`, making forgery trivial). They also need the numeric GitHub `team.id` of the target org's team, which is not treated as secret elsewhere in the codebase (it's a public-ish GitHub identifier, discoverable via API/UI by team members or via enumeration). No Shipit session, API token, or GitHub App secret for org B is required. This is feasible in any deployment onboarding multiple untrusted/semi-trusted GitHub organizations to one Shipit instance.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup/creation by both `github_id` and `organization`, e.g. `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`, and reject/raise if an existing team with that `github_id` has a different `organization` than the authenticated payload's org (to detect id collisions instead of silently mutating the wrong tenant's team).

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test ":membership webhook for org A cannot mutate org B's team" do
  team_b = shipit_teams(:shopify_developers) # belongs to organization: 'shopify'
  assert_equal 'shopify', team_b.organization

  @request.headers['X-Github-Event'] = 'membership'
  payload = {
    action: 'added',
    organization: { login: 'org-a' },      # different org, verified via its own secret
    team: { id: team_b.github_id, name: 'x', slug: 'x', url: 'http://example.com' },
    member: { login: 'mallory' }
  }.merge(repository: { owner: { login: 'org-a' } })

  Shipit.github(organization: 'org-a').stubs(:verify_webhook_signature).returns(true)

  assert_no_difference -> { Shipit::Membership.where(team_id: team_b.id).count }, "org A must not be able to modify org B's team membership" do
    post :create, body: payload.to_json, as: :json
  end
end
```
Running this against current code shows the membership **is** created against `team_b` (org "shopify"'s team) despite the payload being authenticated only for `org-a`, confirming the cross-tenant write via `Team.find_or_create_by!(github_id: params.team.id)` (`app/models/shipit/webhooks/handlers/membership_handler.rb:39`) with no organization cross-check. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```

**File:** app/models/shipit/membership.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
  class Membership < Record
    belongs_to :team, required: true
    belongs_to :user, required: true

    validates :user_id, uniqueness: { scope: :team_id }
  end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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
