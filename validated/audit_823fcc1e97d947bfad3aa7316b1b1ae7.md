### Title
Cross-organization webhook confusion in MembershipHandler allows an org owner to mutate another org's Team membership - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`MembershipHandler#find_or_create_team!` looks up a `Team` solely by `github_id` (`params.team.id`), with no check that the payload's `organization.login` matches the `organization` already stored on that `Team` record. [1](#0-0)  Because `github_id` values are small sequential integers assigned by GitHub, an attacker who owns a GitHub organization (and thus its `webhook_secret`) can send a `membership` webhook whose signature is valid for their own org but whose `team.id` references a `Team` row that belongs to a different, victim organization, causing `team.add_member`/`team.members.delete` to mutate that victim team. [2](#0-1) 

### Finding Description
The broken binding the code implicitly assumes but never enforces is:
`Team.find_by(github_id: params.team.id).organization == params.organization.login`

**Path traced:**
1. `WebhooksController#verify_signature` derives `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(signature, raw_body)`. [3](#0-2)  This only proves the request was signed with **that** organization's `webhook_secret` — it says nothing about which `team.id` is embedded in the body.
2. `MembershipHandler.params` requires `organization.login`, `team.id`, `member.login`, etc., but does not tie `team.id` to `organization.login` in any way beyond using it if a *new* record is created. [4](#0-3) 
3. `find_or_create_team!` calls `Team.find_or_create_by!(github_id: params.team.id)`. If a `Team` with that `github_id` already exists (e.g., belonging to victim org B), the block that assigns `team.organization = params.organization.login` never executes, and the existing team object (scoped to org B) is returned unchanged. [1](#0-0) 
4. `process` then calls `team.add_member(member)` or `team.members.delete(member)` on that org-B-owned team, using a member login supplied entirely by the attacker. [2](#0-1)  `Team#add_member` performs no organization check either. [5](#0-4) 

**Attacker request:** Attacker owns org `evil-corp` and installs/configures the Shipit GitHub App there (or otherwise learns/derives its `webhook_secret`, which is legitimately theirs since they administer the org's App installation). They send a `membership` webhook to `POST /webhooks` with `X-Github-Event: membership`, a valid `X-Hub-Signature` computed over the raw body using `evil-corp`'s own `webhook_secret`, `repository.owner.login` (or `organization.login`) = `evil-corp` (to pass `verify_signature`), but `team.id` = the known/guessed `github_id` of a `Team` row already created for victim org `victim-org`, and `member.login` = an accomplice GitHub login the attacker controls.

**Why existing guards fail:** `verify_signature` only validates that the byte stream was signed by the org identified as `repository_owner` in the payload — it never cross-checks that every embedded sub-object (like `team`) actually belongs to that same organization. `ExplicitParameters` schema validates types/presence only, not cross-field organizational consistency. `find_or_create_team!` trusts `params.team.id` as a global, authoritative team identifier without any organization scoping in the lookup.

### Impact Explanation
A request that authenticates for organization A ends up writing a `Membership` row for a `Team` scoped to organization B — a record mutation not authenticated by B. If the victim's `Team` is present in `Shipit.github_teams` (used for authorization via `User#authorized?`, `team_handles`, and `force_github_authentication`), the attacker can add an accomplice `User` (or one they can also log in as via GitHub OAuth) to that team, escalating that accomplice into `Shipit.github_teams`-derived authorization for the victim org — granting access to stacks, deploys, and other privileged UI/actions gated on team membership. This matches "High - escalation into `Shipit.github_teams` authorization." The attack is repeatable against any known/guessable `Team#github_id` and can also be used to *remove* legitimate members (denial of access) via the `removed` action.

### Likelihood Explanation
Preconditions: the attacker needs (a) their own GitHub org with the Shipit GitHub App installed (giving them a legitimate `webhook_secret` for their own org, or ability to compute a signature for at least one org configured in `secrets.yml`), and (b) knowledge/guessing of a `Team#github_id` belonging to the victim org. GitHub team IDs are sequential/enumerable integers and are also disclosed in numerous GitHub API responses and UI contexts, so obtaining a target `team.id` is low-cost. No GitHub App private key, `secret_key_base`, or victim credentials are required — only the attacker's own org's webhook secret, which they legitimately possess as an org owner. This is feasible and repeatable with no interaction with the victim.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization`, and reject (or explicitly re-associate under strict validation) any payload where an existing `Team` for that `github_id` belongs to a different `organization` than `params.organization.login`:
```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "team #{params.team.id} does not belong to organization #{params.organization.login}"
  end
  Team.find_or_create_by!(github_id: params.team.id) do |t|
    t.github_team = params.team
    t.organization = params.organization.login
  end
end
```
Additionally, consider having `verify_signature` bind the verified organization into the request context passed to handlers, and have `MembershipHandler` assert `params.organization.login == verified_organization` before performing any mutation, so the trust boundary established by the signature check is not silently bypassed by sub-object values.

### Proof of Concept
```ruby
# test/models/shipit/webhooks/handlers/membership_handler_test.rb (conceptual, no live GitHub)
test "membership event signed for org A cannot mutate a Team belonging to org B" do
  org_a_team  = Team.create!(github_id: 9001, organization: 'org-a', name: 'A Team', slug: 'a-team', api_url: 'https://x')
  org_b_team  = Team.create!(github_id: 9002, organization: 'org-b', name: 'B Team', slug: 'b-team', api_url: 'https://x')

  payload = {
    'action' => 'added',
    'team' => { 'id' => org_b_team.github_id, 'name' => 'B Team', 'slug' => 'b-team', 'url' => 'https://x' },
    'organization' => { 'login' => 'org-a' }, # signed/authenticated as org A
    'member' => { 'login' => 'accomplice' },
    'repository' => { 'owner' => { 'login' => 'org-a' } }
  }

  # Binding under test: Team.find_by(github_id: 9002).organization == 'org-a' ? (should be false)
  assert_equal 'org-b', org_b_team.reload.organization

  assert_no_difference -> { org_b_team.memberships.count } do
    Shipit::Webhooks::Handlers::MembershipHandler.call(payload) rescue nil
  end

  refute org_b_team.reload.members.exists?(login: 'accomplice')
end
```
This test demonstrates that, without the fix, `MembershipHandler` appends `accomplice` to `org_b_team.members` despite the payload only being validly signed for `org-a`, confirming the cross-tenant write; with the fix applied, the handler must raise/reject instead of mutating org B's team.

### Citations

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
