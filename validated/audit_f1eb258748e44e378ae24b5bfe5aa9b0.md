### Title
Membership webhook lets any authenticated organization graft members onto another organization's authorization `Team` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate a webhook using an organization identifier taken from the payload itself, but `MembershipHandler` then mutates a `Team` record identified only by `github_id`, without ever checking that the `organization.login` in the same payload matches the organization the `Team` actually belongs to. This breaks the binding: "organization whose secret authenticated the request" == "organization whose team membership is written."

### Finding Description
`WebhooksController#verify_signature` picks the GitHub App/secret to verify against using a payload-controlled field: [1](#0-0) [2](#0-1) 

`repository_owner` is read straight from the JSON body (`repository.owner.login` or `organization.login`) — it is not cryptographically bound to anything except "some org whose secret produced a matching HMAC over this exact body." In a multi-organization Shipit deployment (supported natively, see `test/dummy/config/secrets_double_github_app.yml`), each organization has its own independent `webhook_secret`. Any org configured in the instance can therefore produce a validly-signed payload — signature verification only proves "this body was signed with Org X's secret," not "the content of this body pertains to Org X."

`MembershipHandler#process` then looks up/creates a `Team` purely by the GitHub team's numeric `github_id`, and unconditionally adds the member: [3](#0-2) 

Because `find_or_create_by!(github_id: params.team.id)` only assigns `team.organization = params.organization.login` inside the creation block, an **already-existing** `Team` row (e.g., one previously created for the privileged organization referenced in `Shipit.github_teams`) is matched purely by `github_id` and returned as-is — its stored `organization` is never re-checked against the `organization.login` claimed in the current, differently-signed payload. `team.add_member(member)` then runs regardless.

This directly violates the binding the ruleset calls out: *"an organization that authenticated versus the repository [or resource] that is written."* Here, the organization that authenticated (whichever org's secret validated the HMAC) is never checked to equal the organization whose `Team` the handler mutates.

`Team#add_member` performs no additional authorization check: [4](#0-3) 

And membership in `Shipit.github_teams`-listed teams is the sole authorization gate for logged-in users: [5](#0-4) 

### Impact Explanation
An attacker who is a member/administrator of *any* organization configured on the shared Shipit instance (i.e., who knows or can obtain that organization's webhook secret through legitimate means for their own org, such as being the person who configured that org's GitHub App) can forge a `membership` webhook whose signature is valid for their own low-privilege organization, but whose `team.id` field is set to the GitHub team ID of the privileged authorization team belonging to a *different*, higher-privileged organization on the same Shipit deployment. Because `find_or_create_team!` matches solely on `github_id`, this forged event mutates the real authorization `Team` and adds an attacker-chosen `User` (created via `User.find_or_create_by_login!(params.member.login)`) to it. That user then passes `User#authorized?` and gains full deploy/rollback/merge access to every stack gated by `Shipit.github_teams`, which the rules classify as "escalation into `Shipit.github_teams` authorization" — a High-impact, unauthenticated-boundary-crossing escalation, and can lead to an unauthorized deploy/rollback (Critical) once the attacker is authenticated as a privileged user.

### Likelihood Explanation
Exploitability requires only: (1) the Shipit instance is configured for more than one GitHub organization (a documented, supported configuration — see `test/dummy/config/secrets_double_github_app.yml`), (2) the attacker controls/knows the webhook secret for at least one of those organizations (a normal, unprivileged condition for a member/owner of their own org's GitHub App, not requiring any Shipit-side credential), and (3) the attacker can discover the numeric GitHub team ID of the privileged team, which is retrievable via the GitHub Teams API/UI by anyone with visibility into that team (often just org membership, not administrative privilege). No Shipit session, `ApiClient` token, or GitHub App private key is required — only knowledge of one org's webhook secret, which the rules explicitly do not exclude.

### Recommendation
In `MembershipHandler#find_or_create_team!`, verify that any existing `Team` matched by `github_id` has `organization == params.organization.login` before proceeding, and reject/log the event (or re-key lookups by `[organization, github_id]`) if they differ. More generally, `WebhooksController#verify_signature` should ensure the organization used to select the signing secret is the same organization that every downstream handler treats as authoritative for the entities being mutated (teams, repositories) within that single request.

### Proof of Concept
1. Configure Shipit with two organizations, `OrgA` (attacker is an owner and knows its `webhook_secret`) and `OrgB` (has a `Team` record, `github_id: 999`, that is listed in `Shipit.github_teams` for authorization).
2. Attacker crafts a `membership` webhook body:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Ouiche Cooks", "slug": "ouiche-cooks", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "OrgA" },
  "member": { "login": "attacker-controlled-login" }
}
```
3. Attacker computes `X-Hub-Signature: sha1=<HMAC-SHA1(OrgA_webhook_secret, body)>` and POSTs to `/webhooks` with `X-Github-Event: membership`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: "OrgA")`, verifies successfully against `OrgA`'s secret [1](#0-0) .
5. `MembershipHandler#find_or_create_team!` looks up `Team.find_or_create_by!(github_id: 999)`, finds the existing `OrgB` privileged team (organization field untouched), and `team.add_member(User.find_or_create_by_login!("attacker-controlled-login"))` runs [3](#0-2) .
6. The attacker's user now satisfies `User#authorized?` via membership in an `OrgB` team they were never actually added to on GitHub [5](#0-4) .

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
