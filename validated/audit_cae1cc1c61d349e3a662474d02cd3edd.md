### Title
Membership webhook trusts the `organization.login` field for team ownership, allowing a webhook signed by one configured GitHub org to add arbitrary members to a `Team` belonging to a different org - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
Shipit-engine supports multi-tenant GitHub configuration where each organization gets its own webhook secret [1](#0-0) , and the webhook signature is verified using the secret of whatever organization is *named in the unverified JSON body* (`repository.owner.login` / `organization.login`) via `Shipit.github(organization: repository_owner)` [2](#0-1) . This means "the org whose secret authenticated the request" is only bound to "the org named in the payload," not to the org that the handler actually mutates. `MembershipHandler#find_or_create_team!` looks up (or creates) a `Team` **solely by `github_id`**, and only sets the `organization` attribute on the creation branch — it never re-validates that an *existing* team's `organization` matches `params.organization.login` from the (self-declared) payload:

```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [3](#0-2) 

### Finding Description
This is the same bug class as the report: a validation is scoped to the wrong identifier (a mismatched-length/mismatched-key check), so the check that is supposed to bind two related values together silently no-ops instead of enforcing the binding. Here, the binding that should hold is:

`organization that authenticated the webhook signature == organization that owns the Team being mutated`

Concretely:
1. Any org admin who legitimately controls a GitHub organization/app configured in Shipit (e.g., `OrgTwo` in a multi-org Shipit deployment, per `test/dummy/config/secrets_double_github_app.yml`) knows/can compute a valid `X-Hub-Signature` for their own org's `webhook_secret`.
2. `WebhooksController#verify_signature` only checks that the signature matches the org **named in the payload** — it does not check that the org whose secret was used matches any pre-existing resource being touched. The attacker can set `organization.login` to their own org (so the signature check passes) while setting `team.id` to the `github_id` of a **team belonging to a completely different, more privileged organization** already tracked in Shipit's DB (team IDs are visible/enumerable via GitHub's API or prior webhook logs).
3. `Team.find_or_create_by!(github_id: params.team.id)` finds the **existing** team (owned by the privileged org) because the lookup key is only `github_id`; the `organization` field is never checked or re-asserted for existing records.
4. `team.add_member(member)` then adds an attacker-controlled `User` (resolved only by `login` string via `User.find_or_create_by_login!`) to that pre-existing, privileged team.

This mirrors the reported flaw precisely: a check meant to gate a sensitive write (`storeLength`/array-length equality in QuantAMM; `organization` ownership here) is bypassed because the comparison is performed against the wrong quantity (asset-count vs packed length there; `github_id` alone vs. `github_id` + `organization` here).

### Impact Explanation
If the targeted `Team` is one of `Shipit.github_teams` (the set of teams that gate authorization, see `User#authorized?` [4](#0-3)  and `Shipit.github_teams` config in `lib/shipit.rb`), an attacker who controls only an unrelated, lower-privilege GitHub org configured in the same Shipit instance can grant themselves (or any GitHub login) membership in that authorization-gating team — an escalation into `Shipit.github_teams` authorization, which is explicitly listed as a High-impact outcome.

### Likelihood Explanation
Requires: (a) Shipit configured for multiple GitHub organizations (a documented, supported configuration [1](#0-0) ), (b) attacker administers or can send authenticated webhooks for at least one configured org, and (c) knowledge of the numeric GitHub `team.id` of the target privileged team (obtainable via GitHub's team API for teams the attacker can view, or via observed webhook traffic). This is a realistic scenario for any Shipit deployment serving several GitHub orgs/customers with independent webhook secrets, since the engine's own docs describe exactly this multi-tenant setup.

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization`, and reject (rather than silently reuse) an existing team whose `organization` does not match the organization that authenticated the webhook:

```ruby
def find_or_create_team!
  team = Team.find_by(github_id: params.team.id)
  if team && team.organization != params.organization.login
    raise ArgumentError, "team #{params.team.id} does not belong to organization #{params.organization.login}"
  end

  Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login) do |t|
    t.github_team = params.team
  end
end
```
Additionally, `WebhooksController#verify_signature` should carry the authenticated organization forward to the handler (rather than only using it to pick a secret) so handlers can assert that any organization-scoped payload field matches the org whose secret actually verified the request.

### Proof of Concept
1. Shipit configured with two orgs: `PrivilegedOrg` (has team `github_id: 999`, included in `Shipit.github_teams`) and `AttackerOrg` (attacker is an org owner/admin, knows `AttackerOrg`'s `webhook_secret`).
2. Attacker crafts a `membership` webhook payload:
```json
{
  "action": "added",
  "team": { "id": 999, "name": "Ouiche Cooks", "slug": "developers", "url": "https://api.github.com/teams/999" },
  "organization": { "login": "AttackerOrg" },
  "member": { "login": "attacker-login" },
  "repository": { "owner": { "login": "AttackerOrg" } }
}
```
3. Attacker signs the raw body with `AttackerOrg`'s webhook secret and sets `X-Hub-Signature`, `X-Github-Event: membership`.
4. `verify_signature` calls `Shipit.github(organization: 'AttackerOrg')` and the signature check passes [2](#0-1) .
5. `MembershipHandler#process` runs: `find_or_create_team!` finds the existing `Team` with `github_id: 999` (owned by `PrivilegedOrg`), and `team.add_member(member)` adds `attacker-login` to it [5](#0-4) .
6. `attacker-login`'s corresponding `Shipit::User` now belongs to a team in `Shipit.github_teams`, so `User#authorized?` returns `true` for that user without any real membership in `PrivilegedOrg`.

### Citations

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
