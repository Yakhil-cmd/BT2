### Title
Cross-organization Team hijack via unscoped `github_id` lookup in `MembershipHandler` - ([File: app/models/shipit/webhooks/handlers/membership_handler.rb])

### Summary
The `membership` webhook handler resolves the `Team` record to mutate solely by the numeric `github_id` supplied in the payload, with no check that the `organization` value used to select/verify the signing GitHub App actually owns that team. Any organization onboarded onto this Shipit instance (each org has its own `github_id`, `installation_id`, `webhook_secret` per `docs/setup.md` multi-org config) can therefore sign a valid `membership` webhook for its own org and use it to add arbitrary members to a `Team` object that actually belongs to a different, victim organization.

### Finding Description
Webhook signature verification is scoped per-organization: `WebhooksController#verify_signature` picks the app config with `Shipit.github(organization: repository_owner)` and only proves the request was signed with *that org's* `webhook_secret`. [1](#0-0) 
For `membership` events there is no `repository` key, so `repository_owner` falls back to `params.dig('organization', 'login')` — i.e. the attacker's own organization login, which they legitimately control. [2](#0-1) 

Once the signature check passes (using the attacker's own valid webhook secret), the raw JSON body is dispatched unmodified to `MembershipHandler#process`: [3](#0-2) 

The team to be modified is looked up purely by `github_id`, with **no scoping to the authenticating organization**: [4](#0-3) 

The `team.organization = params.organization.login` assignment inside the block only executes when `find_or_create_by!` actually *creates* a new record; if a `Team` with that `github_id` already exists (created earlier by the legitimate owning org's real membership webhook), the existing record is returned unchanged and `team.add_member(member)` runs against it: [5](#0-4) 

This breaks the trust binding: **organization authenticated by the webhook signature (attacker's own org) ≠ organization that owns the `Team` record actually written (victim org)**. The `github_id` is a plain attacker-supplied integer in the JSON body and is never cross-checked against `Team#organization`.

### Impact Explanation
`Shipit::Team` membership (`Team#members`, populated via `add_member`) backs the `Shipit.github_teams` authorization mechanism referenced in `lib/shipit.rb` and `app/controllers/concerns/shipit/authentication.rb` (team-gated login/authorization). By forging a `membership` "added" event that targets a victim org's `Team#github_id` while authenticating with their own org's webhook secret, an attacker can insert an arbitrary `User` (e.g., themselves) as a member of a privileged team they were never actually added to on GitHub — an escalation into `Shipit.github_teams` authorization, matching the High-severity impact category (escalation into `Shipit.github_teams` authorization).

### Likelihood Explanation
This requires the attacker to control (own/administer) at least one GitHub organization that is legitimately configured as a tenant on the shared Shipit instance — a realistic scenario for the documented multi-org deployment mode. No Shipit session, API token, or GitHub App private key of the victim org is needed; only knowledge of the attacker's own already-known webhook secret and the numeric `github_id` of the victim team (discoverable via GitHub's public team API/URL, e.g., `api_url`/`github_team.id` fields visible to team members or via prior GitHub org enumeration).

### Recommendation
In `MembershipHandler#find_or_create_team!`, scope the lookup by both `github_id` and `organization` (matching the authenticating `params.organization.login`), and reject/no-op when an existing team's `organization` does not match the payload's `organization.login`, e.g.:
```ruby
Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login) do |team|
  team.github_team = params.team
end
```
Additionally, `WebhooksController#verify_signature` should assert that whichever organization value is used for signature verification also equals every organization-identifying field consumed downstream by the handler for that event, rather than trusting them as independently attacker-controlled fields.

### Proof of Concept
1. Attacker administers `attacker-org`, a GitHub organization legitimately configured in Shipit's multi-org `github:` settings (own `webhook_secret`).
2. Victim org `victim-org` previously triggered a real `membership` webhook, creating `Shipit::Team` with `github_id: 555, organization: "victim-org"`.
3. Attacker sends `POST /github/webhooks` with header `X-Github-Event: membership`, body:
```json
{
  "action": "added",
  "team": { "id": 555, "name": "Deployers", "slug": "deployers", "url": "https://api.github.com/..." },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-user" }
}
```
signed with `attacker-org`'s real webhook secret (`X-Hub-Signature`).
4. `verify_signature` resolves `Shipit.github(organization: "attacker-org")` and validates successfully.
5. `MembershipHandler#process` finds the existing `Team#github_id == 555` (victim-org's "Deployers" team) and calls `team.add_member(attacker_user)`, granting `attacker-user` membership in a victim-owned, potentially privileged team.

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

**File:** app/models/shipit/team.rb (L41-43)
```ruby
    def add_member(member)
      members.append(member) unless members.include?(member)
    end
```
