### Title
Cross-organization webhook forgery escalates into `Shipit.github_teams` authorization via `MembershipHandler` - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
The equality the engine relies on is: *the GitHub organization whose secret validated the webhook signature* == *the organization that actually owns the `Team` record being mutated by the handler*. `WebhooksController#verify_signature` picks which organization's `webhook_secret` to HMAC-check against using a value taken straight out of the unauthenticated JSON body (`organization.login` / `repository.owner.login`), and `GitHubApp#verify_webhook_signature` treats a missing `webhook_secret` as automatic success. `MembershipHandler#process`, however, looks up (or creates) the `Team` purely by the attacker-supplied `team.id` (GitHub team id), never re-checking that this team actually belongs to the organization that was used to select/validate the signature. This lets a request "authenticated" against one (unsecured) organization mutate a `Team` object belonging to a completely different, privileged organization — including one listed in `Shipit.github_teams`, which gates application authorization.

### Finding Description
`WebhooksController#verify_signature` resolves the signing organization from body content it has not yet verified: [1](#0-0) [2](#0-1) 

For `membership` events there is no `repository` key, so `repository_owner` resolves to `params.dig('organization', 'login')`. `Shipit.github(organization: repository_owner)` then returns the `GitHubApp` config for whichever organization name is embedded in the untrusted payload, and the check passes trivially if that organization has no `webhook_secret` configured: [3](#0-2) 

Multi-org Shipit deployments explicitly support organizations with a blank secret (`webhook_secret: # nil`), as shown in the sample config: [4](#0-3) 

Once `verify_signature` passes, `MembershipHandler#process` mutates state using a field that is completely decoupled from the organization used above — the GitHub `team.id`: [5](#0-4) 

`Team.find_or_create_by!(github_id: params.team.id)` only sets `team.organization = params.organization.login` inside the creation block; if a `Team` row with that `github_id` already exists (e.g. any team listed in `Shipit.github_teams`, which must pre-exist to gate authorization), the lookup succeeds and the `organization` field is never re-validated. `team.add_member(member)` then attaches an attacker-chosen login to that pre-existing, privileged team with no check that the request's authenticated organization matches the team's real organization.

`User#authorized?` gates all application access purely on `Team` membership by id, with no cross-check against the organization that granted it: [6](#0-5) 

So the binding broken is: **organization that authenticated the webhook == organization that owns the `Team` being written**. Before the attacker's request, membership in an authorized `Shipit.github_teams` team can only change via a genuinely signed webhook from that team's real organization. After the forged request, membership in that same team can be granted by anyone able to satisfy signature verification for *any* configured organization that has no `webhook_secret`, regardless of which organization actually owns the target team.

### Impact Explanation
This is a direct escalation into `Shipit.github_teams` authorization (explicitly listed as a High-severity outcome). An attacker who can get a `membership` webhook accepted for any organization instance lacking a `webhook_secret` can add an arbitrary GitHub login as a member of a `Team` that gates access to Shipit — turning an unprivileged GitHub identity into an authorized Shipit user, bypassing the intended team-membership control entirely (`current_user.authorized?` in `app/controllers/concerns/shipit/authentication.rb`).

### Likelihood Explanation
Requires: (a) Shipit configured with more than one GitHub organization (a documented, supported configuration — see `config/secrets.development.shopify.yml` / `docs/setup.md`), and (b) at least one configured organization without a `webhook_secret` (also an explicitly supported, documented state — `verify_webhook_signature` treats it as "always verified"). No GitHub App credentials, session, or repository write access are needed by the attacker; only the ability to deliver an HTTP POST to the public `/github/webhooks` endpoint with a crafted JSON body and a matching `X-Github-Event: membership` header.

### Recommendation
- Do not let `verify_signature` select the verifying organization from unauthenticated payload content when any configured organization may skip verification; require `webhook_secret` to be present for all configured organizations, or fail closed instead of returning `true` when absent.
- In `MembershipHandler#find_or_create_team!` (and any other handler resolving objects by GitHub id), verify that the resolved record's `organization` matches the organization that was used to authenticate the request before mutating membership.

### Proof of Concept
1. Deploy Shipit with two organizations configured: `attacker-org` (no `webhook_secret`) and `victim-org` (has a Shipit-authorized `Team`, e.g. `victim-org/admins`, with a known GitHub `team.id`).
2. POST to `/github/webhooks` with header `X-Github-Event: membership` and body:
```json
{
  "action": "added",
  "team": { "id": <victim-org/admins github_id>, "name": "admins", "slug": "admins", "url": "https://api.github.com/teams/..." },
  "organization": { "login": "attacker-org" },
  "member": { "login": "attacker-github-login" }
}
```
No valid `X-Hub-Signature` is required because `attacker-org` has no `webhook_secret`, so `GitHubApp#verify_webhook_signature` returns `true` unconditionally.
3. `MembershipHandler#process` finds the existing `victim-org/admins` `Team` by `github_id`, creates/finds `User` with login `attacker-github-login`, and calls `team.add_member(member)`.
4. If `attacker-github-login` later authenticates via GitHub OAuth into Shipit, `current_user.authorized?` returns true because the user is now a member of a `Shipit.github_teams` team, despite never being added by `victim-org`.

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** config/secrets.development.shopify.yml (L1-23)
```yaml
host: 'shipit-engine.myshopify.io'

# For creating an app see: https://github.com/Shopify/shipit-engine/blob/main/docs/setup.md#creating-the-github-app

github:
  somegithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
  someothergithuborg:
    app_id:
    installation_id:
    webhook_secret: # nil
    private_key:
    oauth:
      id:
      secret:
      teams:
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
