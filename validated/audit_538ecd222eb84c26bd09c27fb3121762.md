### Title
Cross-organization Team hijack via attacker-chosen `team.id` on a signature-unverified `membership` webhook - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` selects which org's `GitHubApp` to verify against based on the attacker-controlled `repository_owner`/`organization.login` field in the payload, and `verify_webhook_signature` returns `true` unconditionally when that org has no `webhook_secret` configured. Combined with `MembershipHandler#find_or_create_team!` keying solely on the attacker-supplied `team.id` integer, an attacker who controls (or registers) a secret-less org in `Shipit.github(organization:)` config can send a `membership` webhook whose `team.id` collides with an existing `Team#github_id` belonging to an unrelated organization, causing Shipit to fetch and mutate that unrelated `Team`'s membership.

### Finding Description
The broken binding is: `Team#organization` (as persisted/found) should equal the organization whose webhook signature actually verified the request, i.e. `found_team.organization == verifying_org` where `verifying_org = Shipit.github(organization: repository_owner)`'s org. In `find_or_create_team!`: [1](#0-0) 

the lookup key is `github_id: params.team.id` only — a fully attacker-controlled JSON integer, never checked against GitHub or against `params.organization.login` for pre-existing rows. If a `Team` row already exists with that `github_id` (belonging to some other org, e.g. `organization: "shopify"`), `find_or_create_by!` returns that existing record untouched by the `do |team| ... end` block (which only runs on creation), and `process` then calls `team.add_member(member)` / `team.members.delete(member)` on it: [2](#0-1) 

Signature verification does not bind the payload to the *correct* org either. `verify_signature` picks the `GitHubApp` config purely from payload-controlled `repository_owner`: [3](#0-2) [4](#0-3) 

and `verify_webhook_signature` trivially returns `true` when that selected org has no `webhook_secret` configured: [5](#0-4) 

So an attacker who administers (or registers) any GitHub org configured in Shipit without a `webhook_secret` can send a `membership` event where `organization.login` is their own secret-less org (so `verify_signature` passes trivially) but `team.id` is set to the numeric `github_id` of a `Team` row that actually belongs to a different, legitimate organization. `find_or_create_team!` finds and returns that legitimate `Team`, and the attacker's `member.login`/`action` fields then add or remove members on it.

Existing guards do not stop this: `drop_unhandled_event` only checks event type is handled; `ExplicitParameters` schema in the handler only validates types/presence, not cross-referencing `organization.login` against the found `Team#organization`; there is no `User#authorized?`/`require_permission!` check anywhere on this webhook path since it's an unauthenticated GitHub webhook by design, gated only by signature verification — which is bypassable exactly as described when the resolved org has no secret.

### Impact Explanation
A successful request lets the attacker add themselves (or any GitHub login) as a member of, or remove a legitimate member from, a `Team` record belonging to an organization they do not control (e.g., `shopify`). Team membership feeds `User#authorized?` via `Shipit.github_teams`: [6](#0-5) 

so if the victim `Team`'s id is listed in `Shipit.github_teams`, this becomes an authorization escalation path (High/Critical per the rubric's "escalation into `Shipit.github_teams` authorization"). Even without that specific configuration, it is a cross-tenant data-integrity violation: a payload nominally from one org mutates another org's `Team` record. This is repeatable against any `Team#github_id` the attacker can guess or enumerate (GitHub team IDs are sequential/discoverable), and is not limited to a single victim — any org with a `Team` row in the Shipit database is a target as long as the attacker's chosen org is unauthenticated (no `webhook_secret`).

### Likelihood Explanation
Preconditions: (1) at least one GitHub org configured in Shipit (`Shipit.github(organization:)`) with no `webhook_secret` set — this is an operator misconfiguration, not something the attacker needs privileged access to Shipit for, and per the rubric the attacker is assumed to be able to "send HTTP requests to the Shipit host, including POST /webhooks"; (2) a pre-existing `Team` row with a `github_id` the attacker can guess/enumerate. Given these, the attack is a single unauthenticated POST to `/webhooks` with a crafted `membership` JSON body and correct `X-Github-Event` header — no secrets, tokens, or GitHub-side actions required. Feasibility depends entirely on whether such a secret-less org exists in the deployment's Shipit config; this is a real, supported and documented configuration state in this engine (webhook_secret is "presence"-checked and optional), so the vulnerable condition is plausible in production multi-tenant setups.

### Recommendation
In `find_or_create_team!`, do not trust the raw `team.id` alone for updates to pre-existing records: verify that the `Team` found by `github_id` has `organization == params.organization.login` before mutating membership, and reject/ignore the event (or raise) on mismatch. Additionally, `verify_signature` should not resolve the signing org purely from attacker-controlled payload fields without also validating that the resulting `Team`/`Repository` writes are scoped to that same organization; consider requiring a configured `webhook_secret` for all onboarded organizations (fail closed rather than fail open when `webhook_secret` is blank).

### Proof of Concept
Minitest plan (`test/models/shipit/webhooks/handlers/membership_handler_test.rb` style, adaptable):
1. Seed `Team.create!(github_id: 48, organization: 'shopify', slug: 'legit-team', name: 'Legit', api_url: '...')` and add a legit member via `add_member`.
2. Configure `Shipit.github(organization: 'attacker-org')` with a config that has no `webhook_secret` (or use an existing test org fixture with `webhook_secret: nil`).
3. POST to `/webhooks` with header `X-Github-Event: membership`, no/garbage `X-Hub-Signature`, and JSON body:
   ```json
   {
     "action": "added",
     "team": { "id": 48, "name": "evil", "slug": "evil", "url": "https://api.github.com/teams/48" },
     "organization": { "login": "attacker-org" },
     "member": { "login": "attacker-login" }
   }
   ```
4. Assert both sides of the binding: before request, `Team.find_by(github_id: 48).organization == 'shopify'` and `Team.find_by(github_id: 48).members.map(&:login)` does not include `attacker-login`. After the request, assert the response is `200`/`204` (not `422`) and `Team.find_by(github_id: 48).members.map(&:login)` now includes `attacker-login` — proving a payload verified only via `attacker-org`'s (secret-less) signing mutated the `shopify` team.

### Citations

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
