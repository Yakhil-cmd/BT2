### Title
Cross-organization Team membership injection via `membership` webhook `team.id` not scoped to the signing organization - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`WebhooksController#verify_signature` derives the organization used for signature verification from the attacker-controlled payload field `params.dig('organization', 'login')` when the event has no `repository` key (true for `membership` events), and `MembershipHandler#find_or_create_team!` looks up `Team.find_or_create_by!(github_id: params.team.id)` without scoping by that organization. An attacker who owns any real GitHub org (and thus knows that org's `webhook_secret`) can sign a `membership` payload claiming `organization.login` = their own org, but `team.id` = the numeric `github_id` of an existing `Shipit::Team` belonging to a different, Shipit-authorized organization, causing the attacker to be added as a member of that team.

### Finding Description
The broken binding: the organization whose `webhook_secret` verified the request bytes must equal `Team#organization` for the team being mutated — i.e. `verify_signature`'s `repository_owner` must equal `team.organization`. This is not enforced.

- `WebhooksController#verify_signature` computes `repository_owner` as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')` [1](#0-0)  and uses it to select the `GitHubApp` (and thus the `webhook_secret`) used to HMAC-verify the raw body [2](#0-1) . For a `membership` event there is no top-level `repository` key in the real GitHub payload, so `repository_owner` resolves purely from the attacker-supplied `organization.login` field.
- `MembershipHandler#find_or_create_team!` does `Team.find_or_create_by!(github_id: params.team.id)`, keyed only on the numeric `github_id`, with `organization` only set on the `create` branch (i.e. ignored when the record already exists) [3](#0-2) .
- `#process` then calls `team.add_member(member)` where `member` is built from the attacker-controlled `member.login` field via `User.find_or_create_by_login!` [4](#0-3) , and `Team#add_member` unconditionally appends the member to `members` [5](#0-4) .

Exploit flow: attacker owns OrgA (installed the Shipit GitHub App there, knows OrgA's `webhook_secret`). They know or can guess/enumerate the numeric `github_id` of a `Shipit::Team` belonging to OrgB (a Shipit-authorized org, e.g. one listed in `Shipit.github_teams`). They POST to `/webhooks` with `X-Github-Event: membership`, a body `{"action":"added","organization":{"login":"OrgA"},"team":{"id":<OrgB team github_id>,"name":...,"slug":...,"url":...},"member":{"login":"attacker-login"}}`, signed with OrgA's `webhook_secret`. `verify_signature` resolves `repository_owner` = "OrgA", fetches `Shipit.github(organization: "OrgA")`, and the HMAC verifies successfully since it was in fact signed with OrgA's secret. `Team.find_or_create_by!(github_id: ...)` finds OrgB's pre-existing Team row (created earlier via legitimate OrgB webhooks or `refresh_members!`), and the attacker is added as a member of that team.

Existing guards do not catch this: `verify_signature` only ensures the request was signed by *some* valid Shipit-configured organization's secret — it never checks that this organization matches the `team.organization` being mutated. `ExplicitParameters` schema only validates types/presence of `team.id`, `organization.login`, `member.login`, not cross-field consistency. `drop_unhandled_event` and `check_if_ping` are irrelevant here.

### Impact Explanation
Successful exploitation adds the attacker's GitHub user as a member of an arbitrary existing `Shipit::Team` row, keyed only by guessing/knowing that team's numeric GitHub `github_id`. If that team is one referenced in `Shipit.github_teams` (configured via `oauth_teams`, resolved through `Team.find_or_create_by_handle`) [6](#0-5) , then `User#authorized?` — which checks `teams.where(id: Shipit.github_teams.map(&:id)).exists?` [7](#0-6)  — will return true for the attacker on next login, granting them full Shipit session access (deploys, rollbacks, stack management) as if they were a legitimate member of OrgB's authorization team. This is a cross-tenant authorization escalation, matching the High severity category ("escalation into `Shipit.github_teams` authorization"). It is repeatable against any team whose numeric `github_id` the attacker can learn, and the blast radius spans any Shipit deployment federating multiple GitHub organizations (as documented in `docs/setup.md`'s "Using Multiple Github Applications" section) since only such multi-org configurations create the conditions where OrgA's secret differs from OrgB's but both hit the same shared `Team` table.

### Likelihood Explanation
Preconditions: Shipit must be configured for multiple GitHub organizations (per `docs/setup.md` "Using Multiple Github Applications"), the target org (OrgB) must already have a `Shipit::Team` row (created via a prior legitimate `membership`/`refresh_members!` event), and the attacker must know or guess the numeric `github_id` of that team — GitHub team IDs are sequential/enumerable and, notably, the `.rake` task in `lib/tasks/teams.rake` or any prior legitimate webhook delivery could leak such IDs. The attacker only needs their own GitHub org and their own free Shipit-App installation/webhook secret on it — no privileged Shipit role, no OrgB secret. Cost is low (a single crafted HTTP POST), and it is fully repeatable/scriptable against any known team ID.

### Recommendation
In `find_or_create_team!`, scope the lookup by both `github_id` and the verified `organization` (i.e., `Team.find_or_create_by!(github_id: params.team.id, organization: params.organization.login)`), and reject/raise if an existing team with that `github_id` belongs to a different organization than the one that signed the request. Additionally, harden `WebhooksController#repository_owner`/`verify_signature` so that for events without a `repository` key, the organization used for signature verification is cross-checked against the mutated resource's own recorded organization before any write occurs.

### Proof of Concept
Minitest under `test/controllers/webhooks_controller_test.rb`-style setup (illustrative, since `test/**` is out of scope for implementation but demonstrates the binding failure):

1. Create fixture `Team.create!(organization: 'shopify', slug: 'engineers', github_id: 999, name: 'Engineers', api_url: 'https://api.github.com/teams/999')` — this represents OrgB's ("shopify") team.
2. Configure `secrets.github` with two orgs, e.g. `'shopify'` (webhook_secret S1) and `'attacker-org'` (webhook_secret S2), mirroring `test/dummy/config/secrets_double_github_app.yml`.
3. Build a `membership` payload: `{"action":"added","organization":{"login":"attacker-org"},"team":{"id":999,"name":"Engineers","slug":"engineers","url":"https://api.github.com/teams/999"},"member":{"login":"attacker"}}`.
4. Compute `X-Hub-Signature` using `OpenSSL::HMAC.hexdigest('sha1', S2, body)` (the attacker's own, legitimately-known secret for `attacker-org`).
5. POST to `/webhooks` with `X-Github-Event: membership`.
6. Assertions (both sides of the binding):
   - `assert_response :ok` (signature verification passes because it matches `attacker-org`'s secret).
   - `assert_equal 'shopify', Team.find_by(github_id: 999).organization` — the team mutated still belongs to `'shopify'`, NOT `'attacker-org'` — proving the signing org (`attacker-org`) ≠ the mutated team's org (`shopify`), i.e., the binding is broken.
   - `assert Team.find_by(github_id: 999).members.exists?(login: 'attacker')` — the attacker was added as a member of OrgB's team despite never having authenticated as OrgB.
   - Optionally stub `Shipit.github_teams` to include this team and assert `attacker_user.authorized?` becomes `true`, demonstrating the High-severity authorization escalation.

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
