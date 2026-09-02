### Title
Forged `membership` webhook for an org with no `webhook_secret` lets an attacker mutate any `Team`'s membership globally, bypassing per-org signature scoping - (File: `app/controllers/shipit/webhooks_controller.rb`, `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` selects which `GitHubApp` config to check against using an attacker-controlled `organization.login` field, and `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's config has no `webhook_secret`. Because `MembershipHandler` resolves the `Team` to mutate purely by the attacker-supplied numeric `params.team.id` (not scoped to the org used for signature verification), an attacker can pick a permissive org to pass verification while targeting the `Team` row belonging to any other, properly-secured org — including a team present in `Shipit.github_teams` — and add or remove arbitrary members from it.

### Finding Description
The broken binding: the code implicitly assumes `verified_organization(repository_owner) == owning_organization(team_targeted_by_handler)`, but nothing enforces this equality.

- `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and uses it purely to pick which `GitHubApp` config to check the signature against: `Shipit.github(organization: repository_owner)` [2](#0-1) .
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally if that org's config has no `webhook_secret` set: `return true unless webhook_secret` [3](#0-2) .
- `MembershipHandler#find_or_create_team!` resolves the target `Team` solely by the numeric `params.team.id` (`github_id`), independent of which org's config authenticated the request: `Team.find_or_create_by!(github_id: params.team.id)` [4](#0-3) . If a `Team` row with that `github_id` already exists (e.g. synced from a legitimately secured org), the `organization=` assignment in the creation block never runs — the existing row is simply reused for the `team.add_member`/`team.members.delete` mutation [5](#0-4) .
- `User#authorized?` checks membership against `Shipit.github_teams`, which is a global set of `Team` records resolved by handle/`github_id`, independent of any specific stack or org: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) .

Exploit flow: the attacker finds (via multi-org configuration in `secrets.github`) any org whose `GitHubApp` config omits `webhook_secret` — call it `weak-org`. They POST to `/webhooks` with header `X-Github-Event: membership`, a `membership` action=`added` (or `removed`) payload where `organization.login = "weak-org"` (so `repository_owner` resolves to the org with no secret and `verify_webhook_signature` returns `true` unconditionally), but `team.id` is set to the numeric GitHub team ID of a team that is actually associated with `Shipit.github_teams` (a privileged team belonging to a securely-configured org), and `member.login` set to an arbitrary GitHub login (attacker-controlled account). `MembershipHandler` finds the existing privileged `Team` row by `github_id` and adds the attacker's chosen user as a member, or removes an existing member, entirely bypassing the secured org's `webhook_secret`.

Existing guards fail because: `verify_signature` only asserts that *some* org config accepted the signature (or has none configured), not that the resource being mutated by the handler belongs to that org; `MembershipHandler`'s `params` schema (via `ExplicitParameters`) validates types/presence only, not organization ownership of the referenced `team.id`; there is no cross-check between `params.organization.login` (used for auth) and any org value that ties back to the specific `Team` record's provenance.

### Impact Explanation
A successful forged request lets an unprivileged attacker add themselves (or any GitHub login) to a `Team` that participates in `Shipit.github_teams`, which is read by `User#authorized?` to gate deploy/rollback authorization across the whole Shipit instance [6](#0-5) . This is a direct escalation into `Shipit.github_teams` authorization — matching the High severity category explicitly listed in the rules. It is repeatable: each POST can add/remove any member of any known team ID, and blast radius spans all stacks/orgs whose authorization relies on the shared `Shipit.github_teams` set, not just the org that is misconfigured.

### Likelihood Explanation
Preconditions: the Shipit instance must be running in the multi-organization GitHub App configuration mode (`secrets.github` keyed by org) with at least one configured org lacking `webhook_secret` (`GitHubApp#verify_webhook_signature` early-returns `true` in this case) [7](#0-6) , and a `Team`/`Shipit.github_teams` entry whose numeric GitHub `id` the attacker can discover (GitHub team IDs are not secret and are visible via the GitHub API to any team member or via other public signals). No Shipit session, API token, or secret is required. Attacker cost is a single unauthenticated HTTP POST; this is highly repeatable and requires no privileged access.

### Recommendation
Do not let the organization used for signature verification diverge from the organization that owns the resource being mutated. Bind `Team`/`Membership` records to the specific `GitHubApp`/organization context that authenticated the webhook (e.g., scope `Team.find_or_create_by!` by both `github_id` and `organization`, and reject/ignore membership events whose `organization.login` doesn't match the pre-existing team's stored `organization`). Additionally, treat "no `webhook_secret` configured for an org" as a hard misconfiguration that should reject all webhooks for that org rather than silently trust them, or fail loudly at boot if any org lacks a `webhook_secret` in multi-org mode.

### Proof of Concept
```ruby
# test/controllers/webhooks_controller_test.rb (conceptual addition)
test "membership webhook for org without webhook_secret can mutate a team belonging to a different, secured org" do
  # Arrange: multi-org secrets with `weak-org` lacking webhook_secret, `secure-org` having one
  privileged_team = shipit_teams(:some_team) # a Team already in Shipit.github_teams, github_id known
  attacker_login = "attacker-controlled-user"

  refute privileged_team.members.exists?(login: attacker_login) # LHS of the binding: not a member before

  post :create, body: {
    action: 'added',
    team: { id: privileged_team.github_id, name: privileged_team.name, slug: privileged_team.slug, url: 'https://x' },
    organization: { login: 'weak-org' }, # org with NO webhook_secret -> signature check bypassed
    member: { login: attacker_login }
  }.to_json, headers: { 'X-Github-Event' => 'membership', 'X-Hub-Signature' => 'sha1=deadbeef' }

  assert_response :ok
  assert privileged_team.reload.members.exists?(login: attacker_login) # RHS: forged membership succeeded
  # demonstrates the equality (authenticated org == mutated team's owning org) is violated
end
```

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
