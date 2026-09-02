### Title
`MembershipHandler#process` 'removed' branch trusts `team.id`/`organization.login` from webhook payload without verifying the signing organization owns the target team, allowing cross-org deauthorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`Shipit::Webhooks::Handlers::MembershipHandler#process` looks up a `Team` solely by the numeric `params.team.id` (GitHub team id) via `find_or_create_team!`, with no check that the webhook's authenticating organization (`params.organization.login`) actually owns that team. Because signature verification (`Shipit::WebhooksController#verify_signature`) validates the payload against the secret of whatever organization is named in the payload itself, any org that has a webhook configured in Shipit can send a validly-signed `membership` webhook naming a different, privileged team's `github_id`, causing `team.members.delete(member)` to silently revoke a real operator's Shipit team membership.

### Finding Description
The broken binding: `params.organization.login` (the org whose secret validated the signature) must equal `team.organization` (the org that actually owns the `Team` record identified by `params.team.id`). No such equality is ever checked.

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0)  and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [2](#0-1) . For a `membership` event payload, this resolves to the attacker's own organization login taken straight from the payload, and is verified against that organization's own configured `webhook_secret` [3](#0-2) . This only proves the request came from the org named in the payload — it proves nothing about ownership of any `team.id` also present in the same payload.
2. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [4](#0-3) . If a `Team` with that `github_id` already exists (e.g., a privileged team in `Shipit.github_teams`), it is returned as-is; the `organization:` seed value in the block is only used on creation, so an existing team's `organization` is never checked against `params.organization.login`.
3. `member = User.find_or_create_by_login!(params.member.login)` resolves the existing real operator by login [5](#0-4) , `app/models/shipit/user.rb` lines 22-28.
4. For `params.action == 'removed'`, `team.members.delete(member)` removes the `Membership` row [6](#0-5) , with no check that `params.organization.login == team.organization`.

Attacker request: register a webhook-enabled org (attacker owns it, has its `webhook_secret`), and POST to `/webhooks` a `membership` event with `X-Hub-Signature` computed using their own secret, body: `{"action":"removed","team":{"id": <victim_team_github_id>, "name":"...", "slug":"...", "url":"..."},"organization":{"login":"attacker-org"},"member":{"login":"victim-operator"}}`. Signature check passes (verified against attacker-org's own secret). `find_or_create_team!` matches the existing victim `Team` row by `github_id`. `team.members.delete(member)` removes the victim operator's membership, causing `User#authorized?` (`teams.where(id: Shipit.github_teams.map(&:id)).exists?`) [7](#0-6)  to become false for that operator, deauthorizing them from deploy/merge actions gated on team membership.

None of the existing guards prevent this: `verify_signature` only proves org-vs-secret correspondence for the org named in the payload, not org-vs-team ownership; `drop_unhandled_event` and `ExplicitParameters` schema only validate shape, not cross-field integrity; there is no `force_github_authentication`/session check on webhook endpoints (webhooks are inherently unauthenticated except by HMAC); `Team`/`Membership` model validations do not enforce `organization` consistency at update time (only used at creation).

### Impact Explanation
An attacker who owns any organization with a Shipit-registered webhook can strip a legitimate operator out of a privileged `Team` (any team listed in `Shipit.github_teams`) merely by knowing (or brute forcing/discovering) that team's numeric GitHub `id`, without any access to the victim org's webhook secret or GitHub credentials. This is repeatable per request and can be aimed at any team `github_id`, affecting any tenant/org configured in the Shipit install, not just the attacker's own. The immediate effect is removal of deploy/merge authorization for a legitimate operator — an availability/authorization-integrity issue with `Shipit.github_teams` scoped state, matching the "escalation/manipulation of `Shipit.github_teams` authorization" bucket (the `added` branch of the same handler has the mirror-image issue, allowing an attacker to add arbitrary members into a privileged team, which is a direct escalation).

### Likelihood Explanation
Preconditions are low-cost and fully attacker-controlled: own any GitHub organization, install a Shipit-registered webhook app/integration on it (standard onboarding, no special privilege), and know the target team's GitHub numeric id (discoverable via GitHub API/UI for any team the attacker can view, or via team pages if not fully private). No secrets from the victim org are required, only the attacker's own valid webhook secret for their own org, which they legitimately possess. This is straightforward and repeatable against arbitrary teams.

### Recommendation
In `find_or_create_team!` / `MembershipHandler#process`, enforce that `params.organization.login` matches the `organization` already stored on the `Team` matched by `github_id` before performing `add_member`/`members.delete`; reject (or no-op with a log) if they differ, e.g.:
```ruby
def find_or_create_team!
  team = Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
  raise ArgumentError, "organization mismatch" unless team.organization == params.organization.login
  team
end
```

### Proof of Concept
minitest plan (`test/models/webhooks/handlers/membership_handler_test.rb`):
```ruby
test "removed action from unrelated organization deauthorizes a member of a different org's team" do
  victim_team = Team.create!(organization: "victim-org", github_id: 9999, name: "core", slug: "core", api_url: "https://api.github.com/teams/9999")
  operator = User.create!(login: "victim-operator")
  victim_team.add_member(operator)
  assert victim_team.members.include?(operator)

  # Payload signed as if from "attacker-org" (attacker's own valid secret),
  # but referencing victim_team.github_id and the victim operator's login.
  payload = {
    "action" => "removed",
    "team" => { "id" => victim_team.github_id, "name" => "core", "slug" => "core", "url" => victim_team.api_url },
    "organization" => { "login" => "attacker-org" },
    "member" => { "login" => operator.login }
  }

  # Assert the binding BEFORE: attacker-org != victim_team.organization
  refute_equal "attacker-org", victim_team.organization

  Shipit::Webhooks::Handlers::MembershipHandler.new.call(payload)

  # Assert the binding was never checked: membership removed despite org mismatch
  refute victim_team.members.reload.include?(operator)
end
```
This demonstrates that `Membership` deletion occurs purely from `params.team.id` and `params.member.login` correspondence, with `params.organization.login` never checked against `team.organization`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L24-24)
```ruby
          member = User.find_or_create_by_login!(params.member.login)
```

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L29-30)
```ruby
          when 'removed'
            team.members.delete(member)
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
