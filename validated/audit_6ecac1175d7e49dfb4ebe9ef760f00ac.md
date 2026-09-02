### Title
Cross-Organization Team Hijack via Unscoped `github_id` Lookup Persists and Is Fully Deterministic Across Repeated `membership` Webhooks - (File: app/models/shipit/webhooks/handlers/membership_handler.rb)

### Summary
`MembershipHandler#process` and `Team#add_member` never verify that the webhook's authenticated organization (`params.organization.login`, the value used by `verify_signature`) matches the `organization` column of the `Team` being mutated (`find_or_create_team!` looks up solely by `params.team.id`). Because `add_member` is idempotent (`members.append(member) unless members.include?(member)`), an attacker's genuinely-signed, repeated `membership`/`added` webhook does not just succeed once by luck — it succeeds deterministically on every submission while never creating duplicate rows, confirming the escalation path is stable and repeatable rather than a race condition.

### Finding Description
The broken binding, stated as an equality that must hold but does not:
`params.organization.login` (the org whose secret authenticated the request in `WebhooksController#verify_signature`, `app/controllers/shipit/webhooks_controller.rb:24-30,59-62`) `== team.organization` (the org that actually owns the privileged `Team` record being mutated, `app/models/shipit/team.rb`).

Trace:
1. `WebhooksController#verify_signature` computes `repository_owner` from `params.dig('repository','owner','login') || params.dig('organization','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)` [1](#0-0) [2](#0-1) . For a `membership` payload there is no `repository` key, so this resolves to the attacker's own org login, and the HMAC is checked against the attacker's own, legitimately configured `webhook_secret` — a fully valid signature.
2. `MembershipHandler#process` calls `find_or_create_team!`, which does `Team.find_or_create_by!(github_id: params.team.id)` [3](#0-2) . `github_id` is a GitHub-global integer the attacker can simply put the victim's privileged team's id into; the lookup never cross-checks `params.organization.login` against the existing `team.organization`.
3. `team.add_member(member)` is then called [4](#0-3) , and `Team#add_member` only guards against duplicate rows, not against organization mismatch: `members.append(member) unless members.include?(member)` [5](#0-4) .
4. `User#authorized?` grants Shipit-wide authorization purely from team membership: `Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?` [6](#0-5) , with no re-verification of provenance.

Idempotency does not neutralize the bug: resubmitting the identical crafted payload re-runs the same code path each time. `find_or_create_by!` finds the already-hijacked `Team` row, `members.include?(member)` short-circuits the second `append`, so `Membership.count` increases by exactly 1 across N submissions — but every single call still passes `verify_signature` using only the attacker's own secret, and every single call still reaches `add_member` for the victim's team without any organization equality check. None of `drop_unhandled_event`, `ExplicitParameters` (`params.team.id`/`params.organization.login` are simply typed, not cross-validated), or `force_github_authentication` perform this cross-check, so the divergence is never closed on repeat or on first attempt.

### Impact Explanation
Each successful call binds an attacker-controlled `User` to a `Team` whose `id` is present in `Shipit.github_teams`, flipping `User#authorized?` to `true` for that attacker across the whole Shipit instance — i.e., escalation into `Shipit.github_teams` authorization (High/Critical per the given severity taxonomy) without ever possessing the victim org's webhook secret, an `ApiClient` token, or Shipit session. This is repeatable at will and deterministic (idempotent), so the attacker (or anyone who can resend the captured payload) can reconfirm/re-establish membership indefinitely and reliably, though repeated sends do not multiply `Membership` rows.

### Likelihood Explanation
Preconditions: attacker owns a GitHub organization with an app/webhook configured against Shipit (so `Shipit.github(organization: attacker_org)` resolves to a real, attacker-known `webhook_secret`), and knows or can obtain the numeric `github_id` of the victim's privileged team (discoverable via GitHub's public/team APIs or leaked webhook logs). No Shipit credentials, sessions, or victim-org secrets are required. Cost is a single crafted HTTP POST to `/webhooks` with a valid `X-Hub-Signature` computed from the attacker's own secret; the exploit is trivially scriptable and, as this question demonstrates, safely repeatable without side effects that would tip off defenders via duplicate rows.

### Recommendation
In `MembershipHandler#find_or_create_team!` (and analogously anywhere `github_id`-only lookups are used for privileged records), require that the authenticated organization matches the record's `organization` before creating or updating it — e.g., raise/drop the event if an existing `Team` with that `github_id` has `organization != params.organization.login`, and pass the already-authenticated organization into the lookup rather than trusting the payload's own `organization` node blindly re-derived from unverified fields. More generally, `WebhooksController#verify_signature` should assert that any organization/repository referenced inside the payload's mutated entities matches the organization whose secret validated the signature, not just use it to pick which secret to check against.

### Proof of Concept
In a test under `test/` (e.g. `test/models/webhooks/handlers/membership_handler_test.rb`), with no live GitHub:
1. Create `victim_team` with `organization: 'victim-org'`, `github_id: 999`, and add it to `Shipit.github_teams` (stub `Shipit.github_teams`).
2. Configure a second, attacker-controlled org `'attacker-org'` in `Shipit.github` config with its own `webhook_secret`.
3. Build a `membership` payload: `action: 'added'`, `team: { id: 999, name: victim_team.name, slug: victim_team.slug, url: victim_team.api_url }`, `organization: { login: 'attacker-org' }`, `member: { login: 'evil-user' }`.
4. Sign it with `attacker-org`'s `webhook_secret` and POST it twice to `/webhooks` with header `X-Github-Event: membership`.
5. Assert both responses are `200`/`204` (accepted, not `422`).
6. Assert `Membership.where(team: victim_team, user: User.find_by(login: 'evil-user')).count == 1` after both posts (idempotent, exactly one row created despite two authenticated calls).
7. Assert `User.find_by(login: 'evil-user').authorized?` is `true`, proving the attacker gained `Shipit.github_teams` authorization via `victim_team` despite never authenticating as `victim-org`.

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

**File:** app/models/shipit/webhooks/handlers/membership_handler.rb (L26-28)
```ruby
          case params.action
          when 'added'
            team.add_member(member)
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
