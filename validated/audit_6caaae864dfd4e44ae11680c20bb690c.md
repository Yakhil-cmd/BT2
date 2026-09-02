## Analysis

`WebhooksController#verify_signature` selects a `github_app` config purely from a repository/organization login parsed out of the untrusted JSON body, and then validates the *whole raw body* against that org's `webhook_secret` [1](#0-0) . Critically, `verify_webhook_signature` short-circuits to `true` whenever the resolved organization has **no `webhook_secret` configured** (documented as *optional* in `docs/setup.md`), meaning any body is accepted for that tenant with no HMAC check at all [2](#0-1) .

The `membership` event handler then trusts a fully attacker-controlled `team.id` (the GitHub team ID) to look up or create the local `Team` record and add a member to it, without ever re-validating that this team actually belongs to the organization whose credentials were (weakly) checked:

```ruby
def find_or_create_team!
  Team.find_or_create_by!(github_id: params.team.id) do |team|
    team.github_team = params.team
    team.organization = params.organization.login
  end
end
``` [3](#0-2) 

`Team.find_or_create_by!(github_id: params.team.id)` will match an **existing** `Team` row purely by numeric GitHub team ID — including one that is already part of `Shipit.github_teams` — and then execute `team.add_member(member)` for whatever `member.login` is supplied [4](#0-3) . Authorization into the app is governed by exactly this membership relation:

```ruby
def authorized?
  @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
end
``` [5](#0-4) 

## Broken binding

`organization authenticated by verify_signature` ≠ `team.github_id acted upon by MembershipHandler`. The signature check only proves (weakly, or not at all if the secret is unset) that *some* payload came from *an* organization login string embedded in the same untrusted JSON; it never proves that the numeric `team.id` referenced in the `team` object is actually owned by that organization, or that the org has a secret configured at all. This mirrors the `RubiconMarket` pattern: a value acted upon (`team.id`/membership write) is never covered by the actual trust check (a real, per-org verified signature tying the specific team to the org).

## Practical exploitation path

1. In a multi-tenant Shipit deployment (the engine explicitly supports multiple orgs, see `test/dummy/config/secrets_double_github_app.yml` structure with `OrgOne`/`OrgTwo`), if any one configured organization has `webhook_secret` unset — an explicitly documented, supported, optional configuration — `verify_webhook_signature` accepts **any** payload for that org unconditionally [6](#0-5) .
2. An unauthenticated attacker POSTs to `/webhooks` with `X-Github-Event: membership`, `organization.login` set to that no-secret org, and `team.id` set to the GitHub team ID backing one of `Shipit.github_teams` (a privileged team from a *different*, secret-protected org), `action: "added"`, and `member.login` set to the attacker's own existing Shipit `User` login.
3. `MembershipHandler` finds the pre-existing privileged `Team` row by `github_id` and adds the attacker as a member, with no cross-check against the (weakly or non-) verified organization.
4. The attacker's `User#authorized?` now returns `true`, granting full access to the Shipit UI/API for stacks gated by `Shipit.github_teams` — escalation into `Shipit.github_teams` authorization, one of the explicitly listed High-impact outcomes.

## Uncertainty

I was not able to fully confirm within available tool calls (1) whether `Shipit.github_teams` entries are resolved/cached by numeric GitHub team ID versus by slug+org pair (this affects whether the collision purely requires guessing/knowing a numeric team ID), and (2) whether any additional validation of `params.organization.login` against the team's stored `organization` happens elsewhere (e.g., in `Team#add_member` or model callbacks) that I did not locate. These would need to be checked against `app/models/shipit/team.rb` and the `Shipit.github_teams` config loader before treating this as fully proven, but the code inspected shows no such cross-check within `MembershipHandler` or `WebhooksController`.

### Title
Cross-organization team-membership forgery via webhooks with unset `webhook_secret` escalates into `Shipit.github_teams` authorization - (File: `app/models/shipit/webhooks/handlers/membership_handler.rb`)

### Summary
`WebhooksController#verify_signature` resolves the verifying GitHub App/org purely from attacker-supplied JSON and treats an org lacking a configured `webhook_secret` as automatically verified. `MembershipHandler` then mutates team membership using an attacker-controlled numeric `team.id`, without checking that the team belongs to the (weakly) authenticated organization, allowing cross-tenant privilege escalation into any `Shipit.github_teams`-gated team.

### Finding Description
See analysis above: `verify_signature` [7](#0-6)  and `verify_webhook_signature`'s `return true unless webhook_secret` [2](#0-1)  combined with `MembershipHandler#find_or_create_team!`/`#process` [8](#0-7)  and the authorization check in `User#authorized?` [5](#0-4) .

### Impact Explanation
Successful exploitation grants an unprivileged attacker membership in any `Shipit.github_teams`-authorized team, bypassing GitHub's real team membership entirely and granting full Shipit access (deploys, rollbacks, stack management) — escalation into `Shipit.github_teams` authorization.

### Likelihood Explanation
Requires a multi-tenant Shipit deployment where at least one configured organization has no `webhook_secret` set (an explicitly documented optional setting) and requires the attacker to know/guess the numeric GitHub `team.id` of a privileged team. This lowers likelihood relative to a fully unconditional bypass, but the underlying code path performs no cross-organization ownership check regardless of secret presence.

### Recommendation
`MembershipHandler` (and other handlers keyed by cross-referenceable IDs) should validate that `params.organization.login` matches the organization actually verified by `verify_signature`, and `Team` records should be scoped/looked-up per-organization rather than by a bare `github_id`. Additionally, `verify_webhook_signature` should not silently accept unsigned payloads when `webhook_secret` is unset in a multi-tenant configuration, or Shipit should require a secret whenever more than one organization is configured.

### Proof of Concept
Not independently executed; derived from static code review of `app/controllers/shipit/webhooks_controller.rb` and `app/models/shipit/webhooks/handlers/membership_handler.rb` per the exploitation steps above.

### Citations

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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```
