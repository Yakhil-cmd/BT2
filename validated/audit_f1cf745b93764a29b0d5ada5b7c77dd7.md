### Title
Membership webhook forges `Shipit.github_teams` membership when organization has no `webhook_secret` configured - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#repository_owner` falls back to `params.dig('organization', 'login')` for events (like `membership`) that lack a `repository` key, and `verify_webhook_signature` returns `true` unconditionally when the resolved organization has no `webhook_secret` configured. Combined with `MembershipHandler`, which trusts the same attacker-supplied `organization.login` field to create/attribute a `Team`, an attacker can add themselves to any `github_id`/team under an org that has no `webhook_secret` set, with no HMAC ever validated.

### Finding Description
The claimed binding is: *organization whose `webhook_secret` verified the request bytes == organization owning the `Team`/`Shipit.github_teams` entry mutated*. Trace:

- `WebhooksController#verify_signature` resolves the verifying org via `repository_owner`: [1](#0-0) 
- `repository_owner` falls back to the attacker-controlled `organization.login` payload field when `repository` is absent: [2](#0-1) 
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally if that org's config has no `webhook_secret`: [3](#0-2) 
- `MembershipHandler` then reads the very same `params.organization.login` to create/attribute the `Team`, and reads `params.team.id` / `params.member.login` to mutate membership, all without any further authorization check: [4](#0-3) 

Since the same attacker-chosen field (`organization.login`) is used both to select the "verifying" org and to attribute the resulting `Team`, an attacker configured with an org that has `webhook_secret: nil` in `Shipit` secrets can name that org in the payload, skip HMAC entirely (`return true unless webhook_secret`), and still have `find_or_create_team!` / `team.add_member` execute using attacker-supplied `team.id`, `team.name`, `team.slug`, `team.url`, and `member.login`. `drop_unhandled_event` does not block `membership`, since it's a handled event via `Shipit::Webhooks.for_event`, and no other check re-validates the org/signature relationship inside `MembershipHandler`.

**However**, this requires the target Shipit installation to have configured at least one GitHub organization with no `webhook_secret` — this is an application/operator misconfiguration precondition, not a flaw the attacker can force on a properly configured install. If every configured organization has a `webhook_secret` set (as documented/expected in `docs/setup.md` and the secrets examples), `verify_webhook_signature` never returns `true` vacuously for any org name the attacker can supply, and the exploit path is closed. The vulnerability is real code behavior, but its reachability strictly depends on an operator leaving `webhook_secret` unset for some configured organization, which is not guaranteed by default and not enforceable/observable by the unprivileged attacker described in scope (they cannot know or force this configuration state).

### Impact Explanation
If reachable, an attacker can create a `Team` record for an arbitrary `github_id`/`organization`/`slug` and add an arbitrary GitHub login (their own) as a member via `team.add_member`, without ever presenting a valid HMAC signature. If that team is later linked into `Shipit.github_teams` (via `oauth_teams` config matching `organization/slug`), this escalates the attacker into whatever authorization gating uses `Shipit.github_teams` — matching the High-severity category "escalation into `Shipit.github_teams` authorization." [5](#0-4) 

### Likelihood Explanation
Requires a Shipit deployment with at least one organization entry in `secrets.github` lacking `webhook_secret` (all documented examples set it). An unprivileged internet attacker who knows or guesses such an org's login name could then POST a crafted `membership` webhook. This is a configuration-dependent precondition outside the attacker's control and not something they can verify without prior information leakage; it is not a universal bypass against a correctly configured instance.

### Recommendation
Do not treat missing `webhook_secret` as "verified" — treat it as verification failure (`return false unless webhook_secret`), and require every configured GitHub organization to have a mandatory `webhook_secret`. Additionally, `MembershipHandler` should not trust `params.organization.login` for team attribution beyond the org that was cryptographically confirmed by `verify_signature`; ideally pass the verified organization down explicitly rather than re-reading it from the payload.

### Proof of Concept
Minitest plan (would need to be added under `test/`, out of scope for this audit but described for completeness):
1. Configure `secrets.github` with an org `evilorg` that has no `webhook_secret`.
2. POST to `/webhooks` with header `X-Github-Event: membership`, no `X-Hub-Signature`, and body `{"action":"added","team":{"id":999,"name":"n","slug":"s","url":"u"},"organization":{"login":"evilorg"},"member":{"login":"attacker"}}`.
3. Assert response is `200`/`ok` (not `422`), and assert `Shipit::Team.find_by(github_id: 999).members.map(&:login)` includes `"attacker"`.
4. Assert `request.headers['X-Hub-Signature']` was never validated (no HMAC computed against real secret).

Given the configuration-dependent precondition, I flag this as valid but conditional — it is a real code defect in `WebhooksController`/`GitHubApp#verify_webhook_signature`/`MembershipHandler`, but not exploitable against a correctly configured deployment where every organization has a `webhook_secret`.

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

**File:** lib/shipit.rb (L256-258)
```ruby
  def github_teams
    @github_teams ||= github.oauth_teams.map { |t| Team.find_or_create_by_handle(t) }
  end
```
